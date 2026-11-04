# eBPF/XDP Programmable Data Plane for SDN

This project moves the classical SDN split (an OpenFlow controller programming
Open vSwitch match-action tables) into the Linux kernel itself. An eBPF program
running at the **XDP** (driver) or **TC** (clsact) hook does the packet
processing. A Python control plane manages policy and load-balancer state
through pinned BPF maps.

For a full explanation of the concepts, the code, a packet's path through the
system and the results, see **[docs/GUIDE.md](docs/GUIDE.md)**.

```
           control_plane.py  (CLI  ·  REST API  ·  conntrack GC thread)
                   │  libbpf (ctypes)  ─  /sys/fs/bpf/sdn_dp/*
 ──────────────────┼────────────────────────────────────────── kernel
                   ▼
   NIC/veth ─► xdp_dataplane / tc_dataplane
               parse ─► firewall ─► L4 LB ─► telemetry ─► NAT ─► (FIB fwd)
                 │         │          │          │
          Eth/VLAN/ARP  firewall_map  lb_services   flow_stats   (PERCPU_ARRAY)
          IPv4/TCP/UDP  fw_conntrack  lb_backends   global_stats (PERCPU_ARRAY)
          ICMP                        lb_conntrack
                                      lb_reverse
```

| Path | Purpose |
|---|---|
| `bpf/` | Kernel data plane. `xdp_prog.c` holds the two entry points (`xdp_dataplane`, `tc_dataplane`); each pipeline stage is its own header (`parser.h`, `firewall.h`, `lb.h`, `telemetry.h`, `pipeline.h`, `xdp_nat.h`, `tc_nat.h`), with the shared ABI in `abi.h` and maps in `maps.h`. |
| `sdn/` | Control plane package: libbpf bindings, map backends, loader, one manager per feature under `dataplane/`, REST API, daemon, CLI |
| `testbed/` | Mininet testbed: addressing, topology, a `Gateway` interface with eBPF / kernel / OVS implementations, Tests 1–4 |
| `tests/` | Unit tests (no root) and kernel data-plane tests via `BPF_PROG_TEST_RUN` (root) |
| `control_plane.py`, `topology.py` | Thin entry points for `sdn` and `testbed` |
| `benchmark.sh` | Test 4 across eBPF-XDP, eBPF-TC, eBPF-TC+FIB, plain kernel and OVS+OpenFlow |
| `services.json` | Example service definition for `control_plane.py daemon --services` |
| `Makefile` | Build (`clang -O2 -target bpf` → `build/xdp_prog.o`), tests, lint, bench |

## Data plane design (`bpf/`)

**Parser.** Handles Ethernet, an optional 802.1Q/802.1ad tag, ARP (IPv4 over
Ethernet), IPv4 (including options and fragments), TCP, UDP and ICMP. Every
header access is preceded by an explicit `data_end` bounds check, so the
verifier accepts it. Truncated or invalid headers are dropped and counted
(`drop_malformed`).

**Stateful firewall.** `firewall_map` is a `BPF_MAP_TYPE_HASH` whose key holds
either a 5-tuple or a MAC 2-tuple (`kind` field). Lookups go from most to least
specific:

```
MAC(src,dst) → MAC(src,*) → IP(proto,src,dst,sport,dport) → IP(proto,src,dst,*,dport)
→ IP(proto,src,dst,sport,*) → IP(proto,src,dst,*,*) → IP(*,src,dst) → IP(*,src,*) → IP(*,*,dst)
```

A `drop` hit returns `XDP_DROP` (or `TC_ACT_SHOT`). An `allow` hit, or no hit
under the default `allow` policy, passes the packet. Allowed flows are recorded
in `fw_conntrack` (an LRU hash). With `fw default drop`, reply traffic of
tracked flows and load-balanced connections is still let through, as on a
stateful firewall. Rule hit counters are updated atomically.

**L4 load balancer.**
- `lb_services` (hash) maps `{VIP, port, proto}` to a service id.
- `lb_backends` (`BPF_MAP_TYPE_ARRAY`) holds up to 16 backends per service.
- New flows are hashed with a jhash mix over the 5-tuple and placed on the
  first *active* backend, probing linearly from there.
- The choice is pinned in `lb_conntrack`, so connections stay sticky. If the
  backend is drained, the connection is re-placed.
- A reverse entry in `lb_reverse` handles the return path.

On the forward path the destination is rewritten (DNAT); on the return path the
source is rewritten back to the VIP (SNAT). Checksums are recomputed in the
kernel:

| Hook | L3 checksum | L4 checksum |
|---|---|---|
| XDP | `bpf_csum_diff()` incremental update | one `bpf_csum_diff()` over pseudo-header IP + port word |
| TC | `bpf_l3_csum_replace()` | `bpf_l4_csum_replace()` with `BPF_F_PSEUDO_HDR` (handles `CHECKSUM_PARTIAL`; UDP zero checksum is kept via `BPF_F_MARK_MANGLED_0`) |

With `--fib-forward`, the program also calls `bpf_fib_lookup()`, rewrites
source and destination MACs, decrements the TTL and redirects to the egress
interface. This bypasses the IP stack. If the lookup fails (for example, no
neighbour entry yet), the packet goes to the stack instead.

**Telemetry.**
- `flow_stats` is a `BPF_MAP_TYPE_PERCPU_ARRAY` with 1024 slots indexed by
  flow hash. Each slot holds the flow key plus packet, byte and last-seen
  counters. The control plane merges the per-CPU copies.
- `global_stats` holds the pipeline counters: rx, pass, drops by reason,
  DNAT/SNAT, new connections, ARP, FIB forwards.

## Control plane (`control_plane.py`)

The control plane uses no BCC. It calls `libbpf.so.1` directly through
`ctypes`, so it works with the ahead-of-time `clang -target bpf` object. Maps
are pinned under `/sys/fs/bpf/sdn_dp/`. That lets several interfaces,
one-shot CLI calls and the long-running daemon share the same kernel state.
Attachments survive after the loader exits.

```bash
# load + attach (builds build/xdp_prog.o if stale); --hook tc for the TC program
python3 control_plane.py load -i gw-eth0 -i gw-eth1 [--hook xdp|tc] \
        [--xdp-mode auto|native|generic] [--fib-forward] [--default allow|drop]

# firewall
python3 control_plane.py fw add --src 10.0.1.1 --dst 10.0.2.3 --bidir          # drop host pair
python3 control_plane.py fw add --src 10.0.1.1 --dst 10.0.2.2 --proto tcp --dport 22
python3 control_plane.py fw add --src-mac 00:00:00:00:01:01                    # drop a MAC
python3 control_plane.py fw add --src 10.0.1.4 --dst 10.0.2.1 --action allow
python3 control_plane.py fw default drop
python3 control_plane.py fw list | del ... | flush

# load balancer
python3 control_plane.py lb add-service --vip 10.100.0.1 --port 80 \
        -b 10.0.2.1:80 -b 10.0.2.2:80 -b 10.0.2.3:80 -b 10.0.2.4:80
python3 control_plane.py lb backend --vip 10.100.0.1 --port 80 --backend 10.0.2.1 down
python3 control_plane.py lb list

# state + telemetry
python3 control_plane.py ct list | flush | gc --idle-timeout 30
python3 control_plane.py stats [--json] [--top 20] [--watch 1]

# daemon: REST API + conntrack expiry (OpenFlow idle_timeout / hard_timeout analogue)
python3 control_plane.py daemon --api 127.0.0.1:8080 --services services.json \
        --idle-timeout 60 --fin-timeout 10 [--hard-timeout 300] [-i gw-eth0 ...]

python3 control_plane.py unload -i gw-eth0 -i gw-eth1
```

### REST API

| Method | Path | Body |
|---|---|---|
| GET | `/stats`, `/flows`, `/firewall`, `/services`, `/conntrack` | – |
| POST | `/firewall` | `{"src","dst","proto","sport","dport","src_mac","dst_mac","action","bidir"}` |
| DELETE | `/firewall` | same as POST (empty body = flush) |
| PUT | `/firewall/default` | `{"action":"allow"\|"drop"}` |
| POST | `/services` | `{"vip","port","proto","backends":["ip:port",...]}` |
| DELETE | `/services` | `{"vip","port","proto"}` |
| PUT | `/services/backend` | `{"vip","port","backend","state":"up"\|"down"}` |
| DELETE | `/conntrack` | – |

```bash
curl -X POST localhost:8080/firewall -d '{"src":"10.0.1.1","dst":"10.0.2.3","bidir":true}'
```

**Conntrack GC.** A background thread compares each entry's `last_seen_ns`
(written by the data plane with `bpf_ktime_get_ns()`, i.e. `CLOCK_MONOTONIC`)
against the configured timeouts:

- `--idle-timeout` applies to idle flows.
- `--fin-timeout` applies once FIN or RST has been seen.
- `--hard-timeout`, if set, caps any flow's total lifetime.

When an LB entry expires, its reverse-NAT entry is deleted with it. Adding a
`drop` rule also flushes any matching established state, so existing
connections cannot bypass the new policy.

## Topology (`topology.py`)

```
 c1 10.0.1.1 ─┐                     ┌─ s1 10.0.2.1
 c2 10.0.1.2 ─┤                     ├─ s2 10.0.2.2      VIP 10.100.0.1:80
 c3 10.0.1.3 ─┼──── gw (eth0..7) ───┼─ s3 10.0.2.3       → s1..s4:80
 c4 10.0.1.4 ─┘                     └─ s4 10.0.2.4
```

Each host has its own veth link to the gateway, using routed access with /32
host routes and proxy ARP. Because of that, **all** traffic crosses the
gateway's data plane, including traffic between two clients.

| `--mode` | Gateway |
|---|---|
| `ebpf` | Linux router with `xdp_prog.c` on all eight gateway interfaces (`--hook xdp\|tc`, `--fib-forward`) |
| `kernel` | the same router without eBPF (baseline) |
| `ovs` | Open vSwitch bridge acting as the L3 gateway through OpenFlow 1.3 rules only. Table 0 holds ACL drops, the VIP → `select` group and stateless reverse-SNAT. Table 1 does routing (MAC rewrite + `dec_ttl`). |

Tests:

1. `pingall` across all 8 hosts (56 pairs).
2. Installs `drop c1↔s3` through the REST API. Checks that c1→s3 is blocked,
   c1→s2 still works and the drops show up in the in-kernel counter. Then
   removes the rule and checks c1→s3 works again.
3. 25 HTTP requests from each of c1–c4 to `10.100.0.1:80`. Every request must
   succeed and all four backends must be hit. It also checks that conntrack
   was populated and that a drained backend (s1) gets no new connections.
4. Benchmark:
   - TCP throughput (`iperf3`)
   - 64-byte UDP packet rate (`iperf3 -u -l 22 -b 0`)
   - ICMP RTT (500 pings)
   - new-connection rate through the VIP
   - in-kernel firewall drop rate during a UDP flood

## Setup

Requirements:

- Linux ≥ 5.10 (TC mode with `--fib-forward` uses `bpf_fib_lookup`; tested on 7.2)
- clang/LLVM
- libbpf ≥ 1.0 with headers
- Python ≥ 3.8
- Mininet ≥ 2.3
- iperf3, iproute2, curl, ethtool (optional; there is an ioctl fallback)
- Open vSwitch, only for `--mode ovs`

```bash
sudo make deps-debian          # Debian/Ubuntu (Arch: make deps-arch, Mininet from AUR)
make                           # clang -O2 -g -target bpf -c bpf/xdp_prog.c -o build/xdp_prog.o
make check                     # build + unit tests + static checks, no root needed
make lint                      # ruff, or pyflakes if ruff is missing
sudo make test-bpf             # kernel data-plane tests (BPF_PROG_TEST_RUN), no Mininet
sudo make test                 # Tests 1-3, XDP hook
sudo make test-tc              # Tests 1-3, TC hook
sudo ./benchmark.sh            # Test 4: ebpf-xdp ebpf-tc ebpf-tc-fib kernel ovs
sudo python3 topology.py --mode ebpf --cli   # interactive; e.g. `gw python3 control_plane.py stats`
sudo make clean-net            # after an interrupted run: mn -c + remove pinned maps
```

For OVS mode, `ovsdb-server` and `ovs-vswitchd` must be running
(`systemctl start openvswitch` or `service openvswitch-switch start`).

## Verified results

All of the following ran on the host (Arch Linux, kernel 7.2.5, libbpf 1.7,
Mininet 2.3.1b4, Open vSwitch 4.0):

- Both programs pass the in-kernel verifier.
- `make test` (XDP) and `make test-tc` (TC) each **pass 9/9**.
- `make unittest`: 33 control-plane tests pass. `make test-bpf`: 35 kernel
  tests pass on both hooks, including checks that every checksum is valid
  after NAT.
- `--mode ovs` passes Tests 1–3, skipping the two checks OpenFlow 1.3 can't
  support (conntrack, backend draining).
- The conntrack GC was checked separately: LB conntrack and reverse entries
  with FIN set were expired after `--fin-timeout`.

Test 4 (`./benchmark.sh`), 10-second runs, single veth path c1 → gw → s2:

| config | TCP Gbps | UDP64 rx pps | RTT avg ms | LB conn/s | FW drop pps |
|---|---|---|---|---|---|
| ebpf-xdp | 3.02 | 148 k | 0.047 | 390 | 231 k |
| ebpf-tc | 2.38 | 139 k | 0.014 | 524 | 277 k |
| ebpf-tc-fib | 2.90 | 144 k | 0.023 | 393 | 241 k |
| kernel (no eBPF) | 3.17 | 187 k | 0.011 | – | – |
| ovs + OpenFlow | 3.41 | 184 k | 0.014 | 393 | – |

The FW drop pps runs dropped every packet sent (721 k of 721 k in the XDP run).
Raw numbers are in `results/*.json`.

**How to read these numbers.**

- On **veth**, XDP does not show its real advantage. Native veth XDP converts
  each skb into an `xdp_buff` and disables GRO/TSO aggregation for that path,
  which is why TCP throughput drops compared with the plain kernel router.
- XDP pays off on physical NICs with native driver support (i40e, ice, mlx5,
  …). There, `XDP_DROP` and `XDP_REDIRECT` run before any skb is allocated.
- The "FW drop pps" column is capped by the single-threaded Python UDP sender,
  not by the data plane.
- For publishable numbers: run on a physical NIC, pin CPUs, use `pktgen` or
  TRex as the generator, and use runs longer than 5 s.

## Notes and limitations

- **Checksum offload.** `topology.py` disables TX checksum offload on all
  veths. Otherwise XDP sees `CHECKSUM_PARTIAL` packets whose L4 checksum field
  holds only a pseudo-header sum. The TC hook handles that case correctly
  regardless.
- **XDP fast-forward on veth.** `--fib-forward` with the XDP hook uses
  `XDP_REDIRECT`. On veth this only works if the *peer* has an XDP program
  attached, so use it with `--hook tc` in Mininet, or with XDP on physical
  NICs.
- **Firewall vs. NAT order.** Firewall rules are evaluated on the pre-NAT
  tuple. To restrict who may reach a service, write the rule against the VIP.
- **OVS baseline reverse NAT.** OpenFlow 1.3 has no conntrack, so the OVS
  baseline uses stateless reverse NAT. Direct (non-VIP) HTTP to a backend's
  port 80 is rewritten to the VIP in OVS mode.
- **Telemetry collisions.** `flow_stats` is a fixed-size hash-indexed array.
  On a slot collision the newest flow replaces the older one. Use `ct list`
  for exact per-connection counters.
