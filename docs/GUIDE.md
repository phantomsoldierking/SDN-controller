# eBPF/XDP Programmable Data Plane: The Complete Guide

This guide explains the whole project from first principles: the networking
ideas behind it, the tools it uses (Mininet, Open vSwitch, eBPF, XDP, TC), how
each source file works line by line, how a packet travels through the system,
what the tests check, and what the benchmark results mean.

The [README](../README.md) is the short reference: how to build, run and use
the CLI. This document is the long explanation.

---

## Table of contents

1. [What this project is](#1-what-this-project-is)
2. [Background concepts](#2-background-concepts)
   - 2.1 Software-Defined Networking (SDN)
   - 2.2 OpenFlow and Open vSwitch
   - 2.3 Mininet
   - 2.4 eBPF
   - 2.5 XDP and TC: the two hook points
   - 2.6 BPF maps
   - 2.7 The verifier
   - 2.8 Firewalls, conntrack, NAT and L4 load balancing
   - 2.9 Checksums and incremental updates
3. [Architecture](#3-architecture)
4. [The test network](#4-the-test-network)
5. [A packet's journey, step by step](#5-a-packets-journey-step-by-step)
6. [Code walkthrough: `xdp_prog.c`](#6-code-walkthrough-xdp_progc)
7. [Code walkthrough: `control_plane.py`](#7-code-walkthrough-control_planepy)
8. [Code walkthrough: `topology.py`](#8-code-walkthrough-topologypy)
9. [`benchmark.sh` and the `Makefile`](#9-benchmarksh-and-the-makefile)
10. [Test results](#10-test-results)
11. [Benchmark results and how to read them](#11-benchmark-results-and-how-to-read-them)
12. [Problems found along the way and how they were fixed](#12-problems-found-along-the-way-and-how-they-were-fixed)
13. [Limitations and possible extensions](#13-limitations-and-possible-extensions)
14. [Glossary](#14-glossary)

---

## 1. What this project is

Classical SDN splits a network into two parts:

- **Switches** that forward packets by looking them up in match-action tables.
- **A controller** that fills those tables, usually over the OpenFlow protocol.

This project builds the same split differently. The "switch" is a small
program running **inside the Linux kernel**, loaded with eBPF and attached at
the earliest point a packet can be seen (XDP) or just after (TC). The
"controller" is a Python program that writes rules into shared kernel tables
(BPF maps) while the system is running.

The kernel program implements four network functions on a gateway:

| Function | What it does |
|---|---|
| **Packet parser** | Safely decodes Ethernet, VLAN, ARP, IPv4, TCP, UDP and ICMP headers. |
| **Stateful firewall** | Drops or allows traffic by 5-tuple or MAC address, and remembers allowed connections. |
| **L4 load balancer** | Spreads connections to a virtual IP (`10.100.0.1:80`) over four backend servers, rewriting addresses and checksums in the kernel. |
| **Telemetry** | Counts packets and bytes per flow and per event, without locks. |

Around it are a control plane (CLI + REST API + connection-expiry thread), a
Mininet test network with 1 gateway, 4 clients and 4 servers, four automated
tests, and a benchmark comparing the eBPF data plane with plain Linux routing
and with a classical Open vSwitch + OpenFlow setup.

---

## 2. Background concepts

### 2.1 Software-Defined Networking (SDN)

In a traditional network every router and switch decides for itself how to
forward packets, using its own built-in logic and protocols. SDN separates
two jobs:

- The **data plane** moves packets. It must be fast and simple: look at a
  packet, find a matching rule, apply the rule's action (forward, drop,
  rewrite).
- The **control plane** decides what the rules should be. It can be slow and
  smart, and it usually runs in ordinary software on a server.

The benefit is programmability. A firewall policy, a load-balancing pool or a
routing change becomes "write a few table entries" instead of "reconfigure
every box".

### 2.2 OpenFlow and Open vSwitch

**OpenFlow** is the standard protocol a controller uses to program switches.
A switch holds one or more **flow tables**. Each entry has:

- a **match**: header fields such as `ip,nw_src=10.0.1.1,nw_dst=10.0.2.3`
- a **priority**: the highest-priority match wins
- **actions**: `output:3`, `drop`, `set_field:...`, `dec_ttl`, `goto_table:1`,
  `group:1`, …
- optional **timeouts**: `idle_timeout` removes an entry after N seconds
  without traffic; `hard_timeout` removes it N seconds after creation.

**Groups** extend this. A `select` group holds several **buckets** (action
lists) and picks one bucket per flow by hashing packet fields. That is how
OpenFlow does load balancing.

**Open vSwitch (OVS)** is the most widely used software switch that speaks
OpenFlow. It has a user-space daemon (`ovs-vswitchd`), a configuration
database (`ovsdb-server`) and a kernel module (`openvswitch.ko`) that caches
flows for speed. `ovs-ofctl` is the command-line tool to install flows by
hand. In this project's `ovs` mode, OVS is the classical baseline.

### 2.3 Mininet

**Mininet** is a network emulator: it creates a realistic virtual network on
one Linux machine in a second. It doesn't use virtual machines. Instead it
relies on two kernel features:

- **Network namespaces.** Each emulated host (`c1`, `s3`, `gw`, …) is a shell
  process in its own network namespace. A namespace has its own interfaces,
  IP addresses, routing table, ARP table and firewall rules, so to programs
  inside it, it looks like a separate machine. All hosts still share the same
  filesystem and process table.
- **veth pairs.** A virtual Ethernet pair is two interfaces joined by a wire:
  a packet sent into one end comes out of the other. Mininet puts one end in
  each of two namespaces to create a "cable" between two hosts.

Mininet can also create switches (usually OVS bridges) and connect a
controller. Its Python API (`Mininet`, `addHost`, `addLink`, `net.ping`,
`host.cmd(...)`) lets a script build the topology, run commands inside any
host and check the results. That's exactly what `topology.py` does.

Because hosts are just processes, Mininet is cheap and fast. Because
everything shares one kernel, a BPF program attached to an interface in the
`gw` namespace is a real kernel program processing real packets, not a
simulation.

### 2.4 eBPF

**eBPF** (extended Berkeley Packet Filter) lets you load small programs into
the running Linux kernel without writing a kernel module or rebooting. The
workflow is:

1. Write the program in restricted C.
2. Compile it with `clang -target bpf` into BPF bytecode, stored in an ELF
   object (`xdp_prog.o`).
3. Load it with the `bpf()` system call (here via **libbpf**). The kernel's
   **verifier** checks that it is safe.
4. The kernel JIT-compiles it to native machine code.
5. **Attach** it to a hook, such as a network interface. From then on it runs
   for every event at that hook.

eBPF programs can't call arbitrary kernel functions. They call a fixed set of
**helper functions** (`bpf_map_lookup_elem`, `bpf_csum_diff`,
`bpf_fib_lookup`, `bpf_redirect`, …) and store state in **maps**.

eBPF is what Cilium (Kubernetes networking), Katran (Facebook's load
balancer) and Cloudflare's DDoS protection are built on. That's the
"cloud-native kernel offloading" in this project's title.

### 2.5 XDP and TC: the two hook points

Linux can run a network BPF program at several points. This project supports
the two that matter for a data plane:

```
  wire ─► NIC driver ─► [XDP] ─► allocate sk_buff ─► [TC ingress] ─► IP stack ─► ...
                          ▲                                ▲
                    xdp_dataplane                    tc_dataplane
```

**XDP (eXpress Data Path)** runs inside the network driver, before the kernel
has allocated its packet structure (`sk_buff`). The program sees raw packet
bytes (`struct xdp_md`) and returns a verdict:

| Return value | Meaning |
|---|---|
| `XDP_DROP` | Discard immediately. This is the cheapest possible drop, which is why DDoS filters use it. |
| `XDP_PASS` | Continue into the normal kernel network stack. |
| `XDP_TX` / `XDP_REDIRECT` | Send the packet back out, or out of another interface, without touching the stack. |

Physical NICs with driver support run XDP in **native mode**. Any interface
can use **generic mode**, which runs after the `sk_buff` exists and so loses
most of the speed advantage. `veth` interfaces have their own native XDP
support.

**TC (traffic control) clsact** runs a little later, after the `sk_buff` has
been built. The program gets a `struct __sk_buff` and returns `TC_ACT_OK`
(continue), `TC_ACT_SHOT` (drop) or a `bpf_redirect()` result. TC is slightly
slower than native XDP, but it can use helpers that need an `sk_buff`, such
as `bpf_l3_csum_replace` and `bpf_l4_csum_replace`. Those understand the
kernel's checksum-offload state.

The task asked for both XDP-style processing and the TC-only checksum helpers,
so `xdp_prog.c` contains **two entry points sharing one pipeline and one set
of maps**. You choose one at load time with `--hook xdp|tc`.

### 2.6 BPF maps

A **map** is a key-value store that lives in the kernel and is shared by BPF
programs and user space. The kernel program reads and writes it on every
packet; the control plane reads and writes it through the `bpf()` system
call. Map types used here:

| Type | Behaviour | Used for |
|---|---|---|
| `BPF_MAP_TYPE_HASH` | Hash table with arbitrary keys | Firewall rules, LB services |
| `BPF_MAP_TYPE_LRU_HASH` | Hash table that evicts the least-recently-used entry when full | Connection tracking, which can never "fill up" and stop working |
| `BPF_MAP_TYPE_ARRAY` | Fixed-size array indexed by integer | Backend pools, configuration |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | An array with one private copy per CPU | Counters: each CPU increments its own copy with no locks or atomics, and the control plane adds the copies together when reading |

Maps can be **pinned** to the BPF filesystem (`/sys/fs/bpf/...`). A pinned
map outlives the program that created it, and any process can open it by
path. This project pins all maps under `/sys/fs/bpf/sdn_dp/`. That's how the
one-shot CLI commands, the REST daemon and the expiry thread all reach the
same state.

### 2.7 The verifier

Before the kernel runs a BPF program, the **verifier** simulates every
possible path through it and refuses to load it unless it can prove the
program:

- never reads or writes outside the packet or a map value,
- never dereferences a possibly-NULL pointer (every map lookup must be
  NULL-checked),
- always terminates (loops must have a provable upper bound),
- only calls helpers allowed at that hook.

The practical consequence for a packet parser is that **every header access
must be preceded by an explicit bounds check**:

```c
struct iphdr *iph = data + off;
if ((void *)(iph + 1) > data_end)   // without this, the verifier rejects the program
    return PARSE_MALFORMED;
```

Getting a non-trivial program past the verifier is the main difficulty of eBPF
development. Both programs in this project passed it on the first load.

### 2.8 Firewalls, conntrack, NAT and L4 load balancing

**5-tuple.** A transport connection is identified by
`(source IP, destination IP, source port, destination port, protocol)`.
Firewall rules and connection tables are keyed by it, or by parts of it.

**Stateless vs. stateful firewall.** A stateless firewall judges every packet
on its own. A **stateful** firewall also remembers connections it has
allowed. That lets a "default drop" policy still accept *replies* to
connections that were allowed going out. This memory is called **connection
tracking (conntrack)**.

**NAT (Network Address Translation)** rewrites addresses in packet headers:

- **DNAT** (destination NAT) changes where a packet is going. Here,
  `client → 10.100.0.1:80` becomes `client → 10.0.2.3:80`.
- **SNAT** (source NAT) changes where a packet appears to come from. Here,
  the reply `10.0.2.3:80 → client` becomes `10.100.0.1:80 → client`, so the
  client sees the address it originally contacted.

**L4 load balancer.** Clients connect to one **virtual IP (VIP)**. The load
balancer picks a backend for each new connection, then keeps all packets of
that connection on the same backend (**stickiness**). If packets of one TCP
connection went to different servers, the connection would break. Picking is
done by **hashing** the 5-tuple, and the choice is recorded in a conntrack
table.

### 2.9 Checksums and incremental updates

IPv4 headers carry a 16-bit **header checksum**. TCP and UDP carry a checksum
over their header, payload and a **pseudo-header** containing the source and
destination IP addresses. So rewriting an IP address requires updating
**both** checksums, and rewriting a port requires updating the L4 checksum.

Recomputing a checksum over the whole packet would be slow. Instead, the
Internet checksum (ones'-complement sum) allows an **incremental update**
(RFC 1624):

```
new_checksum = ~( ~old_checksum + ~old_value + new_value )
```

Only the changed words matter, whatever the packet size. In this project:

- **XDP path:** `bpf_csum_diff(from, from_size, to, to_size, seed)` computes
  the `~old + new` part, and the code folds the result back into 16 bits.
- **TC path:** `bpf_l3_csum_replace()` and `bpf_l4_csum_replace()` do the
  whole update. With the `BPF_F_PSEUDO_HDR` flag they also handle packets
  whose checksum hasn't been finalised yet (checksum offload, see §12.3).

---

## 3. Architecture

```
                 ┌──────────────────────── user space ────────────────────────┐
                 │  control_plane.py                                          │
                 │   ├─ CLI           (fw / lb / ct / stats / load / unload)  │
                 │   ├─ REST API      (http://127.0.0.1:8080)                 │
                 │   └─ GC thread     (expires idle connections)              │
                 │            │ libbpf.so (ctypes)                            │
                 └────────────┼───────────────────────────────────────────────┘
                              │  bpf() syscalls on pinned maps
             /sys/fs/bpf/sdn_dp/{firewall_map, fw_conntrack, lb_services, ...}
                              │
 ─────────────────────────────┼──────────────── kernel ────────────────────────
                              ▼
   packet ─► xdp_dataplane / tc_dataplane
               │
               ├─ 1. parse_packet()      Eth ─► VLAN ─► ARP | IPv4 ─► TCP/UDP/ICMP
               ├─ 2. telemetry()         flow_stats, global_stats  (per-CPU)
               ├─ 3. firewall()          firewall_map ─► fw_conntrack
               ├─ 4. load_balance()      lb_services ─► lb_backends ─► lb_conntrack / lb_reverse
               ├─ 5. apply NAT           XDP: bpf_csum_diff   TC: bpf_l3/l4_csum_replace
               └─ 6. verdict             DROP / PASS / (FIB lookup ─► MAC rewrite ─► redirect)
```

Data flows one way per packet, top to bottom. The control plane never
touches packets. It only changes the tables the data plane consults, which is
the SDN split exactly.

### The nine maps

| Map | Type | Key → Value | Written by |
|---|---|---|---|
| `firewall_map` | HASH (4096) | `fw_key` (5-tuple or MAC pair) → `{action, hits}` | control plane (rules), data plane (hit counter) |
| `fw_conntrack` | LRU_HASH (65536) | `flow_key` → `{created, last_seen, packets, bytes, TCP flags}` | data plane; GC deletes |
| `lb_services` | HASH (16) | `{VIP, port, proto}` → `{service id, backend count}` | control plane |
| `lb_backends` | ARRAY (16×16) | `service_id*16 + i` → `{IP, port, active}` | control plane |
| `lb_conntrack` | LRU_HASH (65536) | client→VIP `flow_key` → `{chosen backend, timestamps, counters}` | data plane; GC deletes |
| `lb_reverse` | LRU_HASH (65536) | backend→client `flow_key` → `{VIP, VIP port}` | data plane; GC deletes |
| `flow_stats` | PERCPU_ARRAY (1024) | `hash(flow) % 1024` → `{flow key, packets, bytes, last_seen}` | data plane |
| `global_stats` | PERCPU_ARRAY (13) | counter index → `u64` | data plane |
| `dp_config_map` | ARRAY (1) | `0` → `{default action, flags}` | control plane |

All IP addresses and ports in keys and values are stored in **network byte
order** (exactly as on the wire), so the data plane never has to convert
them. The Python side converts at the edges (`ip2be`, `port2be`).

---

## 4. The test network

```
 c1 10.0.1.1 ──┐                         ┌── s1 10.0.2.1
 c2 10.0.1.2 ──┤                         ├── s2 10.0.2.2       Service VIP
 c3 10.0.1.3 ──┼──────── gw ─────────────┼── s3 10.0.2.3       10.100.0.1:80
 c4 10.0.1.4 ──┘   gw-eth0 … gw-eth7     └── s4 10.0.2.4       → s1..s4 :80
      clients: 10.0.1.0/24, gateway 10.0.1.254
      servers: 10.0.2.0/24, gateway 10.0.2.254
```

### Why every host has its own link to the gateway

A simpler design would put the clients on one switch and the servers on
another. But then c1 → c2 traffic would never reach the gateway, and the
firewall could not see it. Instead, each of the 8 hosts has a **direct veth
link** to the gateway (`gw-eth0` … `gw-eth7`), so **every packet between any
two hosts crosses the gateway's data plane**. This is the "routed access"
design used by Kubernetes CNIs such as Calico.

Making this work with ordinary IP subnets takes three tricks, all set up in
`setup_router()` ([topology.py:163](../topology.py:163)):

1. **The same gateway address on several interfaces.** `10.0.1.254/32` is
   added to each of `gw-eth0..3` and `10.0.2.254/32` to each of `gw-eth4..7`.
   Every client finds "its" gateway on its own link.
2. **/32 host routes.** `ip route add 10.0.1.1/32 dev gw-eth0` and so on.
   The gateway knows exactly which link each host is on.
3. **Proxy ARP.** When c1 wants to reach c2 (same /24), it ARPs for
   `10.0.1.2` on its own link. Only the gateway is on that link. With
   `proxy_arp=1`, the gateway answers with its own MAC because it has a route
   to `10.0.1.2` via another interface. c1 then sends the packet to the
   gateway, which routes it.

On top of that, the gateway has `ip_forward=1` (act as a router) and
`rp_filter=0`. Reverse-path filtering would otherwise drop replies whose
source was rewritten to the VIP, since the gateway has no route back to
`10.100.0.1`.

### The three modes

| `--mode` | What `gw` is | What does the work |
|---|---|---|
| `ebpf` | A Linux host acting as a router | `xdp_prog.c` attached to all 8 gateway interfaces, plus the kernel's routing |
| `kernel` | The same Linux router | Only the kernel's routing: no firewall, no LB. This is the "cost of doing nothing" baseline. |
| `ovs` | An Open vSwitch bridge | OpenFlow 1.3 rules emulate the router, the firewall and the load balancer (§8.3) |

---

## 5. A packet's journey, step by step

Follow one HTTP request from c1 to the VIP in `ebpf` mode with the XDP hook.

**Step 0: setup.** The control plane has installed a service: `lb_services`
has `{10.100.0.1, 80, TCP} → {id 0, count 4}`, and `lb_backends[0..3]` holds
s1–s4.

**Step 1: c1 sends a SYN.** c1's routing table says `default via 10.0.1.254`.
c1 builds `10.0.1.1:53902 → 10.100.0.1:80 [SYN]` with the gateway's MAC as
destination and sends it out `c1-eth0`.

**Step 2: XDP runs on `gw-eth0`.** Before the gateway's kernel builds an
`sk_buff`, `xdp_dataplane` runs:

1. `parse_packet()` checks bounds and decodes Ethernet → IPv4 → TCP, filling
   `p.key = {10.0.1.1, 10.100.0.1, 53902, 80, TCP}`.
2. `telemetry()` hashes the key to a slot in `flow_stats` and increments this
   CPU's counters.
3. `firewall()` looks up the key in `firewall_map` from most to least
   specific. Nothing matches and the default is "allow". The flow is recorded
   in `fw_conntrack`.
4. `load_balance()` finds `{10.100.0.1, 80, TCP}` in `lb_services`. There's no
   `lb_conntrack` entry for this 5-tuple yet, so it's a new connection:
   - `flow_hash(key) % 4` = 2, so it picks backend index 2, which is s3. If
     s3 were marked down, it would probe index 3, then 0, and so on.
   - It records `lb_conntrack[c1:53902→VIP:80] = s3:80`.
   - It records `lb_reverse[s3:80→c1:53902] = VIP:80`, ready for the reply.
   - It sets the verdict to DNAT, `10.100.0.1:80 → 10.0.2.3:80`.
5. `xdp_apply_nat()` rewrites the destination IP to `10.0.2.3` and updates
   the IP header checksum and the TCP checksum (pseudo-header changed) with
   `bpf_csum_diff`.
6. It returns `XDP_PASS`.

**Step 3: the kernel routes it.** The gateway's IP stack now sees a packet for
`10.0.2.3`, finds the `/32` route via `gw-eth6`, rewrites the MAC addresses,
decrements the TTL and sends it. (With `--fib-forward`, the BPF program does
this itself with `bpf_fib_lookup` + `bpf_redirect` and skips the stack.)

**Step 4: s3 answers.** s3's web server sees a normal connection from
`10.0.1.1:53902` to its own address and replies with
`10.0.2.3:80 → 10.0.1.1:53902 [SYN,ACK]`.

**Step 5: XDP runs on `gw-eth6`.**
`load_balance()` finds no service for destination `10.0.1.1:53902`, so it
checks `lb_reverse` with the packet's key, gets a hit and sets the verdict
to SNAT, `10.0.2.3:80 → 10.100.0.1:80`. After the rewrite, the packet reads
`10.100.0.1:80 → 10.0.1.1:53902`.

**Step 6: c1 receives the reply.** From c1's point of view it talked to
`10.100.0.1` the whole time. The connection completes, and every later packet
of it hits the existing `lb_conntrack` / `lb_reverse` entries and goes to s3.

**Step 7: cleanup.** When the connection closes, the FIN flag is recorded in
the conntrack entries. The control plane's GC thread sees `FIN` plus more than
`--fin-timeout` seconds idle and deletes both entries. This is the OpenFlow
`idle_timeout` behaviour, implemented in user space.

**What a firewall drop looks like.** With rule `drop 10.0.1.1 ↔ 10.0.2.3`,
step 2.3 finds a match on `IP(*, 10.0.1.1, 10.0.2.3, *, *)`, increments the
rule's hit counter and `global_stats[drop_firewall]`, and returns `XDP_DROP`.
The packet never reaches the kernel's IP stack.

---

## 6. Code walkthrough: `xdp_prog.c`

The file is organised top to bottom in pipeline order.

### 6.1 Shared ABI ([xdp_prog.c:59-197](../xdp_prog.c:59))

The structs that serve as map keys and values are the **contract** between C
and Python. Every struct is padded explicitly, for example `__u8 pad[2]`, so
there is no compiler-inserted padding. `control_plane.py` defines the same
structs with `ctypes` and checks the sizes at import time
(`assert ct.sizeof(FlowKey) == 16`, and so on). If the two sides ever drift
apart, the control plane refuses to start instead of silently corrupting
maps.

The key structs are:

- `flow_key` (16 bytes): source and destination address, source and
  destination port, protocol, plus an `l3` field that tells ARP from IPv4
  entries.
- `fw_key` (28 bytes): a `kind` field (IP or MAC) plus room for both a
  5-tuple and two MAC addresses. Unused fields are zero, and zero means
  "wildcard" in the lookup order.

### 6.2 Maps ([xdp_prog.c:199-260](../xdp_prog.c:199))

These are declared in libbpf's BTF style:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FW_RULES);
    __type(key, struct fw_key);
    __type(value, struct fw_rule);
} firewall_map SEC(".maps");
```

libbpf reads the `.maps` section and creates each map at load time, or reuses
an existing pinned map with the same name.

### 6.3 Helpers ([xdp_prog.c:302-355](../xdp_prog.c:302))

- `stat_add()` increments a per-CPU counter. It needs no atomic operation
  because each CPU owns its copy.
- `flow_hash()` is Bob Jenkins' `jhash` final mix over the 5-tuple. It is
  deterministic, so the same flow always hashes the same way, and it spreads
  well enough for a fair backend split.
- `reverse_key()` swaps source and destination, to find the other direction
  of a connection.
- `csum_fold()` folds a 32-bit ones'-complement sum into 16 bits and inverts
  it. The fixed 4-iteration `#pragma unroll` loop keeps the verifier happy.

### 6.4 Parser ([xdp_prog.c:374-470](../xdp_prog.c:374))

`parse_packet(data, data_end, &p)` takes only raw pointers, so the same code
works for XDP (`ctx->data`) and TC (`skb->data`). In order:

1. **Ethernet.** Bounds check, read `h_proto`.
2. **VLAN.** If the frame has one 802.1Q or 802.1ad tag, skip 4 bytes and
   read the inner protocol.
3. **ARP.** Check it's Ethernet/IPv4 ARP (`hln == 6`, `pln == 4`) and record
   sender and target IPs for telemetry and MAC rules.
4. **IPv4.** Check `version == 4` and `ihl >= 5`, then check the full header
   *including options* (`ihl * 4` bytes) fits, and that `tot_len` is
   consistent. Malformed packets return `PARSE_MALFORMED` and are dropped.
5. **Fragments.** If the fragment offset is non-zero, there's no L4 header in
   this packet, so stop. The first fragment, with offset 0, still has one.
6. **TCP/UDP/ICMP.** Bounds-check the L4 header and record ports, plus TCP
   flags (byte 13 of the header) for connection tracking.

Each step returns early on failure. Because every pointer is checked against
`data_end` before use, the verifier can prove there are no out-of-bounds
reads.

### 6.5 Stateful firewall ([xdp_prog.c:490-645](../xdp_prog.c:490))

`fw_lookup()` tries up to 9 keys, most specific first, and stops at the first
hit:

```
MAC(src,dst) → MAC(src,*)
IP(proto,src,dst,sport,dport) → IP(proto,src,dst,*,dport) → IP(proto,src,dst,sport,*)
→ IP(proto,src,dst,*,*) → IP(*,src,dst,*,*) → IP(*,src,*,*,*) → IP(*,*,dst,*,*)
```

That gives OpenFlow-like wildcards ("block this host", "block this host pair",
"block TCP/22 between these two") using an exact-match hash table. A hit
increments the rule's `hits` counter with `__sync_fetch_and_add` (atomic,
because rules are shared across CPUs).

`firewall()` turns the lookup result into a decision:

- An explicit `drop` rule always wins.
- ARP is only subject to MAC rules, so a strict IP policy can't break address
  resolution.
- If no rule matched and the default policy is `drop`, the packet is still
  allowed if `ct_established()` finds it belongs to a known connection: an
  existing entry in either direction in `fw_conntrack`, or a load-balancer
  reply in `lb_reverse`. This is what makes the firewall stateful.
- `ct_touch()` records or refreshes allowed flows. If the packet is the reply
  direction of an existing entry, it sets the `REPLY` flag on that entry
  instead of creating a second one.

### 6.6 Load balancer ([xdp_prog.c:648-784](../xdp_prog.c:648))

`load_balance()` handles both directions.

**Forward (client → VIP).**

1. Look up `{dst IP, dst port, proto}` in `lb_services`.
2. If `lb_conntrack` has this 5-tuple *and* the recorded backend is still
   active with the same IP, reuse it. Otherwise choose a new backend with
   `lb_select()`. That way, draining a backend moves its connections
   elsewhere.
3. `lb_select()` starts at `hash % count` and probes linearly for the first
   `active` backend. The loop is bounded by `MAX_BACKENDS_PER_SVC` (16) so the
   verifier can prove it ends. If no backend is active, the packet is dropped
   and counted as `drop_no_backend`.
4. New connections write both the forward entry (`lb_conntrack`) and the
   reverse entry (`lb_reverse`). The reverse key is built exactly as the
   backend's reply will look: `{backend IP, client IP, backend port, client
   port, proto}`.
5. The verdict is DNAT from `{VIP, VIP port}` to `{backend IP, backend port}`.

**Reverse (backend → client).** A hit in `lb_reverse` gives the verdict SNAT
from `{backend IP, port}` back to `{VIP, VIP port}`.

The function only *decides*. The actual packet rewrite happens in the
hook-specific code (§6.9), because XDP and TC rewrite packets differently.

### 6.7 Telemetry ([xdp_prog.c:786-805](../xdp_prog.c:786))

The flow key is hashed to one of 1024 slots in the per-CPU `flow_stats`
array. If the slot holds a different flow (a hash collision), the new flow
takes it over and the counters reset. Packets and bytes are then added, and
`last_seen` is updated. This bounded, lock-free design suits telemetry; exact
per-connection numbers are kept in the conntrack maps.

### 6.8 The shared pipeline ([xdp_prog.c:807-848](../xdp_prog.c:807))

`pipeline()` calls everything above in order: config lookup, timestamp
(`bpf_ktime_get_ns()`), parse, counters, telemetry, firewall, load balancer.
It fills a `struct verdict` `{drop, nat kind, old/new address, old/new port}`.
Both entry points call this one function, so XDP and TC behave identically by
construction.

### 6.9 XDP entry point ([xdp_prog.c:850-984](../xdp_prog.c:850))

`xdp_apply_nat()` rewrites the packet in place, through the bounds-checked
header pointers from the parser:

```c
/* L4: pseudo-header address + port word, one bpf_csum_diff() call. */
__u32 from[2] = { v->old_addr, old_ports };
__u32 to[2]   = { v->new_addr, new_ports };
sum = bpf_csum_diff(from, 8, to, 8, (__u16)~(*l4_check));
*l4_check = csum_fold(sum);
```

The first 4 bytes of both TCP and UDP headers are `(source port, destination
port)`. That lets the IP-address change and the port change go into one
8-byte `bpf_csum_diff`, which requires sizes that are multiples of 4. A UDP
checksum of 0 means "no checksum" and is left alone. A computed result of 0
becomes `0xffff`, as the UDP spec requires. The IP header checksum is updated
the same way. Then the new address and ports are written.

`xdp_fib_forward()` (optional, `--fib-forward`):

1. Asks the kernel's routing table with `bpf_fib_lookup()`: "where does this
   packet go, and what are the next-hop MAC addresses?"
2. If the lookup succeeds, decrements the TTL and patches the checksum by
   hand (`ip_decrease_ttl`, as the kernel does it).
3. Rewrites both MACs and returns `bpf_redirect(egress_ifindex)`.

If the TTL is 1, or there's no neighbour entry yet, it returns `XDP_PASS` and
lets the stack handle it. That way TTL-exceeded errors and ARP resolution
still work.

`xdp_dataplane()` itself is short: run the pipeline, then drop if the verdict
says so, then apply NAT, then either FIB-forward or `XDP_PASS`.

### 6.10 TC entry point ([xdp_prog.c:986-1101](../xdp_prog.c:986))

`tc_dataplane()` first calls `bpf_skb_pull_data()` if the headers might sit
in the non-linear part of the `sk_buff`. Then it runs the same pipeline.

`tc_apply_nat()` uses the skb helpers named in the task:

```c
bpf_l4_csum_replace(skb, csum_off, old_ip,   new_ip,   BPF_F_PSEUDO_HDR | 4);
bpf_l4_csum_replace(skb, csum_off, old_port, new_port, 2);
bpf_l3_csum_replace(skb, ip_csum_off, old_ip, new_ip, 4);
bpf_skb_store_bytes(skb, addr_off, &new_ip, 4, 0);
bpf_skb_store_bytes(skb, port_off, &new_port, 2, 0);
```

These helpers take byte offsets rather than pointers, and they understand
`CHECKSUM_PARTIAL` packets (§12.3), so TC NAT is correct even with checksum
offload on. `BPF_F_MARK_MANGLED_0` keeps the UDP "no checksum" rule.

`tc_fib_forward()` works like the XDP version, but reads the IP header with
`bpf_skb_load_bytes` (direct packet pointers are invalidated after the
helpers above modify the packet). It updates the TTL's checksum word with
`bpf_l3_csum_replace` and redirects with `bpf_redirect()`. Redirecting to a
veth works reliably from TC, which is why `ebpf-tc-fib` is a benchmark
configuration.

---

## 7. Code walkthrough: `control_plane.py`

### 7.1 Talking to libbpf without BCC ([control_plane.py:212-260](../control_plane.py:212))

The task allowed BCC or libbpf. BCC compiles C at runtime with its own macro
dialect, which conflicts with a normal `clang -target bpf` build. So the
control plane calls the system's **libbpf.so.1 directly through Python's
`ctypes`**. The `Libbpf` class declares the argument and return types for
about 20 libbpf functions (`bpf_object__open_file`, `bpf_xdp_attach`,
`bpf_tc_attach`, `bpf_map_update_elem`, …). Pointer-returning functions are
declared `c_void_p`, which avoids 64-bit pointer truncation, a classic
`ctypes` bug. `check()` turns negative errno results into readable
exceptions.

The `TcHook` and `TcOpts` ctypes structs mirror libbpf's
`struct bpf_tc_hook` and `struct bpf_tc_opts` exactly. Their `sz` field
carries the struct size, as libbpf's versioned-options convention requires.

### 7.2 ABI mirror ([control_plane.py:66-142](../control_plane.py:66))

`FlowKey`, `FwKey`, `LbCt` and the rest are `ctypes.Structure` copies of the
C structs, followed by an `assert` on every size. The `MAPS` dictionary maps
each map name to its key type, value type and whether it is per-CPU.

Byte-order helpers ([control_plane.py:147-195](../control_plane.py:147))
convert at the edges. `ip2be("10.0.2.3")` produces the integer whose in-memory
little-endian bytes equal the on-wire bytes, which is exactly what the kernel
program compares against.

### 7.3 Build, load, attach ([control_plane.py:272-375](../control_plane.py:272))

`build()` recompiles `xdp_prog.o` only if the C source is newer.

`load_and_attach()`:

1. Opens the object file.
2. For every map, sets a pin path under `/sys/fs/bpf/sdn_dp/`. If a pinned
   map already exists, libbpf **reuses** it, so attaching to more interfaces
   later (or reloading) keeps all rules and state.
3. Enables autoload only for the program that matches `--hook`, so a TC-only
   problem can never block an XDP load, and the other way round.
4. Calls `bpf_object__load()`. This is where the verifier runs.
5. Attaches to each interface: `bpf_xdp_attach(ifindex, fd, mode)` for XDP,
   or for TC, `bpf_tc_hook_create` (creates the clsact qdisc) plus
   `bpf_tc_attach`.
6. Writes the initial config: default action, stateful flag and FIB-forward
   flag.
7. Closes the object. Both attachment types are held by the kernel, so the
   program keeps running after the loader exits.

`detach()` removes both hook types and unpins the maps. It temporarily
silences libbpf's logging, since "there was nothing attached here" is not an
error worth printing.

### 7.4 Map access ([control_plane.py:378-428](../control_plane.py:378))

`BpfMap` opens a pinned map with `bpf_obj_get(path)` and wraps lookup,
update, delete and iteration (`bpf_map_get_next_key`). For per-CPU maps, the
kernel returns one value per *possible* CPU, each padded to 8 bytes.
`_percpu_values()` splits that buffer into a list.

### 7.5 `DataPlane`: all operations in one place ([control_plane.py:431-678](../control_plane.py:431))

Both the CLI and the REST API call these methods, so there is one
implementation of every operation:

| Method | What it does |
|---|---|
| `fw_add` / `fw_del` / `fw_list` / `fw_flush` | Convert a rule dict (src, dst, proto, ports, MACs, `bidir`, action) into one or two `FwKey`s and write them. Invalid combinations, such as ports without TCP/UDP, are rejected with a clear message. |
| `_flush_ct_matching` | After adding a **drop** rule, deletes matching conntrack entries, so already-established connections can't keep using a now-forbidden path |
| `lb_add_service` | Allocates a free service id, writes up to 16 backends into the array slots `id*16 … id*16+15` (clearing unused slots), then publishes the service. Backends are written *before* the service, so the data plane never sees a service with an empty pool. |
| `lb_set_backend_state` | Flips a backend's `active` flag. This drains it from new connections, and the data plane also re-places existing connections on its next packet. |
| `ct_list` / `ct_flush` | Show or clear the three connection tables |
| `ct_gc` | Deletes entries idle longer than `idle_timeout`, or `fin_timeout` once FIN/RST was seen, or older than `hard_timeout`. Deleting an LB entry also deletes its reverse-NAT partner. |
| `stats` / `flows` | Sum the per-CPU counters, and merge per-CPU flow slots by key into a top-N list |

Time values compare `bpf_ktime_get_ns()` (written by the kernel) with Python's
`time.clock_gettime_ns(CLOCK_MONOTONIC)`. They use the same clock, so idle
times are exact.

### 7.6 REST API and daemon ([control_plane.py:681-815](../control_plane.py:681))

`Api` is a standard-library `BaseHTTPRequestHandler` with a route table
(`GET /stats`, `POST /firewall`, `PUT /services/backend`, …). It speaks JSON
in both directions and turns errors into HTTP 400 responses with a message.
`run_daemon()` optionally loads and attaches, optionally loads services from
`services.json`, starts the **GC thread** (`gc_loop`, runs every
`--gc-interval` seconds), and serves the API with a threading HTTP server
until it gets SIGTERM or SIGINT.

### 7.7 CLI ([control_plane.py:817-981](../control_plane.py:817))

`argparse` subcommands (`build`, `load`, `unload`, `daemon`, `fw`, `lb`,
`ct`, `stats`) map one-to-one onto the functions above. `print_table()`
formats output; `stats --watch 1` gives a live view.

---

## 8. Code walkthrough: `topology.py`

### 8.1 Building the network ([topology.py:134-220](../topology.py:134))

`build_net(mode)`:

1. Creates a `Mininet` object with no controller and no automatic MAC or ARP
   setup.
2. Adds `gw`, either as a host (eBPF and kernel modes) or as an `OVSSwitch`
   with `failMode="secure"` and OpenFlow 1.3 (OVS mode).
3. Adds 8 hosts with fixed IPs and MACs and a default route, each linked to
   `gw` with predictable interface names.
4. Disables TX checksum offload on every host interface (§12.3).
5. Configures the gateway (`setup_router` or `setup_ovs_gateway`).

`txoff()` uses `ethtool` if present. Otherwise it runs `helper_txoff()`
([topology.py:63](../topology.py:63)), which makes the same `SIOCETHTOOL`
ioctl directly from Python.

### 8.2 eBPF gateway lifecycle ([topology.py:222-271](../topology.py:222))

`EbpfGateway` runs `control_plane.py` **inside the gw namespace** (via
`gw.cmd`), because interface names and indexes are per-namespace. It loads the
data plane on `gw-eth0..7`, starts the daemon in the background with short
timeouts (idle 30 s, FIN 5 s, GC every 2 s), and waits until the REST API
answers. The tests then drive the control plane **through REST**, the same
way an orchestrator would.

### 8.3 The OVS baseline ([topology.py:185-220](../topology.py:185))

To compare fairly, OVS mode rebuilds the same three functions purely as
OpenFlow 1.3 rules.

**Table 0 (policy):**

| Priority | Match | Action |
|---|---|---|
| 400 | firewall rule, e.g. `ip,nw_src=10.0.1.1,nw_dst=10.0.2.3` | `drop` (added by Test 2) |
| 300 | `tcp,nw_dst=10.100.0.1,tp_dst=80` | `group:1` (load balancer) |
| 300 | `tcp,nw_src=10.0.2.X,tp_src=80,nw_dst=10.0.1.0/24` | `set_field:10.100.0.1->ip_src, goto_table:1` (reverse NAT) |
| 100 | `arp,arp_tpa=<host>` | `output:<host port>` (deliver ARP directly) |
| 0 | anything | `goto_table:1` |

**Table 1 (routing):**

| Priority | Match | Action |
|---|---|---|
| 100 | `ip,nw_dst=<host>` | `set_field:<gw MAC>->eth_src, set_field:<host MAC>->eth_dst, dec_ttl, output:<port>` |

**Group 1** is of type `select`, with one bucket per backend. Each bucket
rewrites the destination IP and MAC, decrements the TTL and outputs to the
backend's port. OVS hashes each flow to a bucket.

The hosts get a static ARP entry for a virtual gateway MAC
(`02:00:00:00:00:fe`), since there's no real router to answer ARP.

The difference from the eBPF design is instructive. OpenFlow 1.3 has no
connection tracking, so the reverse NAT is **stateless**: any reply from a
backend's port 80 to a client is rewritten to the VIP. The eBPF version keeps
real per-connection state (`lb_reverse`), so it only rewrites replies that
belong to load-balanced connections.

### 8.4 Tests ([topology.py:291-472](../topology.py:291))

| Test | Function | How it decides PASS |
|---|---|---|
| 1 | `test1_connectivity` | `net.ping()` between all 8 hosts (56 ordered pairs) reports 0% loss |
| 2 | `test2_firewall` | After `POST /firewall {c1↔s3 drop}`: 3 pings c1→s3 all lost; c1→s2 all succeed; `drop_firewall` rose by ≥3 (proves the *kernel program* dropped them); after `DELETE`, c1→s3 works again |
| 3 | `test3_loadbalancer` | Each client makes 25 HTTP requests (a new TCP connection each) to the VIP. Every backend's web page returns its own name, so the responses show who served them. PASS needs 0 failures, all 4 backends used, both conntrack tables populated, and, after draining s1, no responses from s1. |
| 4 | `test4_benchmark` | Measures, then saves JSON (details in §11) |

Each backend runs `python3 -m http.server` serving a one-line `index.html`
containing its own name. The servers' PIDs are recorded and killed
individually at the end. A blanket `pkill` would also kill unrelated
processes, because Mininet hosts share the host's process table.

Helper modes (`--http-probe`, `--udp-blast`, `--txoff`) let the same file run
small tools *inside* Mininet hosts without extra scripts.

---

## 9. `benchmark.sh` and the `Makefile`

`benchmark.sh` runs `topology.py --test 4` once per configuration, each in a
freshly built network:

| Label | Mode |
|---|---|
| `ebpf-xdp` | eBPF on the XDP hook, kernel routing |
| `ebpf-tc` | eBPF on the TC hook, kernel routing |
| `ebpf-tc-fib` | eBPF on the TC hook, forwarding in eBPF (`bpf_fib_lookup` + `bpf_redirect`) |
| `kernel` | No eBPF: plain Linux routing |
| `ovs` | Open vSwitch + OpenFlow rules (skipped if `ovs-vsctl show` fails) |

It writes `results/<label>.json` for each configuration, then prints a table
and saves `results/summary.json`. `DURATION` and `REQUESTS` can be set as
environment variables.

`Makefile` targets:

| Target | Action |
|---|---|
| `make` | `clang -O2 -g -Wall -Wextra -target bpf -c xdp_prog.c -o xdp_prog.o` |
| `make check` | Checks the object has `xdp`, `tc` and `.maps` sections, Python syntax, the ctypes ABI size checks and shell syntax. No root needed. |
| `sudo make test` / `test-tc` | Tests 1–3 on the XDP / TC hook |
| `sudo make bench` | `./benchmark.sh` |
| `sudo make clean-net` | `mn -c` and remove pinned maps after an interrupted run |
| `deps-debian` / `deps-arch` | Install dependencies |

---

## 10. Test results

These were run on the development machine (Arch Linux, kernel 7.2.5,
libbpf 1.7, Mininet 2.3.1b4, Open vSwitch 4.0).

### `sudo make test`: XDP hook, 9/9 PASS

```
PASS  T1 pingall (8 hosts, 56 pairs)               0.0% loss
PASS  T2a c1 -> s3 blocked
PASS  T2b c1 -> s2 still reachable
PASS  T2c drops counted in-kernel (drop_firewall)  3 packets dropped by XDP
PASS  T2d c1 -> s3 restored after rule removal
PASS  T3a all requests to VIP answered             100 ok, 0 failed
PASS  T3b traffic spread over all backends         s1=28, s2=27, s3=20, s4=25
PASS  T3c conntrack populated (lb + reverse NAT)   100 lb / 100 reverse entries
PASS  T3d drained backend s1 receives no new connections {'s4': 8, 's2': 11, 's3': 6}
```

### `sudo make test-tc`: TC hook, 9/9 PASS

```
PASS  T1 pingall (8 hosts, 56 pairs)               0.0% loss
PASS  T2c drops counted in-kernel (drop_firewall)  3 packets dropped by TC
PASS  T3b traffic spread over all backends         s1=25, s2=25, s3=25, s4=25
PASS  T3d drained backend s1 receives no new connections {'s4': 5, 's2': 14, 's3': 6}
(all other checks PASS as above)
```

### What the data-plane counters showed after the XDP test run

```
rx_packets 1680   pass 1677   drop_firewall 3   drop_malformed 0
lb_dnat 751       lb_snat 749 lb_new_conn 125   arp 32
```

- **`lb_dnat ≈ lb_snat`.** Every request packet that was rewritten had a
  matching rewritten reply.
- **`lb_new_conn 125`.** The 100 requests in T3a/b plus 25 in T3d: one new LB
  connection per HTTP request, as expected, since each request opens a new
  TCP connection.
- **`drop_firewall 3`.** Exactly the three pings sent while the rule was
  active.

### Connection expiry (GC)

Checked separately. After 10 HTTP requests, `lb_conntrack` and `lb_reverse`
held 10 entries each, flagged `SYN,FIN`. Nine seconds later, with
`--fin-timeout 5`, both tables were empty, and the daemon logged the expiry.

---

## 11. Benchmark results and how to read them

`sudo ./benchmark.sh`, 10-second runs, path c1 → gw → s2 over veth:

| Config | TCP Gbps | UDP 64B rx pps | UDP loss % | RTT avg ms | RTT max ms | LB conn/s | LB ms/req | FW drop pps |
|---|---|---|---|---|---|---|---|---|
| ebpf-xdp | 3.02 | 147,585 | 0.71 | 0.047 | 0.378 | 390 | 2.56 | 230,537 |
| ebpf-tc | 2.38 | 138,596 | 0.00 | 0.014 | 0.094 | 524 | 1.91 | 276,990 |
| ebpf-tc-fib | 2.90 | 144,360 | 0.07 | 0.023 | 0.185 | 393 | 2.54 | 240,743 |
| kernel | 3.17 | 186,564 | 0.07 | 0.011 | 0.081 | – | – | – |
| ovs | 3.41 | 183,643 | 0.08 | 0.014 | 0.673 | 393 | 2.54 | – |

### What each column measures

| Column | How it is measured |
|---|---|
| **TCP Gbps** | `iperf3` single-stream TCP throughput c1 → s2. Measures bulk forwarding with large packets. |
| **UDP 64B rx pps** | `iperf3 -u -l 22 -b 0`: minimum-size frames (22 B payload + 8 UDP + 20 IP + 14 Ethernet = 64 B) sent as fast as possible, counting packets that *arrived*. This is the classic per-packet cost test. |
| **RTT** | 500 pings at 2 ms intervals: average and worst-case round-trip time. |
| **LB conn/s, ms/req** | Sequential HTTP requests to the VIP, each a new TCP connection. Every request exercises conntrack creation, backend selection, DNAT and SNAT. |
| **FW drop pps** | A firewall rule drops UDP c1→s3:9999 while c1 floods it; the `drop_firewall` counter's growth divided by time. |

### Interpretation

**1. Correctness under load is perfect.**

- **Firewall:** in every eBPF configuration the drop rule caught every packet
  of the flood (XDP 721,408 / 721,408, TC 861,952 / 861,952, TC-FIB
  765,952 / 765,952).
- **Load balancer:** there were zero failed requests in all four modes that
  run it.

**2. On veth links, eBPF doesn't beat the plain kernel. That's expected.**

The kernel and OVS rows are fastest at small packets (~185k pps vs ~140–148k
pps for eBPF). The reasons:

- **XDP on veth isn't the "fast path" it is on hardware.** On a physical NIC,
  XDP runs *before* the kernel allocates an `sk_buff`, which is where its
  speed comes from. A veth already has an `sk_buff`. Native veth XDP has to
  *convert* it into an XDP buffer and back, and it disables GRO/TSO batching
  on that path. That's extra work, not saved work.
- **The eBPF configurations also do more work per packet** than the kernel
  baseline. Every packet goes through parsing, up to 9 firewall lookups, a
  service lookup, a reverse-NAT lookup, conntrack updates and telemetry. The
  kernel baseline does none of that, so it's naturally faster.

**3. TC had the best latency and LB connection rate of the eBPF hooks.** TC
showed the lowest average and worst-case RTT (0.014 / 0.094 ms) and the
highest connection rate (524/s). XDP's veth conversion adds latency to every
packet, which shows up in its 0.047 ms average RTT.

**4. In-kernel FIB forwarding (`ebpf-tc-fib`) helped bulk traffic.**
Throughput was 2.90 vs 2.38 Gbps for TC alone, and small packets 144k vs
139k pps. Skipping the kernel's IP routing layer with `bpf_redirect` saves
work, as intended.

**5. OVS is very competitive here.** OVS's kernel datapath caches flows
(megaflows) and is highly optimised. For this workload it matched plain
routing. The difference between OVS and eBPF is less about raw speed on veth
and more about expressiveness:

| | eBPF data plane | OVS + OpenFlow 1.3 |
|---|---|---|
| Load balancer reverse NAT | Stateful (`lb_reverse`); rewrites only replies of LB connections | Stateless; rewrites *every* reply from backend port 80 |
| Drain a backend | Existing connections re-placed on their next packet | Requires rewriting the group |
| Telemetry | Per-flow counters on the data path | Per-rule counters only |

**6. Caveats on precision.**

- Each configuration ran **once for 10 seconds**, so differences of 10–20%
  between configurations are within run-to-run noise. Only large gaps, such as
  kernel/OVS vs eBPF at 64 B, are clear results.
- The FW drop pps column is limited by the **single-threaded Python sender**,
  not by the data plane. Every sent packet was dropped, so the true drop
  capacity is higher.
- The LB rate (~390–520 requests/s) is dominated by Python HTTP client and
  server overhead, not by the network.

**7. How to get publishable numbers:**

- Attach XDP to a **physical NIC with native driver support** (Intel i40e/ice,
  Mellanox mlx5, …).
- Generate traffic from another machine with `pktgen` or TRex.
- Pin CPUs, use multiple RX queues, and repeat each run 5+ times, reporting
  mean ± standard deviation.

On real NICs, published measurements typically show XDP dropping at tens of
millions of packets per second per core, roughly 5–10× what the kernel stack
can do. This project's architecture is built for that environment; veth only
demonstrates that it works correctly.

---

## 12. Problems found along the way and how they were fixed

### 12.1 First ping lost in `pingall` (proxy-ARP delay)

In the first run, 1 of 56 pairs failed. Linux's proxy ARP waits a **random
0–800 ms** before answering (`proxy_delay`, meant to let a real host answer
first). Mininet's ping timeout is 1 s, and the first packet also needs two
ARP resolutions, so occasionally it timed out. Fix: set
`net.ipv4.neigh.<if>.proxy_delay=0` on the gateway interfaces.

### 12.2 Reverse-path filtering vs. SNAT

After SNAT, a reply's source is the VIP `10.100.0.1`, which the gateway has no
route for. Strict reverse-path filtering (`rp_filter`) would drop it. Fix:
`rp_filter=0` on the gateway.

### 12.3 Checksum offload on veth

Linux normally leaves TCP/UDP checksum calculation to the network card
(`CHECKSUM_PARTIAL`). On veth the checksum is never actually finished, and
the field holds only a partial pseudo-header sum. An XDP program that
incrementally updates that field produces a wrong checksum. Fix: disable TX
checksum offload on all Mininet interfaces, so checksums are always complete.
The TC path doesn't need this, because `bpf_l4_csum_replace(...,
BPF_F_PSEUDO_HDR)` handles partial checksums correctly. That's one practical
reason TC exists alongside XDP.

### 12.4 OVS availability check

`benchmark.sh` first checked only that the `ovs-vsctl` *command* existed.
That passed even when the OVS daemon wasn't running. Fix: check
`ovs-vsctl show`, which only succeeds when the database is reachable.

### 12.5 Installing Mininet on Arch Linux

| Problem | Cause | Fix |
|---|---|---|
| `yay`: "certificate signed by unknown authority" | Temporary network/TLS issue | Retried later |
| Build failed: `Can't locate Locale/gettext.pm` | **Partial system upgrade.** `perl` was 5.42 but `perl-locale-gettext` was built for Perl 5.44, so `help2man` (used to generate Mininet's man page) couldn't load it | Built the package with a stand-in `help2man` that writes a minimal man page; Mininet itself is unchanged. The proper fix is `pacman -Syu`. |
| `pacman`: "/usr/bin/mnexec exists in filesystem" | A manually built `mnexec` from a source checkout had been copied there | `pacman -U --overwrite /usr/bin/mnexec ...` |
| A `mininet/` source checkout inside the project | Leftover from a manual install attempt | Moved to `~/src/mininet` |

### 12.6 Process cleanup in Mininet

Mininet hosts share the host's process table. `pkill -f http.server` inside a
host would kill *every* such process on the machine. Fix: record each
server's PID and kill only those.

---

## 13. Limitations and possible extensions

**Limitations:**

- **IPv4 only.** IPv6 packets are passed through untouched (counted as
  `non_ip`).
- **Firewall rules are matched before NAT.** To restrict access to a service,
  write the rule against the VIP, not the backend.
- **Fixed wildcard patterns.** The firewall supports the specific wildcard
  patterns listed in §6.5, not arbitrary masks or CIDR prefixes. Prefix
  matching would need a `BPF_MAP_TYPE_LPM_TRIE`.
- **Telemetry collisions.** `flow_stats` keeps the newest flow per slot.
  Exact per-connection counters are in the conntrack maps.
- **Rebalancing.** When the backend count changes, the `hash % count` choice
  moves many new flows. Existing ones are protected by conntrack. Maglev or
  rendezvous hashing would reduce that churn.
- **XDP redirect on veth.** `--fib-forward` with the XDP hook only works on
  veth if the peer interface also has an XDP program. Use it with TC in
  Mininet, or with XDP on physical NICs.

**Possible extensions:**

- LPM-trie CIDR rules and port ranges.
- Maglev consistent hashing for the backend choice.
- Health checks in the daemon that mark backends down automatically.
- Direct Server Return, where backends reply straight to clients (needs IP
  encapsulation).
- Prometheus metrics export from `/stats`.
- AF_XDP to hand selected flows to user space.
- An OVS baseline using `ct()` actions (OpenFlow 1.5 / Nicira extensions) for
  stateful NAT, for an even fairer comparison.

---

## 14. Glossary

| Term | Meaning |
|---|---|
| **5-tuple** | (source IP, destination IP, source port, destination port, protocol): identifies a connection |
| **ARP** | Address Resolution Protocol: finds the MAC address for an IP on the local link |
| **BPF map** | Kernel key-value store shared between BPF programs and user space |
| **BTF** | BPF Type Format: type information embedded in the object; lets libbpf create maps from C declarations |
| **clsact** | A special qdisc that provides TC ingress/egress hooks for BPF programs |
| **Conntrack** | Connection tracking: a table of active connections and their state |
| **Control plane** | The part that decides the rules (here `control_plane.py`) |
| **Data plane** | The part that moves packets according to the rules (here `xdp_prog.c`) |
| **DNAT / SNAT** | Destination / source network address translation |
| **eBPF** | Framework for running verified, JIT-compiled programs inside the Linux kernel |
| **FIB** | Forwarding Information Base: the kernel's routing table, queried with `bpf_fib_lookup` |
| **GRO / TSO** | Generic Receive Offload / TCP Segmentation Offload: batching packets for efficiency |
| **Helper function** | A kernel function a BPF program is allowed to call |
| **jhash** | Bob Jenkins' hash function, used widely in the Linux kernel |
| **libbpf** | The standard C library for loading BPF objects and managing maps |
| **LRU** | Least Recently Used: an eviction policy for full tables |
| **Mininet** | A network emulator built on network namespaces and veth pairs |
| **Namespace (network)** | An isolated copy of the Linux network stack |
| **OpenFlow** | Protocol for programming switch flow tables from a controller |
| **OVS** | Open vSwitch, a production software switch that speaks OpenFlow |
| **Pinning** | Saving a BPF map or program in `/sys/fs/bpf` so it outlives its creator |
| **pps** | Packets per second |
| **Proxy ARP** | A router answering ARP requests on behalf of hosts on other links |
| **rp_filter** | Reverse-path filtering: drops packets whose source the router wouldn't route back to |
| **sk_buff** | The Linux kernel's packet data structure |
| **TC** | Linux Traffic Control subsystem; offers a BPF hook after sk_buff creation |
| **Verifier** | The kernel component that proves a BPF program is safe before running it |
| **veth** | Virtual Ethernet pair: two interfaces connected like a cable |
| **VIP** | Virtual IP: the service address clients connect to; backed by several servers |
| **XDP** | eXpress Data Path: BPF hook in the network driver, before sk_buff allocation |
