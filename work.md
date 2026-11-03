# TASK PROMPT: Implementation of High-Performance eBPF-Based Cloud-Native Kernel Offloading for Programmable Data Planes

## Context & Objectives
You are building an advanced Software-Defined Networking project that transitions classical SDN (OpenFlow control plane and Open vSwitch match-action tables) to cloud-native kernel offloading using eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path).

The goal is to build an eBPF-powered programmable data plane operating directly inside the Linux kernel and a user-space control plane agent that manages packet filtering policies and load-balancing state.

---

## Technical Specifications & Requirements

### 1. eBPF Kernel Data Plane (`xdp_prog.c`)
Write an eBPF program written in C designed to run at the XDP/TC hook point:
- **Packet Parser**: Parse Ethernet, ARP, IPv4, TCP, and UDP headers defensively with strict boundary checks to pass the eBPF kernel verifier.
- **Stateful Firewall Engine**:
  - Look up standard 5-tuple flow entries `(src_ip, dst_ip, src_port, dst_port, protocol)` or 2-tuple MAC entries in a `BPF_MAP_TYPE_HASH` map called `firewall_map`.
  - Perform actions: Return `XDP_DROP` for blocked flows, `XDP_PASS` for allowed flows.
- **L4 Load Balancer Engine**:
  - Intercept packets destined for a Service VIP (e.g., `10.100.0.1:80`).
  - Hash client flow keys to pick a active backend server IP from a `BPF_MAP_TYPE_ARRAY` map.
  - Rewrite packet IP/MAC headers (DNAT/SNAT) and recompute L3/L4 checksums directly in kernel space using helper functions (`bpf_csum_diff`, `bpf_l3_csum_replace`, `bpf_l4_csum_replace`).
- **Telemetry Counters**:
  - Store total bytes and packet counts per flow in a `BPF_MAP_TYPE_PERCPU_ARRAY` map for real-time telemetry.

### 2. User-Space Control Plane Daemon (`control_plane.py`)
Write a Python control application (using `bcc` or `ebpf-go` / `pyebpf`):
- **eBPF Loader & Attacher**: Compile `xdp_prog.c`, load the bytecode into kernel space, and attach the program to target virtual interfaces (`veth` pairs or Mininet switch interfaces).
- **Runtime Policy Management API**:
  - CLI/REST endpoints to dynamically insert or remove firewall rules in `firewall_map`.
  - Pre-populate backend server pools in the load balancer map.
- **Connection Tracker Expiration**: Periodic cleanup thread that polls flow activity and clears expired connection tracking keys (emulating OpenFlow `idle_timeout` behavior).

### 3. Emulated Topology & Testing Framework (`topology.py` & `benchmark.sh`)
- **Mininet / veth Setup**:
  - Create a topology with 1 Gateway node, 4 Client nodes (`c1-c4`), and 4 Container Backend nodes (`s1-s4`).
- **Verification Tests**:
  - Test 1 (L2/L3 Connectivity): Verify basic ICMP reachability (`pingall`).
  - Test 2 (Firewall Policy Enforcement): Add rule dropping traffic between `c1` and `s3`; verify `XDP_DROP` blocks traffic while `c1` to `s2` remains accessible.
  - Test 3 (L4 Load Balancing): Send HTTP requests from `c1-c4` to Service VIP `10.100.0.1:80` and verify traffic distributes across backends `s1-s4`.
  - Test 4 (Performance Benchmark): Benchmark throughput (packets per second) and latency using `iperf3` or `pktgen`, comparing eBPF/XDP offload vs. traditional Open vSwitch + OpenFlow rules.

---

## Deliverables Required
1. `xdp_prog.c`: Complete C source code for kernel-space eBPF processing.
2. `control_plane.py`: Python daemon using BCC/libbpf for map manipulation and control plane logic.
3. `topology.py`: Script setting up the virtual network environment in Mininet.
4. `Makefile` & `README.md`: Compilation commands (`clang -O2 -target bpf`), dependency setup instructions, and execution steps.
