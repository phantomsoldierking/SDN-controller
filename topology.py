#!/usr/bin/env python3
"""
topology.py - Mininet testbed for the eBPF/XDP SDN data plane.

    c1 ─┐                       ┌─ s1
    c2 ─┤                       ├─ s2       clients  10.0.1.1-4/24  (gw 10.0.1.254)
    c3 ─┼──────── gw ───────────┼─ s3       backends 10.0.2.1-4/24  (gw 10.0.2.254)
    c4 ─┘   (gw-eth0..gw-eth7)  └─ s4       service  VIP 10.100.0.1:80 -> s1..s4:80

Modes
  ebpf    Linux router + xdp_prog (XDP by default, --hook tc for TC)
  kernel  Linux router without eBPF (baseline)
  ovs     Open vSwitch acting as the gateway through OpenFlow 1.3 rules

Tests
  1  ICMP pingall between all 8 hosts
  2  firewall: drop c1<->s3, c1->s2 must still work
  3  L4 LB: HTTP from c1-c4 to the VIP spreads over s1-s4
  4  benchmark: TCP throughput, 64B UDP pps, latency, LB rate, drop rate

Usage (root):
  sudo python3 topology.py --mode ebpf --test all
  sudo python3 topology.py --mode ovs  --test 4 --bench-out results/ovs.json
  sudo python3 topology.py --mode ebpf --cli

The implementation lives in the `testbed` package.
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from testbed import benchmark, scenarios  # noqa: E402
from testbed.backends import BackendServers  # noqa: E402
from testbed.config import SERVERS, VIP, VPORT  # noqa: E402
from testbed.gateways import Unsupported, make_gateway  # noqa: E402
from testbed.net import build_network  # noqa: E402
from testbed.report import Report  # noqa: E402


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["ebpf", "kernel", "ovs"], default="ebpf")
    ap.add_argument("--hook", choices=["xdp", "tc"], default="xdp")
    ap.add_argument("--xdp-mode", choices=["auto", "native", "generic"], default="auto")
    ap.add_argument("--fib-forward", action="store_true",
                    help="eBPF forwards via bpf_fib_lookup+redirect (best with --hook tc)")
    ap.add_argument("--test", default="all", help="all | none | comma list of 1,2,3,4")
    ap.add_argument("--requests", type=int, default=25, help="HTTP requests per client")
    ap.add_argument("--duration", type=int, default=10, help="iperf3 seconds")
    ap.add_argument("--bench-out", help="write Test 4 JSON here")
    ap.add_argument("--cli", action="store_true", help="drop into the Mininet CLI afterwards")
    a = ap.parse_args()
    a.tests = ({"1", "2", "3", "4"} if a.test == "all"
               else set() if a.test == "none" else set(a.test.split(",")))
    return a


def run(a, net, gw, report: Report, workdir: str) -> None:
    if "1" in a.tests:
        scenarios.test_connectivity(net, gw, report)
    if "2" in a.tests:
        scenarios.test_firewall(net, gw, report)
    if "3" in a.tests:
        scenarios.test_load_balancer(net, gw, report, a.requests)
    else:
        try:  # make the VIP usable for Test 4 and interactive use
            gw.add_service(VIP, VPORT, SERVERS)
        except Unsupported:
            pass
    if "4" in a.tests:
        benchmark.run(net, gw, report, a.duration, a.requests * 4, a.bench_out, workdir)
    if a.tests and gw.report():
        print("\n*** Data-plane counters")
        print(gw.report())


def main() -> int:
    a = parse_args()
    if os.geteuid() != 0:
        sys.exit("topology.py must run as root (Mininet + BPF)")
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("warning")

    workdir = tempfile.mkdtemp(prefix="sdn_ebpf_")
    net = build_network(gateway_is_switch=a.mode == "ovs")
    gw = make_gateway(net, a.mode, a.hook, a.xdp_mode, a.fib_forward, workdir)
    print(f"*** Topology up (mode={gw.label})")
    backends = BackendServers(net, os.path.join(workdir, "www"))
    report = Report()
    try:
        gw.start()
        backends.start()
        run(a, net, gw, report, workdir)
        if a.tests:
            report.print_summary()
        if a.cli:
            print("*** Mininet CLI. Try:  gw python3 control_plane.py stats")
            CLI(net)
    finally:
        backends.stop()
        gw.stop()
        net.stop()
        shutil.rmtree(os.path.join(workdir, "www"), ignore_errors=True)
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
