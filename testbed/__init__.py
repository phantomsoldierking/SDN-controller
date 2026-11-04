"""Mininet testbed for the eBPF/XDP data plane.

    config      addressing plan (hosts, gateway IPs, VIP)
    net         topology construction + small shell helpers
    gateways    Gateway interface with eBPF, kernel and OVS implementations
    backends    HTTP backend servers and the HTTP probe client
    scenarios   Tests 1-3 (connectivity, firewall, load balancing)
    benchmark   Test 4 (throughput, pps, latency, LB rate, drop rate)
    report      PASS/FAIL/SKIP bookkeeping
    hosttools   standalone helper script executed *inside* Mininet hosts
"""
