#!/usr/bin/env python3
"""Replay the backend choices recorded in scenario T3 through an offline model
of the data plane's selection (flow_hash in bpf/util.h, j* = lambda[h mod n_act]
in bpf/lb.h) and report how many recorded connections it reproduces.

    python3 testbed/verify_t3.py results/rev3

The hash is unseeded, so the backend of a connection is a function of its
4-tuple alone; differences between configurations in T3 come from the client
ports the kernel happened to allocate in that run.
"""
from __future__ import annotations

import json
import math
import os
import socket
import struct
import sys

M = 0xFFFFFFFF
VIP, VPORT, TCP = "10.100.0.1", 80, 6


def _rol(x: int, k: int) -> int:
    return ((x << k) | (x >> (32 - k))) & M


def flow_hash(saddr: int, daddr: int, sport: int, dport: int, proto: int) -> int:
    """bpf/util.h flow_hash (jhash_3words final mix with the 0xdeadbeef init)."""
    a = (saddr + 0xDEADBEEF + 12) & M
    b = (daddr + 0xDEADBEEF + 12) & M
    c = ((((sport << 16) | dport) + (proto << 8)) + 0xDEADBEEF + 12) & M
    c ^= b; c = (c - _rol(b, 14)) & M
    a ^= c; a = (a - _rol(c, 11)) & M
    b ^= a; b = (b - _rol(a, 25)) & M
    c ^= b; c = (c - _rol(b, 16)) & M
    a ^= c; a = (a - _rol(c, 4)) & M
    b ^= a; b = (b - _rol(a, 14)) & M
    c ^= b; c = (c - _rol(b, 24)) & M
    return c


def _ip(addr: str) -> int:
    """Address as the program sees it: network-order bytes read as a host u32."""
    return struct.unpack("<I", socket.inet_aton(addr))[0]


def _port(p: int) -> int:
    return ((p & 0xFF) << 8) | (p >> 8)


def predict(client: str, port: int, active: list[str]) -> str:
    h = flow_hash(_ip(client), _ip(VIP), _port(port), _port(VPORT), TCP)
    return active[h % len(active)]


def chi2_p(counts: list[int]) -> tuple[float, float]:
    n, k = sum(counts), len(counts)
    e = n / k
    chi = sum((x - e) ** 2 / e for x in counts)
    # survival function of chi^2 for k-1 = 2 or 3 degrees of freedom
    dof = k - 1
    if dof == 2:
        p = math.exp(-chi / 2)
    elif dof == 3:
        p = math.erfc(math.sqrt(chi / 2)) + math.sqrt(2 * chi / math.pi) * math.exp(-chi / 2)
    else:
        p = float("nan")
    return chi, p


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "results/rev3"
    for cfg in ("ebpf-xdp", "ebpf-tc", "ebpf-tc-fib"):
        path = os.path.join(out, "scenarios", f"{cfg}.json")
        if not os.path.exists(path):
            continue
        data = json.load(open(path))["data"]
        ok = n = 0
        for cl, conns in data.get("t3_connections", {}).items():
            client = f"10.0.1.{cl[1:]}"
            for port, backend in conns:
                ok += predict(client, port, ["s1", "s2", "s3", "s4"]) == backend
                n += 1
        dok = sum(predict("10.0.1.1", port, ["s2", "s3", "s4"]) == backend
                  for port, backend in data.get("t3_after_drain_connections", []))
        dn = len(data.get("t3_after_drain_connections", []))
        print(f"{cfg:12} reproduced {ok}/{n} before and {dok}/{dn} after the drain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
