#!/usr/bin/env python3
"""Small tools run *inside* Mininet hosts (standard library only, no imports
from this project, so it works from any host namespace).

    hosttools.py txoff IFACE             disable TX checksum offload (no ethtool needed)
    hosttools.py probe URL N             N HTTP requests, one TCP connection each -> JSON
    hosttools.py blast DST PORT SECONDS  UDP flood as fast as Python can -> JSON
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import socket
import struct
import sys
import time
import urllib.request

SIOCETHTOOL, ETHTOOL_STXCSUM = 0x8946, 0x00000017


def txoff(iface: str) -> None:
    """XDP sees veth packets before the checksum is finalised; with offload on,
    the L4 checksum field only holds a partial pseudo-header sum."""
    value = ctypes.create_string_buffer(struct.pack("II", ETHTOOL_STXCSUM, 0))
    ifreq = struct.pack("16sQ16x", iface.encode(), ctypes.addressof(value))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        fcntl.ioctl(s, SIOCETHTOOL, ifreq)


def probe(url: str, n: int, timeout: float = 2.0) -> dict:
    backends: dict[str, int] = {}
    ok = fail = 0
    latencies = []
    start = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"Connection": "close"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode().strip()
            backends[body] = backends.get(body, 0) + 1
            ok += 1
            latencies.append((time.perf_counter() - t) * 1000)
        except OSError:
            fail += 1
    elapsed = time.perf_counter() - start
    return {"ok": ok, "fail": fail, "backends": backends,
            "rps": round(ok / elapsed, 1) if elapsed else 0,
            "avg_ms": round(sum(latencies) / len(latencies), 3) if latencies else None}


def blast(dst: str, port: int, seconds: float, frame_size: int = 64) -> dict:
    payload = b"x" * (frame_size - 42)  # 14 Ethernet + 20 IPv4 + 8 UDP
    sent = 0
    end = time.perf_counter() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while time.perf_counter() < end:
            for _ in range(256):
                try:
                    s.sendto(payload, (dst, port))
                    sent += 1
                except OSError:
                    pass
    return {"sent": sent, "seconds": seconds}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("txoff").add_argument("iface")
    p = sub.add_parser("probe")
    p.add_argument("url")
    p.add_argument("n", type=int)
    p = sub.add_parser("blast")
    p.add_argument("dst")
    p.add_argument("port", type=int)
    p.add_argument("seconds", type=float)
    a = ap.parse_args()

    if a.cmd == "txoff":
        txoff(a.iface)
    elif a.cmd == "probe":
        print(json.dumps(probe(a.url, a.n)))
    else:
        print(json.dumps(blast(a.dst, a.port, a.seconds)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
