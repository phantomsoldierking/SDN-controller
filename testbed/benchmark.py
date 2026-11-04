"""Test 4: performance benchmark on the c1 -> gw -> s2 path."""
from __future__ import annotations

import json
import os
import re
import shutil
import time

from .backends import probe
from .config import VIP, VPORT, host
from .gateways import Gateway, Unsupported
from .net import host_tool
from .report import Report

DROP_TEST_PORT = 9999


def _iperf(node, args: str) -> dict:
    out = node.cmd(f"iperf3 {args} -J")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def tcp_throughput(client, server_ip: str, duration: int) -> dict:
    bps = _iperf(client, f"-c {server_ip} -t {duration}").get("end", {}) \
        .get("sum_received", {}).get("bits_per_second")
    return {"tcp_gbps": round(bps / 1e9, 3) if bps else None}


def udp_small_packets(client, server_ip: str, duration: int) -> dict:
    # 22 B payload + 8 UDP + 20 IPv4 + 14 Ethernet = 64-byte frames
    s = _iperf(client, f"-c {server_ip} -u -b 0 -l 22 -t {duration}").get("end", {}).get("sum", {})
    received = s.get("packets", 0) - s.get("lost_packets", 0)
    seconds = s.get("seconds") or duration
    return {"udp64_rx_pps": int(received / seconds) if received > 0 else None,
            "udp64_loss_pct": round(s.get("lost_percent", 0), 2) if s else None}


def latency(client, server_ip: str) -> dict:
    out = client.cmd(f"ping -c 500 -i 0.002 -q {server_ip}")
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    if not m:
        return {}
    return dict(zip(("rtt_min_ms", "rtt_avg_ms", "rtt_max_ms", "rtt_mdev_ms"),
                    map(float, m.groups())))


def lb_rate(client, requests: int) -> dict:
    r = probe(client, f"http://{VIP}:{VPORT}/", requests)
    return {"lb_rps": r.get("rps"), "lb_avg_ms": r.get("avg_ms"), "lb_fail": r.get("fail")}


def firewall_drop_rate(gw: Gateway, client, src_ip: str, dst_ip: str) -> dict:
    """Flood a blocked UDP port and count drops in the data plane."""
    gw.block(src_ip, dst_ip, proto="udp", dport=DROP_TEST_PORT, bidir=False)
    try:
        before = gw.drop_count()
        start = time.perf_counter()
        sent = host_tool(client, "blast", dst_ip, DROP_TEST_PORT, 3)["sent"]
        elapsed = time.perf_counter() - start
        dropped = gw.drop_count() - before
    finally:
        gw.unblock(src_ip, dst_ip, proto="udp", dport=DROP_TEST_PORT, bidir=False)
    return {"fw_drop_pps": int(dropped / elapsed), "fw_drop_sent": sent, "fw_dropped": dropped}


def run(net, gw: Gateway, report: Report, duration: int, requests: int, out_path: str | None,
        workdir: str) -> dict:
    print(f"\n*** Test 4: performance benchmark [{gw.label}]")
    if not shutil.which("iperf3"):
        report.skip("T4 benchmark", "iperf3 not installed")
        return {}
    c1, s2, s3 = host("c1"), host("s2"), host("s3")
    client, server = net.get(c1.name), net.get(s2.name)
    pidfile = os.path.join(workdir, "iperf3_s2.pid")
    server.cmd(f"iperf3 -s -D --pidfile {pidfile}")
    time.sleep(0.5)

    result = {"mode": gw.label, "duration_s": duration}
    try:
        result.update(tcp_throughput(client, s2.ip, duration))
        result.update(udp_small_packets(client, s2.ip, duration))
        result.update(latency(client, s2.ip))
        if gw.has_load_balancer:  # the service is installed by Test 3 / topology.py
            result.update(lb_rate(client, requests))
        try:
            result.update(firewall_drop_rate(gw, client, c1.ip, s3.ip))
        except Unsupported:
            pass
    finally:
        server.cmd(f"kill $(cat {pidfile}) 2>/dev/null")

    print(json.dumps(result, indent=2))
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"    results written to {out_path}")
    report.add("T4 benchmark completed", result.get("tcp_gbps") is not None,
               f"tcp={result.get('tcp_gbps')} Gbps, udp64={result.get('udp64_rx_pps')} pps, "
               f"rtt={result.get('rtt_avg_ms')} ms")
    return result
