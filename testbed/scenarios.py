"""Tests 1-3. Each scenario only uses the Gateway interface; operations a
gateway does not support are reported as SKIP."""
from __future__ import annotations

from .backends import probe
from .config import CLIENTS, HOSTS, SERVERS, VIP, VPORT, host
from .gateways import Gateway, Unsupported
from .net import nodes, ping_ok
from .report import Report


def test_connectivity(net, gw: Gateway, report: Report) -> None:
    print("\n*** Test 1: L2/L3 connectivity (pingall)")
    loss = net.ping(nodes(net, HOSTS), timeout="1")
    report.add(f"T1 pingall ({len(HOSTS)} hosts, {len(HOSTS) * (len(HOSTS) - 1)} pairs)",
               loss == 0, f"{loss}% loss")


def test_firewall(net, gw: Gateway, report: Report) -> None:
    print("\n*** Test 2: firewall policy (drop c1 <-> s3)")
    c1, s2, s3 = host("c1"), host("s2"), host("s3")
    c1_node = net.get(c1.name)
    try:
        before = gw.drop_count()
    except Unsupported:
        before = None
    try:
        gw.block(c1.ip, s3.ip)
    except Unsupported as e:
        report.skip("T2 firewall", str(e))
        return

    report.add("T2a c1 -> s3 blocked", not ping_ok(c1_node, s3.ip))
    report.add("T2b c1 -> s2 still reachable", ping_ok(c1_node, s2.ip))
    if before is not None:
        dropped = gw.drop_count() - before
        report.add("T2c drops counted in-kernel (drop_firewall)", dropped >= 3,
                   f"{dropped} packets dropped by the data plane")
    gw.unblock(c1.ip, s3.ip)
    report.add("T2d c1 -> s3 restored after rule removal", ping_ok(c1_node, s3.ip))


def test_load_balancer(net, gw: Gateway, report: Report, requests: int) -> None:
    print(f"\n*** Test 3: L4 load balancing ({VIP}:{VPORT} -> s1..s4)")
    try:
        gw.add_service(VIP, VPORT, SERVERS)
    except Unsupported as e:
        report.skip("T3 load balancer", str(e))
        return

    url = f"http://{VIP}:{VPORT}/"
    totals: dict[str, int] = {}
    fails = 0
    conns: dict[str, list] = {}
    for c in CLIENTS:
        r = probe(net.get(c.name), url, requests)
        print(f"    {c.name}: ok={r['ok']} fail={r['fail']} backends={r['backends']}")
        fails += r["fail"]
        conns[c.name] = r.get("connections", [])  # [client port, backend] per connection
        for backend, n in r["backends"].items():
            totals[backend] = totals.get(backend, 0) + n
    report.data["t3_backend_counts"] = {s.name: totals.get(s.name, 0) for s in SERVERS}
    report.data["t3_connections"] = conns
    answered = sum(totals.values())
    report.add("T3a all requests to VIP answered", fails == 0 and answered > 0,
               f"{answered} ok, {fails} failed")
    report.add("T3b traffic spread over all backends",
               all(totals.get(s.name) for s in SERVERS),
               ", ".join(f"{s.name}={totals.get(s.name, 0)}" for s in SERVERS))

    try:
        n = gw.lb_connections(VIP, VPORT)
        report.add("T3c connection tracking populated", n > 0, f"{n} tracked LB connections")
    except Unsupported as e:
        report.skip("T3c conntrack", str(e))

    drained = SERVERS[0]
    try:
        gw.set_backend(VIP, VPORT, drained, up=False)
    except Unsupported as e:
        report.skip("T3d backend draining", str(e))
        return
    r = probe(net.get(CLIENTS[0].name), url, requests)
    report.data["t3_after_drain"] = r["backends"]
    report.data["t3_after_drain_connections"] = r.get("connections", [])
    report.add(f"T3d drained backend {drained.name} receives no new connections",
               r["fail"] == 0 and drained.name not in r["backends"], str(r["backends"]))
    gw.set_backend(VIP, VPORT, drained, up=True)
