#!/usr/bin/env python3
"""
topology.py - Mininet testbed for the eBPF/XDP SDN data plane.

    c1 ─┐                       ┌─ s1
    c2 ─┤                       ├─ s2       clients  10.0.1.1-4/24  (gw 10.0.1.254)
    c3 ─┼──────── gw ───────────┼─ s3       backends 10.0.2.1-4/24  (gw 10.0.2.254)
    c4 ─┘   (gw-eth0..gw-eth7)  └─ s4       service  VIP 10.100.0.1:80 -> s1..s4:80

Every host has a point-to-point veth link to the gateway, so *all* traffic
(including c1<->c2) crosses the gateway's data plane.

Modes
  ebpf    gw = Linux router (routed access + proxy ARP); xdp_prog.c attached to
          gw-eth0..7 via control_plane.py (XDP by default, --hook tc for TC).
  kernel  same router, no eBPF: plain Linux forwarding (baseline).
  ovs     gw = Open vSwitch bridge acting as L3 gateway purely through
          OpenFlow 1.3 rules (routing, ACL drop rules, select-group LB).

Tests
  1  L2/L3 connectivity: ICMP pingall between all 8 hosts
  2  firewall: drop c1<->s3, verify c1->s3 blocked and c1->s2 still allowed
  3  L4 LB: HTTP from c1-c4 to 10.100.0.1:80, verify spread over s1-s4
  4  benchmark: TCP throughput, 64B UDP pps, ICMP latency, HTTP-via-VIP rate

Usage (root):
  sudo python3 topology.py --mode ebpf --test all
  sudo python3 topology.py --mode ovs  --test 4 --bench-out results/ovs.json
  sudo python3 topology.py --mode ebpf --cli
"""
import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CP = os.path.join(HERE, "control_plane.py")
PY = sys.executable

CLIENTS = [(f"c{i}", f"10.0.1.{i}", f"00:00:00:00:01:{i:02x}") for i in range(1, 5)]
SERVERS = [(f"s{i}", f"10.0.2.{i}", f"00:00:00:00:02:{i:02x}") for i in range(1, 5)]
HOSTS = CLIENTS + SERVERS
CLIENT_GW, SERVER_GW = "10.0.1.254", "10.0.2.254"
VIP, VPORT = "10.100.0.1", 80
OVS_GW_MAC = "02:00:00:00:00:fe"
API = "127.0.0.1:8080"


def gw_ip(ip):
    return CLIENT_GW if ip.startswith("10.0.1.") else SERVER_GW


# ==========================================================================
# Helper modes executed *inside* Mininet hosts (no Mininet import needed)
# ==========================================================================
def helper_txoff(iface):
    """Disable TX checksum offload via SIOCETHTOOL (fallback when ethtool is absent).

    XDP sees veth packets before the checksum is finalised; with offload on, the
    L4 checksum field only holds a partial pseudo-header sum."""
    import ctypes
    import fcntl
    import struct
    SIOCETHTOOL, ETHTOOL_STXCSUM = 0x8946, 0x00000017
    ev = ctypes.create_string_buffer(struct.pack("II", ETHTOOL_STXCSUM, 0))
    ifr = struct.pack("16sQ16x", iface.encode(), ctypes.addressof(ev))  # struct ifreq
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        fcntl.ioctl(s, SIOCETHTOOL, ifr)


def helper_http_probe(url, n, timeout=2.0):
    """n sequential HTTP requests (new TCP connection each); JSON summary."""
    import urllib.request
    backends, ok, fail, lat = {}, 0, 0, []
    t0 = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"Connection": "close"})
            body = urllib.request.urlopen(req, timeout=timeout).read().decode().strip()
            backends[body] = backends.get(body, 0) + 1
            ok += 1
            lat.append((time.perf_counter() - t) * 1000)
        except Exception:
            fail += 1
    dt = time.perf_counter() - t0
    print(json.dumps({"ok": ok, "fail": fail, "backends": backends,
                      "rps": round(ok / dt, 1) if dt else 0,
                      "avg_ms": round(sum(lat) / len(lat), 3) if lat else None}))


def helper_udp_blast(dst, port, seconds, size=64):
    """Send UDP datagrams as fast as Python can for `seconds`; prints count."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload, n = b"x" * (size - 42), 0
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        for _ in range(256):
            try:
                s.sendto(payload, (dst, port))
                n += 1
            except OSError:
                pass
    print(json.dumps({"sent": n, "seconds": seconds}))


# ==========================================================================
# Topology construction
# ==========================================================================
def sh(node, cmd, check=False):
    out = node.cmd(cmd + "; echo __RC=$?")
    m = re.search(r"__RC=(\d+)\s*$", out)
    rc = int(m.group(1)) if m else -1
    out = out[:m.start()] if m else out
    if check and rc != 0:
        raise RuntimeError(f"[{node.name}] `{cmd}` failed (rc={rc}):\n{out}")
    return out


def txoff(node, intf):
    if shutil.which("ethtool"):
        node.cmd(f"ethtool -K {intf} tx off >/dev/null 2>&1")
    else:
        node.cmd(f"{PY} {__file__} --txoff {intf}")


def build_net(mode):
    from mininet.net import Mininet
    from mininet.node import OVSSwitch

    net = Mininet(controller=None, build=False, autoSetMacs=False, autoStaticArp=False)
    if mode == "ovs":
        gw = net.addSwitch("gw", cls=OVSSwitch, failMode="secure", protocols="OpenFlow13",
                           dpid="0000000000000001")
    else:
        gw = net.addHost("gw", ip=None)

    for idx, (name, ip, mac) in enumerate(HOSTS):
        h = net.addHost(name, ip=f"{ip}/24", mac=mac, defaultRoute=f"via {gw_ip(ip)}")
        kw = {"port2": idx + 1} if mode == "ovs" else {}
        net.addLink(h, gw, intfName1=f"{name}-eth0", intfName2=f"gw-eth{idx}", **kw)

    net.build()
    net.start()

    for name, _, _ in HOSTS:
        txoff(net.get(name), f"{name}-eth0")

    if mode == "ovs":
        setup_ovs_gateway(net)
    else:
        setup_router(net.get("gw"))
    return net


def setup_router(gw):
    """Routed-access gateway: /32 host routes + proxy ARP on each veth."""
    for k in ("ip_forward",):
        gw.cmd(f"sysctl -qw net.ipv4.{k}=1")
    gw.cmd("sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
    for idx, (name, ip, _) in enumerate(HOSTS):
        intf = f"gw-eth{idx}"
        sh(gw, f"ip addr add {gw_ip(ip)}/32 dev {intf}", check=False)
        sh(gw, f"ip route replace {ip}/32 dev {intf} scope link", check=True)
        # proxy_delay=0: answer proxied ARP immediately (default is a random 0-800 ms)
        gw.cmd(f"sysctl -qw net.ipv4.conf.{intf}.proxy_arp=1 "
               f"net.ipv4.conf.{intf}.rp_filter=0 net.ipv4.neigh.{intf}.proxy_delay=0")
        txoff(gw, intf)


def ofctl(sw, *args):
    for a in args:
        out = sw.cmd(f"ovs-ofctl -O OpenFlow13 {a}")
        if out.strip():
            raise RuntimeError(f"ovs-ofctl {a}: {out}")


def setup_ovs_gateway(net):
    """Classical SDN baseline: the gateway's routing, ACL and LB as OpenFlow rules.

    table 0: ACL (prio 400) -> VIP select-group / reverse-SNAT (prio 300)
             -> ARP forwarding (prio 100) -> goto table 1
    table 1: L3 routing: rewrite MACs, dec_ttl, output
    """
    sw = net.get("gw")
    ports = {name: idx + 1 for idx, (name, _, _) in enumerate(HOSTS)}
    for name, ip, _ in HOSTS:
        h = net.get(name)
        h.cmd(f"ip neigh replace {gw_ip(ip)} lladdr {OVS_GW_MAC} dev {name}-eth0 nud permanent")

    flows = []
    for name, ip, mac in HOSTS:
        p = ports[name]
        flows.append(f"table=0,priority=100,arp,arp_tpa={ip},actions=output:{p}")
        flows.append(f"table=1,priority=100,ip,nw_dst={ip},actions=set_field:{OVS_GW_MAC}"
                     f"->eth_src,set_field:{mac}->eth_dst,dec_ttl,output:{p}")
    flows.append("table=0,priority=0,actions=goto_table:1")
    ofctl(sw, *(f"add-flow gw {shlex.quote(f)}" for f in flows))

    buckets = ",".join(
        f"bucket=set_field:{ip}->ip_dst,set_field:{OVS_GW_MAC}->eth_src,"
        f"set_field:{mac}->eth_dst,dec_ttl,output:{ports[name]}"
        for name, ip, mac in SERVERS)
    ofctl(sw, f"add-group gw {shlex.quote(f'group_id=1,type=select,{buckets}')}")
    lb = [f"table=0,priority=300,tcp,nw_dst={VIP},tp_dst={VPORT},actions=group:1"]
    # Stateless reverse NAT (OpenFlow 1.3 has no conntrack): backend:80 -> client
    lb += [f"table=0,priority=300,tcp,nw_src={ip},tp_src={VPORT},nw_dst=10.0.1.0/24,"
           f"actions=set_field:{VIP}->ip_src,goto_table:1" for _, ip, _ in SERVERS]
    ofctl(sw, *(f"add-flow gw {shlex.quote(f)}" for f in lb))


# ==========================================================================
# eBPF control plane lifecycle (runs inside the gw namespace)
# ==========================================================================
class EbpfGateway:
    def __init__(self, net, hook, xdp_mode, fib_forward, logdir):
        self.gw = net.get("gw")
        self.ifaces = [f"gw-eth{i}" for i in range(len(HOSTS))]
        self.hook, self.xdp_mode, self.fib = hook, xdp_mode, fib_forward
        self.log = os.path.join(logdir, "control_plane.log")
        self.daemon = None

    def cp(self, args, check=True):
        return sh(self.gw, f"{PY} {CP} {args}", check=check)

    def start(self):
        self.cp("unload --hook all " + " ".join(f"-i {i}" for i in self.ifaces), check=False)
        self.cp("build")
        args = (f"load --hook {self.hook} --xdp-mode {self.xdp_mode} "
                + ("--fib-forward " if self.fib else "")
                + " ".join(f"-i {i}" for i in self.ifaces))
        print(self.cp(args).rstrip())
        self.daemon = self.gw.popen(
            [PY, CP, "daemon", "--api", API, "--idle-timeout", "30", "--fin-timeout", "5",
             "--gc-interval", "2"],
            stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        for _ in range(50):
            if '"rx_packets"' in self.gw.cmd(f"curl -s http://{API}/stats"):
                print(f"*** control-plane daemon up (REST http://{API}, log {self.log})")
                return
            time.sleep(0.1)
        raise RuntimeError(f"control-plane daemon did not start, see {self.log}")

    def rest(self, method, path, body=None):
        data = f"-H 'Content-Type: application/json' -d {shlex.quote(json.dumps(body))}" \
            if body is not None else ""
        out = self.gw.cmd(f"curl -s -X {method} {data} http://{API}{path}")
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            raise RuntimeError(f"REST {method} {path}: {out!r}")

    def stats(self):
        return self.rest("GET", "/stats")

    def stop(self):
        if self.daemon:
            self.daemon.terminate()
            self.daemon.wait(timeout=5)
        self.cp("unload --hook all " + " ".join(f"-i {i}" for i in self.ifaces), check=False)


# ==========================================================================
# Tests
# ==========================================================================
class Results:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, detail=""):
        self.rows.append((name, ok, detail))
        tag = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        print(f"[{tag}] {name}" + (f" - {detail}" if detail else ""))

    def summary(self):
        print("\n" + "=" * 72)
        for name, ok, detail in self.rows:
            tag = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
            print(f"  {tag:<5} {name:<44} {detail}")
        print("=" * 72)
        return all(ok is not False for _, ok, _ in self.rows)


def ping_ok(src, dst_ip, count=3):
    out = src.cmd(f"ping -c {count} -i 0.2 -W 1 {dst_ip}")
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    return m is not None and float(m.group(1)) == 0.0, out


def test1_connectivity(net, res):
    print("\n*** Test 1: L2/L3 connectivity (pingall)")
    hosts = [net.get(n) for n, _, _ in HOSTS]
    loss = net.ping(hosts, timeout="1")
    res.add("T1 pingall (8 hosts, 56 pairs)", loss == 0, f"{loss}% loss")


def test2_firewall(net, mode, egw, res):
    print("\n*** Test 2: firewall policy (drop c1 <-> s3)")
    c1 = net.get("c1")
    s2_ip, s3_ip, c1_ip = SERVERS[1][1], SERVERS[2][1], CLIENTS[0][1]
    rule = {"src": c1_ip, "dst": s3_ip, "action": "drop", "bidir": True}

    if mode == "kernel":
        res.add("T2 firewall", None, "n/a in kernel baseline mode")
        return
    before = egw.stats()["drop_firewall"] if egw else 0
    if egw:
        r = egw.rest("POST", "/firewall", rule)
        print(f"    REST POST /firewall {rule} -> {r}")
    else:
        sw = net.get("gw")
        ofctl(sw, f"add-flow gw table=0,priority=400,ip,nw_src={c1_ip},nw_dst={s3_ip},actions=drop",
              f"add-flow gw table=0,priority=400,ip,nw_src={s3_ip},nw_dst={c1_ip},actions=drop")

    blocked, _ = ping_ok(c1, s3_ip)
    allowed, _ = ping_ok(c1, s2_ip)
    res.add("T2a c1 -> s3 blocked", not blocked)
    res.add("T2b c1 -> s2 still reachable", allowed)
    if egw:
        dropped = egw.stats()["drop_firewall"] - before
        res.add("T2c drops counted in-kernel (drop_firewall)", dropped >= 3,
                f"{dropped} packets dropped by {egw.hook.upper()}")
        egw.rest("DELETE", "/firewall", rule)
    else:
        sw = net.get("gw")
        ofctl(sw, f"del-flows gw --strict table=0,priority=400,ip,nw_src={c1_ip},nw_dst={s3_ip}",
              f"del-flows gw --strict table=0,priority=400,ip,nw_src={s3_ip},nw_dst={c1_ip}")
    restored, _ = ping_ok(c1, s3_ip)
    res.add("T2d c1 -> s3 restored after rule removal", restored)


def start_backends(net, wwwdir):
    """Start one HTTP server per backend; returns {host: pid}. Each answers with its name."""
    pids = {}
    for name, ip, _ in SERVERS:
        d = os.path.join(wwwdir, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "index.html"), "w") as f:
            f.write(name + "\n")
        h = net.get(name)
        out = h.cmd(f"{PY} -m http.server {VPORT} --bind {ip} --directory {d} "
                    f">/dev/null 2>&1 & echo $!")
        pids[name] = int(out.strip().splitlines()[-1])
    for name, ip, _ in SERVERS:
        h = net.get(name)
        for _ in range(50):
            if name in h.cmd(f"curl -s --max-time 1 http://{ip}:{VPORT}/"):
                break
            time.sleep(0.1)
    return pids


def probe(host, url, n):
    out = host.cmd(f"{PY} {__file__} --http-probe {url} {n}")
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"ok": 0, "fail": n, "backends": {}, "error": out}


def test3_loadbalancer(net, mode, egw, res, requests):
    print(f"\n*** Test 3: L4 load balancing ({VIP}:{VPORT} -> s1..s4)")
    if mode == "kernel":
        res.add("T3 load balancer", None, "n/a in kernel baseline mode")
        return
    if egw:
        r = egw.rest("POST", "/services", {"vip": VIP, "port": VPORT, "proto": "tcp",
                                           "backends": [f"{ip}:{VPORT}" for _, ip, _ in SERVERS]})
        print(f"    REST POST /services -> {r}")
    total, fails = {}, 0
    for name, _, _ in CLIENTS:
        r = probe(net.get(name), f"http://{VIP}:{VPORT}/", requests)
        print(f"    {name}: ok={r['ok']} fail={r['fail']} backends={r['backends']}")
        fails += r["fail"]
        for b, n in r["backends"].items():
            total[b] = total.get(b, 0) + n
    n_ok = sum(total.values())
    res.add("T3a all requests to VIP answered", fails == 0 and n_ok > 0,
            f"{n_ok} ok, {fails} failed")
    used = sorted(b for b in total if b in {s for s, _, _ in SERVERS})
    res.add("T3b traffic spread over all backends", len(used) == len(SERVERS),
            ", ".join(f"{b}={total.get(b, 0)}" for b, _, _ in SERVERS))
    if egw:
        ctl = egw.rest("GET", "/conntrack")
        res.add("T3c conntrack populated (lb + reverse NAT)",
                bool(ctl["lb"]) and bool(ctl["lb_reverse"]),
                f"{len(ctl['lb'])} lb / {len(ctl['lb_reverse'])} reverse entries")
        # drain s1 and verify no new connection lands on it
        egw.rest("PUT", "/services/backend", {"vip": VIP, "port": VPORT,
                                              "backend": SERVERS[0][1], "state": "down"})
        r = probe(net.get("c1"), f"http://{VIP}:{VPORT}/", requests)
        res.add("T3d drained backend s1 receives no new connections",
                r["fail"] == 0 and "s1" not in r["backends"], str(r["backends"]))
        egw.rest("PUT", "/services/backend", {"vip": VIP, "port": VPORT,
                                              "backend": SERVERS[0][1], "state": "up"})


def test4_benchmark(net, mode, egw, res, duration, requests, out_path, label):
    print(f"\n*** Test 4: performance benchmark [{label}]")
    c1, s2 = net.get("c1"), net.get("s2")
    s2_ip = SERVERS[1][1]
    result = {"mode": label, "duration_s": duration}

    if not shutil.which("iperf3"):
        res.add("T4 benchmark", None, "iperf3 not installed")
        return
    pidfile = os.path.join(os.path.dirname(egw.log) if egw else tempfile.gettempdir(),
                           "iperf3_s2.pid")
    s2.cmd(f"iperf3 -s -D --pidfile {pidfile}")
    time.sleep(0.5)

    # TCP throughput
    j = json.loads(c1.cmd(f"iperf3 -c {s2_ip} -t {duration} -J") or "{}")
    bps = j.get("end", {}).get("sum_received", {}).get("bits_per_second")
    result["tcp_gbps"] = round(bps / 1e9, 3) if bps else None

    # Small-packet UDP rate (64B frames) - packets per second actually received
    j = json.loads(c1.cmd(f"iperf3 -c {s2_ip} -u -b 0 -l 22 -t {duration} -J") or "{}")
    s = j.get("end", {}).get("sum", {})
    recv = s.get("packets", 0) - s.get("lost_packets", 0)
    secs = s.get("seconds") or duration
    result["udp64_rx_pps"] = int(recv / secs) if recv > 0 else None
    result["udp64_loss_pct"] = round(s.get("lost_percent", 0), 2) if s else None

    # Latency
    out = c1.cmd(f"ping -c 500 -i 0.002 -q {s2_ip}")
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    if m:
        result.update(rtt_min_ms=float(m.group(1)), rtt_avg_ms=float(m.group(2)),
                      rtt_max_ms=float(m.group(3)), rtt_mdev_ms=float(m.group(4)))

    # L4 LB connection rate (new TCP connection per request)
    if mode != "kernel":
        r = probe(c1, f"http://{VIP}:{VPORT}/", requests)
        result.update(lb_rps=r.get("rps"), lb_avg_ms=r.get("avg_ms"), lb_fail=r.get("fail"))

    # In-kernel drop rate: XDP_DROP on a firewall rule while c1 floods s3
    if egw:
        rule = {"src": CLIENTS[0][1], "dst": SERVERS[2][1], "proto": "udp", "dport": 9999,
                "action": "drop"}
        egw.rest("POST", "/firewall", rule)
        before = egw.stats()["drop_firewall"]
        t0 = time.perf_counter()
        sent = json.loads(c1.cmd(f"{PY} {__file__} --udp-blast {SERVERS[2][1]} 9999 3")
                          .strip().splitlines()[-1])
        dt = time.perf_counter() - t0
        dropped = egw.stats()["drop_firewall"] - before
        egw.rest("DELETE", "/firewall", rule)
        result.update(fw_drop_pps=int(dropped / dt), fw_drop_sent=sent["sent"],
                      fw_dropped=dropped)

    s2.cmd(f"kill $(cat {pidfile}) 2>/dev/null")
    print(json.dumps(result, indent=2))
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"    results written to {out_path}")
    res.add("T4 benchmark completed", result.get("tcp_gbps") is not None,
            f"tcp={result.get('tcp_gbps')} Gbps, udp64={result.get('udp64_rx_pps')} pps, "
            f"rtt={result.get('rtt_avg_ms')} ms")


# ==========================================================================
# Main
# ==========================================================================
def main():
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
    # helper modes (run inside Mininet hosts)
    ap.add_argument("--txoff", metavar="IFACE", help=argparse.SUPPRESS)
    ap.add_argument("--http-probe", nargs=2, metavar=("URL", "N"), help=argparse.SUPPRESS)
    ap.add_argument("--udp-blast", nargs=3, metavar=("DST", "PORT", "SECS"),
                    help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.txoff:
        return helper_txoff(a.txoff)
    if a.http_probe:
        return helper_http_probe(a.http_probe[0], int(a.http_probe[1]))
    if a.udp_blast:
        return helper_udp_blast(a.udp_blast[0], int(a.udp_blast[1]), float(a.udp_blast[2]))

    if os.geteuid() != 0:
        sys.exit("topology.py must run as root (Mininet + BPF)")
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("warning")

    tests = {"1", "2", "3", "4"} if a.test == "all" else \
        set() if a.test == "none" else set(a.test.split(","))
    label = a.mode if a.mode != "ebpf" else f"ebpf-{a.hook}" + ("-fib" if a.fib_forward else "")
    workdir = tempfile.mkdtemp(prefix="sdn_ebpf_")
    print(f"*** Building topology (mode={label})")
    net = build_net(a.mode)
    egw, res, http_pids = None, Results(), {}
    ok = False
    try:
        if a.mode == "ebpf":
            egw = EbpfGateway(net, a.hook, a.xdp_mode, a.fib_forward, workdir)
            egw.start()
        http_pids = start_backends(net, os.path.join(workdir, "www"))

        if "1" in tests:
            test1_connectivity(net, res)
        if "2" in tests:
            test2_firewall(net, a.mode, egw, res)
        if "3" in tests:
            test3_loadbalancer(net, a.mode, egw, res, a.requests)
        elif egw:  # Test 3 normally installs the service through the REST API
            egw.rest("POST", "/services", {"vip": VIP, "port": VPORT,
                                           "backends": [ip for _, ip, _ in SERVERS]})
        if "4" in tests:
            test4_benchmark(net, a.mode, egw, res, a.duration, a.requests * 4,
                            a.bench_out, label)
        if egw and tests:
            print("\n*** Data-plane counters")
            print(egw.cp("stats --top 10"))
        ok = res.summary() if tests else True
        if a.cli:
            print("*** Mininet CLI. Try:  gw python3 control_plane.py stats")
            CLI(net)
    finally:
        for name, pid in http_pids.items():
            net.get(name).cmd(f"kill {pid} 2>/dev/null")
        if egw:
            egw.stop()
            print(f"*** control-plane log kept at {egw.log}")
        net.stop()
        shutil.rmtree(os.path.join(workdir, "www"), ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
