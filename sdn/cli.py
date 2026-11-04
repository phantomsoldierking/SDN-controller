"""Command-line front end. Each subcommand is a small function taking parsed args."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from . import PIN_DIR
from .dataplane import DataPlane, FirewallRule, Timeouts
from .dataplane.config import ACTIONS
from .libbpf import XDP_FLAGS, BpfError
from .loader import AttachOptions, build, detach, load_and_attach

PROTO_CHOICES = ["any", "icmp", "tcp", "udp"]


# ---- output ----------------------------------------------------------------
def print_table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("  (empty)")
        return
    width = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  " + "  ".join(c.upper().ljust(width[c]) for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "")).ljust(width[c]) for c in cols))


# ---- argument helpers ------------------------------------------------------
def add_attach_args(p: argparse.ArgumentParser, iface_required: bool) -> None:
    p.add_argument("--iface", "-i", action="append", required=iface_required, default=[],
                   help="interface to attach to (repeatable)")
    p.add_argument("--hook", choices=["xdp", "tc"], default="xdp")
    p.add_argument("--xdp-mode", choices=list(XDP_FLAGS), default="auto")
    p.add_argument("--fib-forward", action="store_true",
                   help="forward in eBPF via bpf_fib_lookup + redirect (bypass the stack)")
    p.add_argument("--stateless", action="store_true", help="disable firewall conntrack")
    p.add_argument("--default", choices=list(ACTIONS), default="allow",
                   help="default firewall action for unmatched IPv4")


def attach_options(a) -> AttachOptions:
    return AttachOptions(hook=a.hook, xdp_mode=a.xdp_mode, fib_forward=a.fib_forward,
                         stateful=not a.stateless, default_action=a.default)


def add_rule_args(p: argparse.ArgumentParser, with_action: bool) -> None:
    p.add_argument("--src", help="source IPv4")
    p.add_argument("--dst", help="destination IPv4")
    p.add_argument("--proto", choices=PROTO_CHOICES, default="any")
    p.add_argument("--sport", type=int, default=0)
    p.add_argument("--dport", type=int, default=0)
    p.add_argument("--src-mac")
    p.add_argument("--dst-mac")
    p.add_argument("--bidir", action="store_true", help="also match the reverse direction")
    if with_action:
        p.add_argument("--action", choices=list(ACTIONS), default="drop")


def rule_from_args(a) -> FirewallRule:
    return FirewallRule(src=a.src, dst=a.dst, proto=a.proto, sport=a.sport, dport=a.dport,
                        src_mac=a.src_mac, dst_mac=a.dst_mac, bidir=a.bidir,
                        action=getattr(a, "action", "drop"))


def add_service_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp")


def add_timeout_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--idle-timeout", type=float, default=60.0)
    p.add_argument("--fin-timeout", type=float, default=10.0)
    p.add_argument("--hard-timeout", type=float, default=0.0, help="0 = disabled")


def timeouts(a) -> Timeouts:
    return Timeouts(idle=a.idle_timeout, fin=a.fin_timeout, hard=a.hard_timeout)


# ---- commands --------------------------------------------------------------
def cmd_build(a):
    build(force=a.force)


def cmd_load(a):
    load_and_attach(a.iface, attach_options(a), obj=a.obj, pin_dir=a.pin_dir)


def cmd_unload(a):
    detach(a.iface, a.hook, pin_dir=a.pin_dir, unpin=not a.keep_maps)


def cmd_daemon(a):
    from .daemon import DaemonOptions, run
    if a.iface:
        load_and_attach(a.iface, attach_options(a), pin_dir=a.pin_dir)
    run(DataPlane.open(a.pin_dir), DaemonOptions(listen=a.api, timeouts=timeouts(a),
                                                 gc_interval=a.gc_interval,
                                                 services_file=a.services))


def cmd_fw(a):
    dp = DataPlane.open(a.pin_dir)
    if a.fw_cmd == "add":
        print(f"added {dp.firewall.add(rule_from_args(a))} rule(s)")
    elif a.fw_cmd == "del":
        print(f"deleted {dp.firewall.delete(rule_from_args(a))} rule(s)")
    elif a.fw_cmd == "flush":
        print(f"deleted {dp.firewall.flush()} rule(s)")
    elif a.fw_cmd == "default":
        dp.config.apply(default_action=a.action)
        print(f"default action: {a.action}")
    else:
        print(f"default action: {dp.config.describe()['default_action']}")
        print_table(dp.firewall.list(), ["kind", "action", "proto", "src", "dst", "sport",
                                         "dport", "src_mac", "dst_mac", "hits"])


def cmd_lb(a):
    dp = DataPlane.open(a.pin_dir)
    if a.lb_cmd == "add-service":
        sid = dp.lb.add_service(a.vip, a.port, a.backend, a.proto)
        print(f"service {a.vip}:{a.port}/{a.proto} id={sid} backends={a.backend}")
    elif a.lb_cmd == "del-service":
        print("deleted" if dp.lb.delete_service(a.vip, a.port, a.proto) else "not found")
    elif a.lb_cmd == "backend":
        ok = dp.lb.set_backend_state(a.vip, a.port, a.backend, a.state == "up", a.proto)
        print(f"{a.backend} -> {a.state}" if ok else "backend not found")
    else:
        for svc in dp.lb.list():
            print(f"{svc['vip']}:{svc['port']}/{svc['proto']} (id {svc['id']})")
            print_table(svc["backends"], ["ip", "port", "active"])


def cmd_ct(a):
    dp = DataPlane.open(a.pin_dir)
    if a.ct_cmd == "flush":
        print(f"deleted {dp.conntrack.flush()} entries")
    elif a.ct_cmd == "gc":
        print(dp.conntrack.expire(timeouts(a)))
    else:
        tables = dp.conntrack.list()
        cols = ["proto", "src", "sport", "dst", "dport"]
        for title, key, extra in (("firewall conntrack", "firewall",
                                   ["packets", "bytes", "flags", "idle_s"]),
                                  ("load-balancer conntrack", "lb",
                                   ["backend", "packets", "flags", "idle_s"]),
                                  ("load-balancer reverse NAT", "lb_reverse",
                                   ["vip", "flags", "idle_s"])):
            print(f"{title}:")
            print_table(tables[key], cols + extra)


def cmd_stats(a):
    dp = DataPlane.open(a.pin_dir)
    while True:
        counters, flows = dp.telemetry.counters(), dp.telemetry.top_flows(a.top)
        if a.json:
            print(json.dumps({"stats": counters, "flows": flows}))
        else:
            if a.watch:
                print("\033[2J\033[H", end="")
            print("global counters:")
            for name, value in counters.items():
                print(f"  {name:<16} {value}")
            print(f"top {a.top} flows (by bytes):")
            print_table(flows, ["l3", "proto", "src", "sport", "dst", "dport", "packets",
                                "bytes", "idle_s"])
        if not a.watch:
            return
        time.sleep(a.watch)


# ---- parser ----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="control_plane.py",
        description="Control plane for the eBPF/XDP SDN data plane (libbpf, pinned maps).")
    ap.add_argument("--pin-dir", default=PIN_DIR, help=f"BPF map pin directory ({PIN_DIR})")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build", help="compile bpf/xdp_prog.c")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("load", help="load + attach the data plane")
    add_attach_args(p, iface_required=True)
    p.add_argument("--obj", help="prebuilt object (default: build bpf/xdp_prog.c)")
    p.set_defaults(func=cmd_load)

    p = sub.add_parser("unload", help="detach and unpin")
    p.add_argument("--iface", "-i", action="append", default=[])
    p.add_argument("--hook", choices=["xdp", "tc", "all"], default="all")
    p.add_argument("--keep-maps", action="store_true")
    p.set_defaults(func=cmd_unload)

    p = sub.add_parser("daemon", help="REST API + conntrack reaper (optionally load first)")
    add_attach_args(p, iface_required=False)
    add_timeout_args(p)
    p.add_argument("--api", default="127.0.0.1:8080", help="listen host:port")
    p.add_argument("--services", help="JSON file: [{vip, port, proto, backends:[ip:port]}]")
    p.add_argument("--gc-interval", type=float, default=5.0)
    p.set_defaults(func=cmd_daemon)

    fw = sub.add_parser("fw", help="firewall rules")
    fw.set_defaults(func=cmd_fw)
    fws = fw.add_subparsers(dest="fw_cmd", required=True)
    add_rule_args(fws.add_parser("add"), with_action=True)
    add_rule_args(fws.add_parser("del"), with_action=False)
    fws.add_parser("list")
    fws.add_parser("flush")
    fws.add_parser("default").add_argument("action", choices=list(ACTIONS))

    lb = sub.add_parser("lb", help="load balancer")
    lb.set_defaults(func=cmd_lb)
    lbs = lb.add_subparsers(dest="lb_cmd", required=True)
    p = lbs.add_parser("add-service")
    add_service_args(p)
    p.add_argument("--backend", "-b", action="append", required=True, help="ip[:port]")
    add_service_args(lbs.add_parser("del-service"))
    p = lbs.add_parser("backend", help="drain (down) or restore (up) a backend")
    add_service_args(p)
    p.add_argument("--backend", required=True)
    p.add_argument("state", choices=["up", "down"])
    lbs.add_parser("list")

    c = sub.add_parser("ct", help="connection tracking")
    c.set_defaults(func=cmd_ct)
    cs = c.add_subparsers(dest="ct_cmd", required=True)
    cs.add_parser("list")
    cs.add_parser("flush")
    add_timeout_args(cs.add_parser("gc", help="run one expiry pass"))

    p = sub.add_parser("stats", help="counters + per-flow telemetry")
    p.add_argument("--json", action="store_true")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--watch", type=float, help="refresh every N seconds")
    p.set_defaults(func=cmd_stats)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(name)s] %(message)s", stream=sys.stdout)
    try:
        args.func(args)
    except (BpfError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0
