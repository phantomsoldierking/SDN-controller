"""Gateway implementations behind one interface.

The scenarios and the benchmark only talk to `Gateway`; what actually
forwards, filters and balances traffic depends on the implementation:

    KernelGateway    Linux router, no policy (baseline)
    EbpfGateway      Linux router + the eBPF data plane, driven through REST
    NetfilterGateway Linux router + nftables (stateful firewall) + IPVS (L4 LB)
    OvsGateway       Open vSwitch, stateless OpenFlow 1.3 rules (classical SDN)
    OvsCtGateway     Open vSwitch with connection tracking and NAT (ct/nat actions)
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .config import API_LISTEN, CONTROL_PLANE, HOSTS, OVS_GW_MAC, PYTHON, Host
from .cpus import AUX_CPUS
from .net import disable_tx_offload, sh

log = logging.getLogger("testbed")


class Unsupported(Exception):
    """The gateway implementation cannot do this (the test is skipped)."""


@dataclass
class Service:
    vip: str
    port: int
    proto: str
    backends: list[Host]
    group_id: int = 0
    active: set[str] = field(default_factory=set)


class Gateway(ABC):
    label = ""
    has_load_balancer = False

    def __init__(self, net):
        self.net = net
        self.node = net.get("gw")
        self.services: dict[tuple[str, int, str], Service] = {}

    def _register(self, vip, port, backends, proto) -> Service | None:
        """Record a service; None if it already exists (add_service is idempotent)."""
        key = (vip, port, proto)
        if key in self.services:
            return None
        svc = Service(vip, port, proto, list(backends), len(self.services) + 1,
                      {b.name for b in backends})
        self.services[key] = svc
        return svc

    @abstractmethod
    def start(self) -> None: ...

    def stop(self) -> None:
        pass

    # Policy operations - default: not supported.
    def block(self, src: str, dst: str, proto: str = "any", dport: int = 0,
              bidir: bool = True) -> None:
        raise Unsupported(f"{self.label} has no firewall")

    def unblock(self, src: str, dst: str, proto: str = "any", dport: int = 0,
                bidir: bool = True) -> None:
        raise Unsupported(f"{self.label} has no firewall")

    def add_service(self, vip: str, port: int, backends: list[Host], proto: str = "tcp") -> None:
        raise Unsupported(f"{self.label} has no load balancer")

    def set_backend(self, vip: str, port: int, backend: Host, up: bool,
                    proto: str = "tcp") -> None:
        raise Unsupported(f"{self.label} cannot drain backends")

    def drop_count(self) -> int:
        raise Unsupported(f"{self.label} has no in-kernel drop counter")

    def lb_connections(self, vip: str, port: int) -> int:
        """Number of tracked load-balanced connections of a TCP service."""
        raise Unsupported(f"{self.label} has no connection tracking")

    def report(self) -> str:
        return ""


# ---------------------------------------------------------------------------
class KernelGateway(Gateway):
    """Routed-access Linux router: /32 host routes + proxy ARP on each veth."""
    label = "kernel"

    def start(self) -> None:
        gw = self.node
        gw.cmd("sysctl -qw net.ipv4.ip_forward=1")
        # rp_filter would drop SNATed replies (source = VIP, which has no route back)
        gw.cmd("sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
        for h in HOSTS:
            sh(gw, f"ip addr add {h.gateway_ip}/32 dev {h.gw_intf}")
            sh(gw, f"ip route replace {h.ip}/32 dev {h.gw_intf} scope link", check=True)
            # proxy_delay=0: answer proxied ARP at once (default: random 0-800 ms)
            gw.cmd(f"sysctl -qw net.ipv4.conf.{h.gw_intf}.proxy_arp=1 "
                   f"net.ipv4.conf.{h.gw_intf}.rp_filter=0 "
                   f"net.ipv4.neigh.{h.gw_intf}.proxy_delay=0")
            disable_tx_offload(gw, h.gw_intf)


# ---------------------------------------------------------------------------
class EbpfGateway(KernelGateway):
    """The kernel router with xdp_prog.c attached, managed via the REST API."""
    has_load_balancer = True

    def __init__(self, net, hook: str, xdp_mode: str, fib_forward: bool, logdir: str):
        super().__init__(net)
        self.hook, self.xdp_mode, self.fib_forward = hook, xdp_mode, fib_forward
        self.label = f"ebpf-{hook}" + ("-fib" if fib_forward else "")
        self.ifaces = [h.gw_intf for h in HOSTS]
        self.log_path = os.path.join(logdir, "control_plane.log")
        self._daemon = None

    def _cp(self, args: str, check: bool = True) -> str:
        return sh(self.node, f"{PYTHON} {CONTROL_PLANE} {args}", check=check)

    def _iface_args(self) -> str:
        return " ".join(f"-i {i}" for i in self.ifaces)

    def start(self) -> None:
        super().start()
        self._cp(f"unload {self._iface_args()}", check=False)
        self._cp("build")
        print(self._cp(f"load --hook {self.hook} --xdp-mode {self.xdp_mode} "
                       f"{'--fib-forward ' if self.fib_forward else ''}{self._iface_args()}")
              .rstrip())
        affinity = ["taskset", "-c", AUX_CPUS] if AUX_CPUS else []
        with open(self.log_path, "w") as logf:
            self._daemon = self.node.popen(
                affinity + [PYTHON, CONTROL_PLANE, "daemon", "--api", API_LISTEN,
                            "--idle-timeout", "30", "--fin-timeout", "5", "--gc-interval", "2"],
                stdout=logf, stderr=subprocess.STDOUT)
        for _ in range(50):
            if '"rx_packets"' in self.node.cmd(f"curl -s http://{API_LISTEN}/stats"):
                print(f"*** control-plane daemon up (REST http://{API_LISTEN}, log {self.log_path})")
                return
            time.sleep(0.1)
        raise RuntimeError(f"control-plane daemon did not start, see {self.log_path}")

    def stop(self) -> None:
        if self._daemon:
            self._daemon.terminate()
            self._daemon.wait(timeout=5)
        self._cp(f"unload {self._iface_args()}", check=False)
        print(f"*** control-plane log kept at {self.log_path}")

    def rest(self, method: str, path: str, body: dict | None = None):
        data = (f"-H 'Content-Type: application/json' -d {shlex.quote(json.dumps(body))}"
                if body is not None else "")
        out = self.node.cmd(f"curl -s -X {method} {data} http://{API_LISTEN}{path}")
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            raise RuntimeError(f"REST {method} {path}: {out!r}") from None

    @staticmethod
    def _rule(src, dst, proto, dport, bidir) -> dict:
        rule = {"src": src, "dst": dst, "proto": proto, "action": "drop", "bidir": bidir}
        if dport:
            rule["dport"] = dport
        return rule

    def block(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        rule = self._rule(src, dst, proto, dport, bidir)
        print(f"    REST POST /firewall {rule} -> {self.rest('POST', '/firewall', rule)}")

    def unblock(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        self.rest("DELETE", "/firewall", self._rule(src, dst, proto, dport, bidir))

    def add_service(self, vip, port, backends, proto="tcp") -> None:
        if not self._register(vip, port, backends, proto):
            return
        body = {"vip": vip, "port": port, "proto": proto,
                "backends": [f"{b.ip}:{port}" for b in backends]}
        print(f"    REST POST /services {vip}:{port}/{proto} -> "
              f"{self.rest('POST', '/services', body)}")

    def set_backend(self, vip, port, backend, up, proto="tcp") -> None:
        self.rest("PUT", "/services/backend", {"vip": vip, "port": port, "backend": backend.ip,
                                               "proto": proto, "state": "up" if up else "down"})

    def drop_count(self) -> int:
        return self.rest("GET", "/stats")["drop_firewall"]

    def lb_connections(self, vip, port) -> int:
        tables = self.rest("GET", "/conntrack")
        fwd = [e for e in tables["lb"] if (e["dst"], e["dport"]) == (vip, port)]
        rev = [e for e in tables["lb_reverse"] if e["vip"] == f"{vip}:{port}"]
        return min(len(fwd), len(rev))

    def report(self) -> str:
        return self._cp("stats --top 10")


# ---------------------------------------------------------------------------
class NetfilterGateway(KernelGateway):
    """The kernel router with Linux's native stateful subsystems: nftables with
    connection tracking for the firewall and IPVS (NAT mode, Maglev hashing)
    for the load balancer. Rules are inserted ahead of the conntrack accept, so
    a drop rule wins over established state, as in the eBPF data plane."""
    label = "nft-ipvs"
    has_load_balancer = True

    def _sh(self, cmd: str) -> str:
        return sh(self.node, cmd, check=True)

    def start(self) -> None:
        super().start()
        self.node.cmd("modprobe -q ip_vs; modprobe -q ip_vs_mh")
        self.node.cmd("sysctl -qw net.ipv4.vs.conntrack=1")
        ruleset = ("table inet sdn {\n"
                   "  counter fwdrop { }\n"
                   "  chain forward { type filter hook forward priority 0; policy accept;\n"
                   "    ct state established,related accept\n  }\n}\n")
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
            f.write(ruleset)  # Mininet hosts share the filesystem
        try:
            self._sh(f"nft -f {f.name}")
        finally:
            os.unlink(f.name)
        self._rules: dict[tuple, list[int]] = {}

    def _acl(self, src, dst, proto, dport, bidir):
        pairs = [(src, dst)] + ([(dst, src)] if bidir else [])
        l4 = f"{proto} dport {dport} " if dport else ("" if proto == "any" else f"ip protocol {proto} ")
        return [f"ip saddr {s} ip daddr {d} {l4}counter name fwdrop drop" for s, d in pairs]

    def block(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        handles = []
        for rule in self._acl(src, dst, proto, dport, bidir):
            out = self._sh(f"nft --echo --handle insert rule inet sdn forward {rule}")
            handles.append(int(re.search(r"# handle (\d+)", out).group(1)))
        self._rules[(src, dst, proto, dport, bidir)] = handles

    def unblock(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        for h in self._rules.pop((src, dst, proto, dport, bidir), []):
            self._sh(f"nft delete rule inet sdn forward handle {h}")

    def drop_count(self) -> int:
        m = re.search(r"packets (\d+)", self._sh("nft list counter inet sdn fwdrop"))
        return int(m.group(1)) if m else 0

    @staticmethod
    def _flag(proto: str) -> str:
        return "-u" if proto == "udp" else "-t"

    def add_service(self, vip, port, backends, proto="tcp") -> None:
        if not self._register(vip, port, backends, proto):
            return
        self._sh(f"ip addr replace {vip}/32 dev lo")  # IPVS serves VIPs that are local
        svc = f"{self._flag(proto)} {vip}:{port}"
        if sh(self.node, f"ipvsadm -A {svc} -s mh -b mh-fallback,mh-port").strip():
            self._sh(f"ipvsadm -A {svc} -s rr")  # kernel without ip_vs_mh
        for b in backends:
            self._sh(f"ipvsadm -a {svc} -r {b.ip}:{port} -m -w 1")

    def set_backend(self, vip, port, backend, up, proto="tcp") -> None:
        # weight 0: no new connections; existing ones continue (graceful drain)
        self._sh(f"ipvsadm -e {self._flag(proto)} {vip}:{port} -r {backend.ip}:{port} -m "
                 f"-w {1 if up else 0}")

    def lb_connections(self, vip, port) -> int:
        return sum(1 for line in self._sh("ipvsadm -Lnc").splitlines()
                   if line.startswith("TCP") and f"{vip}:{port}" in line)

    def stop(self) -> None:
        self.node.cmd("ipvsadm -C; nft delete table inet sdn")


# ---------------------------------------------------------------------------
class OvsGateway(Gateway):
    """Classical SDN baseline: routing, ACL and LB purely as stateless OpenFlow
    1.3 rules.

    table 0: ACL drops (prio 400) -> VIP select group / reverse NAT (prio 300)
             -> ARP delivery (prio 100) -> goto table ROUTE
    table 1: L3 routing - rewrite MACs, dec_ttl, output
    """
    label = "ovs"
    has_load_balancer = True
    ACL_PRIORITY = 400
    ROUTE_TABLE = 1

    def _ofctl(self, *commands: str) -> str:
        out = ""
        for c in commands:
            res = self.node.cmd(f"ovs-ofctl -O OpenFlow13 {c}")
            if res.strip() and not c.startswith("dump"):
                raise RuntimeError(f"ovs-ofctl {c}: {res}")
            out += res
        return out

    def _add_flows(self, *flows: str) -> None:
        self._ofctl(*(f"add-flow gw {shlex.quote(f)}" for f in flows))

    def _route(self, h: Host) -> str:
        return (f"table={self.ROUTE_TABLE},priority=100,ip,nw_dst={h.ip},"
                f"actions=set_field:{OVS_GW_MAC}->eth_src,set_field:{h.mac}->eth_dst,"
                f"dec_ttl,output:{h.port}")

    def _pipeline(self) -> list[str]:
        return ["table=0,priority=0,actions=goto_table:1"]

    def start(self) -> None:
        for h in HOSTS:  # the bridge never answers ARP, so pin the gateway MAC
            self.net.get(h.name).cmd(f"ip neigh replace {h.gateway_ip} lladdr {OVS_GW_MAC} "
                                     f"dev {h.intf} nud permanent")
        flows = self._pipeline()
        for h in HOSTS:
            flows.append(f"table=0,priority=100,arp,arp_tpa={h.ip},actions=output:{h.port}")
            flows.append(self._route(h))
        self._add_flows(*flows)

    def _acl(self, src, dst, proto, dport, bidir) -> list[str]:
        match = "ip" if proto == "any" else proto
        pairs = [(src, dst)] + ([(dst, src)] if bidir else [])
        return [f"table=0,priority={self.ACL_PRIORITY},{match},nw_src={s},nw_dst={d}"
                + (f",tp_dst={dport}" if dport else "") for s, d in pairs]

    def block(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        self._add_flows(*(f"{m},actions=drop" for m in self._acl(src, dst, proto, dport, bidir)))

    def unblock(self, src, dst, proto="any", dport=0, bidir=True) -> None:
        self._ofctl(*(f"del-flows gw --strict {shlex.quote(m)}"
                      for m in self._acl(src, dst, proto, dport, bidir)))

    def drop_count(self) -> int:
        """Packets matched by ACL drop rules (OpenFlow counters, kept by the kernel datapath)."""
        self.node.cmd("ovs-appctl revalidator/wait")  # sync datapath stats into rules
        out = self._ofctl("dump-flows gw table=0")
        return sum(int(m.group(1)) for line in out.splitlines()
                   if f"priority={self.ACL_PRIORITY}," in line and "actions=drop" in line
                   for m in [re.search(r"n_packets=(\d+)", line)] if m)

    def _bucket(self, b: Host, svc: Service) -> str:
        return (f"bucket=set_field:{b.ip}->ip_dst,set_field:{OVS_GW_MAC}->eth_src,"
                f"set_field:{b.mac}->eth_dst,dec_ttl,output:{b.port}")

    def _write_group(self, svc: Service, command: str) -> None:
        buckets = ",".join(self._bucket(b, svc) for b in svc.backends if b.name in svc.active)
        group = f"group_id={svc.group_id},type=select,{buckets}"
        self._ofctl(f"{command} gw {shlex.quote(group)}")

    def _service_flows(self, svc: Service) -> list[str]:
        # No conntrack in OpenFlow 1.3, so the reverse NAT is stateless:
        # every reply from a backend's service port to a client is rewritten.
        return [f"table=0,priority=300,{svc.proto},nw_dst={svc.vip},tp_dst={svc.port},"
                f"actions=group:{svc.group_id}",
                *(f"table=0,priority=300,{svc.proto},nw_src={b.ip},tp_src={svc.port},"
                  f"nw_dst=10.0.1.0/24,actions=set_field:{svc.vip}->ip_src,goto_table:1"
                  for b in svc.backends)]

    def add_service(self, vip, port, backends, proto="tcp") -> None:
        svc = self._register(vip, port, backends, proto)
        if svc:
            self._write_group(svc, "add-group")
            self._add_flows(*self._service_flows(svc))

    def set_backend(self, vip, port, backend, up, proto="tcp") -> None:
        """Remove (or restore) the backend's bucket. Without conntrack, flows that
        hashed to it are re-hashed; with conntrack (OvsCtGateway) they continue."""
        svc = self.services[(vip, port, proto)]
        (svc.active.add if up else svc.active.discard)(backend.name)
        self._write_group(svc, "mod-group")


class OvsCtGateway(OvsGateway):
    """OVS with connection tracking (Nicira ct/nat extensions, kernel nf_conntrack).

    table 0: ACL drops (prio 400), ARP (prio 100), then ct(nat) -> table 1
    table 1: new VIP connection -> select group whose buckets ct(commit,nat(dst))
             other new flows -> ct(commit); established/related -> routing
    table 2: L3 routing
    """
    label = "ovs-ct"
    ROUTE_TABLE = 2

    def _pipeline(self) -> list[str]:
        return ["table=0,priority=10,ip,actions=ct(table=1,nat)",
                "table=1,priority=100,ct_state=+trk+new,ip,actions=ct(commit,table=2)",
                "table=1,priority=100,ct_state=+trk+est,ip,actions=goto_table:2",
                "table=1,priority=100,ct_state=+trk+rel,ip,actions=goto_table:2",
                "table=1,priority=0,actions=drop"]

    def _bucket(self, b: Host, svc: Service) -> str:
        return f"bucket=ct(commit,table=2,nat(dst={b.ip}:{svc.port}))"

    def _service_flows(self, svc: Service) -> list[str]:
        return [f"table=1,priority=200,ct_state=+trk+new,{svc.proto},nw_dst={svc.vip},"
                f"tp_dst={svc.port},actions=group:{svc.group_id}"]

    def lb_connections(self, vip, port) -> int:
        out = self.node.cmd("ovs-appctl dpctl/dump-conntrack")
        return sum(1 for line in out.splitlines()
                   if line.startswith("tcp") and f"dst={vip}," in line and f"dport={port})" in line)


def make_gateway(net, mode: str, hook: str = "xdp", xdp_mode: str = "auto",
                 fib_forward: bool = False, logdir: str = "/tmp") -> Gateway:
    if mode == "ebpf":
        return EbpfGateway(net, hook, xdp_mode, fib_forward, logdir)
    if mode == "ovs":
        return OvsGateway(net)
    if mode == "ovs-ct":
        return OvsCtGateway(net)
    if mode == "nft-ipvs":
        return NetfilterGateway(net)
    return KernelGateway(net)

