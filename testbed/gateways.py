"""Gateway implementations behind one interface.

The scenarios and the benchmark only talk to `Gateway`; what actually
forwards, filters and balances traffic depends on the implementation:

    KernelGateway  Linux router, no policy (baseline)
    EbpfGateway    Linux router + the eBPF data plane, driven through REST
    OvsGateway     Open vSwitch with OpenFlow 1.3 rules (classical SDN)
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import time
from abc import ABC, abstractmethod

from .config import API_LISTEN, CONTROL_PLANE, HOSTS, OVS_GW_MAC, PYTHON, Host
from .net import disable_tx_offload, sh

log = logging.getLogger("testbed")


class Unsupported(Exception):
    """The gateway implementation cannot do this (the test is skipped)."""


class Gateway(ABC):
    label = ""
    has_load_balancer = False

    def __init__(self, net):
        self.net = net
        self.node = net.get("gw")

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

    def add_service(self, vip: str, port: int, backends: list[Host]) -> None:
        raise Unsupported(f"{self.label} has no load balancer")

    def set_backend(self, vip: str, port: int, backend: Host, up: bool) -> None:
        raise Unsupported(f"{self.label} cannot drain backends")

    def drop_count(self) -> int:
        raise Unsupported(f"{self.label} has no in-kernel drop counter")

    def conntrack(self) -> dict:
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
        with open(self.log_path, "w") as logf:
            self._daemon = self.node.popen(
                [PYTHON, CONTROL_PLANE, "daemon", "--api", API_LISTEN, "--idle-timeout", "30",
                 "--fin-timeout", "5", "--gc-interval", "2"], stdout=logf, stderr=subprocess.STDOUT)
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

    def add_service(self, vip, port, backends) -> None:
        body = {"vip": vip, "port": port, "proto": "tcp",
                "backends": [f"{b.ip}:{port}" for b in backends]}
        print(f"    REST POST /services -> {self.rest('POST', '/services', body)}")

    def set_backend(self, vip, port, backend, up) -> None:
        self.rest("PUT", "/services/backend", {"vip": vip, "port": port, "backend": backend.ip,
                                               "state": "up" if up else "down"})

    def drop_count(self) -> int:
        return self.rest("GET", "/stats")["drop_firewall"]

    def conntrack(self) -> dict:
        return self.rest("GET", "/conntrack")

    def report(self) -> str:
        return self._cp("stats --top 10")


# ---------------------------------------------------------------------------
class OvsGateway(Gateway):
    """Classical SDN baseline: routing, ACL and LB purely as OpenFlow 1.3 rules.

    table 0: ACL drops (prio 400) -> VIP select group / reverse NAT (prio 300)
             -> ARP delivery (prio 100) -> goto table 1
    table 1: L3 routing - rewrite MACs, dec_ttl, output
    """
    label = "ovs"
    has_load_balancer = True
    ACL_PRIORITY = 400

    def _ofctl(self, *commands: str) -> None:
        for c in commands:
            out = self.node.cmd(f"ovs-ofctl -O OpenFlow13 {c}")
            if out.strip():
                raise RuntimeError(f"ovs-ofctl {c}: {out}")

    def _add_flows(self, *flows: str) -> None:
        self._ofctl(*(f"add-flow gw {shlex.quote(f)}" for f in flows))

    def start(self) -> None:
        for h in HOSTS:  # the bridge never answers ARP, so pin the gateway MAC
            self.net.get(h.name).cmd(f"ip neigh replace {h.gateway_ip} lladdr {OVS_GW_MAC} "
                                     f"dev {h.intf} nud permanent")
        flows = ["table=0,priority=0,actions=goto_table:1"]
        for h in HOSTS:
            flows.append(f"table=0,priority=100,arp,arp_tpa={h.ip},actions=output:{h.port}")
            flows.append(f"table=1,priority=100,ip,nw_dst={h.ip},actions=set_field:{OVS_GW_MAC}"
                         f"->eth_src,set_field:{h.mac}->eth_dst,dec_ttl,output:{h.port}")
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

    def add_service(self, vip, port, backends) -> None:
        buckets = ",".join(f"bucket=set_field:{b.ip}->ip_dst,set_field:{OVS_GW_MAC}->eth_src,"
                           f"set_field:{b.mac}->eth_dst,dec_ttl,output:{b.port}"
                           for b in backends)
        self._ofctl(f"add-group gw {shlex.quote(f'group_id=1,type=select,{buckets}')}")
        # OpenFlow 1.3 has no conntrack, so the reverse NAT is stateless:
        # every reply from a backend's service port to a client is rewritten.
        self._add_flows(f"table=0,priority=300,tcp,nw_dst={vip},tp_dst={port},actions=group:1",
                        *(f"table=0,priority=300,tcp,nw_src={b.ip},tp_src={port},"
                          f"nw_dst=10.0.1.0/24,actions=set_field:{vip}->ip_src,goto_table:1"
                          for b in backends))


def make_gateway(net, mode: str, hook: str = "xdp", xdp_mode: str = "auto",
                 fib_forward: bool = False, logdir: str = "/tmp") -> Gateway:
    if mode == "ebpf":
        return EbpfGateway(net, hook, xdp_mode, fib_forward, logdir)
    if mode == "ovs":
        return OvsGateway(net)
    return KernelGateway(net)

