"""Topology construction and shell helpers for Mininet nodes.

Every host gets its own veth link to the gateway, so all traffic - even
c1 <-> c2 - crosses the gateway's data plane. How the gateway forwards is
decided by the Gateway implementation (see gateways.py).
"""
from __future__ import annotations

import json
import re
import shutil

from .config import HOSTS, HOSTTOOLS, PYTHON, Host


def sh(node, cmd: str, check: bool = False) -> str:
    """Run `cmd` in a node; optionally raise on a non-zero exit status."""
    out = node.cmd(cmd + "; echo __RC=$?")
    m = re.search(r"__RC=(\d+)\s*$", out)
    rc = int(m.group(1)) if m else -1
    out = out[:m.start()] if m else out
    if check and rc != 0:
        raise RuntimeError(f"[{node.name}] `{cmd}` failed (rc={rc}):\n{out}")
    return out


def host_tool(node, *args) -> dict:
    """Run testbed/hosttools.py inside a node and parse its JSON output."""
    out = node.cmd(f"{PYTHON} {HOSTTOOLS} " + " ".join(str(a) for a in args))
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        raise RuntimeError(f"hosttools {args[0]} failed in {node.name}: {out!r}") from None


def disable_tx_offload(node, intf: str) -> None:
    if shutil.which("ethtool"):
        node.cmd(f"ethtool -K {intf} tx off >/dev/null 2>&1")
    else:
        node.cmd(f"{PYTHON} {HOSTTOOLS} txoff {intf}")


def ping_ok(src, dst_ip: str, count: int = 3) -> bool:
    out = src.cmd(f"ping -c {count} -i 0.2 -W 1 {dst_ip}")
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    return m is not None and float(m.group(1)) == 0.0


def build_network(gateway_is_switch: bool):
    """Create the 9-node topology. The gateway is a plain host (router modes)
    or an OpenFlow 1.3 OVS bridge with no controller (OVS mode)."""
    from mininet.net import Mininet
    from mininet.node import OVSSwitch

    net = Mininet(controller=None, build=False, autoSetMacs=False, autoStaticArp=False)
    if gateway_is_switch:
        gw = net.addSwitch("gw", cls=OVSSwitch, failMode="secure", protocols="OpenFlow13",
                           dpid="0000000000000001")
    else:
        gw = net.addHost("gw", ip=None)

    for h in HOSTS:
        node = net.addHost(h.name, ip=f"{h.ip}/24", mac=h.mac, defaultRoute=f"via {h.gateway_ip}")
        extra = {"port2": h.port} if gateway_is_switch else {}
        net.addLink(node, gw, intfName1=h.intf, intfName2=h.gw_intf, **extra)

    net.build()
    net.start()
    for h in HOSTS:
        disable_tx_offload(net.get(h.name), h.intf)
    return net


def nodes(net, hosts: list[Host]) -> list:
    return [net.get(h.name) for h in hosts]
