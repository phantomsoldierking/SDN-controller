"""Firewall rules (firewall_map).

A rule is either an IP rule (5-tuple, zero = wildcard) or a MAC rule
(src MAC, optional dst MAC). The kernel tries keys from most to least
specific; see fw_lookup() in bpf/firewall.h for the supported patterns.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from ..abi import Action, FwKey, FwKind, FwRule, Proto
from ..codec import (bytes_to_mac, ip_to_wire, mac_to_bytes, parse_proto, port_to_wire,
                     proto_name, wire_to_ip, wire_to_port)
from ..maps import MapBackend
from .config import action_name, parse_action


@dataclass
class FirewallRule:
    src: str | None = None
    dst: str | None = None
    proto: str | int = "any"
    sport: int = 0
    dport: int = 0
    src_mac: str | None = None
    dst_mac: str | None = None
    action: str = "drop"
    bidir: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "FirewallRule":
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown rule field(s): {', '.join(sorted(unknown))}")
        return cls(**d)

    @property
    def is_mac(self) -> bool:
        return bool(self.src_mac or self.dst_mac)

    def validate(self) -> None:
        parse_action(self.action)
        if self.is_mac:
            if not self.src_mac:
                raise ValueError("MAC rules need src_mac (dst_mac may be omitted = any)")
            return
        proto = parse_proto(self.proto)
        if not self.src and not self.dst:
            raise ValueError("IP rules need at least src or dst")
        if (self.sport or self.dport) and proto not in (Proto.TCP, Proto.UDP):
            raise ValueError("port match requires proto tcp or udp")
        if (self.sport or self.dport or proto) and not (self.src and self.dst):
            raise ValueError("proto/port match requires both src and dst")

    def keys(self) -> list[FwKey]:
        """Map keys for this rule; `bidir` adds the reverse direction."""
        self.validate()
        if self.is_mac:
            pairs = [(self.src_mac, self.dst_mac)]
            if self.bidir and self.dst_mac:
                pairs.append((self.dst_mac, self.src_mac))
            return [FwKey(kind=FwKind.MAC, smac=mac_to_bytes(s), dmac=mac_to_bytes(d))
                    for s, d in pairs]
        proto = parse_proto(self.proto)
        dirs = [(self.src, self.dst, self.sport, self.dport)]
        if self.bidir:
            dirs.append((self.dst, self.src, self.dport, self.sport))
        return [FwKey(kind=FwKind.IP, proto=proto, saddr=ip_to_wire(s), daddr=ip_to_wire(d),
                      sport=port_to_wire(sp), dport=port_to_wire(dp)) for s, d, sp, dp in dirs]


def describe_key(k: FwKey, rule: FwRule) -> dict:
    out = {"action": action_name(rule.action), "hits": rule.hits}
    if k.kind == FwKind.MAC:
        out.update(kind="mac", src_mac=bytes_to_mac(k.smac),
                   dst_mac=bytes_to_mac(k.dmac) if any(k.dmac) else "*")
    else:
        out.update(kind="ip", proto=proto_name(k.proto),
                   src=wire_to_ip(k.saddr) if k.saddr else "*",
                   dst=wire_to_ip(k.daddr) if k.daddr else "*",
                   sport=wire_to_port(k.sport) or "*", dport=wire_to_port(k.dport) or "*")
    return out


class Firewall:
    def __init__(self, maps: dict[str, MapBackend], lock: threading.RLock, conntrack):
        self._rules, self._lock, self._conntrack = maps["firewall_map"], lock, conntrack

    def add(self, rule: FirewallRule) -> int:
        keys = rule.keys()
        action = parse_action(rule.action)
        with self._lock:
            for k in keys:
                self._rules.update(k, FwRule(action=action))
            if action == Action.DROP:
                # A new DROP rule must not be bypassed by already-established state.
                self._conntrack.flush_matching(
                    [(k.saddr, k.daddr) for k in keys if k.kind == FwKind.IP])
        return len(keys)

    def delete(self, rule: FirewallRule) -> int:
        with self._lock:
            return sum(self._rules.delete(k) for k in rule.keys())

    def flush(self) -> int:
        with self._lock:
            return sum(self._rules.delete(k) for k in self._rules.keys())

    def list(self) -> list[dict]:
        return [describe_key(k, v) for k, v in self._rules.items()]

