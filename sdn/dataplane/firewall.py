"""Firewall rules (firewall_map).

A rule is a MAC rule (src MAC, optional dst MAC) or an IP rule over the
5-tuple. Every rule maps to exactly one pattern (`FwMask`), which is stored in
the key, so unspecified fields are true wildcards and a packet with port 0 or
protocol 0 can never match a wildcarded rule by accident. The kernel tries the
patterns in `FwMask` order and the first hit wins (see bpf/firewall.h).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from ..abi import Action, FwKey, FwKind, FwMask, FwRule, Proto
from ..codec import (bytes_to_mac, ip_to_wire, mac_to_bytes, parse_proto, port_to_wire,
                     proto_name, wire_to_ip, wire_to_port)
from ..maps import MapBackend
from .config import action_name, parse_action

# Which fields an IP pattern matches on: (src, dst, sport, dport, proto)
_IP_PATTERNS = {
    (True, True, True, True, True): FwMask.IP_EXACT,
    (True, True, False, True, True): FwMask.IP_DPORT,
    (True, True, True, False, True): FwMask.IP_SPORT,
    (True, True, False, False, True): FwMask.IP_PROTO,
    (True, True, False, False, False): FwMask.IP_PAIR,
    (False, True, False, True, True): FwMask.SVC_PORT,
    (True, False, False, False, False): FwMask.IP_SRC,
    (False, True, False, False, False): FwMask.IP_DST,
}
SUPPORTED_IP_PATTERNS = (
    "src+dst+proto+sport+dport, src+dst+proto+dport, src+dst+proto+sport, src+dst+proto, "
    "src+dst, dst+proto+dport (any source), src, dst")


def ip_pattern(src, dst, sport, dport, proto) -> FwMask:
    shape = (bool(src), bool(dst), bool(sport), bool(dport), bool(proto))
    try:
        return _IP_PATTERNS[shape]
    except KeyError:
        raise ValueError(f"unsupported rule shape; supported: {SUPPORTED_IP_PATTERNS}") from None


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
    def from_dict(cls, d: dict) -> FirewallRule:
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown rule field(s): {', '.join(sorted(unknown))}")
        return cls(**d)

    @property
    def is_mac(self) -> bool:
        return bool(self.src_mac or self.dst_mac)

    def _directions(self) -> list[tuple]:
        dirs = [(self.src, self.dst, self.sport, self.dport)]
        if self.bidir:
            dirs.append((self.dst, self.src, self.dport, self.sport))
        return dirs

    def validate(self) -> None:
        parse_action(self.action)
        if self.is_mac:
            if not self.src_mac:
                raise ValueError("MAC rules need src_mac (dst_mac may be omitted = any)")
            return
        proto = parse_proto(self.proto)
        if (self.sport or self.dport) and proto not in (Proto.TCP, Proto.UDP):
            raise ValueError("port match requires proto tcp or udp")
        for s, d, sp, dp in self._directions():
            ip_pattern(s, d, sp, dp, proto)  # raises for unsupported shapes

    def keys(self) -> list[FwKey]:
        """Map keys for this rule; `bidir` adds the reverse direction."""
        self.validate()
        if self.is_mac:
            pairs = [(self.src_mac, self.dst_mac)]
            if self.bidir and self.dst_mac:
                pairs.append((self.dst_mac, self.src_mac))
            return [FwKey(kind=FwKind.MAC, mask=FwMask.MAC_PAIR if d else FwMask.MAC_SRC,
                          smac=mac_to_bytes(s), dmac=mac_to_bytes(d)) for s, d in pairs]
        proto = parse_proto(self.proto)
        return [FwKey(kind=FwKind.IP, mask=ip_pattern(s, d, sp, dp, proto), proto=proto,
                      saddr=ip_to_wire(s), daddr=ip_to_wire(d),
                      sport=port_to_wire(sp), dport=port_to_wire(dp))
                for s, d, sp, dp in self._directions()]


def describe_key(k: FwKey, rule: FwRule) -> dict:
    out = {"action": action_name(rule.action), "hits": rule.hits,
           "pattern": FwMask(k.mask).name.lower() if k.mask in FwMask._value2member_map_ else "?"}
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

