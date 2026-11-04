"""Connection tracking tables (fw_conntrack, lb_conntrack, lb_reverse).

The data plane creates and refreshes entries; user space expires them. That
split mirrors OpenFlow, where the switch enforces idle_timeout/hard_timeout
that the controller configured.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from ..abi import CONNTRACK_MAPS, CT_F_FIN, CT_F_RST, L3, FlowKey
from ..codec import (ct_flags_to_str, flow_key_to_dict, idle_seconds, monotonic_ns, wire_to_ip,
                     wire_to_port)
from ..maps import MapBackend


@dataclass
class Timeouts:
    idle: float = 60.0   # seconds without traffic
    fin: float = 10.0    # seconds without traffic once FIN/RST was seen
    hard: float = 0.0    # maximum lifetime; 0 = unlimited

    def expired(self, now_ns: int, last_seen_ns: int, flags: int,
                created_ns: int | None = None) -> bool:
        limit = self.fin if flags & (CT_F_FIN | CT_F_RST) else self.idle
        if now_ns - last_seen_ns > limit * 1e9:
            return True
        return bool(self.hard and created_ns is not None and now_ns - created_ns > self.hard * 1e9)


class ConnTrack:
    def __init__(self, maps: dict[str, MapBackend], lock: threading.RLock):
        self._fw, self._lb, self._rev = (maps[n] for n in CONNTRACK_MAPS)
        self._lock = lock

    def list(self, now_ns: int | None = None) -> dict:
        now = monotonic_ns() if now_ns is None else now_ns
        return {
            "firewall": [{**flow_key_to_dict(k), "packets": v.packets, "bytes": v.bytes,
                          "flags": ct_flags_to_str(v.flags),
                          "idle_s": idle_seconds(v.last_seen_ns, now)}
                         for k, v in self._fw.items()],
            "lb": [{**flow_key_to_dict(k),
                    "backend": f"{wire_to_ip(v.backend_ip)}:{wire_to_port(v.backend_port)}",
                    "packets": v.packets, "bytes": v.bytes, "flags": ct_flags_to_str(v.flags),
                    "idle_s": idle_seconds(v.last_seen_ns, now)}
                   for k, v in self._lb.items()],
            "lb_reverse": [{**flow_key_to_dict(k),
                            "vip": f"{wire_to_ip(v.vip)}:{wire_to_port(v.vport)}",
                            "flags": ct_flags_to_str(v.flags),
                            "idle_s": idle_seconds(v.last_seen_ns, now)}
                           for k, v in self._rev.items()],
        }

    def flush(self) -> int:
        with self._lock:
            return sum(m.delete(k) for m in (self._fw, self._lb, self._rev) for k in m.keys())

    def flush_matching(self, addr_pairs: list[tuple[int, int]]) -> int:
        """Delete entries whose (saddr, daddr) match any pair; 0 is a wildcard."""
        if not addr_pairs:
            return 0
        n = 0
        with self._lock:
            for m in (self._fw, self._lb, self._rev):
                for k in m.keys():
                    if any(s in (0, k.saddr) and d in (0, k.daddr) for s, d in addr_pairs):
                        n += m.delete(k)
        return n

    def expire(self, timeouts: Timeouts, now_ns: int | None = None) -> dict[str, int]:
        """One garbage-collection pass. Returns the number removed per table."""
        now = monotonic_ns() if now_ns is None else now_ns
        removed = dict.fromkeys(CONNTRACK_MAPS, 0)
        with self._lock:
            for k, v in self._fw.items():
                if timeouts.expired(now, v.last_seen_ns, v.flags, v.created_ns):
                    removed["fw_conntrack"] += self._fw.delete(k)
            for k, v in self._lb.items():
                if timeouts.expired(now, v.last_seen_ns, v.flags, v.created_ns):
                    removed["lb_conntrack"] += self._lb.delete(k)
                    # the reverse-NAT entry goes with its forward entry
                    removed["lb_reverse"] += self._rev.delete(FlowKey(
                        saddr=v.backend_ip, daddr=k.saddr, sport=v.backend_port,
                        dport=k.sport, proto=k.proto, l3=L3.IPV4))
            for k, v in self._rev.items():
                if timeouts.expired(now, v.last_seen_ns, v.flags):
                    removed["lb_reverse"] += self._rev.delete(k)
        return removed
