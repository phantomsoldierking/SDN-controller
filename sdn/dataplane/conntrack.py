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

    def flush_dropped(self, dropped, vips: set[tuple[int, int, int]]) -> int:
        """Delete the state of connections whose rule decision is now DROP.

        `dropped(k)` evaluates the rule decision A(k) for a client-visible key;
        `vips` holds the (address, port, protocol) of every service.
        Load-balanced connections are judged only by their client-visible key
        kappa (reverse entries are mapped back to it from the VIP they store),
        as the data plane judges both of their directions. A routed connection
        is judged in both orientations, because each direction is matched as
        it travels: if either is now dropped, the shared entry must go so that
        the other direction is no longer admitted as established."""
        n = 0
        with self._lock:
            for k in self._lb.keys():
                if dropped(k):
                    n += self._lb.delete(k)
            for k, v in self._rev.items():
                client = FlowKey(saddr=k.daddr, daddr=v.vip, sport=k.dport, dport=v.vport,
                                 proto=k.proto, l3=L3.IPV4)
                if dropped(client):
                    n += self._rev.delete(k)
            for k in self._fw.keys():
                if (k.daddr, k.dport, k.proto) in vips:
                    hit = dropped(k)
                else:
                    rk = FlowKey(saddr=k.daddr, daddr=k.saddr, sport=k.dport, dport=k.sport,
                                 proto=k.proto, l3=k.l3)
                    hit = dropped(k) or dropped(rk)
                if hit:
                    n += self._fw.delete(k)
        return n

    def flush_backend(self, ip: int, port: int, proto: int) -> int:
        """Delete the load-balancer state of every connection served by backend
        endpoint (ip, port, proto); used when a backend is removed or replaced."""
        n = 0
        with self._lock:
            for k, v in self._lb.items():
                if (v.backend_ip, v.backend_port, k.proto) == (ip, port, proto):
                    n += self._lb.delete(k)
            for k in self._rev.keys():
                if (k.saddr, k.sport, k.proto) == (ip, port, proto):
                    n += self._rev.delete(k)
        return n

    @staticmethod
    def _reply_key(fwd: FlowKey, v) -> FlowKey:
        return FlowKey(saddr=v.backend_ip, daddr=fwd.saddr, sport=v.backend_port,
                       dport=fwd.sport, proto=fwd.proto, l3=L3.IPV4)

    @staticmethod
    def _delete_if_expired(m: MapBackend, key, still_expired) -> int:
        """Re-read the entry right before deleting it: the data plane may have
        refreshed it since this pass read it. bpf() offers no compare-and-delete,
        so a microsecond window remains (see the paper, Section IV-E)."""
        current = m.lookup(key)
        return int(current is not None and still_expired(current) and m.delete(key))

    def expire(self, timeouts: Timeouts, now_ns: int | None = None) -> dict[str, int]:
        """One garbage-collection pass. Returns the number removed per table.

        The data plane refreshes a load-balanced connection's forward and
        reverse entries from both directions, so the pair shares one liveness.
        """
        now = monotonic_ns() if now_ns is None else now_ns
        removed = dict.fromkeys(CONNTRACK_MAPS, 0)

        def fw_dead(v) -> bool:
            return timeouts.expired(now, v.last_seen_ns, v.flags, v.created_ns)

        def rev_dead(v) -> bool:
            return timeouts.expired(now, v.last_seen_ns, v.flags)

        with self._lock:
            for k, v in self._fw.items():
                if fw_dead(v):
                    removed["fw_conntrack"] += self._delete_if_expired(self._fw, k, fw_dead)
            for k, v in self._lb.items():
                if fw_dead(v) and self._delete_if_expired(self._lb, k, fw_dead):
                    removed["lb_conntrack"] += 1
                    # The partner is re-read and judged on its own: if a packet
                    # refreshed it meanwhile, it survives and the data plane
                    # re-creates the forward entry from it (Section III-F).
                    removed["lb_reverse"] += self._delete_if_expired(
                        self._rev, self._reply_key(k, v), rev_dead)
            for k, v in self._rev.items():  # orphans whose forward entry is gone
                if rev_dead(v):
                    removed["lb_reverse"] += self._delete_if_expired(self._rev, k, rev_dead)
        return removed
