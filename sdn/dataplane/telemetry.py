"""Telemetry readers (global_stats, flow_stats). Both maps are per-CPU:
every CPU has its own copy, which is summed here."""
from __future__ import annotations

import ctypes as ct

from ..abi import STAT_NAMES
from ..codec import flow_key_to_dict, idle_seconds, monotonic_ns
from ..maps import MapBackend


class Telemetry:
    def __init__(self, maps: dict[str, MapBackend]):
        self._stats, self._flows = maps["global_stats"], maps["flow_stats"]

    def counters(self) -> dict[str, int]:
        out = {}
        for i, name in enumerate(STAT_NAMES):
            per_cpu = self._stats.lookup(ct.c_uint32(i)) or []
            out[name] = sum(v.value for v in per_cpu)
        return out

    def top_flows(self, top: int = 20) -> list[dict]:
        """Flows ranked by bytes. flow_stats is a per-CPU hash keyed by the flow,
        so each key's per-CPU values are simply summed."""
        rows = []
        for key, per_cpu in self._flows.items():
            packets = sum(fs.packets for fs in per_cpu)
            if packets:
                rows.append((key, packets, sum(fs.bytes for fs in per_cpu),
                             max(fs.last_seen_ns for fs in per_cpu)))
        now = monotonic_ns()
        rows.sort(key=lambda r: r[2], reverse=True)
        return [{**flow_key_to_dict(k), "packets": pk, "bytes": by,
                 "idle_s": idle_seconds(last, now)} for k, pk, by, last in rows[:top]]
