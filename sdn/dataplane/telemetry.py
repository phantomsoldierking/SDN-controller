"""Telemetry readers (global_stats, flow_stats). Both maps are per-CPU:
every CPU has its own copy, which is summed / merged here."""
from __future__ import annotations

import ctypes as ct

from ..abi import STAT_NAMES, FlowKey
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
        merged: dict[bytes, dict] = {}
        for _, per_cpu in self._flows.items():
            for fs in per_cpu:
                if not fs.packets:
                    continue
                key = bytes(fs.key)
                agg = merged.setdefault(key, {"packets": 0, "bytes": 0, "last": 0})
                agg["packets"] += fs.packets
                agg["bytes"] += fs.bytes
                agg["last"] = max(agg["last"], fs.last_seen_ns)
        now = monotonic_ns()
        rows = sorted(merged.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:top]
        return [{**flow_key_to_dict(FlowKey.from_buffer_copy(k)), "packets": a["packets"],
                 "bytes": a["bytes"], "idle_s": idle_seconds(a["last"], now)} for k, a in rows]
