"""DataPlane facade: one object exposing every data-plane feature.

    dp = DataPlane.open()              # real pinned kernel maps
    dp = DataPlane(in_memory_maps())   # unit tests, no root needed

    dp.config      default action, FIB forwarding, stateful firewall
    dp.firewall    rules
    dp.lb          services and backend pools
    dp.conntrack   connection tables and expiry
    dp.telemetry   counters and per-flow stats

All managers share one re-entrant lock, so the REST API, the CLI and the
reaper thread can run concurrently in one process.
"""
from __future__ import annotations

import threading

from .. import PIN_DIR
from ..maps import MapBackend, open_pinned_maps
from .config import ConfigStore
from .conntrack import ConnTrack, Timeouts
from .firewall import Firewall, FirewallRule
from .loadbalancer import LoadBalancer
from .telemetry import Telemetry


class DataPlane:
    def __init__(self, maps: dict[str, MapBackend]):
        lock = threading.RLock()
        self.maps = maps
        self.config = ConfigStore(maps, lock)
        self.conntrack = ConnTrack(maps, lock)
        self.firewall = Firewall(maps, lock, self.conntrack, self.config)
        self.lb = LoadBalancer(maps, lock, self.conntrack)
        self.telemetry = Telemetry(maps)

    @classmethod
    def open(cls, pin_dir: str = PIN_DIR) -> "DataPlane":
        return cls(open_pinned_maps(pin_dir))


__all__ = ["DataPlane", "FirewallRule", "Timeouts"]
