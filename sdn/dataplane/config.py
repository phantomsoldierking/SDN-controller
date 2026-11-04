"""Global data-plane configuration (dp_config_map)."""
from __future__ import annotations

import ctypes as ct
import threading

from ..abi import CFG_F_FIB_FORWARD, CFG_F_FW_STATEFUL, Action, DpConfig
from ..maps import MapBackend

_KEY = ct.c_uint32(0)
ACTIONS = {"allow": Action.ALLOW, "drop": Action.DROP}


def parse_action(name: str) -> Action:
    try:
        return ACTIONS[name]
    except KeyError:
        raise ValueError(f"action must be one of {sorted(ACTIONS)}, got {name!r}") from None


def action_name(value: int) -> str:
    return "drop" if value == Action.DROP else "allow"


class ConfigStore:
    def __init__(self, maps: dict[str, MapBackend], lock: threading.RLock):
        self._map, self._lock = maps["dp_config_map"], lock

    def get(self) -> DpConfig:
        return self._map.lookup(_KEY) or DpConfig()

    def apply(self, default_action: str | None = None, fib_forward: bool | None = None,
              stateful: bool | None = None) -> DpConfig:
        """Update only the settings that are given."""
        with self._lock:
            cfg = self.get()
            if default_action is not None:
                cfg.default_action = parse_action(default_action)
            for flag, enabled in ((CFG_F_FIB_FORWARD, fib_forward), (CFG_F_FW_STATEFUL, stateful)):
                if enabled is not None:
                    cfg.flags = (cfg.flags | flag) if enabled else (cfg.flags & ~flag)
            self._map.update(_KEY, cfg)
            return cfg

    def describe(self) -> dict:
        cfg = self.get()
        return {"default_action": action_name(cfg.default_action),
                "fib_forward": bool(cfg.flags & CFG_F_FIB_FORWARD),
                "stateful": bool(cfg.flags & CFG_F_FW_STATEFUL)}
