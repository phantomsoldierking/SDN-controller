"""L4 load-balancer services and backend pools (lb_services + lb_backends).

Service `id` owns the backend array slots id*16 .. id*16+15. Backends are
written before the service entry is published, so the data plane never sees
a service whose pool is not populated yet.
"""
from __future__ import annotations

import ctypes as ct
import threading

from ..abi import MAX_BACKENDS_PER_SVC, MAX_SERVICES, Backend, SvcInfo, SvcKey
from ..codec import (ip_to_wire, parse_endpoint, parse_proto, port_to_wire, proto_name,
                     wire_to_ip, wire_to_port)
from ..maps import MapBackend


def _slot(svc_id: int, idx: int) -> ct.c_uint32:
    return ct.c_uint32(svc_id * MAX_BACKENDS_PER_SVC + idx)


def _service_key(vip: str, port: int, proto: str) -> SvcKey:
    return SvcKey(vip=ip_to_wire(vip), port=port_to_wire(port), proto=parse_proto(proto))


class LoadBalancer:
    def __init__(self, maps: dict[str, MapBackend], lock: threading.RLock):
        self._services, self._backends, self._lock = maps["lb_services"], maps["lb_backends"], lock

    def add_service(self, vip: str, port: int, backends: list[str], proto: str = "tcp") -> int:
        """Create or replace a service. Backends are 'ip' or 'ip:port'."""
        if not 0 < len(backends) <= MAX_BACKENDS_PER_SVC:
            raise ValueError(f"1..{MAX_BACKENDS_PER_SVC} backends required")
        endpoints = [parse_endpoint(b, port) for b in backends]
        key = _service_key(vip, port, proto)
        with self._lock:
            existing = self._services.lookup(key)
            svc_id = existing.id if existing is not None else self._free_id()
            for i in range(MAX_BACKENDS_PER_SVC):
                if i < len(endpoints):
                    ip, bport = endpoints[i]
                    be = Backend(ip=ip_to_wire(ip), port=port_to_wire(bport), active=1)
                else:
                    be = Backend()
                self._backends.update(_slot(svc_id, i), be)
            self._services.update(key, SvcInfo(id=svc_id, count=len(endpoints)))
        return svc_id

    def _free_id(self) -> int:
        used = {info.id for _, info in self._services.items()}
        for i in range(MAX_SERVICES):
            if i not in used:
                return i
        raise ValueError("service table full")

    def delete_service(self, vip: str, port: int, proto: str = "tcp") -> bool:
        key = _service_key(vip, port, proto)
        with self._lock:
            info = self._services.lookup(key)
            if info is None:
                return False
            self._services.delete(key)
            for i in range(MAX_BACKENDS_PER_SVC):
                self._backends.update(_slot(info.id, i), Backend())
        return True

    def set_backend_state(self, vip: str, port: int, backend: str, up: bool,
                          proto: str = "tcp") -> bool:
        """Drain (up=False) or restore a backend. Returns False if it is not in the pool."""
        info = self._services.lookup(_service_key(vip, port, proto))
        if info is None:
            raise ValueError(f"no service {vip}:{port}/{proto}")
        ip = ip_to_wire(backend.partition(":")[0])
        with self._lock:
            for i in range(info.count):
                be = self._backends.lookup(_slot(info.id, i))
                if be is not None and be.ip == ip:
                    be.active = 1 if up else 0
                    self._backends.update(_slot(info.id, i), be)
                    return True
        return False

    def list(self) -> list[dict]:
        out = []
        for key, info in self._services.items():
            pool = []
            for i in range(info.count):
                be = self._backends.lookup(_slot(info.id, i))
                if be is not None:
                    pool.append({"ip": wire_to_ip(be.ip), "port": wire_to_port(be.port),
                                 "active": bool(be.active)})
            out.append({"vip": wire_to_ip(key.vip), "port": wire_to_port(key.port),
                        "proto": proto_name(key.proto), "id": info.id, "backends": pool})
        return out
