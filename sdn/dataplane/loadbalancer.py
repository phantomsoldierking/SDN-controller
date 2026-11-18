"""L4 load-balancer services and backend pools (lb_services + lb_backends).

Service `id` owns the backend array slots id*16 .. id*16+15. A backend keeps
its slot for as long as it stays in the pool (replacing a service never
shifts the others), because established connections refer to their backend
by slot. Backends are written before the service entry is published, so the
data plane never sees a service whose pool is not populated yet.
"""
from __future__ import annotations

import ctypes as ct
import threading

from ..abi import (MAX_BACKENDS_PER_SVC, MAX_SERVICES, Backend, EndpointInfo, EndpointKey,
                   SvcInfo, SvcKey)
from ..codec import (ip_to_wire, parse_endpoint, parse_proto, port_to_wire, proto_name,
                     wire_to_ip, wire_to_port)
from ..maps import MapBackend


def _slot(svc_id: int, idx: int) -> ct.c_uint32:
    return ct.c_uint32(svc_id * MAX_BACKENDS_PER_SVC + idx)


def _service_key(vip: str, port: int, proto: str) -> SvcKey:
    return SvcKey(vip=ip_to_wire(vip), port=port_to_wire(port), proto=parse_proto(proto))


class LoadBalancer:
    """Services own three structures in the data plane:

    lb_backends   slot id*16+i: the pool (address, port, drain flag)
    lb_active     slot id*16+k: indices of the active backends, k < n_act; new
                  connections pick lb_active[h mod n_act], so drained backends
                  get none and the active ones share them uniformly
    lb_endpoints  (address, port, proto) -> service: lets a reply rebuild lost
                  state, and isolates backend endpoints from direct access
    """

    def __init__(self, maps: dict[str, MapBackend], lock: threading.RLock, conntrack=None):
        self._services, self._backends = maps["lb_services"], maps["lb_backends"]
        self._active, self._endpoints = maps["lb_active"], maps["lb_endpoints"]
        self._lock, self._conntrack = lock, conntrack

    def add_service(self, vip: str, port: int, backends: list[str], proto: str = "tcp") -> int:
        """Create or replace a service. Backends are 'ip' or 'ip:port'.

        On replacement, backends that remain keep their slot; removed backends
        leave an empty slot and their connection state is flushed; new
        backends take the lowest free slots."""
        if not 0 < len(backends) <= MAX_BACKENDS_PER_SVC:
            raise ValueError(f"1..{MAX_BACKENDS_PER_SVC} backends required")
        endpoints = [parse_endpoint(b, port) for b in backends]
        wanted = [(ip_to_wire(ip), port_to_wire(bport)) for ip, bport in endpoints]
        if len(set(wanted)) != len(wanted):
            raise ValueError("duplicate backend")
        key = _service_key(vip, port, proto)
        with self._lock:
            self._check_disjoint(key, endpoints)
            existing = self._services.lookup(key)
            svc_id = existing.id if existing is not None else self._free_id()
            slots: list[tuple[int, int] | None] = [None] * MAX_BACKENDS_PER_SVC
            removed = []
            if existing is not None:
                for i in range(existing.count):
                    be = self._backends.lookup(_slot(svc_id, i))
                    if be is None or not be.ip:
                        continue
                    if (be.ip, be.port) in wanted:
                        slots[i] = (be.ip, be.port)
                    else:
                        removed.append((be.ip, be.port))
                self._remove_endpoints(svc_id, existing.count, key.proto)
            for ep in wanted:
                if ep not in slots:
                    slots[slots.index(None)] = ep
            count = max(i for i, ep in enumerate(slots) if ep is not None) + 1
            pool = []
            for i in range(MAX_BACKENDS_PER_SVC):
                if slots[i] is not None:
                    be = Backend(ip=slots[i][0], port=slots[i][1], active=1)
                    self._endpoints.update(
                        EndpointKey(ip=be.ip, port=be.port, proto=key.proto),
                        EndpointInfo(vip=key.vip, vport=key.port, svc_id=svc_id, be_idx=i))
                else:
                    be = Backend()
                pool.append(be)
                self._backends.update(_slot(svc_id, i), be)
            # Publish the active list before the service entry, so the data plane
            # never sees a service whose pool is not populated yet.
            n_act = self._write_active(svc_id, pool[:count])
            self._services.update(key, SvcInfo(id=svc_id, count=count, active=n_act))
            self._flush_backends(removed, key.proto)
        return svc_id

    def _flush_backends(self, backends: list[tuple[int, int]], proto: int) -> None:
        if self._conntrack is not None:
            for ip, bport in backends:
                self._conntrack.flush_backend(ip, bport, proto)

    def _write_active(self, svc_id: int, pool: list[Backend]) -> int:
        """Write the active-backend list; the caller publishes the new count after.

        Order matters because the data plane reads lb_active[h mod n_act]
        concurrently: entries are written before the count changes, so a
        restore never exposes an unwritten slot. During a drain the old count
        may briefly cover a stale entry naming the drained backend, which the
        data plane skips because that backend's active flag is cleared first."""
        active = [i for i, be in enumerate(pool) if be.active and be.ip]
        for k, idx in enumerate(active):
            self._active.update(_slot(svc_id, k), ct.c_uint32(idx))
        return len(active)

    def _check_disjoint(self, key: SvcKey, endpoints: list[tuple[str, int]]) -> None:
        """Reverse-NAT keys are reply 5-tuples, which do not contain the VIP, so a
        backend endpoint (address, port, protocol) may serve only one service."""
        for ip, port in endpoints:
            ek = EndpointKey(ip=ip_to_wire(ip), port=port_to_wire(port), proto=key.proto)
            owner = self._endpoints.lookup(ek)
            if owner is not None and (owner.vip, owner.vport) != (key.vip, key.port):
                raise ValueError(
                    f"backend {ip}:{port}/{proto_name(key.proto)} already serves "
                    f"{wire_to_ip(owner.vip)}:{wire_to_port(owner.vport)}; backend "
                    "endpoints must be disjoint across services")

    def _remove_endpoints(self, svc_id: int, count: int, proto: int) -> None:
        for i in range(count):
            be = self._backends.lookup(_slot(svc_id, i))
            if be is not None and be.ip:
                self._endpoints.delete(EndpointKey(ip=be.ip, port=be.port, proto=proto))

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
            pool = [self._backends.lookup(_slot(info.id, i)) for i in range(info.count)]
            self._remove_endpoints(info.id, info.count, key.proto)
            for i in range(MAX_BACKENDS_PER_SVC):
                self._backends.update(_slot(info.id, i), Backend())
            self._flush_backends([(be.ip, be.port) for be in pool if be is not None and be.ip],
                                 key.proto)
        return True

    def set_backend_state(self, vip: str, port: int, backend: str, up: bool,
                          proto: str = "tcp") -> bool:
        """Drain (up=False) or restore a backend. A drained backend receives no new
        connections; its existing connections continue until they close or expire.
        Returns False if the backend is not in the pool."""
        key = _service_key(vip, port, proto)
        info = self._services.lookup(key)
        if info is None:
            raise ValueError(f"no service {vip}:{port}/{proto}")
        ip = ip_to_wire(backend.partition(":")[0])
        with self._lock:
            pool = [self._backends.lookup(_slot(info.id, i)) for i in range(info.count)]
            hit = [i for i, be in enumerate(pool) if be is not None and be.ip == ip]
            if not hit:
                return False
            for i in hit:
                pool[i].active = 1 if up else 0
                self._backends.update(_slot(info.id, i), pool[i])
            info.active = self._write_active(info.id, pool)
            self._services.update(key, info)
        return True

    def list(self) -> list[dict]:
        out = []
        for key, info in self._services.items():
            pool = []
            for i in range(info.count):
                be = self._backends.lookup(_slot(info.id, i))
                if be is not None and be.ip:
                    pool.append({"ip": wire_to_ip(be.ip), "port": wire_to_port(be.port),
                                 "active": bool(be.active)})
            out.append({"vip": wire_to_ip(key.vip), "port": wire_to_port(key.port),
                        "proto": proto_name(key.proto), "id": info.id, "backends": pool})
        return out
