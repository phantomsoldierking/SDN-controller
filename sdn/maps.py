"""Map backends.

`MapBackend` is the interface every data-plane manager depends on. Two
implementations exist:

  BpfMap   a real pinned kernel map, accessed through libbpf
  DictMap  an in-memory stand-in with the same semantics, used by unit tests
           so control-plane logic can be tested without root or a kernel
"""
from __future__ import annotations

import ctypes as ct
import os
from typing import Iterator, Protocol

from .abi import MAP_SPECS, MapSpec
from .libbpf import BPF_ANY, BpfError, get_libbpf


class MapBackend(Protocol):
    name: str
    spec: MapSpec

    def lookup(self, key): ...
    def update(self, key, value) -> None: ...
    def delete(self, key) -> bool: ...
    def keys(self) -> list: ...
    def items(self) -> Iterator[tuple]: ...


class BpfMap:
    """A pinned BPF map. Per-CPU maps return a list with one value per possible CPU."""

    def __init__(self, name: str, pin_dir: str):
        self.name, self.spec = name, MAP_SPECS[name]
        self._lib = get_libbpf()
        path = os.path.join(pin_dir, name)
        self._fd = self._lib.bpf_obj_get(path.encode())
        if self._fd < 0:
            raise BpfError(f"map {path} not found - run `control_plane.py load` first "
                           f"({os.strerror(self._lib.last_errno())})")
        if self.spec.percpu:
            self._ncpu = self._lib.libbpf_num_possible_cpus()
            # the kernel lays out per-CPU values at 8-byte aligned strides
            self._stride = (ct.sizeof(self.spec.value) + 7) & ~7

    def close(self):
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def _value_buffer(self):
        if self.spec.percpu:
            return ct.create_string_buffer(self._stride * self._ncpu)
        return self.spec.value()

    def _split_percpu(self, buf):
        size = ct.sizeof(self.spec.value)
        return [self.spec.value.from_buffer_copy(buf.raw[i * self._stride:i * self._stride + size])
                for i in range(self._ncpu)]

    def lookup(self, key):
        buf = self._value_buffer()
        if self._lib.bpf_map_lookup_elem(self._fd, ct.byref(key), ct.byref(buf)) < 0:
            return None
        return self._split_percpu(buf) if self.spec.percpu else buf

    def update(self, key, value) -> None:
        self._lib.check(self._lib.bpf_map_update_elem(self._fd, ct.byref(key), ct.byref(value),
                                                      BPF_ANY), f"update {self.name}")

    def delete(self, key) -> bool:
        return self._lib.bpf_map_delete_elem(self._fd, ct.byref(key)) == 0

    def keys(self) -> list:
        out, prev, nxt = [], None, self.spec.key()
        while self._lib.bpf_map_get_next_key(
                self._fd, ct.byref(prev) if prev is not None else None, ct.byref(nxt)) == 0:
            out.append(nxt)
            prev, nxt = nxt, self.spec.key()
        return out

    def items(self):
        for k in self.keys():
            v = self.lookup(k)
            if v is not None:
                yield k, v


class DictMap:
    """In-memory MapBackend. Keys/values are stored as bytes, so callers get
    independent copies exactly as with a kernel map."""

    def __init__(self, name: str, ncpu: int = 2):
        self.name, self.spec, self._ncpu = name, MAP_SPECS[name], ncpu
        self._data: dict[bytes, bytes | list[bytes]] = {}

    def _decode(self, raw):
        if self.spec.percpu:
            return [self.spec.value.from_buffer_copy(r) for r in raw]
        return self.spec.value.from_buffer_copy(raw)

    def lookup(self, key):
        raw = self._data.get(bytes(key))
        return None if raw is None else self._decode(raw)

    def update(self, key, value) -> None:
        if self.spec.percpu:
            values = value if isinstance(value, list) else [value] * self._ncpu
            self._data[bytes(key)] = [bytes(v) for v in values]
        else:
            self._data[bytes(key)] = bytes(value)

    def delete(self, key) -> bool:
        return self._data.pop(bytes(key), None) is not None

    def keys(self) -> list:
        return [self.spec.key.from_buffer_copy(k) for k in list(self._data)]

    def items(self):
        for k in self.keys():
            v = self.lookup(k)
            if v is not None:
                yield k, v


def open_pinned_maps(pin_dir: str) -> dict[str, BpfMap]:
    return {name: BpfMap(name, pin_dir) for name in MAP_SPECS}


def in_memory_maps(ncpu: int = 2) -> dict[str, DictMap]:
    return {name: DictMap(name, ncpu) for name in MAP_SPECS}
