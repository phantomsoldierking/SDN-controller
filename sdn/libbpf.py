"""ctypes bindings to libbpf.so.1 (libbpf >= 1.0).

Only the functions the control plane needs are declared. Pointer-returning
functions use c_void_p so 64-bit pointers are never truncated to int.
"""
from __future__ import annotations

import contextlib
import ctypes as ct
import ctypes.util
import os

BPF_ANY = 0
XDP_FLAGS = {"auto": 0, "generic": 1 << 1, "native": 1 << 2, "offload": 1 << 3}
BPF_TC_INGRESS, BPF_TC_EGRESS = 1 << 0, 1 << 1
BPF_TC_F_REPLACE = 1 << 0


class BpfError(RuntimeError):
    """A libbpf / bpf() call failed."""


class TcHook(ct.Structure):
    """struct bpf_tc_hook"""
    _fields_ = [("sz", ct.c_size_t), ("ifindex", ct.c_int), ("attach_point", ct.c_int),
                ("parent", ct.c_uint32), ("handle", ct.c_uint32), ("qdisc", ct.c_char_p)]


class TcOpts(ct.Structure):
    """struct bpf_tc_opts"""
    _fields_ = [("sz", ct.c_size_t), ("prog_fd", ct.c_int), ("flags", ct.c_uint32),
                ("prog_id", ct.c_uint32), ("handle", ct.c_uint32), ("priority", ct.c_uint32)]


class TestRunOpts(ct.Structure):
    """struct bpf_test_run_opts (BPF_PROG_TEST_RUN)"""
    _fields_ = [("sz", ct.c_size_t),
                ("data_in", ct.c_void_p), ("data_out", ct.c_void_p),
                ("data_size_in", ct.c_uint32), ("data_size_out", ct.c_uint32),
                ("ctx_in", ct.c_void_p), ("ctx_out", ct.c_void_p),
                ("ctx_size_in", ct.c_uint32), ("ctx_size_out", ct.c_uint32),
                ("retval", ct.c_uint32), ("repeat", ct.c_int), ("duration", ct.c_uint32),
                ("flags", ct.c_uint32), ("cpu", ct.c_uint32), ("batch_size", ct.c_uint32)]


_vp, _int, _u32 = ct.c_void_p, ct.c_int, ct.c_uint32
_SIGNATURES = {
    "bpf_object__open_file": (_vp, [ct.c_char_p, _vp]),
    "bpf_object__load": (_int, [_vp]),
    "bpf_object__close": (None, [_vp]),
    "bpf_object__find_program_by_name": (_vp, [_vp, ct.c_char_p]),
    "bpf_object__next_map": (_vp, [_vp, _vp]),
    "bpf_object__next_program": (_vp, [_vp, _vp]),
    "bpf_program__fd": (_int, [_vp]),
    "bpf_program__name": (ct.c_char_p, [_vp]),
    "bpf_program__set_autoload": (_int, [_vp, ct.c_bool]),
    "bpf_map__name": (ct.c_char_p, [_vp]),
    "bpf_map__set_pin_path": (_int, [_vp, ct.c_char_p]),
    "bpf_xdp_attach": (_int, [_int, _int, _u32, _vp]),
    "bpf_xdp_detach": (_int, [_int, _u32, _vp]),
    "bpf_tc_hook_create": (_int, [ct.POINTER(TcHook)]),
    "bpf_tc_hook_destroy": (_int, [ct.POINTER(TcHook)]),
    "bpf_tc_attach": (_int, [ct.POINTER(TcHook), ct.POINTER(TcOpts)]),
    "bpf_obj_get": (_int, [ct.c_char_p]),
    "bpf_map_lookup_elem": (_int, [_int, _vp, _vp]),
    "bpf_map_update_elem": (_int, [_int, _vp, _vp, ct.c_uint64]),
    "bpf_map_delete_elem": (_int, [_int, _vp]),
    "bpf_map_get_next_key": (_int, [_int, _vp, _vp]),
    "bpf_prog_test_run_opts": (_int, [_int, ct.POINTER(TestRunOpts)]),
    "libbpf_num_possible_cpus": (_int, []),
    "libbpf_set_print": (_vp, [_vp]),
}


class Libbpf:
    def __init__(self):
        path = ctypes.util.find_library("bpf") or "libbpf.so.1"
        try:
            self._lib = ct.CDLL(path, use_errno=True)
        except OSError as e:
            raise BpfError(f"cannot load libbpf ({path}): {e}. Install libbpf >= 1.0.") from e
        for name, (restype, argtypes) in _SIGNATURES.items():
            fn = getattr(self._lib, name)
            fn.restype, fn.argtypes = restype, argtypes
            setattr(self, name, fn)

    @staticmethod
    def check(rc, what: str):
        """Raise BpfError for a negative return code (libbpf 1.x convention)."""
        if rc is None or (isinstance(rc, int) and rc < 0):
            err = -rc if isinstance(rc, int) else ct.get_errno()
            raise BpfError(f"{what}: {os.strerror(err)} (errno {err})")
        return rc

    @staticmethod
    def last_errno() -> int:
        return ct.get_errno()

    @contextlib.contextmanager
    def quiet(self):
        """Silence libbpf's own warnings (e.g. detaching hooks that are not attached)."""
        prev = self.libbpf_set_print(None)
        try:
            yield
        finally:
            self.libbpf_set_print(prev)


_instance: Libbpf | None = None


def get_libbpf() -> Libbpf:
    global _instance
    if _instance is None:
        _instance = Libbpf()
    return _instance
