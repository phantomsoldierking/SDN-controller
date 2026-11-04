"""Build the BPF object, load it into the kernel and attach it to interfaces."""
from __future__ import annotations

import contextlib
import ctypes as ct
import errno
import glob
import logging
import os
import socket
import subprocess
from dataclasses import dataclass

from . import BPF_OBJ, BPF_SRC, BPF_SRC_DIR, PIN_DIR
from .libbpf import (BPF_TC_EGRESS, BPF_TC_F_REPLACE, BPF_TC_INGRESS, XDP_FLAGS, BpfError,
                     TcHook, TcOpts, get_libbpf)

log = logging.getLogger("sdn.loader")

PROGRAMS = {"xdp": "xdp_dataplane", "tc": "tc_dataplane"}


@dataclass
class AttachOptions:
    hook: str = "xdp"            # "xdp" | "tc"
    xdp_mode: str = "auto"       # "auto" | "native" | "generic" | "offload"
    fib_forward: bool = False    # forward in eBPF via bpf_fib_lookup + redirect
    stateful: bool = True        # track allowed flows in fw_conntrack
    default_action: str = "allow"

    def __post_init__(self):
        if self.hook not in PROGRAMS:
            raise ValueError(f"hook must be one of {sorted(PROGRAMS)}")
        if self.xdp_mode not in XDP_FLAGS:
            raise ValueError(f"xdp_mode must be one of {sorted(XDP_FLAGS)}")


# ---- build -----------------------------------------------------------------
def _sources() -> list[str]:
    return glob.glob(os.path.join(BPF_SRC_DIR, "*.[ch]"))


def build(obj: str = BPF_OBJ, force: bool = False) -> str:
    """Compile bpf/xdp_prog.c if the object is missing or older than any source."""
    if (not force and os.path.exists(obj)
            and os.path.getmtime(obj) >= max(os.path.getmtime(s) for s in _sources())):
        return obj
    os.makedirs(os.path.dirname(obj), exist_ok=True)
    cmd = ["clang", "-O2", "-g", "-Wall", "-Wextra", "-target", "bpf", "-c", BPF_SRC, "-o", obj]
    arch_inc = f"/usr/include/{os.uname().machine}-linux-gnu"
    if os.path.isdir(arch_inc):
        cmd[1:1] = ["-I", arch_inc]
    log.info("%s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise BpfError("clang not found - install clang to build the BPF object") from None
    if proc.stderr:
        log.warning("%s", proc.stderr.rstrip())
    if proc.returncode != 0:
        if proc.returncode == 127 or "error while loading shared libraries" in proc.stderr:
            raise BpfError("clang cannot run (toolchain problem, not a code problem): clang and "
                           "its LLVM libraries are at different versions. Update the whole "
                           "system (Arch: pacman -Syu, Omarchy: omarchy update).")
        raise BpfError(f"compiling {BPF_SRC} failed (exit {proc.returncode})")
    return obj


# ---- load ------------------------------------------------------------------
def ensure_bpffs() -> None:
    if not os.path.ismount("/sys/fs/bpf"):
        subprocess.run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], check=True)


def ifindex(name: str) -> int:
    try:
        return socket.if_nametoindex(name)
    except OSError:
        raise BpfError(f"interface {name!r} not found in this network namespace") from None


class LoadedObject:
    """A loaded BPF object with one program enabled.

    Maps are pinned in `pin_dir`; an existing pin with the same name is reused,
    so repeated loads (and every attached interface) share one set of maps.
    """

    def __init__(self, hook: str, obj: str | None = None, pin_dir: str = PIN_DIR):
        self._lib = get_libbpf()
        self.hook, self.pin_dir = hook, pin_dir
        self.program = PROGRAMS[hook]
        path = obj or build()
        ensure_bpffs()
        os.makedirs(pin_dir, exist_ok=True)

        self._obj = self._lib.bpf_object__open_file(path.encode(), None)
        if not self._obj:
            self._lib.check(-self._lib.last_errno(), f"open {path}")
        try:
            self._configure()
            self._lib.check(self._lib.bpf_object__load(self._obj),
                            "bpf_object__load (the verifier log is printed above)")
            prog = self._lib.bpf_object__find_program_by_name(self._obj, self.program.encode())
            self.prog_fd = self._lib.check(self._lib.bpf_program__fd(prog), "program fd")
        except Exception:
            self.close()
            raise

    def _configure(self):
        m = self._lib.bpf_object__next_map(self._obj, None)
        while m:
            name = self._lib.bpf_map__name(m).decode()
            self._lib.check(self._lib.bpf_map__set_pin_path(
                m, os.path.join(self.pin_dir, name).encode()), f"pin {name}")
            m = self._lib.bpf_object__next_map(self._obj, m)
        # Load only the requested program, so a problem in one hook can't block the other.
        p = self._lib.bpf_object__next_program(self._obj, None)
        while p:
            self._lib.bpf_program__set_autoload(p, self._lib.bpf_program__name(p).decode()
                                                == self.program)
            p = self._lib.bpf_object__next_program(self._obj, p)

    def attach(self, iface: str, xdp_mode: str = "auto") -> None:
        idx = ifindex(iface)
        if self.hook == "xdp":
            self._lib.check(self._lib.bpf_xdp_attach(idx, self.prog_fd, XDP_FLAGS[xdp_mode], None),
                            f"XDP attach {iface} ({xdp_mode})")
        else:
            hook = TcHook(sz=ct.sizeof(TcHook), ifindex=idx, attach_point=BPF_TC_INGRESS)
            rc = self._lib.bpf_tc_hook_create(ct.byref(hook))
            if rc < 0 and rc != -errno.EEXIST:
                self._lib.check(rc, f"tc hook create {iface}")
            opts = TcOpts(sz=ct.sizeof(TcOpts), prog_fd=self.prog_fd, flags=BPF_TC_F_REPLACE,
                          handle=1, priority=1)
            self._lib.check(self._lib.bpf_tc_attach(ct.byref(hook), ct.byref(opts)),
                            f"tc attach {iface}")
        log.info("%s attached to %s (ifindex %d, hook=%s%s)", self.program, iface, idx,
                 self.hook, f", mode={xdp_mode}" if self.hook == "xdp" else "")

    def close(self) -> None:
        """Release the object. Attachments and pinned maps keep the program alive."""
        if self._obj:
            self._lib.bpf_object__close(self._obj)
            self._obj = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def load_and_attach(ifaces: list[str], opts: AttachOptions, obj: str | None = None,
                    pin_dir: str = PIN_DIR) -> None:
    from .dataplane import DataPlane  # local import: dataplane does not depend on the loader

    with LoadedObject(opts.hook, obj, pin_dir) as loaded:
        for iface in ifaces:
            loaded.attach(iface, opts.xdp_mode)
    DataPlane.open(pin_dir).config.apply(default_action=opts.default_action,
                                         fib_forward=opts.fib_forward, stateful=opts.stateful)


# ---- detach ----------------------------------------------------------------
def detach(ifaces: list[str], hook: str = "all", pin_dir: str = PIN_DIR,
           unpin: bool = True) -> None:
    lib = get_libbpf()
    with lib.quiet():
        for iface in ifaces:
            idx = ifindex(iface)
            if hook in ("xdp", "all"):
                for mode in ("generic", "native"):
                    lib.bpf_xdp_detach(idx, XDP_FLAGS[mode], None)
            if hook in ("tc", "all"):
                tc = TcHook(sz=ct.sizeof(TcHook), ifindex=idx,
                            attach_point=BPF_TC_INGRESS | BPF_TC_EGRESS)
                lib.bpf_tc_hook_destroy(ct.byref(tc))
            log.info("detached from %s", iface)
    if unpin:
        unpin_maps(pin_dir)


def unpin_maps(pin_dir: str = PIN_DIR) -> None:
    if not os.path.isdir(pin_dir):
        return
    for name in os.listdir(pin_dir):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(os.path.join(pin_dir, name))
    os.rmdir(pin_dir)
    log.info("unpinned maps in %s", pin_dir)
