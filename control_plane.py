#!/usr/bin/env python3
"""
control_plane.py - user-space control plane for the eBPF/XDP SDN data plane.

Talks to the kernel through libbpf (ctypes bindings to libbpf.so.1), so the
only runtime requirements are Python 3.8+, libbpf >= 1.0 and clang (to build
xdp_prog.o). All maps are pinned under /sys/fs/bpf/sdn_dp so every CLI
invocation, the REST daemon and the GC thread share the same kernel state.

  load      compile (if stale), load and attach to interfaces (XDP or TC)
  unload    detach from interfaces and unpin maps
  daemon    REST API + conntrack idle-timeout garbage collector
  fw        firewall rules (5-tuple / MAC 2-tuple), default policy
  lb        L4 load-balancer services and backend pools
  ct        connection-tracking tables
  stats     global counters and per-flow telemetry

Run `control_plane.py <command> -h` for details.
"""
import argparse
import ctypes as ct
import ctypes.util
import errno
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, "xdp_prog.c")
DEFAULT_OBJ = os.path.join(HERE, "xdp_prog.o")
PIN_DIR = os.environ.get("SDN_PIN_DIR", "/sys/fs/bpf/sdn_dp")

# --------------------------------------------------------------------------
# ABI shared with xdp_prog.c (keep in sync)
# --------------------------------------------------------------------------
FW_KIND_IP, FW_KIND_MAC = 1, 2
ACT_NONE, ACT_ALLOW, ACT_DROP = 0, 1, 2
L3_ARP, L3_IPV4 = 1, 4
MAX_SERVICES, MAX_BACKENDS_PER_SVC = 16, 16
CFG_F_FIB_FORWARD, CFG_F_FW_STATEFUL = 1 << 0, 1 << 1
CT_F_SYN, CT_F_FIN, CT_F_RST, CT_F_REPLY = 1, 2, 4, 8

STAT_NAMES = [
    "rx_packets", "rx_bytes", "pass", "drop_firewall", "drop_malformed",
    "drop_no_backend", "lb_dnat", "lb_snat", "lb_new_conn", "ct_established",
    "arp", "non_ip", "fib_forward",
]
PROTOS = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
PROTO_NAMES = {v: k for k, v in PROTOS.items()}
ACTIONS = {"allow": ACT_ALLOW, "drop": ACT_DROP}
ACTION_NAMES = {v: k for k, v in ACTIONS.items()}

XDP_FLAGS = {"auto": 0, "generic": 1 << 1, "native": 1 << 2, "offload": 1 << 3}
BPF_ANY, BPF_NOEXIST = 0, 1
BPF_TC_INGRESS, BPF_TC_EGRESS = 1 << 0, 1 << 1
BPF_TC_F_REPLACE = 1 << 0


class FlowKey(ct.Structure):
    _fields_ = [("saddr", ct.c_uint32), ("daddr", ct.c_uint32),
                ("sport", ct.c_uint16), ("dport", ct.c_uint16),
                ("proto", ct.c_uint8), ("l3", ct.c_uint8), ("pad", ct.c_uint8 * 2)]


class FwKey(ct.Structure):
    _fields_ = [("kind", ct.c_uint8), ("proto", ct.c_uint8),
                ("sport", ct.c_uint16), ("dport", ct.c_uint16), ("pad", ct.c_uint16),
                ("saddr", ct.c_uint32), ("daddr", ct.c_uint32),
                ("smac", ct.c_uint8 * 6), ("dmac", ct.c_uint8 * 6)]


class FwRule(ct.Structure):
    _fields_ = [("action", ct.c_uint32), ("pad", ct.c_uint32), ("hits", ct.c_uint64)]


class CtEntry(ct.Structure):
    _fields_ = [("created_ns", ct.c_uint64), ("last_seen_ns", ct.c_uint64),
                ("packets", ct.c_uint64), ("bytes", ct.c_uint64),
                ("flags", ct.c_uint32), ("pad", ct.c_uint32)]


class SvcKey(ct.Structure):
    _fields_ = [("vip", ct.c_uint32), ("port", ct.c_uint16),
                ("proto", ct.c_uint8), ("pad", ct.c_uint8)]


class SvcInfo(ct.Structure):
    _fields_ = [("id", ct.c_uint32), ("count", ct.c_uint32)]


class Backend(ct.Structure):
    _fields_ = [("ip", ct.c_uint32), ("port", ct.c_uint16), ("active", ct.c_uint16)]


class LbCt(ct.Structure):
    _fields_ = [("backend_ip", ct.c_uint32), ("backend_port", ct.c_uint16),
                ("svc_id", ct.c_uint8), ("be_idx", ct.c_uint8),
                ("created_ns", ct.c_uint64), ("last_seen_ns", ct.c_uint64),
                ("packets", ct.c_uint64), ("bytes", ct.c_uint64),
                ("flags", ct.c_uint32), ("pad", ct.c_uint32)]


class LbRev(ct.Structure):
    _fields_ = [("vip", ct.c_uint32), ("vport", ct.c_uint16), ("pad", ct.c_uint16),
                ("last_seen_ns", ct.c_uint64), ("flags", ct.c_uint32), ("pad2", ct.c_uint32)]


class FlowStat(ct.Structure):
    _fields_ = [("key", FlowKey), ("packets", ct.c_uint64),
                ("bytes", ct.c_uint64), ("last_seen_ns", ct.c_uint64)]


class DpConfig(ct.Structure):
    _fields_ = [("default_action", ct.c_uint32), ("flags", ct.c_uint32)]


# Sizes must match the C structs exactly.
for _s, _n in ((FlowKey, 16), (FwKey, 28), (FwRule, 16), (CtEntry, 40), (SvcKey, 8),
               (SvcInfo, 8), (Backend, 8), (LbCt, 48), (LbRev, 24), (FlowStat, 40),
               (DpConfig, 8)):
    assert ct.sizeof(_s) == _n, (_s.__name__, ct.sizeof(_s), _n)

# map name -> (key type, value type, per-cpu)
MAPS = {
    "firewall_map": (FwKey, FwRule, False),
    "fw_conntrack": (FlowKey, CtEntry, False),
    "lb_services": (SvcKey, SvcInfo, False),
    "lb_backends": (ct.c_uint32, Backend, False),
    "lb_conntrack": (FlowKey, LbCt, False),
    "lb_reverse": (FlowKey, LbRev, False),
    "flow_stats": (ct.c_uint32, FlowStat, True),
    "global_stats": (ct.c_uint32, ct.c_uint64, True),
    "dp_config_map": (ct.c_uint32, DpConfig, False),
}


# --------------------------------------------------------------------------
# Byte-order helpers (maps hold wire-format / network-order values)
# --------------------------------------------------------------------------
def ip2be(ip):
    return int.from_bytes(socket.inet_aton(str(ip)), "little") if ip else 0


def be2ip(v):
    return socket.inet_ntoa(int(v).to_bytes(4, "little"))


def port2be(p):
    return socket.htons(int(p)) if p else 0


def be2port(p):
    return socket.ntohs(int(p))


def mac2bytes(mac):
    return (ct.c_uint8 * 6)(*bytes.fromhex(mac.replace(":", "").replace("-", ""))) \
        if mac else (ct.c_uint8 * 6)()


def bytes2mac(b):
    return ":".join(f"{x:02x}" for x in bytes(b))


def mono_ns():
    # bpf_ktime_get_ns() is CLOCK_MONOTONIC
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def flow_key(src, dst, sport, dport, proto, l3=L3_IPV4):
    return FlowKey(ip2be(src), ip2be(dst), port2be(sport), port2be(dport), proto, l3)


def flow_key_dict(k):
    if k.l3 == L3_ARP:
        return {"l3": "arp", "src": be2ip(k.saddr), "dst": be2ip(k.daddr),
                "op": be2port(k.sport)}
    return {"l3": "ipv4", "src": be2ip(k.saddr), "dst": be2ip(k.daddr),
            "sport": be2port(k.sport), "dport": be2port(k.dport),
            "proto": PROTO_NAMES.get(k.proto, str(k.proto))}


def ct_flags_str(f):
    return ",".join(n for b, n in ((CT_F_SYN, "SYN"), (CT_F_FIN, "FIN"),
                                   (CT_F_RST, "RST"), (CT_F_REPLY, "REPLY")) if f & b) or "-"


# --------------------------------------------------------------------------
# libbpf ctypes bindings
# --------------------------------------------------------------------------
class TcHook(ct.Structure):
    _fields_ = [("sz", ct.c_size_t), ("ifindex", ct.c_int), ("attach_point", ct.c_int),
                ("parent", ct.c_uint32), ("handle", ct.c_uint32), ("qdisc", ct.c_char_p)]


class TcOpts(ct.Structure):
    _fields_ = [("sz", ct.c_size_t), ("prog_fd", ct.c_int), ("flags", ct.c_uint32),
                ("prog_id", ct.c_uint32), ("handle", ct.c_uint32), ("priority", ct.c_uint32)]


class BpfError(RuntimeError):
    pass


class Libbpf:
    def __init__(self):
        path = ctypes.util.find_library("bpf") or "libbpf.so.1"
        try:
            self.lib = ct.CDLL(path, use_errno=True)
        except OSError as e:
            raise BpfError(f"cannot load libbpf ({path}): {e}. Install libbpf >= 1.0.")
        L, vp, i, u32, sz = self.lib, ct.c_void_p, ct.c_int, ct.c_uint32, ct.c_size_t
        sigs = {
            "bpf_object__open_file": (vp, [ct.c_char_p, vp]),
            "bpf_object__load": (i, [vp]),
            "bpf_object__close": (None, [vp]),
            "bpf_object__find_program_by_name": (vp, [vp, ct.c_char_p]),
            "bpf_object__next_map": (vp, [vp, vp]),
            "bpf_object__next_program": (vp, [vp, vp]),
            "bpf_program__fd": (i, [vp]),
            "bpf_program__name": (ct.c_char_p, [vp]),
            "bpf_program__set_autoload": (i, [vp, ct.c_bool]),
            "bpf_map__name": (ct.c_char_p, [vp]),
            "bpf_map__set_pin_path": (i, [vp, ct.c_char_p]),
            "bpf_xdp_attach": (i, [i, i, u32, vp]),
            "bpf_xdp_detach": (i, [i, u32, vp]),
            "bpf_tc_hook_create": (i, [ct.POINTER(TcHook)]),
            "bpf_tc_hook_destroy": (i, [ct.POINTER(TcHook)]),
            "bpf_tc_attach": (i, [ct.POINTER(TcHook), ct.POINTER(TcOpts)]),
            "bpf_obj_get": (i, [ct.c_char_p]),
            "bpf_map_lookup_elem": (i, [i, vp, vp]),
            "bpf_map_update_elem": (i, [i, vp, vp, ct.c_uint64]),
            "bpf_map_delete_elem": (i, [i, vp]),
            "bpf_map_get_next_key": (i, [i, vp, vp]),
            "libbpf_num_possible_cpus": (i, []),
            "libbpf_strerror": (i, [i, ct.c_char_p, sz]),
        }
        for name, (res, args) in sigs.items():
            fn = getattr(L, name)
            fn.restype, fn.argtypes = res, args

    def __getattr__(self, name):
        return getattr(self.lib, name)

    def check(self, rc, what):
        if rc is None or (isinstance(rc, int) and rc < 0):
            err = -rc if isinstance(rc, int) and rc < 0 else ct.get_errno()
            raise BpfError(f"{what}: {os.strerror(err)} (errno {err})")
        return rc


_LIBBPF = None


def libbpf():
    global _LIBBPF
    if _LIBBPF is None:
        _LIBBPF = Libbpf()
    return _LIBBPF


# --------------------------------------------------------------------------
# Build / load / attach
# --------------------------------------------------------------------------
def build(src=DEFAULT_SRC, obj=DEFAULT_OBJ, force=False):
    if not force and os.path.exists(obj) and os.path.getmtime(obj) >= os.path.getmtime(src):
        return obj
    arch_inc = f"/usr/include/{os.uname().machine}-linux-gnu"
    cmd = ["clang", "-O2", "-g", "-Wall", "-target", "bpf", "-c", src, "-o", obj]
    if os.path.isdir(arch_inc):
        cmd[1:1] = ["-I", arch_inc]
    print("[build]", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return obj


def ensure_bpffs():
    if os.path.ismount("/sys/fs/bpf"):
        return
    subprocess.run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], check=True)


def ifindex(name):
    try:
        return socket.if_nametoindex(name)
    except OSError:
        raise BpfError(f"interface {name!r} not found in this network namespace")


def load_and_attach(ifaces, hook="xdp", xdp_mode="auto", obj=None, fib_forward=False,
                    stateful=True, default_action="allow"):
    lb = libbpf()
    ensure_bpffs()
    obj_path = obj or build()
    os.makedirs(PIN_DIR, exist_ok=True)

    o = lb.bpf_object__open_file(obj_path.encode(), None)
    if not o:
        lb.check(-ct.get_errno(), f"open {obj_path}")

    # Maps are pinned by name; an existing pin is reused, so all interfaces
    # (and repeated `load` calls) share one set of kernel maps.
    m = lb.bpf_object__next_map(o, None)
    while m:
        name = lb.bpf_map__name(m).decode()
        lb.check(lb.bpf_map__set_pin_path(m, f"{PIN_DIR}/{name}".encode()), f"pin {name}")
        m = lb.bpf_object__next_map(o, m)

    want = "xdp_dataplane" if hook == "xdp" else "tc_dataplane"
    p = lb.bpf_object__next_program(o, None)
    while p:
        lb.bpf_program__set_autoload(p, lb.bpf_program__name(p).decode() == want)
        p = lb.bpf_object__next_program(o, p)

    lb.check(lb.bpf_object__load(o), "bpf_object__load (see verifier log above)")
    prog = lb.bpf_object__find_program_by_name(o, want.encode())
    prog_fd = lb.check(lb.bpf_program__fd(prog), "program fd")

    for name in ifaces:
        idx = ifindex(name)
        if hook == "xdp":
            lb.check(lb.bpf_xdp_attach(idx, prog_fd, XDP_FLAGS[xdp_mode], None),
                     f"XDP attach {name} ({xdp_mode})")
        else:
            h = TcHook(sz=ct.sizeof(TcHook), ifindex=idx, attach_point=BPF_TC_INGRESS)
            rc = lb.bpf_tc_hook_create(ct.byref(h))
            if rc < 0 and rc != -errno.EEXIST:
                lb.check(rc, f"tc hook create {name}")
            opts = TcOpts(sz=ct.sizeof(TcOpts), prog_fd=prog_fd, flags=BPF_TC_F_REPLACE,
                          handle=1, priority=1)
            lb.check(lb.bpf_tc_attach(ct.byref(h), ct.byref(opts)), f"tc attach {name}")
        print(f"[load] {want} attached to {name} (ifindex {idx}, hook={hook}"
              f"{', mode=' + xdp_mode if hook == 'xdp' else ''})")

    dp = DataPlane()
    cfg = dp.get_config()
    cfg.flags = (CFG_F_FIB_FORWARD if fib_forward else 0) | (CFG_F_FW_STATEFUL if stateful else 0)
    cfg.default_action = ACTIONS[default_action]
    dp.set_config(cfg)
    # The object can be closed: attachments and pinned maps keep the program alive.
    lb.bpf_object__close(o)


def detach(ifaces, hook="xdp", unpin=False):
    lb = libbpf()
    # Detaching hooks that were never attached is fine; silence libbpf's warnings.
    lb.libbpf_set_print.restype = ct.c_void_p
    lb.libbpf_set_print.argtypes = [ct.c_void_p]
    prev_print = lb.libbpf_set_print(None)
    for name in ifaces:
        idx = ifindex(name)
        if hook in ("xdp", "all"):
            for mode in ("generic", "native"):
                lb.bpf_xdp_detach(idx, XDP_FLAGS[mode], None)
        if hook in ("tc", "all"):
            h = TcHook(sz=ct.sizeof(TcHook), ifindex=idx,
                       attach_point=BPF_TC_INGRESS | BPF_TC_EGRESS)
            lb.bpf_tc_hook_destroy(ct.byref(h))
        print(f"[unload] detached from {name}")
    lb.libbpf_set_print(prev_print)
    if unpin and os.path.isdir(PIN_DIR):
        for f in os.listdir(PIN_DIR):
            os.unlink(os.path.join(PIN_DIR, f))
        os.rmdir(PIN_DIR)
        print(f"[unload] unpinned maps in {PIN_DIR}")


# --------------------------------------------------------------------------
# Map access
# --------------------------------------------------------------------------
class BpfMap:
    def __init__(self, name):
        self.name = name
        self.key_t, self.val_t, self.percpu = MAPS[name]
        self.lb = libbpf()
        path = f"{PIN_DIR}/{name}"
        self.fd = self.lb.bpf_obj_get(path.encode())
        if self.fd < 0:
            raise BpfError(f"map {path} not found: run `control_plane.py load` first "
                           f"({os.strerror(ct.get_errno())})")
        if self.percpu:
            self.ncpu = self.lb.libbpf_num_possible_cpus()
            # per-CPU values are laid out at 8-byte aligned strides
            self.stride = (ct.sizeof(self.val_t) + 7) & ~7

    def _val_buf(self):
        if self.percpu:
            return ct.create_string_buffer(self.stride * self.ncpu)
        return self.val_t()

    def _percpu_values(self, buf):
        return [self.val_t.from_buffer_copy(buf.raw[i * self.stride:
                                                    i * self.stride + ct.sizeof(self.val_t)])
                for i in range(self.ncpu)]

    def lookup(self, key):
        buf = self._val_buf()
        if self.lb.bpf_map_lookup_elem(self.fd, ct.byref(key), ct.byref(buf)) < 0:
            return None
        return self._percpu_values(buf) if self.percpu else buf

    def update(self, key, value, flags=BPF_ANY):
        self.lb.check(self.lb.bpf_map_update_elem(self.fd, ct.byref(key), ct.byref(value),
                                                  flags), f"update {self.name}")

    def delete(self, key):
        return self.lb.bpf_map_delete_elem(self.fd, ct.byref(key)) == 0

    def keys(self):
        out, prev, nxt = [], None, self.key_t()
        while self.lb.bpf_map_get_next_key(self.fd, ct.byref(prev) if prev is not None else None,
                                           ct.byref(nxt)) == 0:
            out.append(nxt)
            prev, nxt = nxt, self.key_t()
        return out

    def items(self):
        for k in self.keys():
            v = self.lookup(k)
            if v is not None:
                yield k, v


class DataPlane:
    """High-level operations on the pinned maps (shared by CLI, REST and GC)."""

    def __init__(self):
        self.m = {name: BpfMap(name) for name in MAPS}
        self.lock = threading.Lock()

    # ---- config ----
    def get_config(self):
        return self.m["dp_config_map"].lookup(ct.c_uint32(0)) or DpConfig()

    def set_config(self, cfg):
        self.m["dp_config_map"].update(ct.c_uint32(0), cfg)

    def set_default_action(self, action):
        with self.lock:
            cfg = self.get_config()
            cfg.default_action = ACTIONS[action]
            self.set_config(cfg)

    # ---- firewall ----
    @staticmethod
    def _fw_keys(rule):
        """Yield FwKey(s) for a rule dict; `bidir` also yields the reverse direction."""
        if rule.get("src_mac") or rule.get("dst_mac"):
            pairs = [(rule.get("src_mac"), rule.get("dst_mac"))]
            if rule.get("bidir") and rule.get("dst_mac"):
                pairs.append((rule.get("dst_mac"), rule.get("src_mac")))
            for s, d in pairs:
                if not s:
                    raise ValueError("MAC rules need src_mac (dst_mac may be omitted = any)")
                yield FwKey(kind=FW_KIND_MAC, smac=mac2bytes(s), dmac=mac2bytes(d))
            return
        proto = PROTOS[rule.get("proto", "any")] if isinstance(rule.get("proto", "any"), str) \
            else int(rule["proto"])
        src, dst = rule.get("src"), rule.get("dst")
        sport, dport = int(rule.get("sport") or 0), int(rule.get("dport") or 0)
        if not src and not dst:
            raise ValueError("IP rules need at least src or dst")
        if (sport or dport) and proto not in (6, 17):
            raise ValueError("port match requires proto tcp or udp")
        if (sport or dport or proto) and not (src and dst):
            raise ValueError("proto/port match requires both src and dst")
        dirs = [(src, dst, sport, dport)]
        if rule.get("bidir"):
            dirs.append((dst, src, dport, sport))
        for s, d, sp, dp in dirs:
            yield FwKey(kind=FW_KIND_IP, proto=proto, saddr=ip2be(s), daddr=ip2be(d),
                        sport=port2be(sp), dport=port2be(dp))

    def fw_add(self, rule):
        action = ACTIONS[rule.get("action", "drop")]
        keys = list(self._fw_keys(rule))
        with self.lock:
            for k in keys:
                self.m["firewall_map"].update(k, FwRule(action=action))
            if action == ACT_DROP:
                self._flush_ct_matching(keys)
        return len(keys)

    def fw_del(self, rule):
        n = 0
        with self.lock:
            for k in self._fw_keys(rule):
                n += self.m["firewall_map"].delete(k)
        return n

    def fw_list(self):
        out = []
        for k, v in self.m["firewall_map"].items():
            r = {"action": ACTION_NAMES.get(v.action, v.action), "hits": v.hits}
            if k.kind == FW_KIND_MAC:
                r.update(kind="mac", src_mac=bytes2mac(k.smac),
                         dst_mac=bytes2mac(k.dmac) if any(k.dmac) else "*")
            else:
                r.update(kind="ip", proto=PROTO_NAMES.get(k.proto, k.proto),
                         src=be2ip(k.saddr) if k.saddr else "*",
                         dst=be2ip(k.daddr) if k.daddr else "*",
                         sport=be2port(k.sport) or "*", dport=be2port(k.dport) or "*")
            out.append(r)
        return out

    def fw_flush(self):
        with self.lock:
            return sum(self.m["firewall_map"].delete(k) for k in self.m["firewall_map"].keys())

    def _flush_ct_matching(self, fw_keys):
        """A new DROP rule must not be bypassed by already-established state."""
        ips = {(k.saddr, k.daddr) for k in fw_keys if k.kind == FW_KIND_IP}
        if not ips:
            return
        for name in ("fw_conntrack", "lb_conntrack", "lb_reverse"):
            m = self.m[name]
            for k in m.keys():
                if any((s in (0, k.saddr)) and (d in (0, k.daddr)) for s, d in ips):
                    m.delete(k)

    # ---- load balancer ----
    def lb_add_service(self, vip, port, backends, proto="tcp"):
        sk = SvcKey(vip=ip2be(vip), port=port2be(port), proto=PROTOS[proto])
        if not 0 < len(backends) <= MAX_BACKENDS_PER_SVC:
            raise ValueError(f"1..{MAX_BACKENDS_PER_SVC} backends required")
        with self.lock:
            existing = self.m["lb_services"].lookup(sk)
            if existing is not None:
                sid = existing.id
            else:
                used = {v.id for _, v in self.m["lb_services"].items()}
                free = [i for i in range(MAX_SERVICES) if i not in used]
                if not free:
                    raise ValueError("service table full")
                sid = free[0]
            for i in range(MAX_BACKENDS_PER_SVC):
                if i < len(backends):
                    ip, _, bport = backends[i].partition(":")
                    be = Backend(ip=ip2be(ip), port=port2be(bport or port), active=1)
                else:
                    be = Backend()
                self.m["lb_backends"].update(ct.c_uint32(sid * MAX_BACKENDS_PER_SVC + i), be)
            self.m["lb_services"].update(sk, SvcInfo(id=sid, count=len(backends)))
        return sid

    def lb_del_service(self, vip, port, proto="tcp"):
        sk = SvcKey(vip=ip2be(vip), port=port2be(port), proto=PROTOS[proto])
        with self.lock:
            info = self.m["lb_services"].lookup(sk)
            if info is None:
                return False
            self.m["lb_services"].delete(sk)
            for i in range(MAX_BACKENDS_PER_SVC):
                self.m["lb_backends"].update(ct.c_uint32(info.id * MAX_BACKENDS_PER_SVC + i),
                                             Backend())
        return True

    def lb_set_backend_state(self, vip, port, backend, up, proto="tcp"):
        sk = SvcKey(vip=ip2be(vip), port=port2be(port), proto=PROTOS[proto])
        info = self.m["lb_services"].lookup(sk)
        if info is None:
            raise ValueError("no such service")
        ip = backend.partition(":")[0]
        with self.lock:
            for i in range(info.count):
                slot = ct.c_uint32(info.id * MAX_BACKENDS_PER_SVC + i)
                be = self.m["lb_backends"].lookup(slot)
                if be is not None and be.ip == ip2be(ip):
                    be.active = 1 if up else 0
                    self.m["lb_backends"].update(slot, be)
                    return True
        return False

    def lb_list(self):
        out = []
        for k, info in self.m["lb_services"].items():
            bes = []
            for i in range(info.count):
                be = self.m["lb_backends"].lookup(
                    ct.c_uint32(info.id * MAX_BACKENDS_PER_SVC + i))
                if be is not None:
                    bes.append({"ip": be2ip(be.ip), "port": be2port(be.port),
                                "active": bool(be.active)})
            out.append({"vip": be2ip(k.vip), "port": be2port(k.port),
                        "proto": PROTO_NAMES.get(k.proto, k.proto), "id": info.id,
                        "backends": bes})
        return out

    # ---- conntrack ----
    def ct_list(self):
        now = mono_ns()
        res = {"firewall": [], "lb": [], "lb_reverse": []}
        for k, v in self.m["fw_conntrack"].items():
            res["firewall"].append({**flow_key_dict(k), "packets": v.packets, "bytes": v.bytes,
                                    "flags": ct_flags_str(v.flags),
                                    "idle_s": round((now - v.last_seen_ns) / 1e9, 1)})
        for k, v in self.m["lb_conntrack"].items():
            res["lb"].append({**flow_key_dict(k), "backend": f"{be2ip(v.backend_ip)}:"
                              f"{be2port(v.backend_port)}", "packets": v.packets,
                              "bytes": v.bytes, "flags": ct_flags_str(v.flags),
                              "idle_s": round((now - v.last_seen_ns) / 1e9, 1)})
        for k, v in self.m["lb_reverse"].items():
            res["lb_reverse"].append({**flow_key_dict(k), "vip": f"{be2ip(v.vip)}:"
                                      f"{be2port(v.vport)}", "flags": ct_flags_str(v.flags),
                                      "idle_s": round((now - v.last_seen_ns) / 1e9, 1)})
        return res

    def ct_flush(self):
        n = 0
        with self.lock:
            for name in ("fw_conntrack", "lb_conntrack", "lb_reverse"):
                m = self.m[name]
                n += sum(m.delete(k) for k in m.keys())
        return n

    def ct_gc(self, idle_timeout, fin_timeout, hard_timeout=0):
        """Expire idle connections - the OpenFlow idle_timeout/hard_timeout analogue."""
        now = mono_ns()
        idle_ns, fin_ns, hard_ns = (int(x * 1e9) for x in (idle_timeout, fin_timeout,
                                                            hard_timeout))

        def expired(v, created=None):
            limit = fin_ns if v.flags & (CT_F_FIN | CT_F_RST) else idle_ns
            if now - v.last_seen_ns > limit:
                return True
            return bool(hard_ns and created is not None and now - created > hard_ns)

        removed = {"fw_conntrack": 0, "lb_conntrack": 0, "lb_reverse": 0}
        with self.lock:
            for k, v in self.m["fw_conntrack"].items():
                if expired(v, v.created_ns):
                    removed["fw_conntrack"] += self.m["fw_conntrack"].delete(k)
            for k, v in self.m["lb_conntrack"].items():
                if expired(v, v.created_ns):
                    removed["lb_conntrack"] += self.m["lb_conntrack"].delete(k)
                    # drop the matching reverse entry with it
                    rk = FlowKey(saddr=v.backend_ip, daddr=k.saddr, sport=v.backend_port,
                                 dport=k.sport, proto=k.proto, l3=L3_IPV4)
                    removed["lb_reverse"] += self.m["lb_reverse"].delete(rk)
            for k, v in self.m["lb_reverse"].items():
                if expired(v):
                    removed["lb_reverse"] += self.m["lb_reverse"].delete(k)
        return removed

    # ---- telemetry ----
    def stats(self):
        out = {}
        for i, name in enumerate(STAT_NAMES):
            vals = self.m["global_stats"].lookup(ct.c_uint32(i)) or []
            out[name] = sum(v.value for v in vals)
        return out

    def flows(self, top=20):
        agg = {}
        for _, per_cpu in self.m["flow_stats"].items():
            for fs in per_cpu:
                if not fs.packets:
                    continue
                key = bytes(fs.key)
                a = agg.setdefault(key, {"key": FlowKey.from_buffer_copy(key),
                                         "packets": 0, "bytes": 0, "last": 0})
                a["packets"] += fs.packets
                a["bytes"] += fs.bytes
                a["last"] = max(a["last"], fs.last_seen_ns)
        now = mono_ns()
        rows = sorted(agg.values(), key=lambda a: a["bytes"], reverse=True)[:top]
        return [{**flow_key_dict(a["key"]), "packets": a["packets"], "bytes": a["bytes"],
                 "idle_s": round((now - a["last"]) / 1e9, 1)} for a in rows]


# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------
class Api(BaseHTTPRequestHandler):
    dp: DataPlane = None
    server_version = "sdn-ebpf-cp/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[api] " + fmt % args + "\n")

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _route(self, method):
        dp, path = self.dp, self.path.split("?")[0].rstrip("/")
        routes = {
            ("GET", "/stats"): lambda b: dp.stats(),
            ("GET", "/flows"): lambda b: dp.flows(100),
            ("GET", "/firewall"): lambda b: {"default": ACTION_NAMES.get(
                dp.get_config().default_action, "allow"), "rules": dp.fw_list()},
            ("POST", "/firewall"): lambda b: {"added": dp.fw_add(b)},
            ("DELETE", "/firewall"): lambda b: {"deleted": dp.fw_del(b) if b else dp.fw_flush()},
            ("PUT", "/firewall/default"): lambda b: dp.set_default_action(b["action"]) or
            {"default": b["action"]},
            ("GET", "/services"): lambda b: dp.lb_list(),
            ("POST", "/services"): lambda b: {"id": dp.lb_add_service(
                b["vip"], int(b["port"]), b["backends"], b.get("proto", "tcp"))},
            ("DELETE", "/services"): lambda b: {"deleted": dp.lb_del_service(
                b["vip"], int(b["port"]), b.get("proto", "tcp"))},
            ("PUT", "/services/backend"): lambda b: {"updated": dp.lb_set_backend_state(
                b["vip"], int(b["port"]), b["backend"], b.get("state", "up") == "up",
                b.get("proto", "tcp"))},
            ("GET", "/conntrack"): lambda b: dp.ct_list(),
            ("DELETE", "/conntrack"): lambda b: {"deleted": dp.ct_flush()},
        }
        fn = routes.get((method, path))
        if fn is None:
            return self._send(404, {"error": f"no route {method} {path}",
                                    "routes": sorted(f"{m} {p}" for m, p in routes)})
        try:
            self._send(200, fn(self._body()))
        except (ValueError, KeyError, BpfError, json.JSONDecodeError) as e:
            self._send(400, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")


def run_daemon(args):
    if args.iface:
        load_and_attach(args.iface, args.hook, args.xdp_mode, fib_forward=args.fib_forward,
                        stateful=not args.stateless, default_action=args.default)
    dp = DataPlane()
    if args.services:
        with open(args.services) as f:
            for s in json.load(f):
                sid = dp.lb_add_service(s["vip"], int(s["port"]), s["backends"],
                                        s.get("proto", "tcp"))
                print(f"[daemon] service {s['vip']}:{s['port']} -> {s['backends']} (id {sid})")

    stop = threading.Event()

    def gc_loop():
        while not stop.wait(args.gc_interval):
            try:
                r = dp.ct_gc(args.idle_timeout, args.fin_timeout, args.hard_timeout)
                if any(r.values()):
                    print(f"[gc] expired {r}", flush=True)
            except BpfError as e:
                print(f"[gc] error: {e}", file=sys.stderr, flush=True)

    threading.Thread(target=gc_loop, name="ct-gc", daemon=True).start()

    host, _, port = args.api.rpartition(":")
    Api.dp = dp
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Api)

    def shutdown(*_):
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print(f"[daemon] REST API on http://{host or '127.0.0.1'}:{port}  "
          f"(idle_timeout={args.idle_timeout}s fin_timeout={args.fin_timeout}s "
          f"gc_interval={args.gc_interval}s)", flush=True)
    srv.serve_forever()
    print("[daemon] stopped")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def print_table(rows, cols):
    if not rows:
        print("  (empty)")
        return
    w = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  " + "  ".join(c.upper().ljust(w[c]) for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "")).ljust(w[c]) for c in cols))


def add_rule_args(p):
    p.add_argument("--src", help="source IPv4")
    p.add_argument("--dst", help="destination IPv4")
    p.add_argument("--proto", choices=PROTOS, default="any")
    p.add_argument("--sport", type=int, default=0)
    p.add_argument("--dport", type=int, default=0)
    p.add_argument("--src-mac")
    p.add_argument("--dst-mac")
    p.add_argument("--bidir", action="store_true", help="also install the reverse direction")


def rule_from_args(a):
    return {k: v for k, v in dict(src=a.src, dst=a.dst, proto=a.proto, sport=a.sport,
                                  dport=a.dport, src_mac=a.src_mac, dst_mac=a.dst_mac,
                                  bidir=a.bidir, action=getattr(a, "action", "drop")).items()
            if v not in (None, 0, False)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build", help="compile xdp_prog.c -> xdp_prog.o")
    p.add_argument("--force", action="store_true")

    def attach_args(p, required):
        p.add_argument("--iface", "-i", action="append", required=required, default=[],
                       help="interface to attach to (repeatable)")
        p.add_argument("--hook", choices=["xdp", "tc"], default="xdp")
        p.add_argument("--xdp-mode", choices=list(XDP_FLAGS), default="auto")
        p.add_argument("--fib-forward", action="store_true",
                       help="forward in eBPF via bpf_fib_lookup + redirect (bypass the stack)")
        p.add_argument("--stateless", action="store_true", help="disable fw connection tracking")
        p.add_argument("--default", choices=ACTIONS, default="allow",
                       help="default firewall action for unmatched IPv4")

    p = sub.add_parser("load", help="load + attach the data plane")
    attach_args(p, True)
    p.add_argument("--obj", help="prebuilt object (default: build xdp_prog.c)")

    p = sub.add_parser("unload", help="detach and (optionally) unpin")
    p.add_argument("--iface", "-i", action="append", default=[])
    p.add_argument("--hook", choices=["xdp", "tc", "all"], default="all")
    p.add_argument("--keep-maps", action="store_true")

    p = sub.add_parser("daemon", help="REST API + conntrack GC (optionally load first)")
    attach_args(p, False)
    p.add_argument("--api", default="127.0.0.1:8080", help="listen host:port")
    p.add_argument("--services", help="JSON file: [{vip, port, proto, backends:[ip:port]}]")
    p.add_argument("--idle-timeout", type=float, default=60.0)
    p.add_argument("--fin-timeout", type=float, default=10.0)
    p.add_argument("--hard-timeout", type=float, default=0.0, help="0 = disabled")
    p.add_argument("--gc-interval", type=float, default=5.0)

    fw = sub.add_parser("fw", help="firewall rules").add_subparsers(dest="fwcmd", required=True)
    p = fw.add_parser("add")
    add_rule_args(p)
    p.add_argument("--action", choices=ACTIONS, default="drop")
    add_rule_args(fw.add_parser("del"))
    fw.add_parser("list")
    fw.add_parser("flush")
    p = fw.add_parser("default")
    p.add_argument("action", choices=ACTIONS)

    lb = sub.add_parser("lb", help="load balancer").add_subparsers(dest="lbcmd", required=True)
    p = lb.add_parser("add-service")
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    p.add_argument("--backend", "-b", action="append", required=True, help="ip[:port]")
    p = lb.add_parser("del-service")
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    p = lb.add_parser("backend")
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    p.add_argument("--backend", required=True)
    p.add_argument("state", choices=["up", "down"])
    lb.add_parser("list")

    c = sub.add_parser("ct", help="connection tracking").add_subparsers(dest="ctcmd",
                                                                        required=True)
    c.add_parser("list")
    c.add_parser("flush")
    p = c.add_parser("gc", help="run one expiry pass")
    p.add_argument("--idle-timeout", type=float, default=60.0)
    p.add_argument("--fin-timeout", type=float, default=10.0)

    p = sub.add_parser("stats", help="counters + per-flow telemetry")
    p.add_argument("--json", action="store_true")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--watch", type=float, help="refresh every N seconds")

    a = ap.parse_args(argv)
    try:
        return dispatch(a)
    except (BpfError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def dispatch(a):
    if a.cmd == "build":
        build(force=a.force)
        return 0
    if a.cmd == "load":
        load_and_attach(a.iface, a.hook, a.xdp_mode, a.obj, a.fib_forward, not a.stateless,
                        a.default)
        return 0
    if a.cmd == "unload":
        detach(a.iface, a.hook, unpin=not a.keep_maps)
        return 0
    if a.cmd == "daemon":
        run_daemon(a)
        return 0

    dp = DataPlane()
    if a.cmd == "fw":
        if a.fwcmd == "add":
            print(f"added {dp.fw_add(rule_from_args(a))} rule(s)")
        elif a.fwcmd == "del":
            print(f"deleted {dp.fw_del(rule_from_args(a))} rule(s)")
        elif a.fwcmd == "flush":
            print(f"deleted {dp.fw_flush()} rule(s)")
        elif a.fwcmd == "default":
            dp.set_default_action(a.action)
            print(f"default action: {a.action}")
        else:
            print(f"default action: {ACTION_NAMES.get(dp.get_config().default_action, 'allow')}")
            print_table(dp.fw_list(), ["kind", "action", "proto", "src", "dst", "sport", "dport",
                                       "src_mac", "dst_mac", "hits"])
    elif a.cmd == "lb":
        if a.lbcmd == "add-service":
            sid = dp.lb_add_service(a.vip, a.port, a.backend, a.proto)
            print(f"service {a.vip}:{a.port}/{a.proto} id={sid} backends={a.backend}")
        elif a.lbcmd == "del-service":
            print("deleted" if dp.lb_del_service(a.vip, a.port, a.proto) else "not found")
        elif a.lbcmd == "backend":
            ok = dp.lb_set_backend_state(a.vip, a.port, a.backend, a.state == "up", a.proto)
            print(f"{a.backend} -> {a.state}" if ok else "backend not found")
        else:
            for s in dp.lb_list():
                print(f"{s['vip']}:{s['port']}/{s['proto']} (id {s['id']})")
                print_table(s["backends"], ["ip", "port", "active"])
    elif a.cmd == "ct":
        if a.ctcmd == "flush":
            print(f"deleted {dp.ct_flush()} entries")
        elif a.ctcmd == "gc":
            print(dp.ct_gc(a.idle_timeout, a.fin_timeout))
        else:
            r = dp.ct_list()
            cols = ["proto", "src", "sport", "dst", "dport"]
            print("firewall conntrack:")
            print_table(r["firewall"], cols + ["packets", "bytes", "flags", "idle_s"])
            print("load-balancer conntrack:")
            print_table(r["lb"], cols + ["backend", "packets", "flags", "idle_s"])
            print("load-balancer reverse NAT:")
            print_table(r["lb_reverse"], cols + ["vip", "flags", "idle_s"])
    elif a.cmd == "stats":
        while True:
            s, f = dp.stats(), dp.flows(a.top)
            if a.json:
                print(json.dumps({"stats": s, "flows": f}))
            else:
                if a.watch:
                    print("\033[2J\033[H", end="")
                print("global counters:")
                for k, v in s.items():
                    print(f"  {k:<16} {v}")
                print(f"top {a.top} flows (by bytes):")
                print_table(f, ["l3", "proto", "src", "sport", "dst", "dport", "packets", "bytes",
                                "idle_s"])
            if not a.watch:
                break
            time.sleep(a.watch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
