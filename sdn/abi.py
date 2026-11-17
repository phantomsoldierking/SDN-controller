"""ctypes mirror of bpf/abi.h - the contract between kernel and user space.

Every structure here must match its C counterpart byte for byte. The size
assertions at the bottom run at import time, so a mismatch fails loudly
instead of silently corrupting maps.
"""
from __future__ import annotations

import ctypes as ct
from dataclasses import dataclass
from enum import IntEnum


# ---- enums / flags (bpf/abi.h) ---------------------------------------------
class FwKind(IntEnum):
    IP = 1
    MAC = 2


class FwMask(IntEnum):
    """Rule patterns in lookup order (enum fw_mask in bpf/abi.h)."""
    MAC_PAIR = 1   # (smac, dmac)
    MAC_SRC = 2    # (smac, *)
    IP_EXACT = 3   # (s, d, sport, dport, proto)
    IP_DPORT = 4   # (s, d, *, dport, proto)
    IP_SPORT = 5   # (s, d, sport, *, proto)
    IP_PROTO = 6   # (s, d, *, *, proto)
    IP_PAIR = 7    # (s, d, *, *, *)
    SVC_PORT = 8   # (*, d, *, dport, proto)
    IP_SRC = 9     # (s, *, *, *, *)
    IP_DST = 10    # (*, d, *, *, *)


class Action(IntEnum):
    NONE = 0
    ALLOW = 1
    DROP = 2


class L3(IntEnum):
    ARP = 1
    IPV4 = 4


class Proto(IntEnum):
    ANY = 0
    ICMP = 1
    TCP = 6
    UDP = 17


MAX_SERVICES = 16
MAX_BACKENDS_PER_SVC = 16

CFG_F_FIB_FORWARD = 1 << 0
CFG_F_FW_STATEFUL = 1 << 1

CT_F_SYN = 1 << 0
CT_F_FIN = 1 << 1
CT_F_RST = 1 << 2
CT_F_REPLY = 1 << 3

# Order must match enum stat_idx in bpf/abi.h.
STAT_NAMES = (
    "rx_packets", "rx_bytes", "pass", "drop_firewall", "drop_malformed",
    "drop_no_backend", "lb_dnat", "lb_snat", "lb_new_conn", "ct_established",
    "arp", "non_ip", "fib_forward", "drop_isolation", "lb_recovered",
)


# ---- map key / value structs -----------------------------------------------
class FlowKey(ct.Structure):
    _fields_ = [("saddr", ct.c_uint32), ("daddr", ct.c_uint32),
                ("sport", ct.c_uint16), ("dport", ct.c_uint16),
                ("proto", ct.c_uint8), ("l3", ct.c_uint8), ("pad", ct.c_uint8 * 2)]


class FwKey(ct.Structure):
    _fields_ = [("kind", ct.c_uint8), ("proto", ct.c_uint8),
                ("sport", ct.c_uint16), ("dport", ct.c_uint16),
                ("mask", ct.c_uint8), ("pad", ct.c_uint8),
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
    _fields_ = [("id", ct.c_uint32), ("count", ct.c_uint16), ("active", ct.c_uint16)]


class EndpointKey(ct.Structure):
    _fields_ = [("ip", ct.c_uint32), ("port", ct.c_uint16), ("proto", ct.c_uint8),
                ("pad", ct.c_uint8)]


class EndpointInfo(ct.Structure):
    _fields_ = [("vip", ct.c_uint32), ("vport", ct.c_uint16), ("svc_id", ct.c_uint8),
                ("be_idx", ct.c_uint8)]


class Backend(ct.Structure):
    _fields_ = [("ip", ct.c_uint32), ("port", ct.c_uint16), ("active", ct.c_uint16)]


class LbCt(ct.Structure):
    _fields_ = [("backend_ip", ct.c_uint32), ("backend_port", ct.c_uint16),
                ("svc_id", ct.c_uint8), ("be_idx", ct.c_uint8),
                ("created_ns", ct.c_uint64), ("last_seen_ns", ct.c_uint64),
                ("packets", ct.c_uint64), ("bytes", ct.c_uint64),
                ("flags", ct.c_uint32), ("pad", ct.c_uint32)]


class LbRev(ct.Structure):
    _fields_ = [("vip", ct.c_uint32), ("vport", ct.c_uint16), ("svc_id", ct.c_uint8),
                ("be_idx", ct.c_uint8), ("last_seen_ns", ct.c_uint64), ("flags", ct.c_uint32),
                ("pad2", ct.c_uint32)]


class FlowStat(ct.Structure):
    _fields_ = [("packets", ct.c_uint64), ("bytes", ct.c_uint64),
                ("last_seen_ns", ct.c_uint64)]


class DpConfig(ct.Structure):
    _fields_ = [("default_action", ct.c_uint32), ("flags", ct.c_uint32),
                ("pattern_mask", ct.c_uint32), ("pad", ct.c_uint32)]


# ---- map catalogue ---------------------------------------------------------
@dataclass(frozen=True)
class MapSpec:
    key: type
    value: type
    percpu: bool = False


MAP_SPECS = {
    "firewall_map": MapSpec(FwKey, FwRule),
    "fw_conntrack": MapSpec(FlowKey, CtEntry),
    "lb_services": MapSpec(SvcKey, SvcInfo),
    "lb_backends": MapSpec(ct.c_uint32, Backend),
    "lb_active": MapSpec(ct.c_uint32, ct.c_uint32),
    "lb_endpoints": MapSpec(EndpointKey, EndpointInfo),
    "lb_conntrack": MapSpec(FlowKey, LbCt),
    "lb_reverse": MapSpec(FlowKey, LbRev),
    "flow_stats": MapSpec(FlowKey, FlowStat, percpu=True),
    "global_stats": MapSpec(ct.c_uint32, ct.c_uint64, percpu=True),
    "dp_config_map": MapSpec(ct.c_uint32, DpConfig),
}

CONNTRACK_MAPS = ("fw_conntrack", "lb_conntrack", "lb_reverse")

_EXPECTED_SIZES = {FlowKey: 16, FwKey: 28, FwRule: 16, CtEntry: 40, SvcKey: 8, SvcInfo: 8,
                   Backend: 8, LbCt: 48, LbRev: 24, FlowStat: 24, DpConfig: 16,
                   EndpointKey: 8, EndpointInfo: 8}
for _struct, _size in _EXPECTED_SIZES.items():
    if ct.sizeof(_struct) != _size:
        raise ImportError(f"ABI mismatch: sizeof({_struct.__name__}) = {ct.sizeof(_struct)}, "
                          f"bpf/abi.h expects {_size}")
