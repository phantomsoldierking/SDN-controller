"""Conversions between wire format (as stored in maps) and human-readable values.

Map keys and values hold IPs and ports in network byte order, exactly as on
the wire. ctypes integer fields are host (little-endian) order, so an address
is stored as the integer whose in-memory bytes equal the on-wire bytes.
"""
from __future__ import annotations

import socket
import time

from .abi import CT_F_FIN, CT_F_REPLY, CT_F_RST, CT_F_SYN, L3, FlowKey, Proto


def ip_to_wire(ip) -> int:
    return int.from_bytes(socket.inet_aton(str(ip)), "little") if ip else 0


def wire_to_ip(value: int) -> str:
    return socket.inet_ntoa(int(value).to_bytes(4, "little"))


def port_to_wire(port) -> int:
    return socket.htons(int(port)) if port else 0


def wire_to_port(value: int) -> int:
    return socket.ntohs(int(value))


def mac_to_bytes(mac: str | None):
    import ctypes as ct
    if not mac:
        return (ct.c_uint8 * 6)()
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError(f"invalid MAC address {mac!r}")
    return (ct.c_uint8 * 6)(*raw)


def bytes_to_mac(raw) -> str:
    return ":".join(f"{b:02x}" for b in bytes(raw))


def parse_proto(proto) -> int:
    if isinstance(proto, int):
        return int(Proto(proto))
    try:
        return int(Proto[str(proto).upper()])
    except KeyError:
        raise ValueError(f"unknown protocol {proto!r} (any, icmp, tcp, udp)") from None


def proto_name(value: int) -> str:
    try:
        return Proto(value).name.lower()
    except ValueError:
        return str(value)


def parse_endpoint(text: str, default_port: int) -> tuple[str, int]:
    """'10.0.2.1:8080' -> ('10.0.2.1', 8080); '10.0.2.1' -> ('10.0.2.1', default_port)."""
    host, _, port = str(text).partition(":")
    socket.inet_aton(host)  # validates
    return host, int(port) if port else int(default_port)


def flow_key(src, dst, sport=0, dport=0, proto=Proto.ANY, l3=L3.IPV4) -> FlowKey:
    return FlowKey(saddr=ip_to_wire(src), daddr=ip_to_wire(dst), sport=port_to_wire(sport),
                   dport=port_to_wire(dport), proto=int(proto), l3=int(l3))


def flow_key_to_dict(k: FlowKey) -> dict:
    if k.l3 == L3.ARP:
        return {"l3": "arp", "src": wire_to_ip(k.saddr), "dst": wire_to_ip(k.daddr),
                "op": wire_to_port(k.sport)}
    return {"l3": "ipv4", "src": wire_to_ip(k.saddr), "dst": wire_to_ip(k.daddr),
            "sport": wire_to_port(k.sport), "dport": wire_to_port(k.dport),
            "proto": proto_name(k.proto)}


_CT_FLAG_NAMES = ((CT_F_SYN, "SYN"), (CT_F_FIN, "FIN"), (CT_F_RST, "RST"), (CT_F_REPLY, "REPLY"))


def ct_flags_to_str(flags: int) -> str:
    return ",".join(name for bit, name in _CT_FLAG_NAMES if flags & bit) or "-"


def monotonic_ns() -> int:
    """Same clock as bpf_ktime_get_ns() (CLOCK_MONOTONIC)."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def idle_seconds(last_seen_ns: int, now_ns: int | None = None) -> float:
    now_ns = monotonic_ns() if now_ns is None else now_ns
    return round((now_ns - last_seen_ns) / 1e9, 1)
