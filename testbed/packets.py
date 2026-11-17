"""Minimal packet builder/parser for tests (Ethernet / IPv4 / TCP / UDP)."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

ETH_P_IP, ETH_P_ARP = 0x0800, 0x0806
TCP, UDP = 6, 17


def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _pseudo(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!BBH", 0, proto, length)


def build(src_ip, dst_ip, sport, dport, proto=TCP, payload=b"hello",
          src_mac="00:00:00:00:01:01", dst_mac="00:00:00:00:00:fe",
          tcp_flags=0x02, udp_zero_csum=False, frag_field=0x4000) -> bytes:
    """frag_field: IPv4 flags + fragment offset (default DF; 0x2000 = MF, first fragment)."""
    s, d = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    if proto == TCP:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, tcp_flags, 65535, 0, 0) + payload
        csum = inet_checksum(_pseudo(s, d, TCP, len(l4)) + l4)
        l4 = l4[:16] + struct.pack("!H", csum) + l4[18:]
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        if not udp_zero_csum:
            csum = inet_checksum(_pseudo(s, d, UDP, len(l4)) + l4) or 0xFFFF
            l4 = l4[:6] + struct.pack("!H", csum) + l4[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, frag_field, 64, proto, 0, s, d)
    ip = ip[:10] + struct.pack("!H", inet_checksum(ip)) + ip[12:]
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ETH_P_IP) + ip + l4


@dataclass
class Parsed:
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: int
    ip_csum_ok: bool
    l4_csum_ok: bool
    l4_csum: int


def parse(frame: bytes) -> Parsed:
    ip = frame[14:]
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    s, d = ip[12:16], ip[16:20]
    l4 = ip[ihl:total]
    sport, dport = struct.unpack("!HH", l4[:4])
    csum_off = 16 if proto == TCP else 6
    l4_csum = struct.unpack("!H", l4[csum_off:csum_off + 2])[0]
    if proto == UDP and l4_csum == 0:
        l4_ok = True  # "no checksum" is valid for UDP
    else:
        l4_ok = inet_checksum(_pseudo(s, d, proto, len(l4)) + l4) == 0
    return Parsed(socket.inet_ntoa(s), socket.inet_ntoa(d), sport, dport, proto,
                  inet_checksum(ip[:ihl]) == 0, l4_ok, l4_csum)
