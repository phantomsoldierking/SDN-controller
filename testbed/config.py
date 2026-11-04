"""Addressing plan for the testbed.

    c1-c4  10.0.1.1-4/24  -> gateway 10.0.1.254
    s1-s4  10.0.2.1-4/24  -> gateway 10.0.2.254
    VIP    10.100.0.1:80  -> s1..s4:80
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTROL_PLANE = os.path.join(PROJECT_ROOT, "control_plane.py")
HOSTTOOLS = os.path.join(PROJECT_ROOT, "testbed", "hosttools.py")
PYTHON = sys.executable

CLIENT_GW, SERVER_GW = "10.0.1.254", "10.0.2.254"
VIP, VPORT = "10.100.0.1", 80
OVS_GW_MAC = "02:00:00:00:00:fe"
API_LISTEN = "127.0.0.1:8080"


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    mac: str
    port: int  # 1-based position on the gateway: gw-eth{port-1}, OVS port number

    @property
    def gateway_ip(self) -> str:
        return CLIENT_GW if self.ip.startswith("10.0.1.") else SERVER_GW

    @property
    def intf(self) -> str:
        return f"{self.name}-eth0"

    @property
    def gw_intf(self) -> str:
        return f"gw-eth{self.port - 1}"


CLIENTS = [Host(f"c{i}", f"10.0.1.{i}", f"00:00:00:00:01:{i:02x}", i) for i in range(1, 5)]
SERVERS = [Host(f"s{i}", f"10.0.2.{i}", f"00:00:00:00:02:{i:02x}", 4 + i) for i in range(1, 5)]
HOSTS = CLIENTS + SERVERS


def host(name: str) -> Host:
    return next(h for h in HOSTS if h.name == name)
