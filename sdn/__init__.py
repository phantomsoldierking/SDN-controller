"""User-space control plane for the eBPF/XDP SDN data plane.

Package layout (each module has a single responsibility):

    abi          ctypes mirror of bpf/abi.h + map specs
    codec        wire-format <-> human conversions (byte order, MACs, flags)
    libbpf       ctypes bindings to libbpf.so.1
    maps         MapBackend protocol, pinned BpfMap, in-memory DictMap
    loader       build / load / attach / detach the BPF object
    dataplane/   one manager per data-plane feature, plus the DataPlane facade
    api          REST API over the DataPlane
    daemon       REST server + conntrack reaper thread
    cli          command-line front end
"""
from __future__ import annotations

import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF_SRC_DIR = os.path.join(PROJECT_ROOT, "bpf")
BPF_SRC = os.path.join(BPF_SRC_DIR, "xdp_prog.c")
BPF_OBJ = os.path.join(PROJECT_ROOT, "build", "xdp_prog.o")
PIN_DIR = os.environ.get("SDN_PIN_DIR", "/sys/fs/bpf/sdn_dp")
