"""Kernel data-plane tests via BPF_PROG_TEST_RUN (root required, no Mininet).

The real BPF programs are loaded into the kernel and fed hand-built packets.
Each test checks the verdict, the rewritten headers and that every IP/TCP/UDP
checksum is still valid. The same cases run against both the XDP and the TC
entry point.
"""
from __future__ import annotations

import ctypes as ct
import os
import shutil
import unittest

from sdn.dataplane import DataPlane, FirewallRule
from sdn.libbpf import BpfError, TestRunOpts, get_libbpf
from sdn.loader import LoadedObject, build, unpin_maps
from tests import packets as P

C1, C2, S1, S2, S3, VIP = "10.0.1.1", "10.0.1.2", "10.0.2.1", "10.0.2.2", "10.0.2.3", "10.100.0.1"
BACKENDS = [S1, S2, S3, "10.0.2.4"]

XDP_DROP, XDP_PASS = 1, 2
TC_ACT_OK, TC_ACT_SHOT = 0, 2


def _skip_reason() -> str | None:
    if os.geteuid() != 0:
        return "needs root (BPF_PROG_TEST_RUN)"
    if not shutil.which("clang"):
        return "clang not installed"
    return None


class _DataPlaneCases:
    """Test cases shared by the XDP and TC variants (not collected on its own)."""
    HOOK = ""
    PASS = DROP = 0

    @classmethod
    def setUpClass(cls):
        cls.pin_dir = f"/sys/fs/bpf/sdn_test_{cls.HOOK}_{os.getpid()}"
        build()
        cls.obj = LoadedObject(cls.HOOK, pin_dir=cls.pin_dir)
        cls.dp = DataPlane.open(cls.pin_dir)
        cls.lib = get_libbpf()

    @classmethod
    def tearDownClass(cls):
        cls.obj.close()
        for m in cls.dp.maps.values():
            m.close()
        unpin_maps(cls.pin_dir)

    def setUp(self):
        self.dp.firewall.flush()
        self.dp.conntrack.flush()
        for svc in self.dp.lb.list():
            self.dp.lb.delete_service(svc["vip"], svc["port"], svc["proto"])
        self.dp.config.apply(default_action="allow", fib_forward=False, stateful=True)

    # ---- helpers ----
    def run_packet(self, frame: bytes) -> tuple[int, bytes]:
        out = ct.create_string_buffer(len(frame) + 256)
        inp = ct.create_string_buffer(frame, len(frame))
        opts = TestRunOpts(sz=ct.sizeof(TestRunOpts), data_in=ct.cast(inp, ct.c_void_p),
                           data_out=ct.cast(out, ct.c_void_p), data_size_in=len(frame),
                           data_size_out=len(out), repeat=1)
        rc = self.lib.bpf_prog_test_run_opts(self.obj.prog_fd, ct.byref(opts))
        if rc < 0:
            raise BpfError(f"BPF_PROG_TEST_RUN failed: {os.strerror(-rc)}")
        return opts.retval, out.raw[:opts.data_size_out]

    def counter(self, name: str) -> int:
        return self.dp.telemetry.counters()[name]

    def assert_valid(self, pkt: P.Parsed):
        self.assertTrue(pkt.ip_csum_ok, "IPv4 header checksum broken")
        self.assertTrue(pkt.l4_csum_ok, "L4 checksum broken")

    def add_service(self, proto="tcp", port=80):
        self.dp.lb.add_service(VIP, port, BACKENDS, proto)

    # ---- parser / pass-through ----
    def test_plain_traffic_passes_unmodified(self):
        frame = P.build(C1, S2, 40000, 22)
        verdict, out = self.run_packet(frame)
        self.assertEqual(verdict, self.PASS)
        self.assertEqual(out, frame)

    def test_invalid_ipv4_header_length_is_dropped(self):
        frame = bytearray(P.build(C1, S2, 40000, 22))
        frame[14] = 0x44  # IHL = 4 words (< minimum of 5)
        before = self.counter("drop_malformed")
        self.assertEqual(self.run_packet(bytes(frame))[0], self.DROP)
        self.assertEqual(self.counter("drop_malformed"), before + 1)

    def test_truncated_ipv4_header_is_dropped(self):
        if self.HOOK == "tc":
            self.skipTest("the kernel refuses to build a test skb from a truncated IPv4 frame")
        frame = P.build(C1, S2, 40000, 22)[:14 + 10]
        before = self.counter("drop_malformed")
        self.assertEqual(self.run_packet(frame)[0], self.DROP)
        self.assertEqual(self.counter("drop_malformed"), before + 1)

    # ---- firewall ----
    def test_host_pair_rule_drops_both_directions(self):
        self.dp.firewall.add(FirewallRule(src=C1, dst=S3, bidir=True))
        before = self.counter("drop_firewall")
        self.assertEqual(self.run_packet(P.build(C1, S3, 40000, 80))[0], self.DROP)
        self.assertEqual(self.run_packet(P.build(S3, C1, 80, 40000))[0], self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S2, 40000, 80))[0], self.PASS)
        self.assertEqual(self.counter("drop_firewall"), before + 2)

    def test_port_rule_only_matches_that_port(self):
        self.dp.firewall.add(FirewallRule(src=C1, dst=S2, proto="tcp", dport=22))
        self.assertEqual(self.run_packet(P.build(C1, S2, 40000, 22))[0], self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S2, 40000, 80))[0], self.PASS)
        self.assertEqual(self.run_packet(P.build(C1, S2, 40000, 22, proto=P.UDP))[0], self.PASS)

    def test_mac_rule(self):
        self.dp.firewall.add(FirewallRule(src_mac="00:00:00:00:01:02"))
        self.assertEqual(self.run_packet(P.build(C2, S2, 1, 2, src_mac="00:00:00:00:01:02"))[0],
                         self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S2, 1, 2))[0], self.PASS)

    def test_rule_hit_counter(self):
        self.dp.firewall.add(FirewallRule(src=C1, dst=S3))
        for _ in range(3):
            self.run_packet(P.build(C1, S3, 40000, 80))
        self.assertEqual(self.dp.firewall.list()[0]["hits"], 3)

    def test_default_drop_allows_established_replies(self):
        self.dp.config.apply(default_action="drop")
        self.dp.firewall.add(FirewallRule(src=C1, dst=S2, action="allow"))
        self.assertEqual(self.run_packet(P.build(C1, S2, 40000, 80))[0], self.PASS)
        self.assertEqual(self.run_packet(P.build(S2, C1, 80, 40000, tcp_flags=0x12))[0],
                         self.PASS, "reply of an allowed flow must be let through")
        self.assertEqual(self.run_packet(P.build(S3, C1, 80, 40000))[0], self.DROP,
                         "unrelated flow must hit the default drop")

    # ---- load balancer ----
    def test_dnat_to_backend_with_valid_checksums_and_stickiness(self):
        self.add_service()
        verdict, out = self.run_packet(P.build(C1, VIP, 40000, 80))
        self.assertEqual(verdict, self.PASS)
        pkt = P.parse(out)
        self.assertIn(pkt.dst_ip, BACKENDS)
        self.assertEqual((pkt.src_ip, pkt.sport, pkt.dport), (C1, 40000, 80))
        self.assert_valid(pkt)
        for _ in range(5):  # same 5-tuple -> same backend
            self.assertEqual(P.parse(self.run_packet(P.build(C1, VIP, 40000, 80,
                                                             tcp_flags=0x10))[1]).dst_ip,
                             pkt.dst_ip)

    def test_reply_is_snat_back_to_vip(self):
        self.add_service()
        backend = P.parse(self.run_packet(P.build(C1, VIP, 40001, 80))[1]).dst_ip
        verdict, out = self.run_packet(P.build(backend, C1, 80, 40001, tcp_flags=0x12))
        self.assertEqual(verdict, self.PASS)
        pkt = P.parse(out)
        self.assertEqual((pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport), (VIP, 80, C1, 40001))
        self.assert_valid(pkt)

    def test_port_translation(self):
        self.dp.lb.add_service(VIP, 80, [f"{S1}:8080"])
        pkt = P.parse(self.run_packet(P.build(C1, VIP, 40002, 80))[1])
        self.assertEqual((pkt.dst_ip, pkt.dport), (S1, 8080))
        self.assert_valid(pkt)
        reply = P.parse(self.run_packet(P.build(S1, C1, 8080, 40002))[1])
        self.assertEqual((reply.src_ip, reply.sport), (VIP, 80))
        self.assert_valid(reply)

    def test_connections_spread_over_all_backends(self):
        self.add_service()
        seen = {P.parse(self.run_packet(P.build(C1, VIP, 30000 + i, 80))[1]).dst_ip
                for i in range(64)}
        self.assertEqual(seen, set(BACKENDS))

    def test_drained_backend_gets_no_new_connections(self):
        self.add_service()
        for b in BACKENDS[1:]:
            self.dp.lb.set_backend_state(VIP, 80, b, up=False)
        seen = {P.parse(self.run_packet(P.build(C1, VIP, 31000 + i, 80))[1]).dst_ip
                for i in range(16)}
        self.assertEqual(seen, {BACKENDS[0]})

    def test_no_healthy_backend_drops(self):
        self.add_service()
        for b in BACKENDS:
            self.dp.lb.set_backend_state(VIP, 80, b, up=False)
        before = self.counter("drop_no_backend")
        self.assertEqual(self.run_packet(P.build(C1, VIP, 40003, 80))[0], self.DROP)
        self.assertEqual(self.counter("drop_no_backend"), before + 1)

    def test_udp_service_checksums(self):
        self.add_service(proto="udp", port=53)
        pkt = P.parse(self.run_packet(P.build(C1, VIP, 40004, 53, proto=P.UDP))[1])
        self.assertIn(pkt.dst_ip, BACKENDS)
        self.assert_valid(pkt)

    def test_udp_zero_checksum_stays_zero(self):
        self.add_service(proto="udp", port=53)
        pkt = P.parse(self.run_packet(P.build(C1, VIP, 40005, 53, proto=P.UDP,
                                              udp_zero_csum=True))[1])
        self.assertIn(pkt.dst_ip, BACKENDS)
        self.assertEqual(pkt.l4_csum, 0)

    def test_conntrack_entries_created(self):
        self.add_service()
        self.run_packet(P.build(C1, VIP, 40006, 80))
        tables = self.dp.conntrack.list()
        self.assertEqual([(e["src"], e["sport"]) for e in tables["lb"]], [(C1, 40006)])
        self.assertEqual([(e["dst"], e["dport"]) for e in tables["lb_reverse"]], [(C1, 40006)])
        self.assertEqual(tables["lb"][0]["flags"], "SYN")

    # ---- telemetry ----
    def test_flow_telemetry(self):
        frame = P.build(C2, S1, 45000, 443)
        for _ in range(4):
            self.run_packet(frame)
        flows = [f for f in self.dp.telemetry.top_flows(1000)
                 if (f["src"], f.get("sport")) == (C2, 45000)]
        self.assertEqual(len(flows), 1)
        self.assertGreaterEqual(flows[0]["packets"], 4)


@unittest.skipIf(_skip_reason(), _skip_reason())
class XdpDataPlaneTest(_DataPlaneCases, unittest.TestCase):
    HOOK, PASS, DROP = "xdp", XDP_PASS, XDP_DROP


@unittest.skipIf(_skip_reason(), _skip_reason())
class TcDataPlaneTest(_DataPlaneCases, unittest.TestCase):
    HOOK, PASS, DROP = "tc", TC_ACT_OK, TC_ACT_SHOT


if __name__ == "__main__":
    unittest.main()
