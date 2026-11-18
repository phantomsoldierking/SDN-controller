"""Kernel data-plane tests via BPF_PROG_TEST_RUN (root required, no Mininet).

The real BPF programs are loaded into the kernel and fed hand-built packets.
Each test checks the verdict, the rewritten headers and that every IP/TCP/UDP
checksum is still valid. The same cases run against both the XDP and the TC
entry point.
"""
from __future__ import annotations

import os
import shutil
import unittest

from sdn import abi
from sdn.codec import flow_key, ip_to_wire, port_to_wire
from sdn.dataplane import DataPlane, FirewallRule
from sdn.loader import LoadedObject, build, unpin_maps
from testbed import packets as P

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
        verdict, out, _ = self.obj.test_run(frame)
        return verdict, out

    def counter(self, name: str) -> int:
        return self.dp.telemetry.counters()[name]

    def assert_valid(self, pkt: P.Parsed):
        self.assertTrue(pkt.ip_csum_ok, "IPv4 header checksum broken")
        self.assertTrue(pkt.l4_csum_ok, "L4 checksum broken")

    def add_service(self, proto="tcp", port=80, backends=BACKENDS):
        self.dp.lb.add_service(VIP, port, backends, proto)

    def backend_for(self, client_port: int, flags=0x02) -> str:
        """Send client -> VIP and return the backend it was rewritten to."""
        return P.parse(self.run_packet(P.build(C1, VIP, client_port, 80, tcp_flags=flags))[1]).dst_ip

    def lb_entry(self, client_port: int):
        return self.dp.maps["lb_conntrack"].lookup(flow_key(C1, VIP, client_port, 80, 6))

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

    # ---- connection lifecycle (review round 1) ----
    def test_existing_connection_survives_drain(self):
        """Draining stops new connections only; established ones keep their backend."""
        self.add_service()
        backend = self.backend_for(41000)
        self.dp.lb.set_backend_state(VIP, 80, backend, up=False)
        for _ in range(3):
            self.assertEqual(self.backend_for(41000, flags=0x10), backend)
        self.assertNotEqual(self.backend_for(41001), backend, "new connections avoid it")

    def test_replaced_backend_reassigns_and_removes_stale_reverse_entry(self):
        self.add_service(backends=[S1])
        self.assertEqual(self.backend_for(41010), S1)
        self.dp.lb.add_service(VIP, 80, [S2])          # S1 removed from the pool
        self.assertEqual(self.backend_for(41010, flags=0x10), S2)
        rev = self.dp.maps["lb_reverse"]
        self.assertIsNone(rev.lookup(flow_key(S1, C1, 80, 41010, 6)), "stale entry removed")
        self.assertIsNotNone(rev.lookup(flow_key(S2, C1, 80, 41010, 6)))

    def test_reply_refreshes_forward_entry_and_records_server_fin(self):
        self.add_service()
        backend = self.backend_for(41020)
        before = self.lb_entry(41020).last_seen_ns
        self.run_packet(P.build(backend, C1, 80, 41020, tcp_flags=0x11))  # FIN,ACK from server
        entry = self.lb_entry(41020)
        self.assertGreater(entry.last_seen_ns, before)
        self.assertTrue(entry.flags & 0x2, "server FIN shortens the forward entry's timeout")

    def test_evicted_reverse_entry_is_recreated(self):
        self.add_service()
        backend = self.backend_for(41030)
        rk = flow_key(backend, C1, 80, 41030, 6)
        self.dp.maps["lb_reverse"].delete(rk)            # as if the LRU evicted it
        self.backend_for(41030, flags=0x10)
        self.assertIsNotNone(self.dp.maps["lb_reverse"].lookup(rk))

    # ---- firewall semantics (review round 1) ----
    def test_service_port_rule_allows_any_client(self):
        self.add_service()
        self.dp.config.apply(default_action="drop")
        self.dp.firewall.add(FirewallRule(dst=VIP, proto="tcp", dport=80, action="allow"))
        for client in (C1, C2):
            self.assertEqual(self.run_packet(P.build(client, VIP, 42000, 80))[0], self.PASS)
        self.assertEqual(self.run_packet(P.build(C1, VIP, 42000, 81))[0], self.DROP)

    def test_no_pinhole_to_backend_after_load_balanced_connection(self):
        """Under default drop, a VIP connection must not open direct access to the backend."""
        self.add_service()
        self.dp.config.apply(default_action="drop")
        self.dp.firewall.add(FirewallRule(dst=VIP, proto="tcp", dport=80, action="allow"))
        backend = self.backend_for(42010)
        verdict, out = self.run_packet(P.build(backend, C1, 80, 42010, tcp_flags=0x12))
        self.assertEqual(verdict, self.PASS, "reply of the VIP connection is established")
        self.assertEqual(P.parse(out).src_ip, VIP)
        self.assertEqual(self.run_packet(P.build(C1, backend, 42010, 80, tcp_flags=0x10))[0],
                         self.DROP, "direct client -> backend traffic stays blocked")

    def test_client_backend_rule_does_not_affect_vip_traffic(self):
        self.add_service(backends=[S3])
        self.dp.firewall.add(FirewallRule(src=C1, dst=S3, bidir=True))
        self.assertEqual(self.backend_for(42020), S3)
        self.assertEqual(self.run_packet(P.build(S3, C1, 80, 42020, tcp_flags=0x12))[0], self.PASS)

    def test_one_vip_rule_covers_both_directions_without_conntrack(self):
        """Replies are judged in the client->VIP orientation, so a service-port
        ALLOW rule admits them even with connection tracking disabled."""
        self.add_service(backends=[S1])
        self.dp.config.apply(default_action="drop", stateful=False)
        self.dp.firewall.add(FirewallRule(dst=VIP, proto="tcp", dport=80, action="allow"))
        self.assertEqual(self.backend_for(42030), S1)
        self.assertEqual(self.run_packet(P.build(S1, C1, 80, 42030, tcp_flags=0x12))[0], self.PASS)

    def test_reply_not_dropped_by_broader_rule_on_the_client(self):
        self.add_service(backends=[S1])
        self.dp.firewall.add(FirewallRule(dst=C1))  # "nothing may reach c1"
        self.assertEqual(self.backend_for(42040), S1)
        self.assertEqual(self.run_packet(P.build(S1, C1, 80, 42040, tcp_flags=0x12))[0], self.PASS,
                         "the reply belongs to c1 -> VIP, which the rule does not match")
        self.assertEqual(self.run_packet(P.build(S2, C1, 22, 42041))[0], self.DROP)

    def test_vip_drop_rule_blocks_both_directions(self):
        self.add_service(backends=[S1])
        self.assertEqual(self.backend_for(42050), S1)
        self.dp.firewall.add(FirewallRule(src=C1, dst=VIP))
        self.assertEqual(self.run_packet(P.build(C1, VIP, 42050, 80, tcp_flags=0x10))[0], self.DROP)
        self.assertEqual(self.run_packet(P.build(S1, C1, 80, 42050, tcp_flags=0x10))[0], self.DROP)

    # ---- state recovery and isolation (review round 2) ----
    def test_forward_entry_recovered_while_draining(self):
        """A lost forward entry is rebuilt from the reverse entry, so the connection
        stays on its (draining) backend instead of being re-hashed."""
        self.add_service()
        backend = self.backend_for(43000)
        self.dp.lb.set_backend_state(VIP, 80, backend, up=False)
        self.dp.maps["lb_conntrack"].delete(flow_key(C1, VIP, 43000, 80, 6))
        before = self.counter("lb_recovered")
        self.assertEqual(self.backend_for(43000, flags=0x10), backend)
        self.assertEqual(self.counter("lb_recovered"), before + 1)

    def test_reverse_entry_recovered_on_reply(self):
        self.add_service()
        backend = self.backend_for(43010)
        rk = flow_key(backend, C1, 80, 43010, 6)
        self.dp.maps["lb_reverse"].delete(rk)
        verdict, out = self.run_packet(P.build(backend, C1, 80, 43010, tcp_flags=0x10))
        self.assertEqual(verdict, self.PASS)
        self.assertEqual(P.parse(out).src_ip, VIP, "still SNATed: no backend address leak")
        self.assertIsNotNone(self.dp.maps["lb_reverse"].lookup(rk))

    def test_backend_reply_without_any_state_is_isolated(self):
        self.add_service()
        before = self.counter("drop_isolation")
        verdict, _ = self.run_packet(P.build(S2, C1, 80, 43020, tcp_flags=0x10))
        self.assertEqual(verdict, self.DROP, "never forwarded with the backend's real address")
        self.assertEqual(self.counter("drop_isolation"), before + 1)

    def test_backend_service_endpoint_reachable_only_through_vip(self):
        self.add_service()
        self.assertEqual(self.run_packet(P.build(C1, S1, 43030, 80))[0], self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S1, 43030, 22))[0], self.PASS)

    def test_drained_backend_share_spreads_evenly(self):
        """Selection hashes into the list of active backends: draining one of four
        gives each remaining backend about one third of new connections."""
        self.add_service()
        self.dp.lb.set_backend_state(VIP, 80, S1, up=False)
        counts = {}
        n = 3000
        for i in range(n):
            client = f"10.0.{1 + i % 50}.{1 + (i // 50) % 250}"
            b = P.parse(self.run_packet(P.build(client, VIP, 20000 + i, 80))[1]).dst_ip
            counts[b] = counts.get(b, 0) + 1
        self.assertNotIn(S1, counts)
        expected = n / 3
        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        self.assertLess(chi2, 13.82, f"chi2={chi2:.2f} (df=2, p<0.001 critical value) {counts}")

    def test_fragments_are_not_load_balanced(self):
        """Every fragment, including the first, is port-less: no partial NAT."""
        self.add_service()
        frame = P.build(C1, VIP, 43040, 80, frag_field=0x2000)  # MF set, offset 0
        self.run_packet(frame)
        self.assertIsNone(self.dp.maps["lb_conntrack"].lookup(flow_key(C1, VIP, 43040, 80, 6)))

    # ---- review round 3 ----
    def test_dropped_reply_creates_no_lb_state(self):
        """Reply classification is read-only: a reply whose reverse entry was lost
        and that the firewall then drops must not re-create NAT state."""
        self.add_service()
        backend = self.backend_for(43100)
        fwd, rk = flow_key(C1, VIP, 43100, 80, 6), flow_key(backend, C1, 80, 43100, 6)
        saved = self.dp.maps["lb_conntrack"].lookup(fwd)
        self.dp.firewall.add(FirewallRule(src=C1, dst=VIP, proto="tcp", dport=80))
        self.dp.maps["lb_conntrack"].update(fwd, saved)       # keep L[f], lose T_rev
        self.dp.maps["lb_reverse"].delete(rk)
        verdict, _ = self.run_packet(P.build(backend, C1, 80, 43100, tcp_flags=0x10))
        self.assertEqual(verdict, self.DROP)
        self.assertIsNone(self.dp.maps["lb_reverse"].lookup(rk))

    def test_reply_from_replaced_backend_slot_is_isolated(self):
        """A reverse entry whose slot now holds another backend is stale."""
        self.add_service(backends=[S1])
        self.assertEqual(self.backend_for(43110), S1)
        self.dp.lb.add_service(VIP, 80, [S2])                  # S1 replaced by S2 (slot 0)
        rk = flow_key(S1, C1, 80, 43110, 6)
        self.dp.maps["lb_reverse"].update(rk, abi.LbRev(       # stale entry survived
            vip=ip_to_wire(VIP), vport=port_to_wire(80), svc_id=0, be_idx=0))
        verdict, _ = self.run_packet(P.build(S1, C1, 80, 43110, tcp_flags=0x10))
        self.assertEqual(verdict, self.DROP)

    def test_syn_does_not_rejoin_a_stale_reverse_entry(self):
        """A new TCP connection (SYN) reusing a client port is placed afresh and
        cannot be captured by a leftover reverse entry of a draining backend."""
        self.add_service()
        old = self.backend_for(43120)
        self.dp.lb.set_backend_state(VIP, 80, old, up=False)
        self.dp.maps["lb_conntrack"].delete(flow_key(C1, VIP, 43120, 80, 6))
        before = self.counter("lb_recovered")
        self.assertNotEqual(self.backend_for(43120, flags=0x02), old)
        self.assertEqual(self.counter("lb_recovered"), before)

    # ---- reused tuples and recovery (review round 4) ----
    def test_syn_on_draining_backend_entry_is_placed_afresh(self):
        """A SYN that reuses the tuple of a connection whose backend is now
        draining must not join that backend; the old reverse entry goes."""
        self.add_service()
        old = self.backend_for(43200)
        self.dp.lb.set_backend_state(VIP, 80, old, up=False)
        new = self.backend_for(43200, flags=0x02)
        self.assertNotEqual(new, old)
        self.assertIsNone(self.dp.maps["lb_reverse"].lookup(flow_key(old, C1, 80, 43200, 6)))
        self.assertIsNotNone(self.dp.maps["lb_reverse"].lookup(flow_key(new, C1, 80, 43200, 6)))

    def test_syn_after_fin_restarts_connection_state(self):
        """A SYN reusing the tuple of an ended connection does not inherit its
        FIN flag (short timeout) or its creation time."""
        self.add_service()
        self.backend_for(43210)
        self.backend_for(43210, flags=0x11)                  # FIN|ACK
        ended = self.lb_entry(43210)
        self.assertTrue(ended.flags & abi.CT_F_FIN)
        self.backend_for(43210, flags=0x02)                  # new SYN
        fresh = self.lb_entry(43210)
        self.assertFalse(fresh.flags & abi.CT_F_FIN)
        self.assertGreater(fresh.created_ns, ended.created_ns)
        fw = self.dp.maps["fw_conntrack"].lookup(flow_key(C1, VIP, 43210, 80, 6))
        self.assertFalse(fw.flags & abi.CT_F_FIN, "firewall entry restarted as well")

    def test_retransmitted_syn_keeps_live_connection(self):
        self.add_service()
        first = self.backend_for(43220)
        created = self.lb_entry(43220).created_ns
        self.assertEqual(self.backend_for(43220, flags=0x02), first)
        self.assertEqual(self.lb_entry(43220).created_ns, created)

    def test_recovery_refreshes_reverse_entry(self):
        self.add_service()
        backend = self.backend_for(43230)
        rk = flow_key(backend, C1, 80, 43230, 6)
        rev = self.dp.maps["lb_reverse"].lookup(rk)
        rev.last_seen_ns = 1
        self.dp.maps["lb_reverse"].update(rk, rev)
        self.dp.maps["lb_conntrack"].delete(flow_key(C1, VIP, 43230, 80, 6))
        self.assertEqual(self.backend_for(43230, flags=0x10), backend)
        self.assertGreater(self.dp.maps["lb_reverse"].lookup(rk).last_seen_ns, 1)

    def test_recovery_prefers_most_recent_reverse_entry(self):
        """If a leftover reverse entry of an earlier connection with the same
        tuple coexists with the live one, recovery restores the live one."""
        self.add_service()
        live = self.backend_for(43240)
        rk = flow_key(live, C1, 80, 43240, 6)
        rev = self.dp.maps["lb_reverse"].lookup(rk)
        stale = next(b for b in BACKENDS if b != live)
        old = abi.LbRev(vip=rev.vip, vport=rev.vport, svc_id=rev.svc_id,
                        be_idx=BACKENDS.index(stale), last_seen_ns=1)
        self.dp.maps["lb_reverse"].update(flow_key(stale, C1, 80, 43240, 6), old)
        self.dp.maps["lb_conntrack"].delete(flow_key(C1, VIP, 43240, 80, 6))
        self.assertEqual(self.backend_for(43240, flags=0x10), live)

    def test_syn_after_lost_forward_entry_clears_stale_reverse_entry(self):
        """L[f] was lost while the old reverse entry survived; a SYN reusing the
        port is placed elsewhere and the old entry is removed, so a late
        packet from the old backend is isolated instead of translated."""
        self.add_service()
        old = self.backend_for(43250)
        self.dp.lb.set_backend_state(VIP, 80, old, up=False)
        self.dp.maps["lb_conntrack"].delete(flow_key(C1, VIP, 43250, 80, 6))
        new = self.backend_for(43250, flags=0x02)
        self.assertNotEqual(new, old)
        self.assertIsNone(self.dp.maps["lb_reverse"].lookup(flow_key(old, C1, 80, 43250, 6)))
        late = P.build(old, C1, 80, 43250, tcp_flags=0x11)
        self.assertEqual(self.run_packet(late)[0], self.DROP)

    def test_syn_off_draining_backend_restarts_firewall_entry(self):
        """When the load balancer restarts a reused tuple (draining backend, no
        FIN seen), the firewall entry restarts with it."""
        self.add_service()
        old = self.backend_for(43260)
        key = flow_key(C1, VIP, 43260, 80, 6)
        created = self.dp.maps["fw_conntrack"].lookup(key).created_ns
        self.dp.lb.set_backend_state(VIP, 80, old, up=False)
        self.assertNotEqual(self.backend_for(43260, flags=0x02), old)
        self.assertGreater(self.dp.maps["fw_conntrack"].lookup(key).created_ns, created)

    def test_first_fragment_to_service_endpoint_is_dropped(self):
        self.add_service()
        self.assertEqual(self.run_packet(P.build(C1, S1, 43130, 80, frag_field=0x2000))[0],
                         self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S1, 43130, 22, frag_field=0x2000))[0],
                         self.PASS)

    def test_first_fragment_obeys_port_drop_rules(self):
        self.dp.firewall.add(FirewallRule(src=C1, dst=S2, proto="tcp", dport=22))
        self.assertEqual(self.run_packet(P.build(C1, S2, 43140, 22, frag_field=0x2000))[0],
                         self.DROP)
        self.assertEqual(self.run_packet(P.build(C1, S2, 43140, 23, frag_field=0x2000))[0],
                         self.PASS)
        # a non-first fragment carries no ports and is judged port-less
        self.assertEqual(self.run_packet(P.build(C1, S2, 43140, 22, frag_field=0x0010))[0],
                         self.PASS)

    def test_mac_rule_applies_to_non_ip_frames(self):
        self.dp.firewall.add(FirewallRule(src_mac="00:00:00:00:01:01"))
        ipv6 = P.mac("00:00:00:00:00:fe") + P.mac("00:00:00:00:01:01") + b"\x86\xdd" + bytes(40)
        self.assertEqual(self.run_packet(ipv6)[0], self.DROP)

    def test_reply_does_not_duplicate_firewall_state(self):
        self.run_packet(P.build(C1, S2, 42030, 22))
        self.run_packet(P.build(S2, C1, 22, 42030, tcp_flags=0x12))
        entries = [e for e in self.dp.conntrack.list()["firewall"]
                   if {e["sport"], e["dport"]} == {42030, 22}]
        self.assertEqual(len(entries), 1)
        self.assertIn("REPLY", entries[0]["flags"])

    # ---- telemetry ----
    def test_dropped_packets_are_not_in_flow_telemetry(self):
        self.dp.firewall.add(FirewallRule(src=C2, dst=S3))
        self.run_packet(P.build(C2, S3, 45999, 443))
        self.assertFalse([f for f in self.dp.telemetry.top_flows(10000) if f.get("sport") == 45999])

    def test_flow_telemetry(self):
        frame = P.build(C2, S1, 45000, 443)
        for _ in range(4):
            self.run_packet(frame)
        flows = [f for f in self.dp.telemetry.top_flows(1000)
                 if (f["src"], f.get("sport")) == (C2, 45000)]
        self.assertEqual(len(flows), 1)
        self.assertGreaterEqual(flows[0]["packets"], 4)


CHAIN = ["xdp_chain_fw", "xdp_chain_lb", "xdp_chain_out"]
CHAINM = ["xdp_chainm_fw", "xdp_chainm_lb", "xdp_chainm_out"]


@unittest.skipIf(_skip_reason(), _skip_reason())
class ChainAblationTest(unittest.TestCase):
    """The tail-call chained variant (used only for the ablation benchmark) must
    behave exactly like the single program."""

    @classmethod
    def setUpClass(cls):
        cls.pin_dir = f"/sys/fs/bpf/sdn_test_chain_{os.getpid()}"
        build()
        cls.obj = LoadedObject("xdp", pin_dir=cls.pin_dir,
                               programs=["xdp_dataplane", *CHAIN, *CHAINM])
        cls.obj.fill_prog_array("chain_progs", CHAIN)
        cls.obj.fill_prog_array("chainm_progs", CHAINM)
        cls.dp = DataPlane.open(cls.pin_dir)
        cls.dp.config.apply(default_action="allow", stateful=True)
        cls.dp.lb.add_service(VIP, 80, BACKENDS)
        cls.dp.firewall.add(FirewallRule(src=C1, dst=S3, proto="tcp", dport=22))

    @classmethod
    def tearDownClass(cls):
        cls.obj.close()
        for m in cls.dp.maps.values():
            m.close()
        unpin_maps(cls.pin_dir)

    def test_same_verdicts_and_packets(self):
        backend = P.parse(self.obj.test_run(P.build(C1, VIP, 44000, 80))[1]).dst_ip
        frames = {
            "pass": P.build(C1, S2, 44001, 22),
            "drop": P.build(C1, S3, 44002, 22),
            "dnat": P.build(C1, VIP, 44000, 80, tcp_flags=0x10),
            "snat": P.build(backend, C1, 80, 44000, tcp_flags=0x10),
            "isolate": P.build(S2, C1, 80, 44999, tcp_flags=0x10),
        }
        for name, frame in frames.items():
            with self.subTest(path=name):
                mono = self.obj.test_run(frame)[:2]
                for entry in ("xdp_chain_fw", "xdp_chainm_fw"):
                    self.assertEqual(self.obj.test_run(frame, program=entry)[:2], mono, entry)


@unittest.skipIf(_skip_reason(), _skip_reason())
class XdpDataPlaneTest(_DataPlaneCases, unittest.TestCase):
    HOOK, PASS, DROP = "xdp", XDP_PASS, XDP_DROP


@unittest.skipIf(_skip_reason(), _skip_reason())
class TcDataPlaneTest(_DataPlaneCases, unittest.TestCase):
    HOOK, PASS, DROP = "tc", TC_ACT_OK, TC_ACT_SHOT


if __name__ == "__main__":
    unittest.main()
