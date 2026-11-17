"""Control-plane logic against in-memory maps (no root, no kernel)."""
from __future__ import annotations

import ctypes as ct
import unittest

from sdn import abi
from sdn.abi import FwMask
from sdn.codec import flow_key, ip_to_wire, port_to_wire
from sdn.dataplane import DataPlane, FirewallRule, Timeouts
from sdn.maps import in_memory_maps

C1, S2, S3, VIP = "10.0.1.1", "10.0.2.2", "10.0.2.3", "10.100.0.1"
SEC = 1_000_000_000


def new_dp() -> DataPlane:
    return DataPlane(in_memory_maps())


class FirewallRuleTest(unittest.TestCase):
    def test_bidir_ip_rule_yields_both_directions(self):
        keys = FirewallRule(src=C1, dst=S3, bidir=True).keys()
        self.assertEqual([(k.saddr, k.daddr) for k in keys],
                         [(ip_to_wire(C1), ip_to_wire(S3)), (ip_to_wire(S3), ip_to_wire(C1))])

    def test_bidir_swaps_ports(self):
        fwd, rev = FirewallRule(src=C1, dst=S2, proto="tcp", dport=22, bidir=True).keys()
        self.assertEqual((fwd.sport, fwd.dport), (0, port_to_wire(22)))
        self.assertEqual((rev.sport, rev.dport), (port_to_wire(22), 0))

    def test_each_rule_shape_maps_to_one_pattern(self):
        cases = {
            FwMask.IP_EXACT: FirewallRule(src=C1, dst=S2, proto="tcp", sport=1, dport=22),
            FwMask.IP_DPORT: FirewallRule(src=C1, dst=S2, proto="tcp", dport=22),
            FwMask.IP_SPORT: FirewallRule(src=C1, dst=S2, proto="udp", sport=53),
            FwMask.IP_PROTO: FirewallRule(src=C1, dst=S2, proto="icmp"),
            FwMask.IP_PAIR: FirewallRule(src=C1, dst=S2),
            FwMask.SVC_PORT: FirewallRule(dst=VIP, proto="tcp", dport=80),
            FwMask.IP_SRC: FirewallRule(src=C1),
            FwMask.IP_DST: FirewallRule(dst=S2),
            FwMask.MAC_PAIR: FirewallRule(src_mac="00:00:00:00:01:01", dst_mac="00:00:00:00:00:fe"),
            FwMask.MAC_SRC: FirewallRule(src_mac="00:00:00:00:01:01"),
        }
        for mask, rule in cases.items():
            with self.subTest(mask=mask):
                self.assertEqual([k.mask for k in rule.keys()], [mask])

    def test_validation(self):
        for bad in (FirewallRule(),                                 # nothing to match
                    FirewallRule(src=C1, dst=S2, dport=22),         # port without tcp/udp
                    FirewallRule(src=C1, proto="tcp"),              # src+proto: no such pattern
                    FirewallRule(dst=VIP, proto="tcp"),             # dst+proto without port
                    FirewallRule(dst=VIP, proto="tcp", dport=80, bidir=True),  # no reverse form
                    FirewallRule(dst_mac="00:00:00:00:00:01"),      # MAC rule needs src_mac
                    FirewallRule(src=C1, action="reject")):         # unknown action
            with self.subTest(rule=bad), self.assertRaises(ValueError):
                bad.keys()

    def test_from_dict_rejects_unknown_fields(self):
        with self.assertRaises(ValueError):
            FirewallRule.from_dict({"src": C1, "destination": S2})

    def test_mac_rule(self):
        (k,) = FirewallRule(src_mac="00:00:00:00:01:01").keys()
        self.assertEqual(k.kind, abi.FwKind.MAC)
        self.assertFalse(any(k.dmac))


class FirewallTest(unittest.TestCase):
    def test_add_list_delete(self):
        dp = new_dp()
        self.assertEqual(dp.firewall.add(FirewallRule(src=C1, dst=S3, bidir=True)), 2)
        rules = dp.firewall.list()
        self.assertEqual({(r["src"], r["dst"], r["action"]) for r in rules},
                         {(C1, S3, "drop"), (S3, C1, "drop")})
        self.assertEqual(dp.firewall.delete(FirewallRule(src=C1, dst=S3, bidir=True)), 2)
        self.assertEqual(dp.firewall.list(), [])

    def test_drop_rule_flushes_matching_conntrack(self):
        dp = new_dp()
        fw_ct = dp.maps["fw_conntrack"]
        fw_ct.update(flow_key(C1, S3, 1000, 80, 6), abi.CtEntry())
        fw_ct.update(flow_key(C1, S2, 1000, 80, 6), abi.CtEntry())
        dp.firewall.add(FirewallRule(src=C1, dst=S3))
        remaining = [(k.saddr, k.daddr) for k in fw_ct.keys()]
        self.assertEqual(remaining, [(ip_to_wire(C1), ip_to_wire(S2))])

    def test_drop_rule_on_vip_flushes_its_reverse_nat_entries(self):
        dp = new_dp()
        rev = flow_key(S2, C1, 80, 1000, 6)
        dp.maps["lb_reverse"].update(rev, abi.LbRev(vip=ip_to_wire(VIP), vport=port_to_wire(80)))
        dp.firewall.add(FirewallRule(src=C1, dst=VIP))
        self.assertEqual(dp.maps["lb_reverse"].keys(), [])

    def test_allow_rule_keeps_conntrack(self):
        dp = new_dp()
        dp.maps["fw_conntrack"].update(flow_key(C1, S3, 1, 2, 6), abi.CtEntry())
        dp.firewall.add(FirewallRule(src=C1, dst=S3, action="allow"))
        self.assertEqual(len(dp.maps["fw_conntrack"].keys()), 1)


class ConfigTest(unittest.TestCase):
    def test_apply_only_changes_given_settings(self):
        dp = new_dp()
        dp.config.apply(default_action="drop", fib_forward=True, stateful=True)
        dp.config.apply(fib_forward=False)
        self.assertEqual(dp.config.describe(),
                         {"default_action": "drop", "fib_forward": False, "stateful": True})


class LoadBalancerTest(unittest.TestCase):
    def test_add_service_populates_pool_and_clears_unused_slots(self):
        dp = new_dp()
        backends = dp.maps["lb_backends"]
        for i in range(abi.MAX_BACKENDS_PER_SVC):  # stale data from an earlier service
            backends.update(ct.c_uint32(i), abi.Backend(ip=1, port=1, active=1))
        sid = dp.lb.add_service(VIP, 80, ["10.0.2.1", "10.0.2.2:8080"])
        (svc,) = dp.lb.list()
        self.assertEqual(svc["id"], sid)
        self.assertEqual(svc["backends"], [{"ip": "10.0.2.1", "port": 80, "active": True},
                                           {"ip": "10.0.2.2", "port": 8080, "active": True}])
        self.assertEqual(backends.lookup(ct.c_uint32(sid * 16 + 2)).ip, 0)

    def test_replacing_a_service_keeps_its_id(self):
        dp = new_dp()
        a = dp.lb.add_service(VIP, 80, ["10.0.2.1"])
        b = dp.lb.add_service("10.100.0.2", 443, ["10.0.2.1"])
        self.assertEqual(dp.lb.add_service(VIP, 80, ["10.0.2.4"]), a)
        self.assertNotEqual(a, b)

    def test_drain_and_restore(self):
        dp = new_dp()
        dp.lb.add_service(VIP, 80, ["10.0.2.1", "10.0.2.2"])
        self.assertTrue(dp.lb.set_backend_state(VIP, 80, "10.0.2.1", up=False))
        self.assertFalse(dp.lb.list()[0]["backends"][0]["active"])
        self.assertFalse(dp.lb.set_backend_state(VIP, 80, "10.0.2.9", up=False))
        with self.assertRaises(ValueError):
            dp.lb.set_backend_state("10.100.0.9", 80, "10.0.2.1", up=False)

    def test_backends_must_be_disjoint_across_services(self):
        dp = new_dp()
        dp.lb.add_service(VIP, 80, ["10.0.2.1:80", "10.0.2.2:80"])
        with self.assertRaises(ValueError):
            dp.lb.add_service("10.100.0.2", 80, ["10.0.2.2:80"])
        dp.lb.add_service("10.100.0.2", 80, ["10.0.2.2:8080"])   # other port: fine
        dp.lb.add_service(VIP, 80, ["10.0.2.1:80"])              # re-adding itself: fine

    def test_delete_service(self):
        dp = new_dp()
        dp.lb.add_service(VIP, 80, ["10.0.2.1"])
        self.assertTrue(dp.lb.delete_service(VIP, 80))
        self.assertFalse(dp.lb.delete_service(VIP, 80))
        self.assertEqual(dp.lb.list(), [])

    def test_backend_count_limits(self):
        dp = new_dp()
        with self.assertRaises(ValueError):
            dp.lb.add_service(VIP, 80, [])
        with self.assertRaises(ValueError):
            dp.lb.add_service(VIP, 80, [f"10.0.3.{i}" for i in range(17)])


class ConntrackExpiryTest(unittest.TestCase):
    def setUp(self):
        self.dp = new_dp()
        self.now = 1000 * SEC
        self.t = Timeouts(idle=30, fin=5, hard=0)

    def _lb_conn(self, client_port: int, last_seen: int, flags: int = 0):
        fwd = flow_key(C1, VIP, client_port, 80, 6)
        self.dp.maps["lb_conntrack"].update(fwd, abi.LbCt(
            backend_ip=ip_to_wire(S2), backend_port=port_to_wire(80),
            created_ns=last_seen, last_seen_ns=last_seen, flags=flags))
        rev = flow_key(S2, C1, 80, client_port, 6)
        self.dp.maps["lb_reverse"].update(rev, abi.LbRev(vip=ip_to_wire(VIP), last_seen_ns=last_seen))

    def test_idle_and_fin_timeouts(self):
        self._lb_conn(1001, self.now - 10 * SEC)                       # active
        self._lb_conn(1002, self.now - 31 * SEC)                       # idle too long
        self._lb_conn(1003, self.now - 6 * SEC, flags=abi.CT_F_FIN)    # closed
        removed = self.dp.conntrack.expire(self.t, now_ns=self.now)
        self.assertEqual(removed["lb_conntrack"], 2)
        ports = {k.sport for k in self.dp.maps["lb_conntrack"].keys()}
        self.assertEqual(ports, {port_to_wire(1001)})

    def test_reverse_entry_removed_with_forward_entry(self):
        self._lb_conn(1002, self.now - 31 * SEC)
        self.dp.conntrack.expire(self.t, now_ns=self.now)
        self.assertEqual(self.dp.maps["lb_reverse"].keys(), [])

    def test_entry_refreshed_by_data_plane_is_not_deleted(self):
        class RefreshingMap:
            """Simulates a packet refreshing the entry between read and delete."""
            def __init__(self, inner, now):
                self.inner, self.now, self.reads = inner, now, 0

            def items(self):
                return self.inner.items()

            def keys(self):
                return self.inner.keys()

            def delete(self, k):
                return self.inner.delete(k)

            def update(self, k, v):
                self.inner.update(k, v)

            def lookup(self, k):
                v = self.inner.lookup(k)
                if v is not None:
                    v.last_seen_ns = self.now  # refreshed by an in-flight packet
                return v

        key = flow_key(C1, S2, 5, 6, 6)
        self.dp.maps["fw_conntrack"].update(key, abi.CtEntry(
            created_ns=self.now - 100 * SEC, last_seen_ns=self.now - 100 * SEC))
        self.dp.conntrack._fw = RefreshingMap(self.dp.maps["fw_conntrack"], self.now)
        self.assertEqual(self.dp.conntrack.expire(self.t, self.now)["fw_conntrack"], 0)

    def test_hard_timeout(self):
        key = flow_key(C1, S2, 5, 6, 6)
        self.dp.maps["fw_conntrack"].update(key, abi.CtEntry(
            created_ns=self.now - 100 * SEC, last_seen_ns=self.now))
        self.assertEqual(self.dp.conntrack.expire(Timeouts(idle=30, hard=0), self.now)
                         ["fw_conntrack"], 0)
        self.assertEqual(self.dp.conntrack.expire(Timeouts(idle=30, hard=60), self.now)
                         ["fw_conntrack"], 1)


class TelemetryTest(unittest.TestCase):
    def test_counters_sum_per_cpu_values(self):
        dp = new_dp()
        idx = abi.STAT_NAMES.index("drop_firewall")
        dp.maps["global_stats"].update(ct.c_uint32(idx), [ct.c_uint64(3), ct.c_uint64(4)])
        self.assertEqual(dp.telemetry.counters()["drop_firewall"], 7)

    def test_flows_merged_across_cpus(self):
        dp = new_dp()
        key = flow_key(C1, S2, 1000, 80, 6)
        dp.maps["flow_stats"].update(key, [abi.FlowStat(packets=2, bytes=200),
                                           abi.FlowStat(packets=3, bytes=300)])
        (flow,) = dp.telemetry.top_flows()
        self.assertEqual((flow["src"], flow["packets"], flow["bytes"]), (C1, 5, 500))


if __name__ == "__main__":
    unittest.main()
