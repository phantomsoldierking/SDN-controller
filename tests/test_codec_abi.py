"""ABI layout and wire-format conversions (no root needed)."""
from __future__ import annotations

import ctypes as ct
import unittest

from sdn import abi, codec


class AbiTest(unittest.TestCase):
    def test_struct_sizes_match_bpf_abi_h(self):
        self.assertEqual(ct.sizeof(abi.FlowKey), 16)
        self.assertEqual(ct.sizeof(abi.FwKey), 28)
        self.assertEqual(ct.sizeof(abi.LbCt), 48)

    def test_every_map_has_a_spec(self):
        self.assertEqual(set(abi.MAP_SPECS) >= set(abi.CONNTRACK_MAPS), True)
        self.assertTrue(abi.MAP_SPECS["global_stats"].percpu)


class CodecTest(unittest.TestCase):
    def test_ip_round_trip_is_network_order_in_memory(self):
        v = codec.ip_to_wire("10.0.2.3")
        self.assertEqual(bytes(ct.c_uint32(v)), bytes([10, 0, 2, 3]))
        self.assertEqual(codec.wire_to_ip(v), "10.0.2.3")

    def test_port_round_trip(self):
        v = codec.port_to_wire(80)
        self.assertEqual(bytes(ct.c_uint16(v)), b"\x00\x50")
        self.assertEqual(codec.wire_to_port(v), 80)

    def test_zero_means_wildcard(self):
        self.assertEqual(codec.ip_to_wire(None), 0)
        self.assertEqual(codec.port_to_wire(0), 0)

    def test_mac(self):
        self.assertEqual(codec.bytes_to_mac(codec.mac_to_bytes("00:11:22:33:44:55")),
                         "00:11:22:33:44:55")
        with self.assertRaises(ValueError):
            codec.mac_to_bytes("00:11:22")

    def test_parse_proto(self):
        self.assertEqual(codec.parse_proto("tcp"), 6)
        self.assertEqual(codec.parse_proto(17), 17)
        with self.assertRaises(ValueError):
            codec.parse_proto("sctp")

    def test_parse_endpoint(self):
        self.assertEqual(codec.parse_endpoint("10.0.2.1:8080", 80), ("10.0.2.1", 8080))
        self.assertEqual(codec.parse_endpoint("10.0.2.1", 80), ("10.0.2.1", 80))
        with self.assertRaises(OSError):
            codec.parse_endpoint("not-an-ip", 80)

    def test_ct_flags(self):
        self.assertEqual(codec.ct_flags_to_str(abi.CT_F_SYN | abi.CT_F_FIN), "SYN,FIN")
        self.assertEqual(codec.ct_flags_to_str(0), "-")


if __name__ == "__main__":
    unittest.main()
