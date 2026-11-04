"""REST API end to end over a real HTTP socket, backed by in-memory maps."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from sdn.api import make_server
from sdn.dataplane import DataPlane
from sdn.maps import in_memory_maps


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dp = DataPlane(in_memory_maps())
        cls.server = make_server(cls.dp, "127.0.0.1:0")
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def test_firewall_round_trip(self):
        rule = {"src": "10.0.1.1", "dst": "10.0.2.3", "bidir": True}
        self.assertEqual(self.call("POST", "/firewall", rule), (200, {"added": 2}))
        status, body = self.call("GET", "/firewall")
        self.assertEqual((status, len(body["rules"])), (200, 2))
        self.assertEqual(self.call("DELETE", "/firewall", rule), (200, {"deleted": 2}))

    def test_default_action(self):
        self.assertEqual(self.call("PUT", "/firewall/default", {"action": "drop"}),
                         (200, {"default": "drop"}))
        self.assertEqual(self.call("GET", "/config")[1]["default_action"], "drop")
        self.call("PUT", "/firewall/default", {"action": "allow"})

    def test_services(self):
        svc = {"vip": "10.100.0.1", "port": 80, "backends": ["10.0.2.1", "10.0.2.2"]}
        self.assertEqual(self.call("POST", "/services", svc)[0], 200)
        self.assertEqual(self.call("PUT", "/services/backend",
                                   {"vip": "10.100.0.1", "port": 80, "backend": "10.0.2.1",
                                    "state": "down"}), (200, {"updated": True}))
        (listed,) = self.call("GET", "/services")[1]
        self.assertEqual([b["active"] for b in listed["backends"]], [False, True])
        self.assertEqual(self.call("DELETE", "/services", {"vip": "10.100.0.1", "port": 80}),
                         (200, {"deleted": True}))

    def test_bad_input_is_400(self):
        status, body = self.call("POST", "/firewall", {"src": "10.0.1.1", "dport": 22})
        self.assertEqual(status, 400)
        self.assertIn("ValueError", body["error"])

    def test_unknown_route_is_404(self):
        status, body = self.call("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertIn("GET /stats", body["routes"])


if __name__ == "__main__":
    unittest.main()
