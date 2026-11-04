"""REST API over the DataPlane (JSON in, JSON out, standard library only)."""
from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .dataplane import DataPlane, FirewallRule
from .libbpf import BpfError

log = logging.getLogger("sdn.api")

Handler = Callable[[DataPlane, dict], object]


def _service_args(b: dict) -> tuple:
    return b["vip"], int(b["port"])


def _set_default_action(dp: DataPlane, b: dict) -> dict:
    dp.config.apply(default_action=b["action"])
    return {"default": b["action"]}


ROUTES: dict[tuple[str, str], Handler] = {
    ("GET", "/stats"): lambda dp, b: dp.telemetry.counters(),
    ("GET", "/flows"): lambda dp, b: dp.telemetry.top_flows(100),
    ("GET", "/config"): lambda dp, b: dp.config.describe(),
    ("GET", "/firewall"): lambda dp, b: {"default": dp.config.describe()["default_action"],
                                         "rules": dp.firewall.list()},
    ("POST", "/firewall"): lambda dp, b: {"added": dp.firewall.add(FirewallRule.from_dict(b))},
    ("DELETE", "/firewall"): lambda dp, b: {
        "deleted": dp.firewall.delete(FirewallRule.from_dict(b)) if b else dp.firewall.flush()},
    ("PUT", "/firewall/default"): _set_default_action,
    ("GET", "/services"): lambda dp, b: dp.lb.list(),
    ("POST", "/services"): lambda dp, b: {"id": dp.lb.add_service(
        *_service_args(b), b["backends"], b.get("proto", "tcp"))},
    ("DELETE", "/services"): lambda dp, b: {"deleted": dp.lb.delete_service(
        *_service_args(b), b.get("proto", "tcp"))},
    ("PUT", "/services/backend"): lambda dp, b: {"updated": dp.lb.set_backend_state(
        *_service_args(b), b["backend"], b.get("state", "up") == "up", b.get("proto", "tcp"))},
    ("GET", "/conntrack"): lambda dp, b: dp.conntrack.list(),
    ("DELETE", "/conntrack"): lambda dp, b: {"deleted": dp.conntrack.flush()},
}

_CLIENT_ERRORS = (ValueError, KeyError, TypeError, BpfError, json.JSONDecodeError)


def make_handler(dp: DataPlane) -> type[BaseHTTPRequestHandler]:
    class ApiHandler(BaseHTTPRequestHandler):
        server_version = "sdn-ebpf-cp/2.0"

        def log_message(self, fmt, *args):
            log.info(fmt, *args)

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n)) if n else {}

        def _dispatch(self, method: str) -> None:
            path = self.path.split("?", 1)[0].rstrip("/")
            handler = ROUTES.get((method, path))
            if handler is None:
                self._send(404, {"error": f"no route {method} {path}",
                                 "routes": sorted(f"{m} {p}" for m, p in ROUTES)})
                return
            try:
                self._send(200, handler(dp, self._body()))
            except _CLIENT_ERRORS as e:
                self._send(400, {"error": f"{type(e).__name__}: {e}"})

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PUT(self):
            self._dispatch("PUT")

        def do_DELETE(self):
            self._dispatch("DELETE")

    return ApiHandler


def make_server(dp: DataPlane, listen: str) -> ThreadingHTTPServer:
    host, _, port = listen.rpartition(":")
    return ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(dp))
