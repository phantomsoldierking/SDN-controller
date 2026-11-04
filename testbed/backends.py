"""HTTP backend servers (one per sN host) and the HTTP probe client."""
from __future__ import annotations

import os
import time

from .config import PYTHON, SERVERS, VPORT
from .net import host_tool


class BackendServers:
    """`python3 -m http.server` on every backend; each serves a page containing
    its own name, so a client can tell which backend answered."""

    def __init__(self, net, wwwdir: str):
        self.net, self.wwwdir = net, wwwdir
        self._pids: dict[str, int] = {}

    def start(self) -> None:
        for s in SERVERS:
            docroot = os.path.join(self.wwwdir, s.name)
            os.makedirs(docroot, exist_ok=True)
            with open(os.path.join(docroot, "index.html"), "w") as f:
                f.write(s.name + "\n")
            out = self.net.get(s.name).cmd(
                f"{PYTHON} -m http.server {VPORT} --bind {s.ip} --directory {docroot} "
                f">/dev/null 2>&1 & echo $!")
            self._pids[s.name] = int(out.strip().splitlines()[-1])
        for s in SERVERS:
            node = self.net.get(s.name)
            for _ in range(50):
                if s.name in node.cmd(f"curl -s --max-time 1 http://{s.ip}:{VPORT}/"):
                    break
                time.sleep(0.1)

    def stop(self) -> None:
        # Kill by PID: Mininet hosts share the process table, so a pkill
        # would also hit unrelated processes on the machine.
        for name, pid in self._pids.items():
            self.net.get(name).cmd(f"kill {pid} 2>/dev/null")
        self._pids.clear()


def probe(node, url: str, n: int) -> dict:
    """n HTTP requests from `node`, each on a new TCP connection."""
    try:
        return host_tool(node, "probe", url, n)
    except RuntimeError as e:
        return {"ok": 0, "fail": n, "backends": {}, "error": str(e)}
