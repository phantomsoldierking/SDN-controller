"""Long-running control-plane daemon: REST API + conntrack reaper thread."""
from __future__ import annotations

import json
import logging
import signal
import threading
from dataclasses import dataclass, field

from .api import make_server
from .dataplane import DataPlane, Timeouts
from .libbpf import BpfError

log = logging.getLogger("sdn.daemon")


class Reaper(threading.Thread):
    """Periodically expires idle connections (the OpenFlow idle_timeout analogue)."""

    def __init__(self, dp: DataPlane, timeouts: Timeouts, interval: float):
        super().__init__(name="ct-reaper", daemon=True)
        self._dp, self._timeouts, self._interval = dp, timeouts, interval
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                removed = self._dp.conntrack.expire(self._timeouts)
                if any(removed.values()):
                    log.info("expired %s", removed)
            except BpfError as e:
                log.error("gc pass failed: %s", e)

    def stop(self) -> None:
        self._stop.set()


@dataclass
class DaemonOptions:
    listen: str = "127.0.0.1:8080"
    timeouts: Timeouts = field(default_factory=Timeouts)
    gc_interval: float = 5.0
    services_file: str | None = None


def load_services(dp: DataPlane, path: str) -> None:
    with open(path) as f:
        for svc in json.load(f):
            sid = dp.lb.add_service(svc["vip"], int(svc["port"]), svc["backends"],
                                    svc.get("proto", "tcp"))
            log.info("service %s:%s -> %s (id %d)", svc["vip"], svc["port"], svc["backends"], sid)


def run(dp: DataPlane, opts: DaemonOptions) -> None:
    if opts.services_file:
        load_services(dp, opts.services_file)

    reaper = Reaper(dp, opts.timeouts, opts.gc_interval)
    reaper.start()
    server = make_server(dp, opts.listen)

    def shutdown(*_):
        reaper.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    t = opts.timeouts
    log.info("REST API on http://%s  (idle=%ss fin=%ss hard=%ss gc every %ss)",
             opts.listen, t.idle, t.fin, t.hard or "off", opts.gc_interval)
    server.serve_forever()
    log.info("stopped")
