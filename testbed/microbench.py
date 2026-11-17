"""In-kernel microbenchmark of the data plane (root; no Mininet, no traffic generator).

    sudo python3 -m testbed.microbench [--out results/microbench.json] [--quick]

The real XDP and TC programs are loaded and timed with BPF_PROG_TEST_RUN,
which reports the kernel's own measurement of the program's run time.

  E1  rules:     per-packet cost vs number of installed firewall rules
                 (0..10,000, spread over all ten patterns, none matching, so
                 every lookup level is probed: the worst case)
  E2  state:     per-packet cost vs connection-table occupancy (0..60,000
                 entries in fw_conntrack, lb_conntrack and lb_reverse)
  E3  paths:     cost of each processing path - pass, firewall drop, LB
                 forward (DNAT) and LB reply (SNAT)

E1/E2 use the kernel's repeat loop (`repeat` runs per call, mean reported) on a
packet the program does not modify. E3 rewrites packets (NAT), so the same
buffer cannot be replayed; each call uses repeat=1, which adds a constant
timer overhead - E3 therefore also reports the pass path measured the same
way, so paths are compared like for like.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time

from sdn import abi
from sdn.codec import flow_key, ip_to_wire, port_to_wire
from sdn.dataplane import DataPlane, FirewallRule
from sdn.loader import LoadedObject, build, unpin_maps
from testbed import packets as P
from testbed.aggregate import summarize

C1, S1, S2, S3, VIP = "10.0.1.1", "10.0.2.1", "10.0.2.2", "10.0.2.3", "10.100.0.1"
BACKENDS = [S1, S2, S3, "10.0.2.4"]


def rand_ip(rng: random.Random) -> str:
    # 172.16.0.0/12: never used by the test packets
    return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def rand_mac(rng: random.Random) -> str:
    return "02:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))


def random_rules(n: int, seed: int = 1) -> list[FirewallRule]:
    """n non-matching rules, cycling through all ten patterns."""
    rng = random.Random(seed)
    shapes = [
        lambda: FirewallRule(src_mac=rand_mac(rng), dst_mac=rand_mac(rng)),
        lambda: FirewallRule(src_mac=rand_mac(rng)),
        lambda: FirewallRule(src=rand_ip(rng), dst=rand_ip(rng), proto="tcp",
                             sport=rng.randint(1, 65535), dport=rng.randint(1, 65535)),
        lambda: FirewallRule(src=rand_ip(rng), dst=rand_ip(rng), proto="tcp",
                             dport=rng.randint(1, 65535)),
        lambda: FirewallRule(src=rand_ip(rng), dst=rand_ip(rng), proto="udp",
                             sport=rng.randint(1, 65535)),
        lambda: FirewallRule(src=rand_ip(rng), dst=rand_ip(rng), proto="icmp"),
        lambda: FirewallRule(src=rand_ip(rng), dst=rand_ip(rng)),
        lambda: FirewallRule(dst=rand_ip(rng), proto="tcp", dport=rng.randint(1, 65535)),
        lambda: FirewallRule(src=rand_ip(rng)),
        lambda: FirewallRule(dst=rand_ip(rng)),
    ]
    rules = [shapes[i % len(shapes)]() for i in range(n)]
    for r in rules:
        r.action = "allow"  # never matched anyway; ALLOW avoids per-rule conntrack flushes
    return rules


def fill_conntrack(dp: DataPlane, n: int, seed: int = 2) -> None:
    rng = random.Random(seed)
    for _ in range(n):
        c, b = rand_ip(rng), rand_ip(rng)
        cp, bp = rng.randint(1024, 65535), rng.randint(1, 65535)
        dp.maps["fw_conntrack"].update(flow_key(c, b, cp, bp, 6), abi.CtEntry())
        dp.maps["lb_conntrack"].update(flow_key(c, VIP, cp, 80, 6),
                                       abi.LbCt(backend_ip=ip_to_wire(b), backend_port=port_to_wire(bp)))
        dp.maps["lb_reverse"].update(flow_key(b, c, bp, cp, 6),
                                     abi.LbRev(vip=ip_to_wire(VIP), vport=port_to_wire(80)))


def reset(dp: DataPlane) -> None:
    dp.firewall.flush()
    dp.conntrack.flush()
    for svc in dp.lb.list():
        dp.lb.delete_service(svc["vip"], svc["port"], svc["proto"])
    dp.config.apply(default_action="allow", fib_forward=False, stateful=True)


def repeated(obj: LoadedObject, frame: bytes, repeat: int, trials: int) -> dict:
    """Kernel repeat loop; one sample = mean ns per run over `repeat` runs."""
    obj.test_run(frame, 1000)  # warm caches and connection state
    samples = [obj.test_run(frame, repeat)[2] for _ in range(trials)]
    return summarize(samples)


def single_shot(obj: LoadedObject, make_frame, calls: int, batches: int = 10) -> dict:
    """repeat=1 per call (fresh packet each time); samples = batch means."""
    durations = [obj.test_run(make_frame(i), 1)[2] for i in range(calls)]
    size = calls // batches
    return summarize([statistics.fmean(durations[i * size:(i + 1) * size])
                      for i in range(batches)])


def bench_hook(hook: str, quick: bool) -> dict:
    repeat, trials, calls = (20_000, 5, 2_000) if quick else (200_000, 15, 20_000)
    rule_counts = [0, 10, 100, 1000, 10_000]
    ct_counts = [0, 1000, 10_000, 60_000]
    pin_dir = f"/sys/fs/bpf/sdn_microbench_{hook}_{os.getpid()}"
    obj = LoadedObject(hook, pin_dir=pin_dir)
    dp = DataPlane.open(pin_dir)
    plain = P.build(C1, S2, 40000, 22, tcp_flags=0x10)
    res: dict = {"hook": hook, "repeat": repeat, "trials": trials, "calls": calls}
    try:
        reset(dp)
        res["rules"] = {}
        installed = 0
        for n in rule_counts:
            for rule in random_rules(n)[installed:]:
                dp.firewall.add(rule)
            installed = n
            res["rules"][n] = repeated(obj, plain, repeat, trials)
            print(f"  [{hook}] rules={n:>6}: {res['rules'][n]['mean']:.1f} ns", flush=True)

        reset(dp)
        res["conntrack"] = {}
        filled = 0
        for n in ct_counts:
            fill_conntrack(dp, n - filled, seed=n)
            filled = n
            res["conntrack"][n] = repeated(obj, plain, repeat, trials)
            print(f"  [{hook}] conntrack={n:>6}: {res['conntrack'][n]['mean']:.1f} ns", flush=True)

        reset(dp)
        dp.lb.add_service(VIP, 80, BACKENDS)
        dp.firewall.add(FirewallRule(src=C1, dst=S3))
        backend = P.parse(obj.test_run(P.build(C1, VIP, 50000, 80))[1]).dst_ip
        paths = {
            "pass": lambda i: P.build(C1, S2, 40000, 22, tcp_flags=0x10),
            "fw_drop": lambda i: P.build(C1, S3, 40000, 22, tcp_flags=0x10),
            "lb_dnat": lambda i: P.build(C1, VIP, 50000, 80, tcp_flags=0x10),
            "lb_snat": lambda i: P.build(backend, C1, 80, 50000, tcp_flags=0x10),
        }
        res["paths"] = {}
        for name, make in paths.items():
            res["paths"][name] = single_shot(obj, make, calls)
            print(f"  [{hook}] path {name:<8}: {res['paths'][name]['mean']:.1f} ns", flush=True)
        res["fw_drop_repeated"] = repeated(obj, paths["fw_drop"](0), repeat, trials)
    finally:
        obj.close()
        for m in dp.maps.values():
            m.close()
        unpin_maps(pin_dir)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="results/microbench.json")
    ap.add_argument("--quick", action="store_true", help="fewer repetitions (smoke test)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("microbench needs root (BPF_PROG_TEST_RUN)")
    build()
    from testbed.benchmark import CLIENT_CPU  # same performance core as the benchmark
    if CLIENT_CPU:
        os.sched_setaffinity(0, {int(CLIENT_CPU)})
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    governor = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip() \
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") else "n/a"
    result = {"started": started, "kernel": os.uname().release, "cpu": CLIENT_CPU,
              "governor": governor,
              "hooks": {hook: bench_hook(hook, a.quick) for hook in ("xdp", "tc")}}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"written {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
