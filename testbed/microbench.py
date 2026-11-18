"""In-kernel microbenchmark of the data plane (root; no Mininet, no traffic generator).

    sudo python3 -m testbed.microbench [--out results/microbench.json] [--quick]

The real programs are loaded and timed with BPF_PROG_TEST_RUN, which reports
the kernel's own measurement of the program's run time.

  rules       cost vs number of installed rules (0..10,000 over all ten
              patterns, none matching: every populated pattern is probed)
  conntrack   cost vs connection-table occupancy (0..60,000 entries per table)
  cold        one flow vs cycling through 1,000 / 15,000 / 60,000 tracked flows
              (15,000 fits the 16,384-entry telemetry table; 60,000 does not)
  paths       pass, firewall drop, DNAT (new TCP, new UDP, established), SNAT
  chain       single program vs the same pipeline as a 3-stage tail-call chain,
              with re-parsing (chain) and with shared parse metadata (chainm)
  uniformity  backend choice for 20,000 synthetic connections, before and
              after draining one of four backends (Pearson chi-square)
  reaper      duration of one user-space expiry pass over 60,000 entries/table

`rules`/`conntrack` and the repeat-loop columns use the kernel's repeat loop on
a packet the program does not modify (cache-warm, one flow). NAT rewrites the
packet, so path costs are single-shot (repeat=1 per call); they include a
constant timing overhead, so paths are compared with the single-shot pass path.
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
from sdn.dataplane import DataPlane, FirewallRule, Timeouts
from sdn.loader import LoadedObject, build, unpin_maps
from testbed import packets as P
from testbed.aggregate import summarize
from testbed.rules import background_rules

C1, S1, S2, S3, VIP = "10.0.1.1", "10.0.2.1", "10.0.2.2", "10.0.2.3", "10.100.0.1"
BACKENDS = [S1, S2, S3, "10.0.2.4"]


def rand_ip(rng: random.Random) -> str:
    # 172.16.0.0/12: never used by the test packets
    return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_rules(n: int) -> list[FirewallRule]:
    """n non-matching rules over all ten patterns; ALLOW avoids conntrack flushes."""
    return background_rules(n, seed=1, action="allow")


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


CHAIN = ["xdp_chain_fw", "xdp_chain_lb", "xdp_chain_out"]
CHAINM = ["xdp_chainm_fw", "xdp_chainm_lb", "xdp_chainm_out"]
COLD_FLOWS = [1_000, 15_000, 60_000]


def reset(dp: DataPlane) -> None:
    dp.firewall.flush()
    dp.conntrack.flush()
    for svc in dp.lb.list():
        dp.lb.delete_service(svc["vip"], svc["port"], svc["proto"])
    dp.config.apply(default_action="allow", fib_forward=False, stateful=True)


def repeated(obj: LoadedObject, frame: bytes, repeat: int, trials: int,
             program: str | None = None) -> dict:
    """Kernel repeat loop; one sample = mean ns per run over `repeat` runs."""
    obj.test_run(frame, 1000, program)  # warm caches and connection state
    return summarize([obj.test_run(frame, repeat, program)[2] for _ in range(trials)])


def single_shot(obj: LoadedObject, make_frame, calls: int, batches: int = 10,
                program: str | None = None) -> dict:
    """repeat=1 per call (fresh packet each time); samples = batch means."""
    durations = [obj.test_run(make_frame(i), 1, program)[2] for i in range(calls)]
    size = calls // batches
    return summarize([statistics.fmean(durations[i * size:(i + 1) * size])
                      for i in range(batches)])


def client_ip(i: int) -> str:
    return f"10.{1 + (i >> 16) % 200}.{(i >> 8) & 255}.{1 + (i & 255) % 254}"


def chi_square(counts: list[int]) -> float:
    expected = sum(counts) / len(counts)
    return sum((c - expected) ** 2 / expected for c in counts)


def uniformity(obj: LoadedObject, dp: DataPlane, n: int) -> dict:
    """Backend chosen for n synthetic new connections, before/after a drain."""
    def run(offset: int) -> dict:
        counts: dict[str, int] = {}
        for i in range(n):
            frame = P.build(client_ip(offset + i), VIP, 1024 + (offset + i) % 60000, 80)
            b = P.parse(obj.test_run(frame)[1]).dst_ip
            counts[b] = counts.get(b, 0) + 1
        return counts

    dp.lb.add_service(VIP, 80, BACKENDS)
    before = run(0)
    dp.lb.set_backend_state(VIP, 80, BACKENDS[0], up=False)
    after = run(n)
    return {"n": n,
            "all_active": {"counts": before, "chi2": chi_square(list(before.values())),
                           "dof": len(before) - 1},
            "one_drained": {"counts": after, "chi2": chi_square(list(after.values())),
                            "dof": len(after) - 1}}


def cold_cache(obj: LoadedObject, dp: DataPlane, flows: int, calls: int) -> dict:
    """Single-shot cost when `flows` tracked flows are visited in random order."""
    reset(dp)
    frames = [P.build(client_ip(i), S2, 1024 + i % 60000, 22, tcp_flags=0x10)
              for i in range(flows)]
    for f in frames:  # create their connection and telemetry state
        obj.test_run(f)
    order = random.Random(7).choices(range(flows), k=calls)
    return single_shot(obj, lambda i: frames[order[i]], calls)


def bench_hook(hook: str, quick: bool) -> dict:
    repeat, trials, calls = (20_000, 5, 2_000) if quick else (200_000, 15, 20_000)
    scale = 10 if quick else 1
    rule_counts = [0, 10, 100, 1000, 10_000]
    ct_counts = [0, 1000, 10_000, 60_000]
    pin_dir = f"/sys/fs/bpf/sdn_microbench_{hook}_{os.getpid()}"
    programs = [f"{hook}_dataplane"] + (CHAIN + CHAINM if hook == "xdp" else [])
    obj = LoadedObject(hook, pin_dir=pin_dir, programs=programs)
    if hook == "xdp":
        obj.fill_prog_array("chain_progs", CHAIN)
        obj.fill_prog_array("chainm_progs", CHAINM)
    dp = DataPlane.open(pin_dir)
    plain = P.build(C1, S2, 40000, 22, tcp_flags=0x10)
    res: dict = {"hook": hook, "repeat": repeat, "trials": trials, "calls": calls}
    log = lambda name, st: print(f"  [{hook}] {name:<28} {st['mean']:7.1f} ns", flush=True)  # noqa
    try:
        reset(dp)
        # Warm-up: the first samples after loading ran slower (JIT'ed code and
        # maps not yet in the caches, branch predictors cold).
        for _ in range(5):
            obj.test_run(plain, repeat)

        res["rules"] = {}
        installed = 0
        for n in rule_counts:
            dp.firewall.add_many(random_rules(n)[installed:])
            installed = n
            res["rules"][n] = repeated(obj, plain, repeat, trials)
            log(f"rules={n}", res["rules"][n])

        reset(dp)
        res["conntrack"] = {}
        filled = 0
        for n in ct_counts:
            fill_conntrack(dp, (n - filled) // scale, seed=n)
            filled = n
            res["conntrack"][n] = repeated(obj, plain, repeat, trials)
            log(f"conntrack={n}", res["conntrack"][n])

        reset(dp)
        one = P.build(client_ip(0), S2, 1024, 22, tcp_flags=0x10)
        obj.test_run(one)
        res["cold"] = {"one_flow": single_shot(obj, lambda i: one, calls)}
        log("cold: one flow", res["cold"]["one_flow"])
        for flows in COLD_FLOWS:
            res["cold"][str(flows)] = cold_cache(obj, dp, flows // scale, calls)
            log(f"cold: {flows} flows", res["cold"][str(flows)])

        reset(dp)
        dp.lb.add_service(VIP, 80, BACKENDS)
        dp.lb.add_service(VIP, 80, BACKENDS, "udp")
        dp.firewall.add(FirewallRule(src=C1, dst=S3, proto="tcp", dport=22))
        backend = P.parse(obj.test_run(P.build(C1, VIP, 50000, 80))[1]).dst_ip
        paths = {
            "pass": lambda i: P.build(C1, S2, 40000, 22, tcp_flags=0x10),
            "fw_drop": lambda i: P.build(C1, S3, 40000, 22, tcp_flags=0x10),
            "dnat_established": lambda i: P.build(C1, VIP, 50000, 80, tcp_flags=0x10),
            "dnat_new": lambda i: P.build(client_ip(i), VIP, 1024 + i % 60000, 80),
            "dnat_new_udp": lambda i: P.build(client_ip(i), VIP, 1024 + i % 60000, 80,
                                              proto=P.UDP),
            "snat_established": lambda i: P.build(backend, C1, 80, 50000, tcp_flags=0x10),
        }
        res["paths"] = {}
        for name, make in paths.items():
            res["paths"][name] = single_shot(obj, make, calls)
            log(f"path {name}", res["paths"][name])
        res["pass_repeated"] = repeated(obj, paths["pass"](0), repeat, trials)
        res["fw_drop_repeated"] = repeated(obj, paths["fw_drop"](0), repeat, trials)
        log("pass (repeat loop)", res["pass_repeated"])
        log("drop (repeat loop)", res["fw_drop_repeated"])

        if hook == "xdp":
            for variant, entry in (("chain", "xdp_chain_fw"), ("chainm", "xdp_chainm_fw")):
                res[variant] = {
                    "pass_repeated": repeated(obj, paths["pass"](0), repeat, trials, entry),
                    "drop_repeated": repeated(obj, paths["fw_drop"](0), repeat, trials, entry),
                    "pass": single_shot(obj, paths["pass"], calls, program=entry),
                    "dnat_established": single_shot(obj, paths["dnat_established"], calls,
                                                    program=entry),
                    "snat_established": single_shot(obj, paths["snat_established"], calls,
                                                    program=entry),
                }
                for name, st in res[variant].items():
                    log(f"{variant} {name}", st)

        reset(dp)
        res["uniformity"] = uniformity(obj, dp, 2_000 if quick else 20_000)
        for phase in ("all_active", "one_drained"):
            u = res["uniformity"][phase]
            print(f"  [{hook}] uniformity {phase}: {u['counts']} chi2={u['chi2']:.2f}",
                  flush=True)

        if hook == "xdp":
            reset(dp)
            flows = 60_000 // scale
            fill_conntrack(dp, flows, seed=99)
            start = time.perf_counter()
            dp.conntrack.expire(Timeouts(idle=3600, fin=3600))
            elapsed = time.perf_counter() - start
            res["reaper"] = {"entries_per_table": flows, "tables": 3,
                             "seconds": elapsed, "entries_per_s": 3 * flows / elapsed}
            print(f"  [{hook}] reaper sweep over {3 * flows} entries: {elapsed:.2f} s",
                  flush=True)
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
    from testbed.cpus import CLIENT_CPU  # same performance core as the benchmark
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
