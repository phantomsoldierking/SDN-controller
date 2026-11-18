"""Aggregate repeated benchmark runs: mean, standard deviation and 95% CI.

    python3 -m testbed.aggregate results/repeated ebpf-xdp ebpf-tc kernel ...
    python3 -m testbed.aggregate --compare results/repeated ebpf-xdp kernel ebpf-tc ebpf-xdp

Reads OUT/raw/<config>/run*.json and writes OUT/summary.json; prints a table.
The confidence interval uses Student's t distribution with n-1 degrees of
freedom, so it is valid for the small number of runs used here.

Comparisons: rounds are interleaved (round r runs every configuration once),
so run r of two configurations forms a pair. `paired()` tests the per-round
relative difference 100*(a_r/b_r - 1) against 0 (paired t-test) and gives its
95% CI; `welch()` is the unpaired test, kept for reference.
"""
from __future__ import annotations

import glob
import json
import math
import os
import statistics
import sys

METRICS = [
    ("tcp_gbps", "TCP Gbit/s"),
    ("udp64_rx_pps", "UDP64 rx pps"),
    ("tcp_vip_gbps", "VIP TCP Gbit/s"),
    ("udp64_vip_rx_pps", "VIP UDP64 pps"),
    ("rtt_avg_ms", "RTT avg ms"),
    ("rtt_max_ms", "RTT max ms"),
    ("lb_rps", "LB conn/s"),
    ("fw_drop_pps", "FW drop pps*"),
]

# two-sided 97.5% quantiles of Student's t for 1..30 degrees of freedom
_T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
         2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
         2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def t975(dof: int) -> float:
    return _T975[dof - 1] if dof <= len(_T975) else 1.96


def summarize(values: list[float]) -> dict:
    n = len(values)
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if n > 1 else 0.0
    half = t975(n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    return {"n": n, "mean": mean, "sd": sd, "ci95": half, "min": min(values), "max": max(values),
            "cv_pct": 100 * sd / mean if mean else 0.0}


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes)."""
    qab, qap, qam = a + b, a + 1, a - 1
    c, d = 1.0, 1 - qab * x / qap
    d = 1 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        for aa in (m * (b - m) * x / ((qam + m2) * (a + m2)),
                   -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))):
            d = 1 + aa * d
            d = 1 / (d if abs(d) > 1e-300 else 1e-300)
            c = 1 + aa / c
            c = c if abs(c) > 1e-300 else 1e-300
            h *= d * c
        if abs(d * c - 1) < 1e-12:
            break
    return h


def _betai(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b)."""
    if x <= 0 or x >= 1:
        return 0.0 if x <= 0 else 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return front * _betacf(a, b, x) / a
    return 1 - front * _betacf(b, a, 1 - x) / b


def welch(a: list[float], b: list[float]) -> dict:
    """Welch's two-sample t-test (unequal variances), two-sided p-value."""
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.variance(a) / len(a), statistics.variance(b) / len(b)
    t = (ma - mb) / math.sqrt(va + vb)
    dof = (va + vb) ** 2 / (va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1))
    p = _betai(dof / 2, 0.5, dof / (dof + t * t))
    return {"diff_pct": 100 * (ma / mb - 1), "t": t, "dof": dof, "p": p}


def t_cdf_two_sided(t: float, dof: float) -> float:
    """Two-sided p-value of Student's t."""
    return _betai(dof / 2, 0.5, dof / (dof + t * t))


def paired(a: dict[str, float], b: dict[str, float]) -> dict:
    """Paired t-test on per-round relative differences (rounds present in both)."""
    rounds = sorted(set(a) & set(b))
    d = [100 * (a[r] / b[r] - 1) for r in rounds]
    n = len(d)
    mean = statistics.fmean(d)
    sd = statistics.stdev(d) if n > 1 else 0.0
    half = t975(n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    t = mean / (sd / math.sqrt(n)) if sd > 0 else math.inf
    p = t_cdf_two_sided(t, n - 1) if math.isfinite(t) else 0.0
    return {"n": n, "diff_pct": mean, "ci95": half, "t": t, "dof": n - 1, "p": p}


def by_round(out: str, config: str, key: str) -> dict[str, float]:
    vals = {}
    for path in sorted(glob.glob(os.path.join(out, "raw", config, "run*.json"))):
        with open(path) as f:
            v = json.load(f).get(key)
        if v is not None:
            vals[os.path.basename(path)] = v
    return vals


def load(out: str, config: str) -> list[dict]:
    runs = []
    for path in sorted(glob.glob(os.path.join(out, "raw", config, "run*.json"))):
        with open(path) as f:
            runs.append(json.load(f))
    return runs


def aggregate(out: str, configs: list[str]) -> dict:
    summary = {}
    for cfg in configs:
        runs = load(out, cfg)
        if not runs:
            continue
        summary[cfg] = {"runs": len(runs)}
        for key, _ in METRICS:
            values = [r[key] for r in runs if r.get(key) is not None]
            if values:
                summary[cfg][key] = summarize(values)
    return summary


def fmt(stat: dict | None) -> str:
    if not stat:
        return "-"
    m, h = stat["mean"], stat["ci95"]
    if m >= 1000:
        return f"{m / 1000:.1f}k ±{h / 1000:.1f}k"
    if m >= 10:
        return f"{m:.1f} ±{h:.1f}"
    return f"{m:.3f} ±{h:.3f}"


def compare(out: str, pairs: list[tuple[str, str]],
            metrics=("tcp_gbps", "udp64_rx_pps", "tcp_vip_gbps", "udp64_vip_rx_pps", "lb_rps",
                     "fw_drop_pps")) -> None:
    """Paired and Welch tests of `a` vs `b` for each pair (difference relative to b)."""
    for a, b in pairs:
        for key in metrics:
            va, vb = by_round(out, a, key), by_round(out, b, key)
            if len(va) > 1 and len(vb) > 1:
                pr = paired(va, vb)
                w = welch(list(va.values()), list(vb.values()))
                print(f"{a:>14} vs {b:<14} {key:16} paired {pr['diff_pct']:+6.1f}% "
                      f"±{pr['ci95']:4.1f}  p={pr['p']:.4f}   welch p={w['p']:.4f}")


def main(argv: list[str]) -> int:
    if argv[:1] == ["--compare"] and len(argv) >= 4 and len(argv) % 2 == 0:
        compare(argv[1], list(zip(argv[2::2], argv[3::2])))
        return 0
    if len(argv) < 2:
        print(__doc__)
        return 1
    out, configs = argv[0], argv[1:]
    summary = aggregate(out, configs)
    if not summary:
        print("no results found")
        return 1
    try:
        with open(os.path.join(out, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
    except PermissionError:
        print(f"note: {out}/summary.json not writable; table printed only")
    width = [12] + [16] * len(METRICS) + [4]
    row = lambda cells: "  ".join(str(c).ljust(w) for c, w in zip(cells, width))  # noqa: E731
    print("\n" + row(["config"] + [h for _, h in METRICS] + ["n"]))
    print(row(["-" * w for w in width]))
    for cfg, s in summary.items():
        print(row([cfg] + [fmt(s.get(k)) for k, _ in METRICS] + [s["runs"]]))
    print("\nmean ±95% CI (Student t).  *sender-limited: see testbed/microbench.py for the "
          "in-kernel drop cost")
    print(f"written {out}/summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
