#!/usr/bin/env python3
"""Summarize independent microbenchmark runs of the same binary.

    python3 testbed/microbench_summary.py results/rev4/microbench_*.json

For every measured quantity it prints the mean of the run means, the lowest
and highest run mean, and the within-run 95% CI of each run, so that
run-to-run variation can be compared with the within-run intervals.
"""
from __future__ import annotations

import json
import statistics
import sys


def leaves(d: dict, prefix: str = ""):
    for k, v in d.items():
        if isinstance(v, dict) and "mean" in v and "ci95" in v:
            yield prefix + str(k), v
        elif isinstance(v, dict):
            yield from leaves(v, f"{prefix}{k}.")


def main() -> int:
    runs = [json.load(open(p)) for p in sys.argv[1:]]
    if not runs:
        sys.exit(__doc__)
    table: dict[str, list[dict]] = {}
    for r in runs:
        for hook, data in r["hooks"].items():
            for name, st in leaves(data):
                table.setdefault(f"{hook}.{name}", []).append(st)
    print(f"{'quantity':40} {'mean':>8} {'min':>8} {'max':>8} {'range':>7}  within-run CI")
    for name, sts in table.items():
        means = [s["mean"] for s in sts]
        cis = " ".join(f"{s['ci95']:.1f}" for s in sts)
        print(f"{name:40} {statistics.fmean(means):8.1f} {min(means):8.1f} {max(means):8.1f} "
              f"{max(means) - min(means):7.1f}  {cis}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
