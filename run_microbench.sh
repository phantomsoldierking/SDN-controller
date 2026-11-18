#!/usr/bin/env bash
# run_microbench.sh - repeat the in-kernel microbenchmark under the same CPU
# policy as run_experiments.sh (performance governor, restored on exit).
#
#   sudo OUT=results/rev4 RUNS=3 ./run_microbench.sh
#
# Each run writes $OUT/microbench_<i>.json; independent runs show how far the
# results move between runs of the same binary. The tests run first, so the
# measured binary is the tested one.
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }
OUT=${OUT:-results/rev4}
RUNS=${RUNS:-3}
PY=${PYTHON:-python3}

declare -A SAVED_GOV=()
restore_governor() {
  for f in "${!SAVED_GOV[@]}"; do echo "${SAVED_GOV[$f]}" > "$f" 2>/dev/null || true; done
}
for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [[ -e $f ]] || continue
  g=$(cat "$f" 2>/dev/null) || continue   # offline CPU: no governor to set
  SAVED_GOV[$f]=$g; echo performance > "$f" 2>/dev/null || true
done
trap restore_governor EXIT

make -s build
echo "*** unit + kernel tests"
"$PY" -m unittest discover -s tests -t . -p 'test_*.py'
mkdir -p "$OUT"
for i in $(seq 1 "$RUNS"); do
  echo "*** in-kernel microbenchmark, run $i of $RUNS"
  "$PY" -m testbed.microbench --out "$OUT/microbench_$i.json"
done
echo "*** done: $OUT/microbench_1..$RUNS.json"
