#!/usr/bin/env bash
# run_experiments.sh - everything the paper reports, under one fixed CPU policy.
#
#   sudo ./run_experiments.sh             tests + scenarios + microbench + benchmark (~55 min)
#   sudo ./run_experiments.sh --no-bench  tests + scenarios + microbench           (~7 min)
#
# The CPU frequency governor is set to `performance` for the whole run and
# restored on exit. Results go to $OUT (default results/repeated).
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }
OUT=${OUT:-results/repeated}
PY=${PYTHON:-python3}
BENCH=1
[[ ${1:-} == --no-bench ]] && BENCH=0

declare -A SAVED_GOV=()
restore_governor() {
  for f in "${!SAVED_GOV[@]}"; do echo "${SAVED_GOV[$f]}" > "$f" 2>/dev/null || true; done
}
for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [[ -e $f ]] || continue
  SAVED_GOV[$f]=$(cat "$f"); echo performance > "$f" 2>/dev/null || true
done
trap restore_governor EXIT
export KEEP_GOVERNOR=1   # benchmark.sh must not touch it again

make -s build
echo "*** unit + kernel tests"
"$PY" -m unittest discover -s tests -t . -p 'test_*.py'

echo "*** functional scenarios (Tests 1-3)"
mkdir -p "$OUT/scenarios"
for m in "ebpf --hook xdp" "ebpf --hook tc" kernel nft-ipvs ovs ovs-ct; do
  mn -c >/dev/null 2>&1 || true
  label=$(echo "$m" | sed 's/ --hook /-/')
  # shellcheck disable=SC2086
  "$PY" topology.py --mode $m --test 1,2,3 --report-out "$OUT/scenarios/$label.json" \
    || echo "!!! scenarios failed for $m"
done

echo "*** in-kernel microbenchmark"
"$PY" -m testbed.microbench --out "$OUT/microbench.json"

if [[ $BENCH == 1 ]]; then
  OUT="$OUT" ./benchmark.sh
fi
