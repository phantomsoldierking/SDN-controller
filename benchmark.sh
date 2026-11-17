#!/usr/bin/env bash
# benchmark.sh - Test 4: compare the eBPF data plane with kernel and OVS baselines.
#
# Every configuration is run REPEATS times on a freshly built topology. Runs are
# interleaved (round r runs every configuration once) so slow drift such as
# thermal throttling affects all configurations alike. Results are aggregated
# into mean, standard deviation and a 95% confidence interval per metric.
#
#   sudo ./benchmark.sh                          # all configurations, 10 rounds
#   sudo REPEATS=3 DURATION=5 ./benchmark.sh ebpf-xdp kernel
#
# Configurations: ebpf-xdp ebpf-tc ebpf-tc-fib kernel nft-ipvs ovs ovs-ct
# Environment:    REPEATS (10)  DURATION s (10)  REQUESTS (50)  OUT (results/repeated)
#                 SDN_CLIENT_CPU / SDN_SERVER_CPU (default: two fastest cores)
#                 KEEP_GOVERNOR=1 to leave the CPU frequency governor alone
set -euo pipefail
cd "$(dirname "$0")"

REPEATS=${REPEATS:-10}
DURATION=${DURATION:-10}
REQUESTS=${REQUESTS:-50}
OUT=${OUT:-results/repeated}
PY=${PYTHON:-python3}
CONFIGS=("$@")
[[ ${#CONFIGS[@]} -eq 0 ]] && CONFIGS=(ebpf-xdp ebpf-tc ebpf-tc-fib kernel nft-ipvs ovs ovs-ct)

[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }
for bin in iperf3 ping taskset; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 1; }
done

# ---- fixed CPU frequency policy for the duration of the benchmark ----
GOV_FILES=(/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
declare -A SAVED_GOV=()
restore_governor() {
  for f in "${!SAVED_GOV[@]}"; do echo "${SAVED_GOV[$f]}" > "$f" 2>/dev/null || true; done
}
if [[ -z ${KEEP_GOVERNOR:-} && -e ${GOV_FILES[0]} ]]; then
  for f in "${GOV_FILES[@]}"; do SAVED_GOV[$f]=$(cat "$f"); echo performance > "$f" 2>/dev/null || true; done
  trap restore_governor EXIT
  echo "*** CPU governor: performance (restored on exit; was ${SAVED_GOV[${GOV_FILES[0]}]})"
fi

available() {
  case $1 in
    ovs|ovs-ct) ovs-vsctl show >/dev/null 2>&1 || { echo "skip $1: Open vSwitch not running"; return 1; } ;;
    nft-ipvs)   command -v ipvsadm >/dev/null && command -v nft >/dev/null \
                  || { echo "skip $1: needs nft and ipvsadm"; return 1; } ;;
  esac
}

args_for() {
  case $1 in
    ebpf-xdp)    echo "--mode ebpf --hook xdp" ;;
    ebpf-tc)     echo "--mode ebpf --hook tc" ;;
    ebpf-tc-fib) echo "--mode ebpf --hook tc --fib-forward" ;;
    kernel|nft-ipvs|ovs|ovs-ct) echo "--mode $1" ;;
    *) echo "unknown configuration: $1" >&2; exit 1 ;;
  esac
}

RUN_CONFIGS=()
for cfg in "${CONFIGS[@]}"; do args_for "$cfg" >/dev/null; available "$cfg" && RUN_CONFIGS+=("$cfg"); done
[[ ${#RUN_CONFIGS[@]} -gt 0 ]] || { echo "nothing to run"; exit 1; }

make -s build
mkdir -p "$OUT"
{   # exact environment of this run, for the paper's testbed description
  echo "date:       $(date -Is)"
  echo "kernel:     $(uname -r)"
  echo "cpu:        $(lscpu | sed -n 's/^Model name:[[:space:]]*//p')"
  echo "governor:   $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  echo "clang:      $(clang --version | head -1)"
  echo "libbpf:     $(pkg-config --modversion libbpf 2>/dev/null || echo n/a)"
  echo "python:     $("$PY" --version 2>&1)"
  echo "mininet:    $("$PY" -c 'import mininet.net as m; print(m.VERSION)' 2>/dev/null)"
  echo "iperf3:     $(iperf3 --version | head -1)"
  echo "ovs:        $(ovs-vswitchd --version 2>/dev/null | head -1 || echo n/a)"
  echo "nft:        $(nft --version 2>/dev/null || echo n/a)"
  echo "ipvsadm:    $(ipvsadm --version 2>/dev/null || echo n/a)"
  echo "repeats:    $REPEATS x ${DURATION}s, configs: ${RUN_CONFIGS[*]}"
} > "$OUT/environment.txt"
cat "$OUT/environment.txt"

for ((r = 1; r <= REPEATS; r++)); do
  for cfg in "${RUN_CONFIGS[@]}"; do
    echo
    echo "=================== round $r/$REPEATS: $cfg ==================="
    mn -c >/dev/null 2>&1 || true
    mkdir -p "$OUT/raw/$cfg"
    # shellcheck disable=SC2046
    if ! "$PY" topology.py $(args_for "$cfg") --test 4 --duration "$DURATION" \
          --requests "$REQUESTS" --bench-out "$OUT/raw/$cfg/run$(printf %02d "$r").json"; then
      echo "!!! $cfg round $r failed"
    fi
  done
done

"$PY" -m testbed.aggregate "$OUT" "${RUN_CONFIGS[@]}"
