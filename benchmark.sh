#!/usr/bin/env bash
# benchmark.sh - Test 4: compare eBPF/XDP offload vs. Open vSwitch + OpenFlow
#                (and the plain Linux-kernel router as a reference).
#
# Each configuration builds a fresh Mininet topology, runs topology.py Test 4
# and writes results/<label>.json; a comparison table is printed at the end.
#
#   sudo ./benchmark.sh                     # all configurations, 10 s runs
#   sudo DURATION=20 ./benchmark.sh ebpf-xdp ovs
#
# Configurations: ebpf-xdp  ebpf-tc  ebpf-tc-fib  kernel  ovs
set -euo pipefail
cd "$(dirname "$0")"

DURATION=${DURATION:-10}
REQUESTS=${REQUESTS:-50}
OUT=${OUT:-results}
PY=${PYTHON:-python3}
CONFIGS=("$@")
[[ ${#CONFIGS[@]} -eq 0 ]] && CONFIGS=(ebpf-xdp ebpf-tc ebpf-tc-fib kernel ovs)

[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }
for bin in iperf3 ping; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 1; }
done

mkdir -p "$OUT"
make -s build

run() {
  local label=$1; shift
  echo
  echo "=================== $label ==================="
  mn -c >/dev/null 2>&1 || true
  if ! "$PY" topology.py --test 4 --duration "$DURATION" --requests "$REQUESTS" \
        --bench-out "$OUT/$label.json" "$@"; then
    echo "!!! $label failed"
  fi
}

for cfg in "${CONFIGS[@]}"; do
  case $cfg in
    ebpf-xdp)    run "$cfg" --mode ebpf --hook xdp ;;
    ebpf-tc)     run "$cfg" --mode ebpf --hook tc ;;
    ebpf-tc-fib) run "$cfg" --mode ebpf --hook tc --fib-forward ;;
    kernel)      run "$cfg" --mode kernel ;;
    ovs)
      if ovs-vsctl show >/dev/null 2>&1; then run "$cfg" --mode ovs
      else echo "skipping ovs: Open vSwitch not installed or ovsdb-server not running"; fi ;;
    *) echo "unknown configuration: $cfg"; exit 1 ;;
  esac
done

"$PY" - "$OUT" "${CONFIGS[@]}" <<'EOF'
import json, os, sys
out, cfgs = sys.argv[1], sys.argv[2:]
cols = [("tcp_gbps", "TCP Gbps"), ("udp64_rx_pps", "UDP64 rx pps"),
        ("rtt_avg_ms", "RTT avg ms"), ("rtt_mdev_ms", "RTT mdev"),
        ("lb_rps", "LB conn/s"), ("lb_avg_ms", "LB ms/req"), ("fw_drop_pps", "FW drop pps")]
rows = []
for c in cfgs:
    p = os.path.join(out, f"{c}.json")
    if os.path.exists(p):
        rows.append((c, json.load(open(p))))
if not rows:
    sys.exit("no results")
w = [max(12, *(len(c) for c, _ in rows))] + [max(len(h), 10) for _, h in cols]
fmt = lambda cells: "  ".join(str(x).ljust(n) for x, n in zip(cells, w))
print("\n" + fmt(["config"] + [h for _, h in cols]))
print(fmt(["-" * n for n in w]))
for c, r in rows:
    print(fmt([c] + [r.get(k) if r.get(k) is not None else "-" for k, _ in cols]))
summary = {c: r for c, r in rows}
json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=2)
print(f"\nwritten {out}/summary.json")
EOF
