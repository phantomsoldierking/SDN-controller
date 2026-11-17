"""CPU placement for the benchmark on hybrid (performance/efficiency) CPUs.

    client  first hardware thread of the fastest physical core   (traffic tools)
    server  first hardware thread of the second fastest core      (traffic tools)
    aux     the sibling hardware threads of those two cores        (control-plane
            daemon, ovs-vswitchd), so helper processes also run on
            performance cores but never on the tools' own threads

Override with SDN_CLIENT_CPU / SDN_SERVER_CPU / SDN_AUX_CPUS (comma list).
"""
from __future__ import annotations

import glob
import os


def _read(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


def _cores() -> list[tuple[int, list[int]]]:
    """[(max_freq, [cpus of the core])] sorted fastest first."""
    cores: dict[tuple[int, int], tuple[int, list[int]]] = {}
    for d in glob.glob("/sys/devices/system/cpu/cpu[0-9]*"):
        cpu = int(d.rsplit("cpu", 1)[1])
        try:
            freq = int(_read(f"{d}/cpufreq/cpuinfo_max_freq"))
            core = (int(_read(f"{d}/topology/physical_package_id")),
                    int(_read(f"{d}/topology/core_id")))
        except (OSError, ValueError):
            continue
        f, cpus = cores.get(core, (freq, []))
        cores[core] = (f, sorted(cpus + [cpu]))
    return sorted(cores.values(), key=lambda fc: (-fc[0], fc[1][0]))


def pick() -> tuple[str, str, str]:
    env = (os.environ.get("SDN_CLIENT_CPU"), os.environ.get("SDN_SERVER_CPU"),
           os.environ.get("SDN_AUX_CPUS"))
    if all(env):
        return env  # type: ignore[return-value]
    cores = _cores()
    if len(cores) < 2:
        return "", "", ""
    (_, first), (_, second) = cores[0], cores[1]
    aux = [c for c in first[1:] + second[1:]]
    return str(first[0]), str(second[0]), ",".join(map(str, aux))


CLIENT_CPU, SERVER_CPU, AUX_CPUS = pick()


def pinned(cpus: str, cmd: str) -> str:
    return f"taskset -c {cpus} {cmd}" if cpus else cmd
