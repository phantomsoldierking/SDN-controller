#!/usr/bin/env python3
"""Generate the appendix figures (pgfplots) from a results directory.

    python3 paper/make_figures.py results/rev3 > paper/appendix_figs.tex

Every plot shows means with 95% confidence intervals (Student t). Value axes
are zoomed (they do not start at zero) so that the intervals are visible;
each caption says so.
"""
from __future__ import annotations

import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from testbed.aggregate import by_round, load, paired, summarize  # noqa: E402

NAMES = {"ebpf-xdp": "XDP", "ebpf-tc": "TC", "ebpf-tc-fib": "TC+FIB", "kernel": "Kernel",
         "nft-ipvs": "nft+IPVS", "nft-ft": "nft-FT", "ovs": "OVS", "ovs-ct": "OVS-ct"}
BASE = list(NAMES)
LB = [c for c in BASE if c != "kernel"]
RULES = ["ebpf-tc", "ebpf-tc-fib", "nft-ipvs", "nft-ft", "ovs-ct"]
COLORS = ["blue!55", "orange!65", "teal!55", "red!45", "violet!50"]


def stat(out: str, cfg: str, key: str, scale: float = 1.0):
    vals = [r[key] * scale for r in load(out, cfg) if r.get(key) is not None]
    return summarize(vals) if len(vals) > 1 else None


def nice_range(lows: list[float], highs: list[float], pad: float = 0.12,
               zero_ok: bool = False) -> tuple[float, float]:
    lo, hi = min(lows), max(highs)
    span = hi - lo or abs(hi) or 1.0
    lo, hi = lo - pad * span, hi + pad * span
    if zero_ok:
        lo = min(lo, 0.0)
    step = 10 ** math.floor(math.log10(span)) / 2
    return math.floor(lo / step) * step, math.ceil(hi / step) * step


def axis(ylabel: str, coords: list[str], ymin: float, ymax: float, extra: str = "") -> str:
    xs = ",".join(coords)
    return (f"\\begin{{axis}}[ybar, width=\\linewidth, height=4.3cm, bar width=7pt,\n"
            f"  scaled y ticks=false, yticklabel style={{/pgf/number format/fixed}},\n"
            f"  symbolic x coords={{{xs}}}, xtick=data, ymin={ymin:g}, ymax={ymax:g},\n"
            f"  ylabel={{{ylabel}}}, enlarge x limits=0.08, axis lines*=left,\n"
            f"  ymajorgrids, grid style={{gray!25}}, x tick label style={{rotate=30, anchor=east, font=\\tiny}},\n"
            f"  y tick label style={{font=\\tiny}}, label style={{font=\\scriptsize}},\n"
            f"  error bars/y dir=both, error bars/y explicit{extra}]\n")


def bars(points: list[tuple[str, float, float]], color: str) -> str:
    coords = " ".join(f"({x},{m:.4g}) +- (0,{h:.3g})" for x, m, h in points)
    return (f"\\addplot[fill={color}, draw=black!60, error bars/.cd, y dir=both, y explicit,"
            f" error mark options={{rotate=90, mark size=1.5pt}}] coordinates {{{coords}}};\n")


def panel(body: str, caption: str) -> str:
    return ("\\begin{minipage}[t]{0.48\\textwidth}\\centering\n\\begin{tikzpicture}\n"
            f"{body}\\end{{axis}}\n\\end{{tikzpicture}}\n"
            f"\\captionof{{figure}}{{{caption}}}\n\\end{{minipage}}")


def named(fig, label: str, name: str, quantity: str, configs: str, source: str):
    """Attach a label, a bold short name and index metadata to a panel."""
    if not fig:
        return None
    cap = fig.index("\\captionof{figure}{") + len("\\captionof{figure}{")
    end = fig.rindex("}\n\\end{minipage}")
    body = fig[:cap] + f"\\textbf{{{name}.}} " + fig[cap:end] + f"}}\\label{{{label}}}" + fig[end + 1:]
    return {"tex": body, "label": label, "name": name, "quantity": quantity,
            "configs": configs, "source": source}


def config_bars(out, configs, key, scale, ylabel, caption, color="blue!55", log=False):
    pts = []
    for c in configs:
        st = stat(out, c, key, scale)
        if st:
            pts.append((NAMES[c], st["mean"], st["ci95"]))
    if not pts:
        return None
    if log:
        lo = min(m - h for _, m, h in pts)
        hi = max(m + h for _, m, h in pts)
        ymin, ymax = 10 ** math.floor(math.log10(max(lo, 1e-3))), 10 ** math.ceil(math.log10(hi))
        extra = ", ymode=log, log origin=infty"
        caption += " Logarithmic axis."
    else:
        ymin, ymax = nice_range([m - h for _, m, h in pts], [m + h for _, m, h in pts])
        extra = ""
        caption += f" Axis starts at {ymin:g}."
    body = axis(ylabel, [p[0] for p in pts], ymin, ymax, extra) + bars(pts, color)
    return panel(body, caption)


def rules_bars(out, key, scale, ylabel, caption):
    groups = []
    for suffix, color, label in (("", "blue!55", "empty tables"),
                                 ("+rules", "orange!65", "all ten patterns populated")):
        pts = []
        for c in RULES:
            st = stat(out, c + suffix, key, scale)
            if st:
                pts.append((NAMES[c], st["mean"], st["ci95"]))
        groups.append((pts, color, label))
    if not groups[1][0]:
        return None
    allp = [p for g in groups for p in g[0]]
    ymin, ymax = nice_range([m - h for _, m, h in allp], [m + h for _, m, h in allp])
    body = axis(ylabel, [NAMES[c] for c in RULES], ymin, ymax,
                ", bar width=6pt, legend style={font=\\tiny, at={(0.5,1.02)}, anchor=south, "
                "legend columns=2, draw=none}")
    for pts, color, _ in groups:
        body += bars(pts, color)
    body += "\\legend{" + ", ".join(g[2] for g in groups) + "}\n"
    return panel(body, caption + f" Axis starts at {ymin:g}.")


def paired_bars(out, configs, ref, metrics, ylabel, caption):
    series = []
    for key, color, label in metrics:
        pts = []
        for c in configs:
            if c == ref:
                continue
            a, b = by_round(out, c, key), by_round(out, ref, key)
            if len(set(a) & set(b)) > 1:
                p = paired(a, b)
                pts.append((NAMES[c], p["diff_pct"], p["ci95"]))
        series.append((pts, color, label))
    allp = [p for s in series for p in s[0]]
    if not allp:
        return None
    ymin, ymax = nice_range([m - h for _, m, h in allp], [m + h for _, m, h in allp],
                            zero_ok=True)
    ymax = max(ymax, 0)
    coords = [NAMES[c] for c in configs if c != ref and any(NAMES[c] == p[0] for p in allp)]
    body = axis(ylabel, coords, ymin, ymax,
                ", bar width=6pt, legend style={font=\\tiny, at={(0.5,1.02)}, anchor=south, "
                "legend columns=2, draw=none}, extra y ticks={0}, "
                "extra y tick style={grid style={black, thin}}")
    for pts, color, _ in series:
        body += bars(pts, color)
    body += "\\legend{" + ", ".join(s[2] for s in series) + "}\n"
    return panel(body, caption)


def micro_line(mb, section, xs, xlabels, ylabel, caption, logx=False):
    plots = ""
    lows, highs = [], []
    for hook, color, mark in (("xdp", "blue!70", "*"), ("tc", "teal!80!black", "square*")):
        data = mb["hooks"].get(hook, {}).get(section, {})
        pts = [(lab, data.get(str(x))) for x, lab in zip(xs, xlabels)]
        pts = [(lab, st) for lab, st in pts if st]
        if not pts:
            continue
        lows += [st["mean"] - st["ci95"] for _, st in pts]
        highs += [st["mean"] + st["ci95"] for _, st in pts]
        coords = " ".join(f"({lab},{st['mean']:.4g}) +- (0,{st['ci95']:.3g})" for lab, st in pts)
        plots += (f"\\addplot[{color}, mark={mark}, mark size=1.4pt, error bars/.cd, y dir=both,"
                  f" y explicit] coordinates {{{coords}}};\n")
    if not plots:
        return None
    ymin, ymax = nice_range(lows, highs)
    ymin = max(ymin, 0)
    body = (f"\\begin{{axis}}[width=\\linewidth, height=4.3cm, scaled y ticks=false, symbolic x coords={{{','.join(xlabels)}}},"
            f" xtick=data, ymin={ymin:g}, ymax={ymax:g}, ylabel={{{ylabel}}},\n"
            f"  axis lines*=left, ymajorgrids, grid style={{gray!25}}, tick label style={{font=\\tiny}},"
            f" label style={{font=\\scriptsize}},\n"
            f"  legend style={{font=\\tiny, at={{(0.02,0.98)}}, anchor=north west, draw=none}}]\n"
            + plots + "\\legend{XDP, TC}\n")
    return panel(body, caption)


def micro_paths(mb, caption):
    xdp = mb["hooks"].get("xdp", {})
    variants = [("single program", "blue!55", xdp.get("paths", {}), xdp.get("pass_repeated")),
                ("chain (re-parse)", "orange!65", xdp.get("chain", {}), None),
                ("chain (shared metadata)", "teal!55", xdp.get("chainm", {}), None)]
    cats = [("pass", "Pass"), ("dnat_established", "DNAT est."),
            ("snat_established", "SNAT est.")]
    series, allp = [], []
    for label, color, data, _ in variants:
        pts = [(name, data[key]["mean"], data[key]["ci95"]) for key, name in cats if key in data]
        if pts:
            series.append((pts, color, label))
            allp += pts
    if len(series) < 2:
        return None
    ymin, ymax = nice_range([m - h for _, m, h in allp], [m + h for _, m, h in allp])
    body = axis("ns per packet (single-shot)", [c[1] for c in cats], ymin, ymax,
                ", bar width=8pt, legend style={font=\\tiny, at={(0.5,1.02)}, anchor=south, "
                "legend columns=3, draw=none}")
    for pts, color, _ in series:
        body += bars(pts, color)
    body += "\\legend{" + ", ".join(s[2] for s in series) + "}\n"
    return panel(body, caption + f" Axis starts at {ymin:g}.")


def micro_new_conn(mb, caption):
    pts = []
    for hook in ("xdp", "tc"):
        p = mb["hooks"].get(hook, {}).get("paths", {})
        for key, name in (("dnat_established", "est."), ("dnat_new", "new TCP"),
                          ("dnat_new_udp", "new UDP")):
            if key in p:
                pts.append((f"{hook.upper()} {name}", p[key]["mean"], p[key]["ci95"]))
    if not pts:
        return None
    lo, hi = min(m - h for _, m, h in pts), max(m + h for _, m, h in pts)
    body = axis("ns per packet (single-shot)", [p[0] for p in pts],
                10 ** math.floor(math.log10(lo)), 10 ** math.ceil(math.log10(hi)),
                ", ymode=log, log origin=infty") + bars(pts, "violet!50")
    return panel(body, caption + " Logarithmic axis.")


def micro_hooks(mb, caption):
    cats = [("pass", "Pass"), ("fw_drop", "FW drop"), ("dnat_established", "DNAT est."),
            ("snat_established", "SNAT est.")]
    series, allp = [], []
    for hook, color in (("xdp", "blue!55"), ("tc", "teal!55")):
        p = mb["hooks"].get(hook, {}).get("paths", {})
        pts = [(name, p[k]["mean"], p[k]["ci95"]) for k, name in cats if k in p]
        if pts:
            series.append((pts, color, hook.upper()))
            allp += pts
    if not allp:
        return None
    ymin, ymax = nice_range([m - h for _, m, h in allp], [m + h for _, m, h in allp])
    ymin = max(ymin, 0)
    body = axis("ns per packet (single-shot)", [c[1] for c in cats], ymin, ymax,
                ", bar width=8pt, legend style={font=\\tiny, at={(0.5,1.02)}, anchor=south, "
                "legend columns=2, draw=none}")
    for pts, color, _ in series:
        body += bars(pts, color)
    body += "\\legend{" + ", ".join(s[2] for s in series) + "}\n"
    return panel(body, caption + f" Axis starts at {ymin:g}.")


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "results/rev3"
    with open(os.path.join(out, "microbench.json")) as f:
        mb = json.load(f)
    n = len(load(out, "ebpf-tc"))
    ci = f"mean $\\pm$ 95\\% CI over {n} interleaved rounds."
    src = lambda c: f"\\texttt{{{os.path.basename(os.path.normpath(out))}/{c}}}"  # noqa: E731
    run, mbs = src("<cfg>.json"), src("microbench.json")
    cold_x = ["one_flow", "1000", "15000", "60000", "many_flows"]
    cold_l = ["1", "1k", "15k", "60k", f"{mb['hooks']['xdp'].get('flows', 60000) // 1000}k"]
    figs = [
        named(config_bars(out, BASE, "tcp_gbps", 1, "TCP (Gbit/s)",
                          f"Routed-path TCP throughput, {ci}"),
              "fig:app-tcp", "Routed TCP throughput", "Gbit/s", "all", run),
        named(config_bars(out, BASE, "udp64_rx_pps", 1e-3, "64-B rate (kpps)",
                          f"Routed-path 64-byte packet rate, {ci}", "teal!55"),
              "fig:app-pps", "Routed packet rate", "kpps", "all", run),
        named(config_bars(out, LB, "tcp_vip_gbps", 1, "VIP TCP (Gbit/s)",
                          f"TCP throughput through the load balancer (VIP path), {ci}",
                          "orange!65"),
              "fig:app-viptcp", "VIP TCP throughput", "Gbit/s", "LB-capable", run),
        named(config_bars(out, LB, "udp64_vip_rx_pps", 1e-3, "VIP 64-B rate (kpps)",
                          f"64-byte packet rate through the load balancer, {ci}", "violet!50"),
              "fig:app-vippps", "VIP packet rate", "kpps", "LB-capable", run),
        named(rules_bars(out, "tcp_gbps", 1, "TCP (Gbit/s)",
                         f"Routed TCP throughput with empty rule tables and with 1000 rules "
                         f"populating all ten patterns, {ci}"),
              "fig:app-rulestcp", "Populated rules, TCP", "Gbit/s", "five stateful", run),
        named(rules_bars(out, "udp64_rx_pps", 1e-3, "64-B rate (kpps)",
                         f"Routed 64-byte packet rate with empty and populated rule tables, {ci}"),
              "fig:app-rulespps", "Populated rules, packet rate", "kpps", "five stateful", run),
        named(paired_bars(out, BASE, "kernel",
                          [("tcp_gbps", "blue!55", "TCP"), ("udp64_rx_pps", "teal!55", "64-B rate")],
                          "difference to Kernel (\\%)",
                          "Cost relative to plain kernel routing: per-round paired relative "
                          "difference, mean $\\pm$ 95\\% CI (paired $t$)."),
              "fig:app-vskernel", "Paired difference to Kernel", "\\%", "all", run),
        named(paired_bars(out, LB, "ovs-ct",
                          [("tcp_vip_gbps", "orange!65", "VIP TCP"),
                           ("udp64_vip_rx_pps", "violet!50", "VIP 64-B rate")],
                          "difference to OVS-ct (\\%)",
                          "VIP-path performance relative to OVS-ct: per-round paired relative "
                          "difference, mean $\\pm$ 95\\% CI (paired $t$)."),
              "fig:app-vsovs", "Paired difference to OVS-ct", "\\%", "LB-capable", run),
        named(config_bars(out, BASE, "rtt_avg_ms", 1e3, "avg RTT ($\\mu$s)",
                          f"Average round-trip time on the routed path, {ci}", "red!45"),
              "fig:app-rtt", "Average RTT", "$\\mu$s", "all", run),
        named(config_bars(out, BASE, "rtt_max_ms", 1e3, "max RTT ($\\mu$s)",
                          f"Maximum round-trip time on the routed path, {ci}", "red!45", log=True),
              "fig:app-rttmax", "Maximum RTT", "$\\mu$s", "all", run),
        named(config_bars(out, LB, "lb_rps", 1, "conn./s",
                          f"New-connection rate through the VIP (HTTP), {ci}", "orange!65"),
              "fig:app-lbrps", "VIP connection rate", "conn./s", "LB-capable", run),
        named(micro_line(mb, "conntrack", ["0", "1000", "10000", "60000"],
                         ["0", "1k", "10k", "60k"], "ns per packet",
                         "In-kernel cost of an admitted packet versus tracked connections per "
                         "table (empty rule tables), zoomed view of Fig.~\\ref{fig:scale}; "
                         "mean $\\pm$ 95\\% CI of 15 repeat-loop samples."),
              "fig:app-conntrack", "Connection-table scaling", "ns", "XDP, TC", mbs),
        named(micro_hooks(mb, "In-kernel single-shot cost per processing path at the XDP and "
                              "TC hooks with one installed rule; mean $\\pm$ 95\\% CI of 10 "
                              "batch means."),
              "fig:app-paths", "Per-path cost by hook", "ns", "XDP, TC", mbs),
        named(micro_line(mb, "cold", cold_x, cold_l, "ns per packet",
                         "In-kernel single-shot cost versus the number of tracked flows visited "
                         "in random order (cache-cold, empty rule tables; 15k flows fit the "
                         "16\\,384-entry telemetry table, 60k do not); mean $\\pm$ 95\\% CI "
                         "of 10 batch means."),
              "fig:app-cold", "Cache-cold cost", "ns", "XDP, TC", mbs),
        named(micro_paths(mb, "Tail-call ablation (XDP, single-shot): single program versus "
                              "the same stages chained with tail calls, re-parsing in every "
                              "stage or sharing the parse result through a per-CPU map; "
                              "mean $\\pm$ 95\\% CI of 10 batch means."),
              "fig:app-chain", "Tail-call ablation", "ns", "XDP", mbs),
        named(micro_new_conn(mb, "In-kernel single-shot cost of DNAT for an established "
                                 "connection, a new TCP connection (SYN: no reverse-entry probes) "
                                 "and a new UDP flow (probes the $n=4$ reverse entries of the "
                                 "pool); mean $\\pm$ 95\\% CI of 10 batch means."),
              "fig:app-newconn", "New-connection cost", "ns", "XDP, TC", mbs),
    ]
    figs = [f for f in figs if f]
    # keep the appendix at 12-14 panels; drop the panels most redundant with
    # the main text first (maximum RTT is in Table IV, the connection sweep in Fig. 3)
    for redundant in ("fig:app-rttmax", "fig:app-conntrack"):
        if len(figs) > 14:
            figs = [f for f in figs if f["label"] != redundant]
    figs = figs[:14]

    print("% generated by paper/make_figures.py from", out, "- do not edit")
    print("\\appendix")
    print("\\section{Supplementary Measurement Figures}\n\\label{app:figs}")
    print(f"Figs.~\\ref{{{figs[0]['label']}}}--\\ref{{{figs[-1]['label']}}} plot the "
          "measurements behind Tables~\\ref{tab:perf} and \\ref{tab:paths} with their 95\\% "
          "confidence intervals (Student $t$). Value axes are zoomed so that the intervals are "
          "visible; each caption gives the axis origin, and differences between bars should be "
          "judged against the intervals, not against the axis origin. "
          f"Table~\\ref{{tab:figindex}} lists every figure with its quantity, the "
          f"configurations it covers and its data file in the results directory "
          f"(\\texttt{{{os.path.normpath(out)}}}).\n")
    print("\\begin{table}[!h]\n\\caption{Index of the supplementary figures}\n"
          "\\label{tab:figindex}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{3pt}\n"
          "\\begin{tabular}{@{}rlll@{}}\n\\toprule\nFig. & Name & Unit & Configurations \\\\\n"
          "\\midrule")
    for f in figs:
        print(f"\\ref{{{f['label']}}} & {f['name']} & {f['quantity']} & {f['configs']} \\\\")
    print("\\bottomrule\n\\end{tabular}\n\\\\[2pt]\n"
          f"\\parbox{{\\columnwidth}}{{\\footnotesize Macro-benchmark data: {run} "
          f"({n} interleaved rounds). In-kernel data: {mbs}.}}\n\\end{{table}}\n")
    for i in range(0, len(figs), 8):
        page = [f["tex"] for f in figs[i:i + 8]]
        print("\\begin{figure*}[!p]\\centering")
        rows = ["\n\\hfill\n".join(page[j:j + 2]) for j in range(0, len(page), 2)]
        print("\n\\par\\vspace{2mm}\n".join(rows))
        print("\\end{figure*}")
    print("\\clearpage  % flush the figure pages before the references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
