"""Background rule sets: rules that populate all ten rule patterns but never
match testbed traffic (addresses from 172.16.0.0/12, locally administered
MACs). Used by the microbenchmark and by the populated-rule benchmark runs,
where every gateway installs the same rules in its own form:

    eBPF      firewall_map entries (one hash table per pattern)
    nftables  one set per pattern, matched with concatenations
    OVS       OpenFlow drop flows in the ACL table
"""
from __future__ import annotations

import random

from sdn.dataplane import FirewallRule

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}


def _ip(rng: random.Random) -> str:
    return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _mac(rng: random.Random) -> str:
    return "02:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))


def background_rules(n: int, seed: int = 1, action: str = "drop") -> list[FirewallRule]:
    """n non-matching rules, cycling through all ten patterns (m1..m10)."""
    rng = random.Random(seed)
    port = lambda: rng.randint(1, 65535)  # noqa: E731
    shapes = [
        lambda: FirewallRule(src_mac=_mac(rng), dst_mac=_mac(rng)),                 # m1
        lambda: FirewallRule(src_mac=_mac(rng)),                                    # m2
        lambda: FirewallRule(src=_ip(rng), dst=_ip(rng), proto="tcp",
                             sport=port(), dport=port()),                           # m3
        lambda: FirewallRule(src=_ip(rng), dst=_ip(rng), proto="tcp", dport=port()),  # m4
        lambda: FirewallRule(src=_ip(rng), dst=_ip(rng), proto="udp", sport=port()),  # m5
        lambda: FirewallRule(src=_ip(rng), dst=_ip(rng), proto="icmp"),             # m6
        lambda: FirewallRule(src=_ip(rng), dst=_ip(rng)),                           # m7
        lambda: FirewallRule(dst=_ip(rng), proto="tcp", dport=port()),              # m8
        lambda: FirewallRule(src=_ip(rng)),                                         # m9
        lambda: FirewallRule(dst=_ip(rng)),                                         # m10
    ]
    rules = [shapes[i % len(shapes)]() for i in range(n)]
    for r in rules:
        r.action = action
    return rules


def pattern_of(r: FirewallRule) -> int:
    """Pattern number 1..10 of a rule produced by background_rules()."""
    if r.src_mac:
        return 1 if r.dst_mac else 2
    shape = (bool(r.src), bool(r.dst), bool(r.sport), bool(r.dport), r.proto != "any")
    return {(1, 1, 1, 1, 1): 3, (1, 1, 0, 1, 1): 4, (1, 1, 1, 0, 1): 5, (1, 1, 0, 0, 1): 6,
            (1, 1, 0, 0, 0): 7, (0, 1, 0, 1, 1): 8, (1, 0, 0, 0, 0): 9,
            (0, 1, 0, 0, 0): 10}[tuple(int(x) for x in shape)]


# --- nftables: one set per pattern ------------------------------------------
NFT_SETS = {  # pattern: (set type, match expression)
    1: ("ether_addr . ether_addr", "ether saddr . ether daddr"),
    2: ("ether_addr", "ether saddr"),
    3: ("ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service",
        "ip saddr . ip daddr . meta l4proto . th sport . th dport"),
    4: ("ipv4_addr . ipv4_addr . inet_proto . inet_service",
        "ip saddr . ip daddr . meta l4proto . th dport"),
    5: ("ipv4_addr . ipv4_addr . inet_proto . inet_service",
        "ip saddr . ip daddr . meta l4proto . th sport"),
    6: ("ipv4_addr . ipv4_addr . inet_proto", "ip saddr . ip daddr . meta l4proto"),
    7: ("ipv4_addr . ipv4_addr", "ip saddr . ip daddr"),
    8: ("ipv4_addr . inet_proto . inet_service", "ip daddr . meta l4proto . th dport"),
    9: ("ipv4_addr", "ip saddr"),
    10: ("ipv4_addr", "ip daddr"),
}


def nft_element(r: FirewallRule) -> str:
    p = pattern_of(r)
    proto = PROTO_NUM.get(str(r.proto), 0)
    return {1: f"{r.src_mac} . {r.dst_mac}", 2: f"{r.src_mac}",
            3: f"{r.src} . {r.dst} . {proto} . {r.sport} . {r.dport}",
            4: f"{r.src} . {r.dst} . {proto} . {r.dport}",
            5: f"{r.src} . {r.dst} . {proto} . {r.sport}",
            6: f"{r.src} . {r.dst} . {proto}", 7: f"{r.src} . {r.dst}",
            8: f"{r.dst} . {proto} . {r.dport}", 9: f"{r.src}", 10: f"{r.dst}"}[p]


def nft_ruleset(table: str, chain: str, rules: list[FirewallRule]) -> str:
    """nft script: one set per used pattern and one drop rule per set, inserted
    at the top of `chain` (ahead of the established-state accept)."""
    by_pattern: dict[int, list[str]] = {}
    for r in rules:
        by_pattern.setdefault(pattern_of(r), []).append(nft_element(r))
    lines = []
    for p in sorted(by_pattern, reverse=True):  # inserted in reverse: m1 ends up first
        typ, expr = NFT_SETS[p]
        lines.append(f"add set inet {table} bg{p} {{ type {typ}; }}")
        lines.append(f"add element inet {table} bg{p} {{ {', '.join(by_pattern[p])} }}")
        lines.append(f"insert rule inet {table} {chain} {expr} @bg{p} drop")
    return "\n".join(lines) + "\n"


# --- OpenFlow ----------------------------------------------------------------
def of_match(r: FirewallRule) -> str:
    p = pattern_of(r)
    proto = str(r.proto)
    l4 = proto if proto in ("tcp", "udp") else "ip"
    return {1: f"dl_src={r.src_mac},dl_dst={r.dst_mac}", 2: f"dl_src={r.src_mac}",
            3: f"{l4},nw_src={r.src},nw_dst={r.dst},tp_src={r.sport},tp_dst={r.dport}",
            4: f"{l4},nw_src={r.src},nw_dst={r.dst},tp_dst={r.dport}",
            5: f"{l4},nw_src={r.src},nw_dst={r.dst},tp_src={r.sport}",
            6: f"ip,nw_src={r.src},nw_dst={r.dst},nw_proto={PROTO_NUM.get(proto, 0)}",
            7: f"ip,nw_src={r.src},nw_dst={r.dst}",
            8: f"{l4},nw_dst={r.dst},tp_dst={r.dport}",
            9: f"ip,nw_src={r.src}", 10: f"ip,nw_dst={r.dst}"}[p]
