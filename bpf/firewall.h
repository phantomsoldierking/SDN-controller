/* SPDX-License-Identifier: GPL-2.0 */
/*
 * firewall.h - stateful firewall (firewall_map rules + fw_conntrack).
 */
#ifndef SDN_FIREWALL_H
#define SDN_FIREWALL_H

#include "maps.h"
#include "util.h"
#include "parser.h"

/* ------------------------------------------------------------------ */
/* Stateful firewall                                                   */
/* ------------------------------------------------------------------ */
static __always_inline __u32 fw_hit(struct fw_key *k)
{
	struct fw_rule *r = bpf_map_lookup_elem(&firewall_map, k);

	if (!r)
		return ACT_NONE;
	__sync_fetch_and_add(&r->hits, 1); /* rules are shared by all CPUs */
	return r->action;
}

/* L2 rules (patterns 1-2); applied to every Ethernet frame, IP or not. */
static __always_inline __u32 fw_mac_lookup(const struct ethhdr *eth)
{
	struct fw_key k;
	__u32 a;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_MAC;
	k.mask = FW_M_MAC_PAIR;
	__builtin_memcpy(k.smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(k.dmac, eth->h_dest, ETH_ALEN);
	a = fw_hit(&k);
	if (a != ACT_NONE)
		return a;
	k.mask = FW_M_MAC_SRC;
	__builtin_memset(k.dmac, 0, ETH_ALEN);
	return fw_hit(&k);
}

static __always_inline __u32 fw_ip_try(struct fw_key *k, __u8 mask, const struct flow_key *f,
				       __u32 fields)
{
#define F_S (1U << 0)
#define F_D (1U << 1)
#define F_SP (1U << 2)
#define F_DP (1U << 3)
#define F_P (1U << 4)
	k->mask = mask;
	k->saddr = (fields & F_S) ? f->saddr : 0;
	k->daddr = (fields & F_D) ? f->daddr : 0;
	k->sport = (fields & F_SP) ? f->sport : 0;
	k->dport = (fields & F_DP) ? f->dport : 0;
	k->proto = (fields & F_P) ? f->proto : 0;
	return fw_hit(k);
}

/*
 * L3/L4 rules (patterns 3-10), most specific first; the first hit wins.
 * `f` is the client-visible flow key (see pipeline.h). Port patterns only
 * apply when the packet has ports (TCP/UDP, not a non-first fragment).
 */
static __always_inline __u32 fw_ip_lookup(const struct flow_key *f, int has_ports)
{
	struct fw_key k;
	__u32 a;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_IP;
	if (has_ports) {
		if ((a = fw_ip_try(&k, FW_M_IP_EXACT, f, F_S | F_D | F_SP | F_DP | F_P)))
			return a;
		if ((a = fw_ip_try(&k, FW_M_IP_DPORT, f, F_S | F_D | F_DP | F_P)))
			return a;
		if ((a = fw_ip_try(&k, FW_M_IP_SPORT, f, F_S | F_D | F_SP | F_P)))
			return a;
	}
	if ((a = fw_ip_try(&k, FW_M_IP_PROTO, f, F_S | F_D | F_P)))
		return a;
	if ((a = fw_ip_try(&k, FW_M_IP_PAIR, f, F_S | F_D)))
		return a;
	if (has_ports && (a = fw_ip_try(&k, FW_M_SVC_PORT, f, F_D | F_DP | F_P)))
		return a;
	if ((a = fw_ip_try(&k, FW_M_IP_SRC, f, F_S)))
		return a;
	return fw_ip_try(&k, FW_M_IP_DST, f, F_D);
#undef F_S
#undef F_D
#undef F_SP
#undef F_DP
#undef F_P
}

/* Record or refresh an admitted flow. A reply refreshes the original entry
 * (and marks it REPLY) instead of creating a second one. */
static __always_inline void ct_touch(const struct flow_key *k, struct pkt *p, __u64 now)
{
	struct ct_entry *ct = bpf_map_lookup_elem(&fw_conntrack, k);
	__u32 extra = 0;

	if (!ct) {
		struct flow_key rk;

		reverse_key(k, &rk);
		ct = bpf_map_lookup_elem(&fw_conntrack, &rk);
		extra = CT_F_REPLY;
	}
	if (ct) {
		ct->last_seen_ns = now;
		ct->packets += 1;
		ct->bytes += p->len;
		ct->flags |= extra | tcp_ct_flags(p);
		return;
	}

	struct ct_entry nct = {
		.created_ns = now,
		.last_seen_ns = now,
		.packets = 1,
		.bytes = p->len,
		.flags = tcp_ct_flags(p),
	};
	bpf_map_update_elem(&fw_conntrack, k, &nct, BPF_ANY);
}

/* E(f): the flow, or its reverse, is already tracked. */
static __always_inline int ct_established(const struct flow_key *k)
{
	struct flow_key rk;

	if (bpf_map_lookup_elem(&fw_conntrack, k))
		return 1;
	reverse_key(k, &rk);
	return bpf_map_lookup_elem(&fw_conntrack, &rk) != 0;
}

/*
 * Admission decision for an IPv4 packet with client-visible key `f`
 * (Eq. 4 of the paper). Returns 1 if the packet must be dropped.
 */
static __always_inline int firewall_ip(const struct flow_key *f, int has_ports,
				       struct dp_config *cfg)
{
	__u32 action = fw_ip_lookup(f, has_ports);
	int stateful = cfg && (cfg->flags & CFG_F_FW_STATEFUL);

	if (action == ACT_DROP)
		return 1;
	if (action == ACT_ALLOW || !cfg || cfg->default_action != ACT_DROP)
		return 0;
	/* no rule matched and the default is DROP: admit established flows only */
	if (stateful && ct_established(f)) {
		stat_add(STAT_CT_ESTABLISHED, 1);
		return 0;
	}
	return 1;
}

#endif /* SDN_FIREWALL_H */
