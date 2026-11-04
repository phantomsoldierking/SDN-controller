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
static __always_inline struct fw_rule *fw_try(struct fw_key *k)
{
	return bpf_map_lookup_elem(&firewall_map, k);
}

/*
 * Lookup order, most specific first:
 *   MAC (src, dst) -> MAC (src, *)
 *   IP  (proto, src, dst, sport, dport)
 *   IP  (proto, src, dst, *,     dport)
 *   IP  (proto, src, dst, sport, *)
 *   IP  (proto, src, dst, *,     *)
 *   IP  (*,     src, dst, *,     *)
 *   IP  (*,     src, *,   *,     *)
 *   IP  (*,     *,   dst, *,     *)
 */
static __always_inline __u32 fw_lookup(struct pkt *p)
{
	struct fw_key k;
	struct fw_rule *r;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_MAC;
	__builtin_memcpy(k.smac, p->eth->h_source, ETH_ALEN);
	__builtin_memcpy(k.dmac, p->eth->h_dest, ETH_ALEN);
	r = fw_try(&k);
	if (r)
		goto hit;
	__builtin_memset(k.dmac, 0, ETH_ALEN);
	r = fw_try(&k);
	if (r)
		goto hit;

	if (p->key.l3 != L3_IPV4)
		return ACT_NONE;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_IP;
	k.proto = p->key.proto;
	k.saddr = p->key.saddr;
	k.daddr = p->key.daddr;
	k.sport = p->key.sport;
	k.dport = p->key.dport;
	if (p->has_ports) {
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = 0;
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = p->key.sport;
		k.dport = 0;
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = 0;
	}
	r = fw_try(&k);
	if (r)
		goto hit;
	k.proto = 0;
	r = fw_try(&k);
	if (r)
		goto hit;
	k.daddr = 0;
	r = fw_try(&k);
	if (r)
		goto hit;
	k.saddr = 0;
	k.daddr = p->key.daddr;
	r = fw_try(&k);
	if (r)
		goto hit;
	return ACT_NONE;

hit:
	__sync_fetch_and_add(&r->hits, 1);
	return r->action;
}

static __always_inline void ct_touch(struct flow_key *k, struct pkt *p, __u64 now)
{
	struct ct_entry *ct = bpf_map_lookup_elem(&fw_conntrack, k);

	if (ct) {
		ct->last_seen_ns = now;
		ct->packets += 1;
		ct->bytes += p->len;
		ct->flags |= tcp_ct_flags(p);
		return;
	}

	struct flow_key rk;
	struct ct_entry *rct;

	/* Reply direction of a tracked flow: mark the original as REPLY seen. */
	reverse_key(k, &rk);
	rct = bpf_map_lookup_elem(&fw_conntrack, &rk);
	if (rct) {
		rct->last_seen_ns = now;
		rct->packets += 1;
		rct->bytes += p->len;
		rct->flags |= CT_F_REPLY | tcp_ct_flags(p);
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

static __always_inline int ct_established(struct flow_key *k)
{
	struct flow_key rk;

	if (bpf_map_lookup_elem(&fw_conntrack, k))
		return 1;
	reverse_key(k, &rk);
	if (bpf_map_lookup_elem(&fw_conntrack, &rk))
		return 1;
	/* Return traffic of a load-balanced connection. */
	if (bpf_map_lookup_elem(&lb_reverse, k))
		return 1;
	return 0;
}

/* Returns 1 if the packet must be dropped. */
static __always_inline int firewall(struct pkt *p, struct dp_config *cfg, __u64 now)
{
	__u32 action = fw_lookup(p);
	int stateful = cfg && (cfg->flags & CFG_F_FW_STATEFUL);

	if (action == ACT_DROP)
		return 1;

	if (p->key.l3 != L3_IPV4)
		return 0; /* ARP is only subject to explicit MAC rules */

	if (action == ACT_NONE && cfg && cfg->default_action == ACT_DROP) {
		if (!stateful || !ct_established(&p->key))
			return 1;
		stat_add(STAT_CT_ESTABLISHED, 1);
	}

	if (stateful)
		ct_touch(&p->key, p, now);
	return 0;
}

#endif /* SDN_FIREWALL_H */
