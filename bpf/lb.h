/* SPDX-License-Identifier: GPL-2.0 */
/*
 * lb.h - L4 load balancer: service lookup, backend selection, LB conntrack.
 */
#ifndef SDN_LB_H
#define SDN_LB_H

#include "maps.h"
#include "util.h"
#include "parser.h"

/* ------------------------------------------------------------------ */
/* L4 load balancer                                                    */
/* ------------------------------------------------------------------ */
static __always_inline struct backend *backend_at(__u32 svc_id, __u32 idx)
{
	__u32 slot = svc_id * MAX_BACKENDS_PER_SVC + idx;

	return bpf_map_lookup_elem(&lb_backends, &slot);
}

static __always_inline int lb_select(struct svc_info *svc, __u32 hash, __u32 *out_idx,
				     struct backend **out)
{
	__u32 cnt = svc->count;

	if (cnt == 0 || cnt > MAX_BACKENDS_PER_SVC || svc->id >= MAX_SERVICES)
		return -1;

	__u32 start = hash % cnt;

	for (__u32 i = 0; i < MAX_BACKENDS_PER_SVC; i++) {
		if (i >= cnt)
			break;
		__u32 idx = start + i;

		if (idx >= cnt)
			idx -= cnt;
		struct backend *be = backend_at(svc->id, idx);

		if (be && be->active && be->ip) {
			*out_idx = idx;
			*out = be;
			return 0;
		}
	}
	return -1;
}

/* Returns 1 if the packet must be dropped (service has no healthy backend). */
static __always_inline int load_balance(struct pkt *p, struct verdict *v, __u64 now)
{
	if (p->key.l3 != L3_IPV4 || !p->has_ports)
		return 0;

	/* ---- forward direction: client -> VIP:port ---- */
	struct svc_key sk = {
		.vip = p->key.daddr,
		.port = p->key.dport,
		.proto = p->key.proto,
	};
	struct svc_info *svc = bpf_map_lookup_elem(&lb_services, &sk);

	if (svc) {
		struct lb_ct *ct = bpf_map_lookup_elem(&lb_conntrack, &p->key);
		__u32 be_ip = 0;
		__u16 be_port = 0;

		if (ct) {
			struct backend *be = backend_at(ct->svc_id, ct->be_idx);

			/* Sticky unless the backend was drained or replaced. */
			if (be && be->active && be->ip == ct->backend_ip) {
				be_ip = ct->backend_ip;
				be_port = ct->backend_port;
				ct->last_seen_ns = now;
				ct->packets += 1;
				ct->bytes += p->len;
				ct->flags |= tcp_ct_flags(p);
			}
		}

		if (!be_ip) {
			struct backend *be = 0;
			__u32 idx = 0;

			if (lb_select(svc, flow_hash(&p->key), &idx, &be) < 0 || !be) {
				stat_add(STAT_DROP_NO_BACKEND, 1);
				return 1;
			}
			be_ip = be->ip;
			be_port = be->port ? be->port : p->key.dport;

			struct lb_ct nct = {
				.backend_ip = be_ip,
				.backend_port = be_port,
				.svc_id = (__u8)svc->id,
				.be_idx = (__u8)idx,
				.created_ns = now,
				.last_seen_ns = now,
				.packets = 1,
				.bytes = p->len,
				.flags = tcp_ct_flags(p),
			};
			bpf_map_update_elem(&lb_conntrack, &p->key, &nct, BPF_ANY);

			struct flow_key rk;
			struct lb_rev rev = {
				.vip = p->key.daddr,
				.vport = p->key.dport,
				.last_seen_ns = now,
			};

			__builtin_memset(&rk, 0, sizeof(rk));
			rk.saddr = be_ip;
			rk.daddr = p->key.saddr;
			rk.sport = be_port;
			rk.dport = p->key.sport;
			rk.proto = p->key.proto;
			rk.l3 = L3_IPV4;
			bpf_map_update_elem(&lb_reverse, &rk, &rev, BPF_ANY);
			stat_add(STAT_LB_NEW_CONN, 1);
		}

		v->nat = NAT_DNAT;
		v->old_addr = p->key.daddr;
		v->new_addr = be_ip;
		v->old_port = p->key.dport;
		v->new_port = be_port;
		stat_add(STAT_LB_DNAT, 1);
		return 0;
	}

	/* ---- reverse direction: backend -> client ---- */
	struct lb_rev *rev = bpf_map_lookup_elem(&lb_reverse, &p->key);

	if (rev) {
		rev->last_seen_ns = now;
		rev->flags |= tcp_ct_flags(p);
		v->nat = NAT_SNAT;
		v->old_addr = p->key.saddr;
		v->new_addr = rev->vip;
		v->old_port = p->key.sport;
		v->new_port = rev->vport;
		stat_add(STAT_LB_SNAT, 1);
	}
	return 0;
}

#endif /* SDN_LB_H */
