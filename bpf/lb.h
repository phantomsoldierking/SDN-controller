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

/* Key of the reply a backend sends for client flow `fwd` (Section III-F). */
static __always_inline void reply_key(const struct flow_key *fwd, __u32 be_ip, __u16 be_port,
				      struct flow_key *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->saddr = be_ip;
	out->daddr = fwd->saddr;
	out->sport = be_port;
	out->dport = fwd->sport;
	out->proto = fwd->proto;
	out->l3 = L3_IPV4;
}

/* Effective backend port: 0 in the pool means "same as the service port". */
static __always_inline __u16 backend_port(const struct backend *be, __u16 svc_port)
{
	return be->port ? be->port : svc_port;
}

/* Refresh (or, if the LRU evicted it, re-create) the reverse-NAT entry. */
static __always_inline void rev_refresh(const struct flow_key *fwd, const struct lb_ct *ct,
					__u64 now, __u32 flags)
{
	struct flow_key rk;
	struct lb_rev *rev;

	reply_key(fwd, ct->backend_ip, ct->backend_port, &rk);
	rev = bpf_map_lookup_elem(&lb_reverse, &rk);
	if (rev) {
		rev->last_seen_ns = now;
		rev->flags |= flags;
		return;
	}
	struct lb_rev nrev = {
		.vip = fwd->daddr,
		.vport = fwd->dport,
		.last_seen_ns = now,
		.flags = flags,
	};
	bpf_map_update_elem(&lb_reverse, &rk, &nrev, BPF_ANY);
}

/*
 * Forward direction (client -> VIP). Existing connections stay on their
 * backend even after it is drained (graceful draining); they are only
 * re-placed if the backend was removed or replaced, in which case the stale
 * reverse-NAT entry is deleted first. Returns 1 if the packet must be dropped.
 */
static __always_inline int lb_forward(struct pkt *p, struct svc_info *svc, struct verdict *v,
				      __u64 now)
{
	struct lb_ct *ct = bpf_map_lookup_elem(&lb_conntrack, &p->key);
	__u32 flags = tcp_ct_flags(p);

	if (ct) {
		struct backend *be = backend_at(ct->svc_id, ct->be_idx);

		if (be && be->ip == ct->backend_ip &&
		    backend_port(be, p->key.dport) == ct->backend_port) {
			ct->last_seen_ns = now;
			ct->packets += 1;
			ct->bytes += p->len;
			ct->flags |= flags;
			rev_refresh(&p->key, ct, now, flags);
			goto dnat;
		}
		/* backend removed or replaced: drop its reverse entry, re-place */
		struct flow_key old;

		reply_key(&p->key, ct->backend_ip, ct->backend_port, &old);
		bpf_map_delete_elem(&lb_reverse, &old);
	}

	struct backend *be = 0;
	__u32 idx = 0;

	if (lb_select(svc, flow_hash(&p->key), &idx, &be) < 0 || !be) {
		stat_add(STAT_DROP_NO_BACKEND, 1);
		return 1;
	}
	struct lb_ct nct = {
		.backend_ip = be->ip,
		.backend_port = backend_port(be, p->key.dport),
		.svc_id = (__u8)svc->id,
		.be_idx = (__u8)idx,
		.created_ns = now,
		.last_seen_ns = now,
		.packets = 1,
		.bytes = p->len,
		.flags = flags,
	};
	bpf_map_update_elem(&lb_conntrack, &p->key, &nct, BPF_ANY);
	rev_refresh(&p->key, &nct, now, flags);
	stat_add(STAT_LB_NEW_CONN, 1);
	ct = &nct;

dnat:
	v->nat = NAT_DNAT;
	v->old_addr = p->key.daddr;
	v->new_addr = ct->backend_ip;
	v->old_port = p->key.dport;
	v->new_port = ct->backend_port;
	stat_add(STAT_LB_DNAT, 1);
	return 0;
}

/*
 * Reverse direction (backend -> client), `rev` = lb_reverse[p->key]. The
 * reply also refreshes the forward entry, so a server-to-client stream keeps
 * the connection alive and a server FIN/RST shortens its timeout.
 */
static __always_inline void lb_reverse_nat(struct pkt *p, struct lb_rev *rev, struct verdict *v,
					   __u64 now)
{
	__u32 flags = tcp_ct_flags(p);
	struct flow_key fwd;
	struct lb_ct *ct;

	rev->last_seen_ns = now;
	rev->flags |= flags;

	__builtin_memset(&fwd, 0, sizeof(fwd));
	fwd.saddr = p->key.daddr;
	fwd.daddr = rev->vip;
	fwd.sport = p->key.dport;
	fwd.dport = rev->vport;
	fwd.proto = p->key.proto;
	fwd.l3 = L3_IPV4;
	ct = bpf_map_lookup_elem(&lb_conntrack, &fwd);
	if (ct) {
		ct->last_seen_ns = now;
		ct->flags |= flags;
	}

	v->nat = NAT_SNAT;
	v->old_addr = p->key.saddr;
	v->new_addr = rev->vip;
	v->old_port = p->key.sport;
	v->new_port = rev->vport;
	stat_add(STAT_LB_SNAT, 1);
}

/* Returns 1 if the packet must be dropped (service has no backend). */
static __always_inline int load_balance(struct pkt *p, struct lb_rev *rev, struct verdict *v,
					__u64 now)
{
	if (p->key.l3 != L3_IPV4 || !p->has_ports)
		return 0;
	if (rev) {
		lb_reverse_nat(p, rev, v, now);
		return 0;
	}

	struct svc_key sk = {
		.vip = p->key.daddr,
		.port = p->key.dport,
		.proto = p->key.proto,
	};
	struct svc_info *svc = bpf_map_lookup_elem(&lb_services, &sk);

	return svc ? lb_forward(p, svc, v, now) : 0;
}

#endif /* SDN_LB_H */
