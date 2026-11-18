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

/* Effective backend port: 0 in the pool means "same as the service port". */
static __always_inline __u16 backend_port(const struct backend *be, __u16 svc_port)
{
	return be->port ? be->port : svc_port;
}

/* Key of the reply a backend sends for client flow `fwd` (r(f), Section III-F). */
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

/*
 * New connection: pick the backend lb_active[h mod n_act] (Eq. 6). The control
 * plane keeps lb_active as the list of active backend indices, so drained
 * backends get no new connections and the rest share them uniformly.
 */
static __always_inline int lb_select(struct svc_info *svc, __u32 hash, __u32 *out_idx,
				     struct backend **out)
{
	__u32 n_act = svc->active;

	if (n_act == 0 || n_act > MAX_BACKENDS_PER_SVC || svc->id >= MAX_SERVICES)
		return -1;
	__u32 start = hash % n_act;

	/* Normally the first probe succeeds; later probes only cover the moment
	 * while the control plane rewrites the list during a drain. */
	for (__u32 t = 0; t < MAX_BACKENDS_PER_SVC; t++) {
		if (t >= n_act)
			break;
		__u32 k = start + t;

		if (k >= n_act)
			k -= n_act;
		__u32 slot = svc->id * MAX_BACKENDS_PER_SVC + k;
		__u32 *idx = bpf_map_lookup_elem(&lb_active, &slot);

		if (!idx || *idx >= svc->count)
			continue;
		struct backend *be = backend_at(svc->id, *idx);

		if (be && be->ip && be->active) {
			*out_idx = *idx;
			*out = be;
			return 0;
		}
	}
	return -1;
}

/* Does slot `idx` of service `svc_id` still hold backend (ip, port)? */
static __always_inline int lb_slot_holds(__u32 svc_id, __u32 idx, __u32 ip, __u16 port,
					 __u16 vport)
{
	struct backend *be;

	if (svc_id >= MAX_SERVICES || idx >= MAX_BACKENDS_PER_SVC)
		return 0;
	be = backend_at(svc_id, idx);
	return be && be->ip == ip && backend_port(be, vport) == port;
}

/* A TCP segment that opens a connection (SYN without ACK). */
static __always_inline int tcp_opening(const struct pkt *p)
{
	return p->key.proto == IPPROTO_TCP_ && (p->tcp_flags & 0x12) == 0x02;
}

/*
 * Write the reverse-NAT entry of a connection. `fresh` (new connection)
 * overwrites any stale entry of an earlier connection with the same tuple;
 * otherwise an existing entry is refreshed in place (keeping its flags) and
 * a missing one - evicted by the LRU - is re-created.
 */
static __always_inline void rev_store(const struct flow_key *fwd, const struct lb_ct *ct,
				      __u64 now, __u32 flags, int fresh)
{
	struct flow_key rk;
	struct lb_rev *rev;

	reply_key(fwd, ct->backend_ip, ct->backend_port, &rk);
	if (!fresh) {
		rev = bpf_map_lookup_elem(&lb_reverse, &rk);
		if (rev) {
			rev->last_seen_ns = now;
			rev->flags |= flags;
			return;
		}
	}
	struct lb_rev nrev = {
		.vip = fwd->daddr,
		.vport = fwd->dport,
		.svc_id = ct->svc_id,
		.be_idx = ct->be_idx,
		.last_seen_ns = now,
		.flags = flags,
	};
	bpf_map_update_elem(&lb_reverse, &rk, &nrev, BPF_ANY);
}

/*
 * The forward entry of an established connection was lost (LRU eviction or a
 * reaper race) but its reverse entry survives: find the backend that holds it
 * and restore the binding, even if that backend is draining. Probes at most
 * n <= 16 reverse keys; skipped for TCP SYNs, which always open a new
 * connection (so a stale reverse entry cannot capture a reused port).
 */
static __always_inline int lb_recover_forward(struct pkt *p, struct svc_info *svc,
					      struct lb_ct *out)
{
	for (__u32 i = 0; i < MAX_BACKENDS_PER_SVC; i++) {
		if (i >= svc->count)
			break;
		struct backend *be = backend_at(svc->id, i);

		if (!be || !be->ip)
			continue;
		struct flow_key rk;
		__u16 port = backend_port(be, p->key.dport);

		reply_key(&p->key, be->ip, port, &rk);
		struct lb_rev *rev = bpf_map_lookup_elem(&lb_reverse, &rk);

		if (rev && rev->vip == p->key.daddr && rev->vport == p->key.dport &&
		    rev->be_idx == i) {
			out->backend_ip = be->ip;
			out->backend_port = port;
			out->svc_id = (__u8)svc->id;
			out->be_idx = (__u8)i;
			return 0;
		}
	}
	return -1;
}

/*
 * Forward direction (client -> VIP). Established connections stay on their
 * backend even after it is drained; they are re-placed only if the backend
 * was removed or replaced, in which case its stale reverse entry is deleted.
 * Existing entries are updated in place (creation time and flags are kept);
 * only new or recovered connections insert entries. Returns 1 to drop.
 */
static __always_inline int lb_forward(struct pkt *p, struct svc_info *svc, struct verdict *v,
				      __u64 now)
{
	struct lb_ct *ct = bpf_map_lookup_elem(&lb_conntrack, &p->key);
	__u32 flags = tcp_ct_flags(p);
	struct lb_ct nct = {
		.created_ns = now,
		.last_seen_ns = now,
		.packets = 1,
		.bytes = p->len,
		.flags = flags,
	};

	if (ct) {
		if (lb_slot_holds(ct->svc_id, ct->be_idx, ct->backend_ip, ct->backend_port,
				  p->key.dport)) {
			ct->last_seen_ns = now;
			ct->packets += 1;
			ct->bytes += p->len;
			ct->flags |= flags;
			rev_store(&p->key, ct, now, flags, 0);
			goto dnat;
		}
		/* backend removed or replaced: drop its reverse entry, re-place */
		struct flow_key old;

		reply_key(&p->key, ct->backend_ip, ct->backend_port, &old);
		bpf_map_delete_elem(&lb_reverse, &old);
	} else if (!tcp_opening(p) && lb_recover_forward(p, svc, &nct) == 0) {
		bpf_map_update_elem(&lb_conntrack, &p->key, &nct, BPF_ANY);
		stat_add(STAT_LB_RECOVERED, 1);
		ct = &nct;
		goto dnat;
	}

	struct backend *be = 0;
	__u32 idx = 0;

	if (lb_select(svc, flow_hash(&p->key), &idx, &be) < 0 || !be) {
		stat_add(STAT_DROP_NO_BACKEND, 1);
		return 1;
	}
	nct.backend_ip = be->ip;
	nct.backend_port = backend_port(be, p->key.dport);
	nct.svc_id = (__u8)svc->id;
	nct.be_idx = (__u8)idx;
	bpf_map_update_elem(&lb_conntrack, &p->key, &nct, BPF_ANY);
	rev_store(&p->key, &nct, now, flags, 1);
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

/* Client flow f = (c, v, p_c, p_v, pi) of a backend reply. */
static __always_inline void client_flow(const struct pkt *p, __u32 vip, __u16 vport,
					struct flow_key *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->saddr = p->key.daddr;
	out->daddr = vip;
	out->sport = p->key.dport;
	out->dport = vport;
	out->proto = p->key.proto;
	out->l3 = L3_IPV4;
}

enum lb_reply_kind {
	LB_NOT_REPLY = 0, /* not a load-balanced reply */
	LB_REPLY = 1,     /* reply of a tracked connection; *info is valid */
	LB_ISOLATE = 2,   /* from a backend service endpoint without valid LB state */
};

/*
 * Classify a packet that may be a backend's reply (ClassifyReply in the
 * paper). Read-only: it determines the rule key before the firewall runs;
 * state is refreshed or re-created only after admission (lb_reverse_nat).
 *
 *  - T_rev hit whose service slot still holds this backend: REPLY.
 *  - T_rev miss: if the source is a backend service endpoint (lb_endpoints)
 *    and the client's forward entry names this backend in a slot that still
 *    holds it, REPLY with the recovered (v, p_v, sigma, j).
 *  - otherwise from a service endpoint: ISOLATE (the backend's real address
 *    must never reach a client un-NATed).
 * `*entry` points to the existing T_rev entry, or is NULL if it must be
 * re-created.
 */
static __always_inline int lb_reply_lookup(struct pkt *p, struct lb_rev *info,
					   struct lb_rev **entry)
{
	struct lb_rev *rev;

	*entry = 0;
	if (p->key.l3 != L3_IPV4 || !p->has_ports)
		return LB_NOT_REPLY;
	rev = bpf_map_lookup_elem(&lb_reverse, &p->key);
	if (rev) {
		if (!lb_slot_holds(rev->svc_id, rev->be_idx, p->key.saddr, p->key.sport,
				   rev->vport))
			return LB_ISOLATE; /* backend removed or replaced: stale state */
		*info = *rev;
		*entry = rev;
		return LB_REPLY;
	}

	struct endpoint_key ek = {.ip = p->key.saddr, .port = p->key.sport, .proto = p->key.proto};
	struct endpoint_info *ep = bpf_map_lookup_elem(&lb_endpoints, &ek);

	if (!ep)
		return LB_NOT_REPLY;
	struct flow_key fwd;

	client_flow(p, ep->vip, ep->vport, &fwd);
	struct lb_ct *ct = bpf_map_lookup_elem(&lb_conntrack, &fwd);

	if (!ct || ct->backend_ip != p->key.saddr || ct->backend_port != p->key.sport ||
	    !lb_slot_holds(ct->svc_id, ct->be_idx, p->key.saddr, p->key.sport, ep->vport))
		return LB_ISOLATE;
	__builtin_memset(info, 0, sizeof(*info));
	info->vip = ep->vip;
	info->vport = ep->vport;
	info->svc_id = ct->svc_id;
	info->be_idx = ct->be_idx;
	return LB_REPLY;
}

/*
 * Reverse direction (backend -> client), after admission. Refreshes T_rev or
 * re-creates it from the classification; refreshes the forward entry too - or
 * re-creates it if it was lost - so a server-to-client stream keeps the
 * connection alive and a server FIN/RST shortens its timeout.
 */
static __always_inline void lb_reverse_nat(struct pkt *p, const struct lb_rev *info,
					   struct lb_rev *entry, struct verdict *v, __u64 now)
{
	__u32 flags = tcp_ct_flags(p);
	struct flow_key fwd;
	struct lb_ct *ct;

	if (!entry)
		entry = bpf_map_lookup_elem(&lb_reverse, &p->key);
	if (entry) {
		entry->last_seen_ns = now;
		entry->flags |= flags;
	} else {
		struct lb_rev nrev = *info;

		nrev.last_seen_ns = now;
		nrev.flags = flags;
		bpf_map_update_elem(&lb_reverse, &p->key, &nrev, BPF_ANY);
		stat_add(STAT_LB_RECOVERED, 1);
	}

	client_flow(p, info->vip, info->vport, &fwd);
	ct = bpf_map_lookup_elem(&lb_conntrack, &fwd);
	if (ct) {
		ct->last_seen_ns = now;
		ct->flags |= flags;
	} else {
		/* classification checked that slot be_idx still holds this backend */
		struct lb_ct nct = {
			.backend_ip = p->key.saddr,
			.backend_port = p->key.sport,
			.svc_id = info->svc_id,
			.be_idx = info->be_idx,
			.created_ns = now,
			.last_seen_ns = now,
			.flags = flags,
		};
		bpf_map_update_elem(&lb_conntrack, &fwd, &nct, BPF_ANY);
		stat_add(STAT_LB_RECOVERED, 1);
	}

	v->nat = NAT_SNAT;
	v->old_addr = p->key.saddr;
	v->new_addr = info->vip;
	v->old_port = p->key.sport;
	v->new_port = info->vport;
	stat_add(STAT_LB_SNAT, 1);
}

/* Returns 1 if the packet must be dropped. */
static __always_inline int load_balance(struct pkt *p, int kind, const struct lb_rev *info,
					struct lb_rev *entry, struct verdict *v, __u64 now)
{
	if (p->key.l3 != L3_IPV4 || !p->has_ports)
		return 0;
	if (kind == LB_REPLY) {
		lb_reverse_nat(p, info, entry, v, now);
		return 0;
	}

	struct svc_key sk = {
		.vip = p->key.daddr,
		.port = p->key.dport,
		.proto = p->key.proto,
	};
	struct svc_info *svc = bpf_map_lookup_elem(&lb_services, &sk);

	if (svc)
		return lb_forward(p, svc, v, now);

	/* A backend service endpoint is reachable only through its VIP. */
	struct endpoint_key ek = {.ip = p->key.daddr, .port = p->key.dport, .proto = p->key.proto};

	if (bpf_map_lookup_elem(&lb_endpoints, &ek)) {
		stat_add(STAT_DROP_ISOLATION, 1);
		return 1;
	}
	return 0;
}

/*
 * First fragment of a TCP/UDP datagram to or from a backend service
 * endpoint: dropped (endpoint isolation), since fragments are never NAT-ed.
 * Without its first fragment the receiver cannot reassemble the datagram.
 */
static __always_inline int first_fragment_blocked(const struct pkt *p)
{
	struct endpoint_key ek = {.ip = p->key.daddr, .port = p->ff_dport, .proto = p->key.proto};

	if (bpf_map_lookup_elem(&lb_endpoints, &ek))
		return 1;
	ek.ip = p->key.saddr;
	ek.port = p->ff_sport;
	return bpf_map_lookup_elem(&lb_endpoints, &ek) != 0;
}

#endif /* SDN_LB_H */
