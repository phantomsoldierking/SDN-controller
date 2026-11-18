/* SPDX-License-Identifier: GPL-2.0 */
/*
 * chain.h - ablation variants: the same pipeline split into three XDP
 * programs chained with bpf_tail_call (one program per network function, as
 * in modular eBPF frameworks). Used only by the microbenchmark
 * (testbed/microbench.py) to measure the cost of chaining.
 *
 *   xdp_chain_*   every stage re-parses the packet and re-reads the
 *                 load-balancer state it needs (no shared parse metadata)
 *   xdp_chainm_*  stages share the parsed packet (key, offsets, flags) and
 *                 the reply classification through a per-CPU scratch map;
 *                 the last stage only re-derives header pointers from the
 *                 stored offsets. The difference between the two isolates
 *                 the cost of re-parsing from that of the tail calls.
 */
#ifndef SDN_CHAIN_H
#define SDN_CHAIN_H

#include "pipeline.h"
#include "xdp_nat.h"

enum chain_stage { CHAIN_LB = 1, CHAIN_OUT = 2, CHAIN_STAGES = 3 };

struct chain_ctx {
	struct flow_key ck;   /* rule key (client-visible) */
	struct flow_key key;  /* packet key (meta variant) */
	struct verdict v;
	struct lb_rev info;   /* reply classification */
	__u32 kind;
	__u32 len;
	__u16 l3_off;
	__u16 l4_off;
	__u8 tcp_flags;
	__u8 has_ports;
	__u8 pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, CHAIN_STAGES);
	__type(key, __u32);
	__type(value, __u32);
} chain_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, CHAIN_STAGES);
	__type(key, __u32);
	__type(value, __u32);
} chainm_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct chain_ctx);
} chain_scratch SEC(".maps");

static __always_inline struct chain_ctx *chain_state(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&chain_scratch, &zero);
}

/* Stage 0 (both variants): parse, L2 + L3/L4 rules, stateful admission.
 * Returns -1 to continue with the next stage, else an XDP verdict. */
static __always_inline int chain_stage_fw(struct xdp_md *ctx, struct chain_ctx *st)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&dp_config_map, &zero);
	struct pkt p = {};
	int rc = parse_packet(data, data_end, &p);

	stat_add(STAT_RX_PACKETS, 1);
	stat_add(STAT_RX_BYTES, p.len);
	if (rc == PARSE_MALFORMED || fw_mac_lookup(p.eth, fw_pattern_mask(cfg)) == ACT_DROP)
		return XDP_DROP;
	if (rc == PARSE_NON_IP || p.key.l3 == L3_ARP)
		return XDP_PASS;

	struct lb_rev *entry = 0;
	int kind = lb_reply_lookup(&p, &st->info, &entry);

	if (kind == LB_ISOLATE)
		return XDP_DROP;
	st->ck = p.key;
	if (kind == LB_REPLY)
		client_flow(&p, st->info.vip, st->info.vport, &st->ck);
	if (firewall_ip(&st->ck, p.has_ports, cfg)) {
		stat_add(STAT_DROP_FW, 1);
		return XDP_DROP;
	}
	st->kind = kind;
	st->key = p.key;
	st->len = p.len;
	st->l3_off = p.l3_off;
	st->l4_off = p.l4_off;
	st->tcp_flags = p.tcp_flags;
	st->has_ports = p.has_ports;
	return -1;
}

/* Stage 2 (both variants): connection tracking, telemetry, NAT rewrite. */
static __always_inline int chain_stage_out(struct chain_ctx *st, struct pkt *p, void *data_end)
{
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&dp_config_map, &zero);
	__u64 now = bpf_ktime_get_ns();

	if (cfg && (cfg->flags & CFG_F_FW_STATEFUL))
		ct_touch(&st->ck, p, now, st->kind == LB_REPLY, st->v.fresh);
	telemetry(p, now);
	struct verdict v = st->v;

	if (v.nat != NAT_NONE && xdp_apply_nat(p, &v, data_end) < 0)
		return XDP_DROP;
	stat_add(STAT_PASS, 1);
	return XDP_PASS;
}

/* ---- variant 1: every stage re-parses ---------------------------------- */
SEC("xdp")
int xdp_chain_fw(struct xdp_md *ctx)
{
	struct chain_ctx *st = chain_state();
	int rc;

	if (!st)
		return XDP_ABORTED;
	rc = chain_stage_fw(ctx, st);
	if (rc >= 0)
		return rc;
	bpf_tail_call(ctx, &chain_progs, CHAIN_LB);
	return XDP_ABORTED;
}

SEC("xdp")
int xdp_chain_lb(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct chain_ctx *st = chain_state();
	struct pkt p = {};

	if (!st || parse_packet(data, data_end, &p) != PARSE_OK)
		return XDP_ABORTED;
	__builtin_memset(&st->v, 0, sizeof(st->v));
	if (load_balance(&p, st->kind, &st->info, 0, &st->v, bpf_ktime_get_ns()))
		return XDP_DROP;
	bpf_tail_call(ctx, &chain_progs, CHAIN_OUT);
	return XDP_ABORTED;
}

SEC("xdp")
int xdp_chain_out(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct chain_ctx *st = chain_state();
	struct pkt p = {};

	if (!st || parse_packet(data, data_end, &p) != PARSE_OK)
		return XDP_ABORTED;
	return chain_stage_out(st, &p, data_end);
}

/* ---- variant 2: stages share the parse result ---------------------------- */
static __always_inline void chain_restore(const struct chain_ctx *st, struct pkt *p)
{
	p->key = st->key;
	p->len = st->len;
	p->l3_off = st->l3_off;
	p->l4_off = st->l4_off;
	p->tcp_flags = st->tcp_flags;
	p->has_ports = st->has_ports;
}

SEC("xdp")
int xdp_chainm_fw(struct xdp_md *ctx)
{
	struct chain_ctx *st = chain_state();
	int rc;

	if (!st)
		return XDP_ABORTED;
	rc = chain_stage_fw(ctx, st);
	if (rc >= 0)
		return rc;
	bpf_tail_call(ctx, &chainm_progs, CHAIN_LB);
	return XDP_ABORTED;
}

SEC("xdp")
int xdp_chainm_lb(struct xdp_md *ctx)
{
	struct chain_ctx *st = chain_state();
	struct pkt p = {};

	if (!st)
		return XDP_ABORTED;
	chain_restore(st, &p); /* the load balancer needs only key, length, flags */
	__builtin_memset(&st->v, 0, sizeof(st->v));
	if (load_balance(&p, st->kind, &st->info, 0, &st->v, bpf_ktime_get_ns()))
		return XDP_DROP;
	bpf_tail_call(ctx, &chainm_progs, CHAIN_OUT);
	return XDP_ABORTED;
}

SEC("xdp")
int xdp_chainm_out(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct chain_ctx *st = chain_state();
	struct pkt p = {};

	if (!st)
		return XDP_ABORTED;
	chain_restore(st, &p);
	if (st->v.nat != NAT_NONE) {
		/* header pointers from the stored offsets (bounds re-checked) */
		__u16 l3 = st->l3_off & 0x3f, l4 = st->l4_off & 0x7f;
		struct iphdr *iph = data + l3;
		void *l4p = data + l4;

		if ((void *)(iph + 1) > data_end || l4p + sizeof(struct tcphdr) > data_end)
			return XDP_DROP;
		p.iph = iph;
		p.l4 = l4p;
	}
	return chain_stage_out(st, &p, data_end);
}

#endif /* SDN_CHAIN_H */
