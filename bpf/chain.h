/* SPDX-License-Identifier: GPL-2.0 */
/*
 * chain.h - ablation variant: the same pipeline split into three XDP programs
 * chained with bpf_tail_call, the structure used by modular eBPF frameworks
 * (one program per network function). Every stage re-parses the packet and
 * the stages exchange state through a per-CPU scratch map. Used only by the
 * microbenchmark (testbed/microbench.py) to measure the cost of chaining.
 */
#ifndef SDN_CHAIN_H
#define SDN_CHAIN_H

#include "pipeline.h"
#include "xdp_nat.h"

enum chain_stage { CHAIN_LB = 1, CHAIN_OUT = 2, CHAIN_STAGES = 3 };

struct chain_ctx {
	struct flow_key ck;
	struct verdict v;
	__u32 kind;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, CHAIN_STAGES);
	__type(key, __u32);
	__type(value, __u32);
} chain_progs SEC(".maps");

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

/* Stage 0: parse, L2 + L3/L4 rules, stateful admission. */
SEC("xdp")
int xdp_chain_fw(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&dp_config_map, &zero);
	struct chain_ctx *st = chain_state();
	struct pkt p = {};
	__u64 now = bpf_ktime_get_ns();
	int rc = parse_packet(data, data_end, &p);

	if (!st)
		return XDP_ABORTED;
	stat_add(STAT_RX_PACKETS, 1);
	stat_add(STAT_RX_BYTES, p.len);
	if (rc == PARSE_MALFORMED || fw_mac_lookup(p.eth, fw_pattern_mask(cfg)) == ACT_DROP)
		return XDP_DROP;
	if (rc == PARSE_NON_IP || p.key.l3 == L3_ARP)
		return XDP_PASS;

	struct lb_rev *rev = 0;
	int kind = lb_reply_lookup(&p, now, &rev);

	if (kind == LB_ISOLATE)
		return XDP_DROP;
	st->ck = p.key;
	if (kind == LB_REPLY && rev)
		client_flow(&p, rev->vip, rev->vport, &st->ck);
	if (firewall_ip(&st->ck, p.has_ports, cfg)) {
		stat_add(STAT_DROP_FW, 1);
		return XDP_DROP;
	}
	st->kind = kind;
	bpf_tail_call(ctx, &chain_progs, CHAIN_LB);
	return XDP_ABORTED;
}

/* Stage 1: load balancer (re-parses the packet). */
SEC("xdp")
int xdp_chain_lb(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct chain_ctx *st = chain_state();
	struct pkt p = {};

	if (!st || parse_packet(data, data_end, &p) != PARSE_OK)
		return XDP_ABORTED;
	struct lb_rev *rev = st->kind == LB_REPLY ? bpf_map_lookup_elem(&lb_reverse, &p.key) : 0;

	__builtin_memset(&st->v, 0, sizeof(st->v));
	if (load_balance(&p, rev, &st->v, bpf_ktime_get_ns()))
		return XDP_DROP;
	bpf_tail_call(ctx, &chain_progs, CHAIN_OUT);
	return XDP_ABORTED;
}

/* Stage 2: connection tracking, telemetry, NAT rewrite (re-parses the packet). */
SEC("xdp")
int xdp_chain_out(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&dp_config_map, &zero);
	struct chain_ctx *st = chain_state();
	struct pkt p = {};
	__u64 now = bpf_ktime_get_ns();

	if (!st || parse_packet(data, data_end, &p) != PARSE_OK)
		return XDP_ABORTED;
	if (cfg && (cfg->flags & CFG_F_FW_STATEFUL))
		ct_touch(&st->ck, &p, now, st->kind == LB_REPLY);
	telemetry(&p, now);
	struct verdict v = st->v;

	if (v.nat != NAT_NONE && xdp_apply_nat(&p, &v, data_end) < 0)
		return XDP_DROP;
	stat_add(STAT_PASS, 1);
	return XDP_PASS;
}

#endif /* SDN_CHAIN_H */
