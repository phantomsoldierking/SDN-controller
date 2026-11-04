// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_prog.c - eBPF programmable data plane for the SDN gateway.
 *
 * This file holds only the two program entry points; the pipeline stages
 * live in the headers next to it (one compilation unit = one BPF object).
 *
 * Two entry points share one pipeline and one set of maps:
 *
 *   SEC("xdp") xdp_dataplane  - driver-level fast path. NAT checksums are
 *                               patched incrementally with bpf_csum_diff().
 *   SEC("tc")  tc_dataplane   - clsact ingress path operating on sk_buffs.
 *                               NAT uses bpf_l3_csum_replace() /
 *                               bpf_l4_csum_replace(), which also handle
 *                               CHECKSUM_PARTIAL (offloaded) packets.
 *
 * Pipeline (identical for both hooks):
 *
 *   parse (Eth / 802.1Q / ARP / IPv4 / TCP / UDP / ICMP)
 *     -> stateful firewall   (firewall_map + fw_conntrack)
 *     -> L4 load balancer    (lb_services + lb_backends + lb_conntrack/lb_reverse)
 *     -> telemetry           (flow_stats + global_stats, per-CPU arrays)
 *     -> NAT rewrite         (DNAT client->VIP, SNAT backend->client)
 *     -> optional FIB fast-forward (bpf_fib_lookup + MAC rewrite + redirect)
 *
 * All IPs and ports in map keys/values are stored in network byte order,
 * exactly as they appear on the wire.
 */
#include "xdp_nat.h"
#include "tc_nat.h"

SEC("xdp")
int xdp_dataplane(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct pkt p = {};
	struct verdict v = {};
	struct dp_config *cfg;

	pipeline(data, data_end, &p, &v, &cfg);

	if (v.drop)
		return XDP_DROP;

	if (v.nat != NAT_NONE && xdp_apply_nat(&p, &v, data_end) < 0) {
		stat_add(STAT_DROP_MALFORMED, 1);
		return XDP_DROP;
	}

	if (cfg && (cfg->flags & CFG_F_FIB_FORWARD) && p.key.l3 == L3_IPV4)
		return xdp_fib_forward(ctx, &p, data_end);

	stat_add(STAT_PASS, 1);
	return XDP_PASS;
}

SEC("tc")
int tc_dataplane(struct __sk_buff *skb)
{
	struct pkt p = {};
	struct verdict v = {};
	struct dp_config *cfg;

	/* Make sure the headers we parse live in the linear area. */
	if (skb->data_end - skb->data < 128 && skb->len > skb->data_end - skb->data)
		bpf_skb_pull_data(skb, skb->len < 128 ? skb->len : 128);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	pipeline(data, data_end, &p, &v, &cfg);
	if (v.drop)
		return TC_ACT_SHOT;

	if (v.nat != NAT_NONE && tc_apply_nat(skb, &p, &v) < 0) {
		stat_add(STAT_DROP_MALFORMED, 1);
		return TC_ACT_SHOT;
	}

	if (cfg && (cfg->flags & CFG_F_FIB_FORWARD) && p.key.l3 == L3_IPV4)
		return tc_fib_forward(skb, &p);

	stat_add(STAT_PASS, 1);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
