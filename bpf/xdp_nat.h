/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_nat.h - XDP packet rewriting: NAT via bpf_csum_diff(), FIB fast-forward.
 */
#ifndef SDN_XDP_NAT_H
#define SDN_XDP_NAT_H

#include "pipeline.h"

static __always_inline int xdp_apply_nat(struct pkt *p, struct verdict *v, void *data_end)
{
	struct iphdr *iph = p->iph;
	void *l4 = p->l4;
	__u16 *l4_check = 0;

	if (!iph || !l4)
		return -1;
	if ((void *)(iph + 1) > data_end)
		return -1;

	if (p->key.proto == IPPROTO_TCP_) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > data_end)
			return -1;
		l4_check = &th->check;
	} else {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > data_end)
			return -1;
		if (uh->check) /* UDP checksum 0 == "not computed" */
			l4_check = &uh->check;
	}

	/* First 4 bytes of both TCP and UDP headers are (sport, dport). */
	__u32 *ports = l4;
	__u32 old_ports = *ports;
	__u32 new_ports = old_ports;
	__u16 *np = (__u16 *)&new_ports;

	if (v->nat == NAT_DNAT)
		np[1] = v->new_port;
	else
		np[0] = v->new_port;

	/* L4: pseudo-header address + port word, one bpf_csum_diff() call. */
	if (l4_check) {
		__u32 from[2] = { v->old_addr, old_ports };
		__u32 to[2] = { v->new_addr, new_ports };
		__s64 sum = bpf_csum_diff(from, sizeof(from), to, sizeof(to),
					  (__u16)~(*l4_check));

		if (sum < 0)
			return -1;
		__u16 c = csum_fold((__u32)sum);

		if (p->key.proto == IPPROTO_UDP_ && c == 0)
			c = 0xffff;
		*l4_check = c;
	}

	/* L3 header checksum. */
	__s64 sum = bpf_csum_diff(&v->old_addr, sizeof(__u32), &v->new_addr, sizeof(__u32),
				  (__u16)~iph->check);

	if (sum < 0)
		return -1;
	iph->check = csum_fold((__u32)sum);

	if (v->nat == NAT_DNAT)
		iph->daddr = v->new_addr;
	else
		iph->saddr = v->new_addr;
	*ports = new_ports;
	return 0;
}

static __always_inline void ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;

	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	iph->ttl--;
}

static __always_inline int xdp_fib_forward(struct xdp_md *ctx, struct pkt *p, void *data_end)
{
	struct iphdr *iph = p->iph;
	struct ethhdr *eth = p->eth;
	struct bpf_fib_lookup fib = {};

	if (!iph || (void *)(iph + 1) > data_end || (void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (iph->ttl <= 1)
		return XDP_PASS; /* let the stack send ICMP time-exceeded */

	fib.family = AF_INET;
	fib.tos = iph->tos;
	fib.l4_protocol = iph->protocol;
	fib.tot_len = bpf_ntohs(iph->tot_len);
	fib.ipv4_src = iph->saddr;
	fib.ipv4_dst = iph->daddr;
	fib.ifindex = ctx->ingress_ifindex;

	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_PASS;

	ip_decrease_ttl(iph);
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	stat_add(STAT_FIB_FORWARD, 1);
	return bpf_redirect(fib.ifindex, 0);
}

#endif /* SDN_XDP_NAT_H */
