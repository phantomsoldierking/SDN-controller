/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tc_nat.h - TC packet rewriting: NAT via bpf_l3/l4_csum_replace(), FIB fast-forward.
 */
#ifndef SDN_TC_NAT_H
#define SDN_TC_NAT_H

#include "pipeline.h"

#define IP_CSUM_OFF(l3) ((l3) + __builtin_offsetof(struct iphdr, check))
#define IP_SRC_OFF(l3) ((l3) + __builtin_offsetof(struct iphdr, saddr))
#define IP_DST_OFF(l3) ((l3) + __builtin_offsetof(struct iphdr, daddr))
#define IP_TTL_OFF(l3) ((l3) + __builtin_offsetof(struct iphdr, ttl))

static __always_inline int tc_apply_nat(struct __sk_buff *skb, struct pkt *p, struct verdict *v)
{
	__u32 l3 = p->l3_off;
	__u32 l4 = p->l4_off;
	__u32 csum_off, addr_off, port_off;
	__u64 l4_flags = 0;

	if (p->key.proto == IPPROTO_TCP_) {
		csum_off = l4 + __builtin_offsetof(struct tcphdr, check);
	} else {
		csum_off = l4 + __builtin_offsetof(struct udphdr, check);
		l4_flags = BPF_F_MARK_MANGLED_0; /* keep "no checksum" UDP as-is */
	}

	if (v->nat == NAT_DNAT) {
		addr_off = IP_DST_OFF(l3);
		port_off = l4 + 2; /* dest port */
	} else {
		addr_off = IP_SRC_OFF(l3);
		port_off = l4; /* source port */
	}

	/* L4 checksum: pseudo-header address, then port. */
	if (bpf_l4_csum_replace(skb, csum_off, v->old_addr, v->new_addr,
				l4_flags | BPF_F_PSEUDO_HDR | sizeof(__u32)))
		return -1;
	if (v->old_port != v->new_port &&
	    bpf_l4_csum_replace(skb, csum_off, v->old_port, v->new_port,
				l4_flags | sizeof(__u16)))
		return -1;
	/* L3 header checksum. */
	if (bpf_l3_csum_replace(skb, IP_CSUM_OFF(l3), v->old_addr, v->new_addr, sizeof(__u32)))
		return -1;

	if (bpf_skb_store_bytes(skb, addr_off, &v->new_addr, sizeof(__u32), 0))
		return -1;
	if (v->old_port != v->new_port &&
	    bpf_skb_store_bytes(skb, port_off, &v->new_port, sizeof(__u16), 0))
		return -1;
	return 0;
}

static __always_inline int tc_fib_forward(struct __sk_buff *skb, struct pkt *p)
{
	struct bpf_fib_lookup fib = {};
	struct iphdr iph;
	__u32 l3 = p->l3_off;

	/* Packet pointers were invalidated by the NAT helpers: re-read. */
	if (bpf_skb_load_bytes(skb, l3, &iph, sizeof(iph)))
		return TC_ACT_OK;
	if (iph.ttl <= 1)
		return TC_ACT_OK;

	fib.family = AF_INET;
	fib.tos = iph.tos;
	fib.l4_protocol = iph.protocol;
	fib.tot_len = bpf_ntohs(iph.tot_len);
	fib.ipv4_src = iph.saddr;
	fib.ipv4_dst = iph.daddr;
	fib.ifindex = skb->ingress_ifindex;

	if (bpf_fib_lookup(skb, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS)
		return TC_ACT_OK;

	/* TTL shares a 16-bit checksum word with the protocol field. */
	__u16 old_w = bpf_htons(((__u16)iph.ttl << 8) | iph.protocol);
	__u8 new_ttl = iph.ttl - 1;
	__u16 new_w = bpf_htons(((__u16)new_ttl << 8) | iph.protocol);

	if (bpf_l3_csum_replace(skb, IP_CSUM_OFF(l3), old_w, new_w, sizeof(__u16)))
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, IP_TTL_OFF(l3), &new_ttl, 1, 0))
		return TC_ACT_SHOT;
	if (bpf_skb_store_bytes(skb, 0, fib.dmac, ETH_ALEN, 0) ||
	    bpf_skb_store_bytes(skb, ETH_ALEN, fib.smac, ETH_ALEN, 0))
		return TC_ACT_SHOT;

	stat_add(STAT_FIB_FORWARD, 1);
	return bpf_redirect(fib.ifindex, 0);
}

#endif /* SDN_TC_NAT_H */
