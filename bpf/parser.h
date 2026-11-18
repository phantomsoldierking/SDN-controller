/* SPDX-License-Identifier: GPL-2.0 */
/*
 * parser.h - Ethernet/VLAN/ARP/IPv4/TCP/UDP/ICMP parser.
 *
 * Every header access is preceded by an explicit bounds check against
 * data_end so the verifier can prove memory safety.
 */
#ifndef SDN_PARSER_H
#define SDN_PARSER_H

#include "proto.h"
#include "pkt.h"

static __always_inline int parse_packet(void *data, void *data_end, struct pkt *p)
{
	struct ethhdr *eth = data;
	__u16 off = sizeof(*eth);
	__u16 proto;

	if ((void *)(eth + 1) > data_end)
		return PARSE_MALFORMED;

	p->eth = eth;
	p->len = (__u32)(data_end - data);
	proto = bpf_ntohs(eth->h_proto);

	/* Single 802.1Q / 802.1ad tag */
	if (proto == ETH_P_8021Q_ || proto == ETH_P_8021AD_) {
		struct vlan_hdr_ *vh = data + off;

		if ((void *)(vh + 1) > data_end)
			return PARSE_MALFORMED;
		proto = bpf_ntohs(vh->encap_proto);
		off += sizeof(*vh);
	}

	p->l3_off = off;
	p->l3_proto = proto;

	if (proto == ETH_P_ARP) {
		struct arp_ipv4 *arp = data + off;

		if ((void *)(arp + 1) > data_end)
			return PARSE_MALFORMED;
		if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
			return PARSE_NON_IP;
		p->key.l3 = L3_ARP;
		p->key.saddr = arp->ar_sip;
		p->key.daddr = arp->ar_tip;
		p->key.sport = arp->ar_op; /* expose opcode to telemetry */
		return PARSE_OK;
	}

	if (proto != ETH_P_IP)
		return PARSE_NON_IP;

	struct iphdr *iph = data + off;

	if ((void *)(iph + 1) > data_end)
		return PARSE_MALFORMED;
	if (iph->version != 4 || iph->ihl < 5)
		return PARSE_MALFORMED;

	__u32 ihl_len = iph->ihl * 4;

	if ((void *)iph + ihl_len > data_end)
		return PARSE_MALFORMED;
	if (bpf_ntohs(iph->tot_len) < ihl_len)
		return PARSE_MALFORMED;

	p->iph = iph;
	p->l4_off = off + ihl_len;
	p->key.l3 = L3_IPV4;
	p->key.saddr = iph->saddr;
	p->key.daddr = iph->daddr;
	p->key.proto = iph->protocol;

	void *l4 = (void *)iph + ihl_len;

	/* No reassembly: every fragment, including the first one (MF set,
	 * offset 0), is treated as port-less, so all fragments of a datagram
	 * share one key and none of them is load-balanced or NAT-rewritten.
	 * The first fragment's ports are recorded separately: they are used only
	 * to drop it (port DROP rules, endpoint isolation), which makes the whole
	 * datagram unreassemblable, never to admit it. */
	if (iph->frag_off & bpf_htons(IP_OFFSET | IP_MF)) {
		if (!(iph->frag_off & bpf_htons(IP_OFFSET)) &&
		    (iph->protocol == IPPROTO_TCP_ || iph->protocol == IPPROTO_UDP_)) {
			__u16 *ports = l4;

			if ((void *)(ports + 2) <= data_end) {
				p->first_frag = 1;
				p->ff_sport = ports[0];
				p->ff_dport = ports[1];
			}
		}
		return PARSE_OK;
	}

	if (iph->protocol == IPPROTO_TCP_) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > data_end)
			return PARSE_MALFORMED;
		p->l4 = th;
		p->key.sport = th->source;
		p->key.dport = th->dest;
		p->tcp_flags = ((__u8 *)th)[13];
		p->has_ports = 1;
	} else if (iph->protocol == IPPROTO_UDP_) {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > data_end)
			return PARSE_MALFORMED;
		p->l4 = uh;
		p->key.sport = uh->source;
		p->key.dport = uh->dest;
		p->has_ports = 1;
	} else if (iph->protocol == IPPROTO_ICMP_) {
		/* type/code only; ICMP flows are keyed by (src, dst, proto). */
		if (l4 + 4 > data_end)
			return PARSE_MALFORMED;
		p->l4 = l4;
	}
	return PARSE_OK;
}

static __always_inline __u32 tcp_ct_flags(const struct pkt *p)
{
	__u32 f = 0;

	if (p->key.proto != IPPROTO_TCP_)
		return 0;
	if (p->tcp_flags & 0x02)
		f |= CT_F_SYN;
	if (p->tcp_flags & 0x01)
		f |= CT_F_FIN;
	if (p->tcp_flags & 0x04)
		f |= CT_F_RST;
	return f;
}

#endif /* SDN_PARSER_H */
