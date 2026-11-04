/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pkt.h - per-packet parse state and the pipeline verdict.
 */
#ifndef SDN_PKT_H
#define SDN_PKT_H

#include "abi.h"

/* ------------------------------------------------------------------ */
/* Parsed packet + verdict                                             */
/* ------------------------------------------------------------------ */
struct pkt {
	struct ethhdr *eth;
	struct iphdr *iph;
	void *l4;
	__u32 len;
	__u16 l3_off;
	__u16 l4_off;
	__u16 l3_proto; /* host order ETH_P_* */
	__u8 tcp_flags;
	__u8 has_ports;
	struct flow_key key;
};

enum nat_kind {
	NAT_NONE = 0,
	NAT_DNAT = 1, /* rewrite destination (client -> VIP becomes client -> backend) */
	NAT_SNAT = 2, /* rewrite source (backend -> client becomes VIP -> client) */
};

struct verdict {
	__u32 drop;
	__u32 nat;
	__u32 old_addr;
	__u32 new_addr;
	__u16 old_port;
	__u16 new_port;
};

enum parse_rc {
	PARSE_OK = 0,
	PARSE_NON_IP = 1, /* well-formed, but neither IPv4 nor ARP */
	PARSE_MALFORMED = 2,
};

#endif /* SDN_PKT_H */
