/* SPDX-License-Identifier: GPL-2.0 */
/*
 * proto.h - protocol constants and on-wire header layouts not in uapi headers.
 */
#ifndef SDN_PROTO_H
#define SDN_PROTO_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#define IPPROTO_ICMP_ 1
#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17

#define ETH_P_8021Q_ 0x8100
#define ETH_P_8021AD_ 0x88A8
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

/* ARP for IPv4 over Ethernet (linux/if_arp.h pulls in non-BPF headers). */
struct arp_ipv4 {
	__be16 ar_hrd;
	__be16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__be16 ar_op;
	__u8 ar_sha[ETH_ALEN];
	__be32 ar_sip;
	__u8 ar_tha[ETH_ALEN];
	__be32 ar_tip;
} __attribute__((packed));

struct vlan_hdr_ {
	__be16 tci;
	__be16 encap_proto;
};

#endif /* SDN_PROTO_H */
