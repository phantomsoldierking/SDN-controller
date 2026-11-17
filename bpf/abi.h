/* SPDX-License-Identifier: GPL-2.0 */
/*
 * abi.h - map key/value layouts shared with the Python control plane.
 *
 * Mirrored by sdn/abi.py (ctypes); sizes are asserted there at import time.
 * Every struct is explicitly padded so C and Python agree on the layout.
 */
#ifndef SDN_ABI_H
#define SDN_ABI_H

#include "proto.h"

/* ------------------------------------------------------------------ */
/* Sizing                                                              */
/* ------------------------------------------------------------------ */
#define MAX_FW_RULES 16384
#define MAX_CT_ENTRIES 65536
#define MAX_SERVICES 16
#define MAX_BACKENDS_PER_SVC 16
#define FLOW_TABLE_SIZE 16384 /* per-flow telemetry entries (LRU) */

/* ------------------------------------------------------------------ */
/* Shared ABI with control_plane.py (keep in sync, no implicit padding) */
/* ------------------------------------------------------------------ */
enum fw_kind {
	FW_KIND_IP = 1,  /* 5-tuple (with structured wildcards, see fw_lookup) */
	FW_KIND_MAC = 2, /* 2-tuple (src MAC, dst MAC), dst MAC may be wildcard */
};

/*
 * Rule patterns, in lookup order (most specific first). The mask id is part
 * of the key, so a zero field is never confused with a wildcard (e.g. a
 * packet with port 0 or protocol 0 cannot match a wildcarded rule).
 */
enum fw_mask {
	FW_M_MAC_PAIR = 1,  /* (smac, dmac)                     */
	FW_M_MAC_SRC = 2,   /* (smac, *)                        */
	FW_M_IP_EXACT = 3,  /* (s, d, sport, dport, proto)      TCP/UDP */
	FW_M_IP_DPORT = 4,  /* (s, d, *,     dport, proto)      TCP/UDP */
	FW_M_IP_SPORT = 5,  /* (s, d, sport, *,     proto)      TCP/UDP */
	FW_M_IP_PROTO = 6,  /* (s, d, *,     *,     proto)      */
	FW_M_IP_PAIR = 7,   /* (s, d, *,     *,     *)          */
	FW_M_SVC_PORT = 8,  /* (*, d, *,     dport, proto)      TCP/UDP */
	FW_M_IP_SRC = 9,    /* (s, *, *,     *,     *)          */
	FW_M_IP_DST = 10,   /* (*, d, *,     *,     *)          */
};

enum fw_action {
	ACT_NONE = 0,
	ACT_ALLOW = 1,
	ACT_DROP = 2,
};

enum l3_kind {
	L3_ARP = 1,
	L3_IPV4 = 4,
};

/* Flow identity used by conntrack + telemetry. 16 bytes. */
struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 l3; /* enum l3_kind */
	__u8 pad[2];
};

/* firewall_map key: 5-tuple or MAC 2-tuple. 28 bytes. */
struct fw_key {
	__u8 kind; /* enum fw_kind */
	__u8 proto;
	__u16 sport;
	__u16 dport;
	__u8 mask; /* enum fw_mask: which fields are significant */
	__u8 pad;
	__u32 saddr;
	__u32 daddr;
	__u8 smac[ETH_ALEN];
	__u8 dmac[ETH_ALEN];
};

struct fw_rule {
	__u32 action; /* enum fw_action */
	__u32 pad;
	__u64 hits;
};

/* Connection-tracking flags */
#define CT_F_SYN (1U << 0)
#define CT_F_FIN (1U << 1)
#define CT_F_RST (1U << 2)
#define CT_F_REPLY (1U << 3)

/* fw_conntrack value */
struct ct_entry {
	__u64 created_ns;
	__u64 last_seen_ns;
	__u64 packets;
	__u64 bytes;
	__u32 flags;
	__u32 pad;
};

struct svc_key {
	__u32 vip;
	__u16 port;
	__u8 proto;
	__u8 pad;
};

struct svc_info {
	__u32 id;    /* slot in lb_backends: id * MAX_BACKENDS_PER_SVC + i */
	__u32 count; /* number of configured backends */
};

struct backend {
	__u32 ip;
	__u16 port;
	__u16 active; /* 0 = drained / down */
};

/* lb_conntrack value, keyed by client->VIP flow_key */
struct lb_ct {
	__u32 backend_ip;
	__u16 backend_port;
	__u8 svc_id;
	__u8 be_idx;
	__u64 created_ns;
	__u64 last_seen_ns;
	__u64 packets;
	__u64 bytes;
	__u32 flags;
	__u32 pad;
};

/* lb_reverse value, keyed by backend->client flow_key */
struct lb_rev {
	__u32 vip;
	__u16 vport;
	__u16 pad;
	__u64 last_seen_ns;
	__u32 flags;
	__u32 pad2;
};

/* flow_stats value (per-CPU LRU hash keyed by flow_key; admitted traffic only) */
struct flow_stat {
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
};

#define CFG_F_FIB_FORWARD (1U << 0) /* bypass the stack via bpf_fib_lookup */
#define CFG_F_FW_STATEFUL (1U << 1) /* track allowed flows in fw_conntrack */

struct dp_config {
	__u32 default_action; /* ACT_ALLOW (or 0) / ACT_DROP for unmatched IPv4 */
	__u32 flags;
};

enum stat_idx {
	STAT_RX_PACKETS = 0,
	STAT_RX_BYTES,
	STAT_PASS,
	STAT_DROP_FW,
	STAT_DROP_MALFORMED,
	STAT_DROP_NO_BACKEND,
	STAT_LB_DNAT,
	STAT_LB_SNAT,
	STAT_LB_NEW_CONN,
	STAT_CT_ESTABLISHED,
	STAT_ARP,
	STAT_NON_IP,
	STAT_FIB_FORWARD,
	STAT_MAX,
};

#endif /* SDN_ABI_H */
