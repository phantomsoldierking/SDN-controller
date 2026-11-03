// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_prog.c - eBPF programmable data plane for the SDN gateway.
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

/* ------------------------------------------------------------------ */
/* Sizing                                                              */
/* ------------------------------------------------------------------ */
#define MAX_FW_RULES 4096
#define MAX_CT_ENTRIES 65536
#define MAX_SERVICES 16
#define MAX_BACKENDS_PER_SVC 16
#define FLOW_SLOTS 1024 /* power of two */

/* ------------------------------------------------------------------ */
/* Shared ABI with control_plane.py (keep in sync, no implicit padding) */
/* ------------------------------------------------------------------ */
enum fw_kind {
	FW_KIND_IP = 1,  /* 5-tuple (with structured wildcards, see fw_lookup) */
	FW_KIND_MAC = 2, /* 2-tuple (src MAC, dst MAC), dst MAC may be wildcard */
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
	__u16 pad;
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

/* flow_stats value (per-CPU, slot = hash(flow) % FLOW_SLOTS) */
struct flow_stat {
	struct flow_key key;
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

/* ------------------------------------------------------------------ */
/* Maps                                                                */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FW_RULES);
	__type(key, struct fw_key);
	__type(value, struct fw_rule);
} firewall_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CT_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct ct_entry);
} fw_conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SERVICES);
	__type(key, struct svc_key);
	__type(value, struct svc_info);
} lb_services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SERVICES * MAX_BACKENDS_PER_SVC);
	__type(key, __u32);
	__type(value, struct backend);
} lb_backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CT_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct lb_ct);
} lb_conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CT_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct lb_rev);
} lb_reverse SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FLOW_SLOTS);
	__type(key, __u32);
	__type(value, struct flow_stat);
} flow_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} global_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dp_config);
} dp_config_map SEC(".maps");

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

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static __always_inline void stat_add(__u32 idx, __u64 val)
{
	__u64 *v = bpf_map_lookup_elem(&global_stats, &idx);

	if (v)
		*v += val; /* per-CPU slot: no atomics needed */
}

static __always_inline __u32 rol32(__u32 w, __u32 s)
{
	return (w << s) | (w >> (32 - s));
}

/* Bob Jenkins' final mix (as in jhash_3words) - stable per-flow hash. */
static __always_inline __u32 flow_hash(const struct flow_key *k)
{
	__u32 a = k->saddr + 0xdeadbeef + 12;
	__u32 b = k->daddr + 0xdeadbeef + 12;
	__u32 c = (((__u32)k->sport << 16) | k->dport) + ((__u32)k->proto << 8) + 0xdeadbeef + 12;

	c ^= b; c -= rol32(b, 14);
	a ^= c; a -= rol32(c, 11);
	b ^= a; b -= rol32(a, 25);
	c ^= b; c -= rol32(b, 16);
	a ^= c; a -= rol32(c, 4);
	b ^= a; b -= rol32(a, 14);
	c ^= b; c -= rol32(b, 24);
	return c;
}

static __always_inline void reverse_key(const struct flow_key *in, struct flow_key *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->saddr = in->daddr;
	out->daddr = in->saddr;
	out->sport = in->dport;
	out->dport = in->sport;
	out->proto = in->proto;
	out->l3 = in->l3;
}

static __always_inline __u16 csum_fold(__u64 csum)
{
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return (__u16)~csum;
}

/* ------------------------------------------------------------------ */
/* Parser - every header access is preceded by an explicit bounds      */
/* check against data_end so the verifier can prove safety.            */
/* ------------------------------------------------------------------ */
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

	/* Non-first fragments carry no L4 header. */
	if (iph->frag_off & bpf_htons(IP_OFFSET))
		return PARSE_OK;

	void *l4 = (void *)iph + ihl_len;

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

/* ------------------------------------------------------------------ */
/* Stateful firewall                                                   */
/* ------------------------------------------------------------------ */
static __always_inline struct fw_rule *fw_try(struct fw_key *k)
{
	return bpf_map_lookup_elem(&firewall_map, k);
}

/*
 * Lookup order, most specific first:
 *   MAC (src, dst) -> MAC (src, *)
 *   IP  (proto, src, dst, sport, dport)
 *   IP  (proto, src, dst, *,     dport)
 *   IP  (proto, src, dst, sport, *)
 *   IP  (proto, src, dst, *,     *)
 *   IP  (*,     src, dst, *,     *)
 *   IP  (*,     src, *,   *,     *)
 *   IP  (*,     *,   dst, *,     *)
 */
static __always_inline __u32 fw_lookup(struct pkt *p)
{
	struct fw_key k;
	struct fw_rule *r;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_MAC;
	__builtin_memcpy(k.smac, p->eth->h_source, ETH_ALEN);
	__builtin_memcpy(k.dmac, p->eth->h_dest, ETH_ALEN);
	r = fw_try(&k);
	if (r)
		goto hit;
	__builtin_memset(k.dmac, 0, ETH_ALEN);
	r = fw_try(&k);
	if (r)
		goto hit;

	if (p->key.l3 != L3_IPV4)
		return ACT_NONE;

	__builtin_memset(&k, 0, sizeof(k));
	k.kind = FW_KIND_IP;
	k.proto = p->key.proto;
	k.saddr = p->key.saddr;
	k.daddr = p->key.daddr;
	k.sport = p->key.sport;
	k.dport = p->key.dport;
	if (p->has_ports) {
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = 0;
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = p->key.sport;
		k.dport = 0;
		r = fw_try(&k);
		if (r)
			goto hit;
		k.sport = 0;
	}
	r = fw_try(&k);
	if (r)
		goto hit;
	k.proto = 0;
	r = fw_try(&k);
	if (r)
		goto hit;
	k.daddr = 0;
	r = fw_try(&k);
	if (r)
		goto hit;
	k.saddr = 0;
	k.daddr = p->key.daddr;
	r = fw_try(&k);
	if (r)
		goto hit;
	return ACT_NONE;

hit:
	__sync_fetch_and_add(&r->hits, 1);
	return r->action;
}

static __always_inline void ct_touch(struct flow_key *k, struct pkt *p, __u64 now)
{
	struct ct_entry *ct = bpf_map_lookup_elem(&fw_conntrack, k);

	if (ct) {
		ct->last_seen_ns = now;
		ct->packets += 1;
		ct->bytes += p->len;
		ct->flags |= tcp_ct_flags(p);
		return;
	}

	struct flow_key rk;
	struct ct_entry *rct;

	/* Reply direction of a tracked flow: mark the original as REPLY seen. */
	reverse_key(k, &rk);
	rct = bpf_map_lookup_elem(&fw_conntrack, &rk);
	if (rct) {
		rct->last_seen_ns = now;
		rct->packets += 1;
		rct->bytes += p->len;
		rct->flags |= CT_F_REPLY | tcp_ct_flags(p);
		return;
	}

	struct ct_entry nct = {
		.created_ns = now,
		.last_seen_ns = now,
		.packets = 1,
		.bytes = p->len,
		.flags = tcp_ct_flags(p),
	};
	bpf_map_update_elem(&fw_conntrack, k, &nct, BPF_ANY);
}

static __always_inline int ct_established(struct flow_key *k)
{
	struct flow_key rk;

	if (bpf_map_lookup_elem(&fw_conntrack, k))
		return 1;
	reverse_key(k, &rk);
	if (bpf_map_lookup_elem(&fw_conntrack, &rk))
		return 1;
	/* Return traffic of a load-balanced connection. */
	if (bpf_map_lookup_elem(&lb_reverse, k))
		return 1;
	return 0;
}

/* Returns 1 if the packet must be dropped. */
static __always_inline int firewall(struct pkt *p, struct dp_config *cfg, __u64 now)
{
	__u32 action = fw_lookup(p);
	int stateful = cfg && (cfg->flags & CFG_F_FW_STATEFUL);

	if (action == ACT_DROP)
		return 1;

	if (p->key.l3 != L3_IPV4)
		return 0; /* ARP is only subject to explicit MAC rules */

	if (action == ACT_NONE && cfg && cfg->default_action == ACT_DROP) {
		if (!stateful || !ct_established(&p->key))
			return 1;
		stat_add(STAT_CT_ESTABLISHED, 1);
	}

	if (stateful)
		ct_touch(&p->key, p, now);
	return 0;
}

/* ------------------------------------------------------------------ */
/* L4 load balancer                                                    */
/* ------------------------------------------------------------------ */
static __always_inline struct backend *backend_at(__u32 svc_id, __u32 idx)
{
	__u32 slot = svc_id * MAX_BACKENDS_PER_SVC + idx;

	return bpf_map_lookup_elem(&lb_backends, &slot);
}

static __always_inline int lb_select(struct svc_info *svc, __u32 hash, __u32 *out_idx,
				     struct backend **out)
{
	__u32 cnt = svc->count;

	if (cnt == 0 || cnt > MAX_BACKENDS_PER_SVC || svc->id >= MAX_SERVICES)
		return -1;

	__u32 start = hash % cnt;

	for (__u32 i = 0; i < MAX_BACKENDS_PER_SVC; i++) {
		if (i >= cnt)
			break;
		__u32 idx = start + i;

		if (idx >= cnt)
			idx -= cnt;
		struct backend *be = backend_at(svc->id, idx);

		if (be && be->active && be->ip) {
			*out_idx = idx;
			*out = be;
			return 0;
		}
	}
	return -1;
}

/* Returns 1 if the packet must be dropped (service has no healthy backend). */
static __always_inline int load_balance(struct pkt *p, struct verdict *v, __u64 now)
{
	if (p->key.l3 != L3_IPV4 || !p->has_ports)
		return 0;

	/* ---- forward direction: client -> VIP:port ---- */
	struct svc_key sk = {
		.vip = p->key.daddr,
		.port = p->key.dport,
		.proto = p->key.proto,
	};
	struct svc_info *svc = bpf_map_lookup_elem(&lb_services, &sk);

	if (svc) {
		struct lb_ct *ct = bpf_map_lookup_elem(&lb_conntrack, &p->key);
		__u32 be_ip = 0;
		__u16 be_port = 0;

		if (ct) {
			struct backend *be = backend_at(ct->svc_id, ct->be_idx);

			/* Sticky unless the backend was drained or replaced. */
			if (be && be->active && be->ip == ct->backend_ip) {
				be_ip = ct->backend_ip;
				be_port = ct->backend_port;
				ct->last_seen_ns = now;
				ct->packets += 1;
				ct->bytes += p->len;
				ct->flags |= tcp_ct_flags(p);
			}
		}

		if (!be_ip) {
			struct backend *be = 0;
			__u32 idx = 0;

			if (lb_select(svc, flow_hash(&p->key), &idx, &be) < 0 || !be) {
				stat_add(STAT_DROP_NO_BACKEND, 1);
				return 1;
			}
			be_ip = be->ip;
			be_port = be->port ? be->port : p->key.dport;

			struct lb_ct nct = {
				.backend_ip = be_ip,
				.backend_port = be_port,
				.svc_id = (__u8)svc->id,
				.be_idx = (__u8)idx,
				.created_ns = now,
				.last_seen_ns = now,
				.packets = 1,
				.bytes = p->len,
				.flags = tcp_ct_flags(p),
			};
			bpf_map_update_elem(&lb_conntrack, &p->key, &nct, BPF_ANY);

			struct flow_key rk;
			struct lb_rev rev = {
				.vip = p->key.daddr,
				.vport = p->key.dport,
				.last_seen_ns = now,
			};

			__builtin_memset(&rk, 0, sizeof(rk));
			rk.saddr = be_ip;
			rk.daddr = p->key.saddr;
			rk.sport = be_port;
			rk.dport = p->key.sport;
			rk.proto = p->key.proto;
			rk.l3 = L3_IPV4;
			bpf_map_update_elem(&lb_reverse, &rk, &rev, BPF_ANY);
			stat_add(STAT_LB_NEW_CONN, 1);
		}

		v->nat = NAT_DNAT;
		v->old_addr = p->key.daddr;
		v->new_addr = be_ip;
		v->old_port = p->key.dport;
		v->new_port = be_port;
		stat_add(STAT_LB_DNAT, 1);
		return 0;
	}

	/* ---- reverse direction: backend -> client ---- */
	struct lb_rev *rev = bpf_map_lookup_elem(&lb_reverse, &p->key);

	if (rev) {
		rev->last_seen_ns = now;
		rev->flags |= tcp_ct_flags(p);
		v->nat = NAT_SNAT;
		v->old_addr = p->key.saddr;
		v->new_addr = rev->vip;
		v->old_port = p->key.sport;
		v->new_port = rev->vport;
		stat_add(STAT_LB_SNAT, 1);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Telemetry                                                           */
/* ------------------------------------------------------------------ */
static __always_inline void telemetry(struct pkt *p, __u64 now)
{
	__u32 slot = flow_hash(&p->key) & (FLOW_SLOTS - 1);
	struct flow_stat *fs = bpf_map_lookup_elem(&flow_stats, &slot);

	if (!fs)
		return;
	/* Per-CPU slot: on a hash collision the newest flow takes the slot. */
	if (__builtin_memcmp(&fs->key, &p->key, sizeof(p->key)) != 0) {
		__builtin_memcpy(&fs->key, &p->key, sizeof(p->key));
		fs->packets = 0;
		fs->bytes = 0;
	}
	fs->packets += 1;
	fs->bytes += p->len;
	fs->last_seen_ns = now;
}

/* ------------------------------------------------------------------ */
/* Hook-independent pipeline                                           */
/* ------------------------------------------------------------------ */
static __always_inline int pipeline(void *data, void *data_end, struct pkt *p,
				    struct verdict *v, struct dp_config **cfg_out)
{
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&dp_config_map, &zero);
	__u64 now = bpf_ktime_get_ns();
	int rc;

	*cfg_out = cfg;
	rc = parse_packet(data, data_end, p);
	stat_add(STAT_RX_PACKETS, 1);
	stat_add(STAT_RX_BYTES, p->len);

	if (rc == PARSE_MALFORMED) {
		stat_add(STAT_DROP_MALFORMED, 1);
		v->drop = 1;
		return 0;
	}
	if (rc == PARSE_NON_IP) {
		stat_add(STAT_NON_IP, 1);
		return 0;
	}
	if (p->key.l3 == L3_ARP)
		stat_add(STAT_ARP, 1);

	telemetry(p, now);

	if (firewall(p, cfg, now)) {
		stat_add(STAT_DROP_FW, 1);
		v->drop = 1;
		return 0;
	}

	if (load_balance(p, v, now)) {
		v->drop = 1;
		return 0;
	}
	return 0;
}

/* ================================================================== */
/* XDP hook                                                            */
/* ================================================================== */
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

/* ================================================================== */
/* TC (clsact ingress) hook                                            */
/* ================================================================== */
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
