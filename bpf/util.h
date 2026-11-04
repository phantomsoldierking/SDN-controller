/* SPDX-License-Identifier: GPL-2.0 */
/*
 * util.h - counters, flow hashing and checksum folding.
 */
#ifndef SDN_UTIL_H
#define SDN_UTIL_H

#include "maps.h"
#include "pkt.h"

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

#endif /* SDN_UTIL_H */
