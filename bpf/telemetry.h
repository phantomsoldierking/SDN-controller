/* SPDX-License-Identifier: GPL-2.0 */
/*
 * telemetry.h - per-flow counters in a per-CPU array.
 */
#ifndef SDN_TELEMETRY_H
#define SDN_TELEMETRY_H

#include "maps.h"
#include "util.h"

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

#endif /* SDN_TELEMETRY_H */
