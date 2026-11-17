/* SPDX-License-Identifier: GPL-2.0 */
/*
 * telemetry.h - per-flow counters in a per-CPU array.
 */
#ifndef SDN_TELEMETRY_H
#define SDN_TELEMETRY_H

#include "maps.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/* Telemetry: per-flow counters for admitted traffic                   */
/* ------------------------------------------------------------------ */
/*
 * flow_stats is a per-CPU LRU hash keyed by the exact flow key, so flows never
 * share an entry (no collisions); when the table is full the least recently
 * used flow is evicted. Only admitted packets are counted, so a flood of
 * dropped packets cannot evict legitimate flows (drops are counted globally).
 */
static __always_inline void telemetry(struct pkt *p, __u64 now)
{
	struct flow_stat *fs = bpf_map_lookup_elem(&flow_stats, &p->key);

	if (fs) {
		fs->packets += 1;
		fs->bytes += p->len;
		fs->last_seen_ns = now;
		return;
	}
	struct flow_stat nfs = {.packets = 1, .bytes = p->len, .last_seen_ns = now};

	bpf_map_update_elem(&flow_stats, &p->key, &nfs, BPF_NOEXIST);
}

#endif /* SDN_TELEMETRY_H */
