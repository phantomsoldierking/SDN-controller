/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pipeline.h - hook-independent processing pipeline shared by XDP and TC.
 */
#ifndef SDN_PIPELINE_H
#define SDN_PIPELINE_H

#include "parser.h"
#include "firewall.h"
#include "lb.h"
#include "telemetry.h"

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

#endif /* SDN_PIPELINE_H */
