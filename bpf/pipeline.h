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
/*
 * Order (Algorithm 1 of the paper):
 *   parse -> L2 rules (all frames) -> [IPv4] client-visible key -> L3/L4 rules
 *   + stateful admission -> load balancer -> conntrack update -> telemetry.
 *
 * The firewall judges a load-balanced connection by its client->VIP
 * orientation in both directions: one rule against the VIP covers forward
 * packets and replies, and no firewall state is ever created for a backend's
 * real address.
 */
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
	/* L2 rules apply to every frame, including IPv6 and other non-IP traffic. */
	if (fw_mac_lookup(p->eth, fw_pattern_mask(cfg)) == ACT_DROP) {
		stat_add(STAT_DROP_FW, 1);
		v->drop = 1;
		return 0;
	}
	if (rc == PARSE_NON_IP) {
		stat_add(STAT_NON_IP, 1);
		return 0;
	}
	if (p->key.l3 == L3_ARP) {
		/* ARP is subject only to L2 rules, so IP policy cannot break it. */
		stat_add(STAT_ARP, 1);
		telemetry(p, now);
		return 0;
	}

	/* First fragment: may be dropped by its ports, never admitted by them. */
	if (p->first_frag) {
		struct flow_key fk = p->key;
		__u32 stat = STAT_DROP_ISOLATION;
		int blocked = first_fragment_blocked(p);

		fk.sport = p->ff_sport;
		fk.dport = p->ff_dport;
		if (!blocked && fw_ip_lookup(&fk, 1, fw_pattern_mask(cfg)) == ACT_DROP) {
			blocked = 1;
			stat = STAT_DROP_FW;
		}
		if (blocked) {
			stat_add(stat, 1);
			v->drop = 1;
			return 0;
		}
	}

	/*
	 * Rule key: a load-balanced connection is judged in its client->VIP
	 * orientation in both directions, so one VIP rule covers the connection.
	 * Classification is read-only; LB state changes only after admission.
	 */
	struct lb_rev info;
	struct lb_rev *entry = 0;
	int kind = lb_reply_lookup(p, &info, &entry);
	struct flow_key ck = p->key;

	if (kind == LB_ISOLATE) {
		stat_add(STAT_DROP_ISOLATION, 1);
		v->drop = 1;
		return 0;
	}
	if (kind == LB_REPLY)
		client_flow(p, info.vip, info.vport, &ck);

	if (firewall_ip(&ck, p->has_ports, cfg)) {
		stat_add(STAT_DROP_FW, 1);
		v->drop = 1;
		return 0;
	}
	if (load_balance(p, kind, &info, entry, v, now)) {
		v->drop = 1;
		return 0;
	}
	if (cfg && (cfg->flags & CFG_F_FW_STATEFUL))
		ct_touch(&ck, p, now, kind == LB_REPLY, v->fresh);
	telemetry(p, now);
	return 0;
}

#endif /* SDN_PIPELINE_H */
