/* SPDX-License-Identifier: GPL-2.0 */
/*
 * maps.h - BPF map definitions (pinned by the loader under /sys/fs/bpf/sdn_dp).
 */
#ifndef SDN_MAPS_H
#define SDN_MAPS_H

#include "abi.h"

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

#endif /* SDN_MAPS_H */
