# Revision Report

**Paper:** In-Kernel Programmable Data Planes for SDN: An eBPF/XDP Gateway with
Stateful Firewalling and L4 Load Balancing Compared with Open vSwitch

**Review tool:** Google Deep Review (https://research.google/deepreview/)

| Version | File | Reviewed in |
|---|---|---|
| Initial draft | `paper/versions/v0_draft.pdf` | Round 1 |
| Revision 1 | `paper/versions/v1_revision1.pdf` | Round 2 |
| Revision 2 | `paper/versions/v2_revision2.pdf` | Round 3 (recommended) |

---

## Round 1: review of the initial draft (v0) → Revision 1 (v1)

Full reviewer output: `paper/revisions/round1_comments.md`

Several comments identified genuine defects in the **implementation**, not only
in the text. Because the paper must reflect the implemented system, these were
fixed in the code first (with a regression test for each), and the paper was
then updated to describe the corrected behaviour. All experiments were re-run.

**Legend:** Code = implementation changed · Exp = experiments re-run or added ·
Text = paper text, equations or figures changed.

### A. Defects in the implementation (fixed in code, tested, then described)

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R1.1 | Draining a backend ($\alpha_j=0$) re-routes established connections mid-stream, breaking them with TCP RST (Alg. 2, line 2) | **Agreed; fixed.** Established connections now stay on their backend regardless of $\alpha_j$; draining only affects new connections (graceful drain). Re-selection happens only if the backend is removed or replaced. `bpf/lb.h` `lb_forward()`; new test `test_existing_connection_survives_drain`. Paper: §III-E "Stickiness and graceful draining", Alg. 2 lines 10–11, scenario requirement (iv) | Code, Text |
| R1.2 | Reassigning a connection leaves an orphaned reverse-NAT entry (pinhole) | **Fixed.** The stale reverse entry is deleted before the connection is re-placed. Test `test_replaced_backend_reassigns_and_removes_stale_reverse_entry`. Alg. 2 lines 13–14 | Code, Text |
| R1.3 | Replies do not refresh the forward entry $\mathcal{L}[f]$: long server-to-client transfers can expire mid-stream; server FIN/RST not recorded | **Fixed.** Replies refresh both $\mathcal{T}_{rev}$ and $\mathcal{L}[f]$ and record server FIN/RST. Test `test_reply_refreshes_forward_entry_and_records_server_fin`. §III-F "State coupling", Alg. 2 lines 1–4 | Code, Text |
| R1.4 | $\mathcal{L}$ and $\mathcal{T}_{rev}$ are separate LRU maps; independent eviction can lose $\mathcal{T}_{rev}$ while $\mathcal{L}$ stays | **Fixed.** Forward packets re-create an evicted reverse entry. Test `test_evicted_reverse_entry_is_recreated`. §III-F | Code, Text |
| R1.5 | Reaper read-then-delete is not atomic w.r.t. in-flight packets | **Mitigated and analysed.** The reaper re-reads each entry right before deleting it (unit test `test_entry_refreshed_by_data_plane_is_not_deleted`). The residual microsecond window and its consequence (state re-created by the next forward packet; deterministic re-selection) are described in §IV-E "Reaper consistency" | Code, Text |
| R1.6 | Firewall runs before NAT: backend replies are judged by the backend's real address; c1↔s3 rule drops replies of VIP connections; inserting the pre-SNAT reply into $\mathcal{T}_{fw}$ opens a direct client→backend pinhole; VIP drop rules and flushes miss pre-SNAT entries; duplicate state per connection | **Agreed; redesigned.** The firewall now evaluates the *client-visible flow* $\kappa(x)$ (Eq. 4): replies of load-balanced connections are judged as VIP→client. Rules against the VIP apply in both directions; client↔backend rules do not affect VIP traffic; no state is ever created for a backend's real address; flushes on VIP rules also remove matching reverse-NAT entries. Tests `test_no_pinhole_to_backend_after_load_balanced_connection`, `test_rules_see_the_client_view_of_load_balanced_replies`, `test_drop_rule_on_vip_flushes_its_reverse_nat_entries`. §III-D, Eq. (4)–(5) | Code, Text |
| R1.7 | Duplicate $\mathcal{T}_{fw}$ entries for the two directions of a connection | **Clarified and tested.** The implementation already refreshed the original entry for replies (setting REPLY); this is now stated formally (§III-D) and tested (`test_reply_does_not_duplicate_firewall_state`) | Text, Test |
| R1.8 | Missing $\mathcal{T}_{fw}$ insert/refresh step in Alg. 1; should happen after confirming no NOBACKEND drop | **Fixed.** Connection tracking now runs after the load balancer, only for packets that are not dropped; Alg. 1 lines 19–21 | Code, Text |
| R1.9 | Two services sharing a backend endpoint produce identical reverse-NAT keys | **Fixed.** The control plane rejects a service whose backend endpoint already serves another service; the invariant is stated in §III-F. Test `test_backends_must_be_disjoint_across_services` | Code, Text |
| R1.10 | Wildcards encoded as 0: packets with protocol 0 or port 0 collide with wildcarded rules | **Fixed.** Every rule key now contains its pattern id, so unselected fields are true wildcards. §III-C, Eq. (2); unit test `test_each_rule_shape_maps_to_one_pattern` | Code, Text |
| R1.11 | No rule form for "any client → VIP:port" | **Fixed.** New pattern $m_8=(d,p_d,\pi)$; test `test_service_port_rule_allows_any_client` | Code, Text |
| R1.12 | MAC rules bypassed by non-IP frames (IPv6) | **Fixed.** L2 rules apply to every Ethernet frame. Test `test_mac_rule_applies_to_non_ip_frames`. §III-C, Alg. 1 line 5 | Code, Text |
| R1.13 | 1024-slot telemetry array: collisions, cross-CPU key mismatch, eviction by dropped floods | **Fixed.** Per-flow telemetry is now a per-CPU LRU hash keyed by the exact flow (16,384 entries), updated only for admitted packets. Test `test_dropped_packets_are_not_in_flow_telemetry`. §IV-D | Code, Text |

### B. Experimental design (experiments added or re-run)

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R1.14 | Asymmetric baselines: stateless OpenFlow 1.3 vs. stateful OVS (`ct`/`nat`) and native kernel subsystems (nftables + IPVS) | **Agreed; two stateful baselines added.** `ovs-ct` (OVS with `ct(nat)`, select group with `ct(commit,nat(dst=…))`, drain by removing the bucket) and `nft-ipvs` (nftables + conntrack firewall, IPVS NAT mode with Maglev hashing, drain by weight 0). Both pass all functional checks on the testbed. §II, §V-A, Tables II–III | Code, Exp, Text |
| R1.15 | OVS draining (group modify) and OVS kernel drop counters were marked n/a | **Fixed.** Both OVS baselines now drain via `mod-group` and report drops from the OpenFlow rule counters (synchronised with `revalidator/wait`). Table II | Code, Exp, Text |
| R1.16 | Single 10-s run per configuration; noise of 10–20%; laptop frequency scaling; co-located generators | **Fixed.** 10 interleaved rounds per configuration; CPU governor fixed to `performance` during the run; traffic tools pinned to two performance cores; results reported as mean ± 95% CI (Student t) with Welch t-tests for every comparison claimed. §V-D, §VI-C, Table III, Fig. 3 | Exp, Text |
| R1.17 | $O(1)$ claim not validated (single rule, single flow) | **Fixed.** New in-kernel microbenchmark (`BPF_PROG_TEST_RUN`): per-packet cost for 0–10,000 rules spread over all ten patterns (none matching: worst case) and 0–60,000 tracked connections, plus the cost of each path. Result: 0.21–0.23 µs per admitted packet, flat across both ranges. §VI-E, Fig. 4, Table IV | Exp, Text |
| R1.18 | Firewall drop rate is sender-limited; 721,408/3 s ≠ reported kpps (wall clock included process start-up) | **Fixed.** The flood rate now uses the sender's own measured duration and is labelled sender-limited; the true in-kernel drop cost per packet is measured by the microbenchmark. §V-D, §VI-E | Code, Exp, Text |
| R1.19 | Disabling TX checksum offload also disables TSO/GSO for all configurations, capping TCP throughput | **Agreed; discussed.** §V-B and §VI-G explain the effect and that it applies equally to all configurations | Text |

### C. Model, text and presentation

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R1.20 | Related work omits Polycube, bpf-iptables, OVS/eBPF studies (Tu et al., Oko), nftables/IPVS; novelty framing | **Added** [9], [11], [12], [14], [16], [17], [19], [23] (Polycube, Tu et al., Oko, bpf-iptables, nftables, IPVS/LVS, Tuple Space Search, RFC 768); contribution re-framed as a formally specified single-program pipeline plus a like-for-like evaluation, not a first implementation. §I, §II | Text |
| R1.21 | "Passes 69 tests" vs. 68 passing + 1 skipped | **Fixed** with the new suite: 93 tests, 92 pass, 1 skipped (stated precisely in Abstract, §VI-A, §VII) | Text |
| R1.22 | ARP admission not formalised; $m_6$–$m_9$ not restricted to IPv4; $E(f)$ when tracking is disabled | **Fixed.** §III-D defines admission for non-IPv4 frames, restricts IPv4 patterns, and includes $\gamma$ in $E(k)$ | Text |
| R1.23 | Partial order of mask specificity; tie-breaking; DROP precedence over state | **Clarified.** The pattern order is defined as a total priority order (like OpenFlow priorities), with the resolution of incomparable pairs and the deliberate DROP-over-state precedence stated. §III-C–D | Text |
| R1.24 | $\min\emptyset$ undefined when all backends are drained | **Fixed.** Eq. (6) is conditioned on $\sum_j \alpha_j > 0$ | Text |
| R1.25 | Checksum $\pm 0$: ones'-complement notation; 0x0000→0xFFFF applies only to UDP | **Fixed.** Eq. (8) uses $\oplus$ (ones'-complement addition); §III-G states the UDP-only substitution and the 32-bit accumulate/fold implementation | Text |
| R1.26 | Notation: $E(f)$ boolean vs. integer; mutually exclusive guards; $k\in[0,n)$; "address and port"; spacing of ${\sim}$; unpack $b=(a_b,p_b)$ in Alg. 2 | **All fixed** (Eqs. (4)–(6), (8); Alg. 2) | Text |
| R1.27 | Non-first fragments: masks, tracking, NAT | **Clarified.** §IV-A "Fragments": no reassembly; port patterns skipped ($\rho=0$); tracked under a port-less key; not load-balanced | Text |
| R1.28 | Map names not linked to formal symbols | **Added** Table I (symbols ↔ maps) | Text |
| R1.29 | Global counter updates omitted from Alg. 1 | **Stated** in §IV-A | Text |
| R1.30 | How the XDP L3 checksum update is computed alongside the 8-byte L4 update | **Clarified** in §IV-C (two `bpf_csum_diff` calls: 4 bytes for IPv4, 8 bytes for L4) | Text |
| R1.31 | Ambiguous "21–26% below kernel routing" for TCP vs. packet rate | **Fixed**: the two metrics are reported separately (Abstract, §VII) | Text |
| R1.32 | Verify software versions | **Verified**: versions are now recorded automatically by `benchmark.sh` (`results/repeated/environment.txt`) and copied into §V-B | Exp, Text |
| R1.33 | 4.9% vs. 4.7% rounding; leading zeros in Table II; "re-places" | **Fixed** (all percentages now computed from the reported means; consistent number formatting; wording) | Text |
| R1.34 | Online references lack years/access dates | **Fixed** [7], [8], [16] | Text |
| R1.35 | Citation checker: four references flagged because author lists were abbreviated to "et al." | **Fixed**: full author lists and DOIs for all references; every reference re-checked against Crossref or the publisher | Text |

### D. Findings of the original draft that the revision overturned

The repeated, pinned measurements changed two conclusions of the draft. Both
are corrected in the paper rather than hidden:

| Draft (v0, single unpinned run) | Revision 1 (10 interleaved, pinned rounds) |
|---|---|
| "FIB forwarding improves TCP throughput by 21.9% over TC" | No significant difference (+2.2%, p = 0.58); stated explicitly in §VI-C |
| "XDP has the highest RTT (0.047 ms)" | All average RTTs are 1.9–3.8 µs, at ping's 1 µs resolution; only OVS's maximum RTT differs (first-packet upcall); §VI-D |
| Absolute values ~3 Gbit/s, ~150–190 kpps | ~9–14 Gbit/s, ~0.5–0.7 Mpps: unpinned runs were scheduled on efficiency cores under a power-saving governor; §VI-C |
| "Only the eBPF data plane supports conntrack and draining" | True only for stateless OpenFlow 1.3; OVS-ct and nft+IPVS support both; §VI-F |

### Summary of new evidence in Revision 1

- Automated tests: 93 (37 unit, 56 kernel; 92 pass, 1 skipped by a kernel test-harness limitation).
- Functional scenarios (`results/repeated/scenarios/`): eBPF (XDP, TC), nftables+IPVS and OVS+conntrack pass all 9 checks; stateless OVS passes 8 (no conntrack). Load splits: χ² = 1.52–5.52, p = 0.14–0.68 (uniform not rejected).
- Benchmarks (`results/repeated/raw/`, `summary.json`): 7 configurations × 10 interleaved rounds, governor `performance`, tools pinned to performance cores; mean ± 95% CI, Welch t-tests (`python3 -m testbed.aggregate --compare`).
- Key result: at the TC hook the eBPF data plane is statistically indistinguishable from nftables+IPVS (TCP −2.4%, p = 0.48); OVS+conntrack is 10–19% faster; all stateful designs cost 13–31% vs. plain routing.
- Microbenchmark (`results/repeated/microbench.json`): 0.21–0.23 µs per admitted packet, flat from 0 to 10,000 rules and 0 to 60,000 connections; drop 0.15 µs (6.6–6.9 Mpps per core).
- Environment recorded automatically: `results/repeated/environment.txt` (Linux 7.2.15, Clang 23.1.3, libbpf 1.7.0, OVS 4.0.0, nftables 1.1.7, ipvsadm 1.31, iperf3 3.22).
