# Revision Report

**Paper:** In-Kernel Programmable Data Planes for SDN: An eBPF/XDP Gateway with
Stateful Firewalling and L4 Load Balancing Compared with Open vSwitch

**Review tool:** Google Deep Review (https://research.google/deepreview/)

| Version | File | Reviewed in |
|---|---|---|
| Initial draft | `paper/versions/v0_draft.pdf` | Round 1 |
| Revision 1 | `paper/versions/v1_revision1.pdf` | Round 2 |
| Revision 2 | `paper/versions/v2_revision2.pdf` | Round 3 |
| Revision 3 | `paper/versions/v3_revision3.pdf` | Round 4 (recommended) |

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

---

## Round 2: review of Revision 1 (v1) → Revision 2 (v2)

Full reviewer output: `paper/revisions/round2_comments.md`

As in Round 1, comments that pointed at real behaviour of the implementation
were fixed in the code first, each with a regression test, and the paper was
then updated to describe the corrected system. All experiments were re-run
from scratch (`results/rev2/`, 2026-11-17).

**Legend:** Code = implementation changed · Exp = experiments re-run or added ·
Text = paper text, equations or figures changed.

### A. Framing, positioning and conclusions

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R2.1 | The single-program design is contrasted with chained eBPF frameworks (Polycube, bpf-iptables) without an eBPF baseline or ablation | **Ablation added.** `bpf/chain.h` splits the same code into three programs (firewall → LB/NAT → telemetry) chained by `bpf_tail_call`, each re-parsing the packet; a kernel test checks that it gives the same verdicts and packets (`ChainAblationTest`). Result: the chain costs +35 ns (+37%) on the pass path, +69–80 ns (+33–47%) on DNAT/SNAT, +3 ns on drop. §II now states that the single program is chosen mainly for specification and state coupling, and that Polycube/bpf-iptables themselves are not benchmarked. §I (contribution 1), §V-D (e), §VI-E, Table V | Code, Exp, Text |
| R2.2 | Abstract says OVS-ct is "10–19% faster" with percentages computed against OVS-ct (inverted base) | **Fixed.** With the new data the comparison itself changed (see §D below); every relative figure now states its reference, e.g. "13% below the latter in packet rate" | Text |
| R2.3 | Per-packet range "0.21–0.23 µs" excludes the 259 ns intermediate point | **Fixed.** Abstract and §VII now report ranges that cover every measured point (74–100 ns with empty tables; 250–295 ns with all ten patterns populated) | Exp, Text |
| R2.m1 | `AF_XDP` underscore rendering | Set as `\texttt{AF\_XDP}` | Text |

### B. Formal model and data-plane semantics

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R2.4 | Direction of the client-visible key κ(x): a reply gets (v, c, …) and does not match VIP rules written as destination (m8); interaction with γ = 0 and with DROP rules on in-flight replies | **Fixed in code and model.** κ(x) is now the *canonical* client→VIP orientation (c, v, p_c, p_v, π) for replies (Eq. (4)), so one VIP rule covers both directions even without conntrack, and T_fw entries are shared by both directions. Adding a DROP rule flushes matching state, including reverse-NAT entries for VIP rules. Tests `test_one_vip_rule_covers_both_directions_without_conntrack`, `test_vip_drop_rule_blocks_both_directions`, `test_reply_does_not_duplicate_firewall_state`, `test_drop_rule_on_vip_flushes_its_reverse_nat_entries`. §III-D, Alg. 1 | Code, Text |
| R2.5 | Asymmetric LRU eviction / reaper races between L[f] and T_rev[r(f)]: forward recovery fails while draining; reply-side loss of T_rev not recovered | **Fixed.** T_rev entries now store the service id and backend index j. (i) Forward packet with L[f] missing: the program probes T_rev for each pool backend and restores L[f], also for drained backends (`test_forward_entry_recovered_while_draining`). (ii) Reply with T_rev missing: new endpoint index `lb_endpoints` (E: backend endpoint → service) plus L[f] re-create T_rev (`test_reverse_entry_recovered_on_reply`). (iii) Replies from a service endpoint with no state at all are dropped (isolation, `test_backend_reply_without_any_state_is_isolated`). §III-F "Recovery", Alg. 2, Table I | Code, Text |
| R2.6 | Linear probing gives a drained backend's whole share to its neighbour; n overloaded (pool size vs. active count) | **Fixed.** Selection now indexes a list of active backends λ (`lb_active`, maintained by the control plane): j = λ[h(f) mod n_act]. Eq. (6) and Eq. (7) use n and n_act distinctly. Test `test_drained_backend_share_spreads_evenly`; microbenchmark (f): 20,000 connections, χ² = 0.99 (p = 0.80) with all backends, χ² = 0.13 (p = 0.94) with one drained | Code, Exp, Text |
| R2.7 | Domains of A₂(x) (patterns 1–2 on the frame) and A(k) (patterns 3–10 on the key); role of L2 ALLOW | **Fixed.** Eq. (3) defines A₂ over I₂ = {1,2} on the Ethernet header and A over I₄(x) = {3..10} minus port patterns when ρ(x) = 0; the text states that an L2 ALLOW only exempts a frame from a broader L2 DROP | Text |
| R2.8 | Fragments: first fragment NAT-ed, later ones not; port rules break fragmented flows; zero-port key aliasing; injectivity must be per (address, port, protocol) | **Fixed.** *Every* fragment (first included) is now port-less (ρ = 0) and never load-balanced or rewritten, so a datagram's fragments are treated consistently (`test_fragments_are_not_load_balanced`). §IV-A lists the consequences (address-level rules needed; shared port-less entry; services require unfragmented traffic). Backend disjointness is enforced per (ip, port, proto) (`test_disjointness_is_per_protocol`); §III-F. Direct access to a backend's service endpoint is isolated (`test_backend_service_endpoint_reachable_only_through_vip`) | Code, Text |
| R2.m2 | Fig. 1 order vs. Alg. 1 | Caption explains "Conn. track" = T_fw update, "NAT" = rewrite, and that reply classification precedes the firewall | Text |
| R2.m3 | "pattern" vs. "pattern id" | Table I uses "pattern id" | Text |
| R2.m4 | Eq. (4) (d, p_d) vs. (c, p_c) | §III-D states (d, p_d) = (c, p_c) for a reply | Text |
| R2.m5 | Σ bounds | Σ_{j=0}^{n−1} used consistently, via n_act | Text |
| R2.m6 | Forward FIN/RST flags | §III-F states both directions record FIN/RST in L[f] | Text |
| R2.m7 | T_fin typesetting | All multi-letter subscripts use `\mathrm` | Text |

### C. Pipeline and control plane

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R2.9 | Telemetry keyed by f, firewall by k: intended? | **Intentional, now stated.** §IV-D explains that telemetry uses the packet's own pre-NAT key so per-backend return traffic is visible | Text |
| R2.10 | How one 8-byte `bpf_csum_diff` covers address and port word, which are not adjacent | **Clarified.** §IV-C: the program stages old and new (address, 32-bit port word) in two contiguous 8-byte stack buffers | Text |
| R2.m8 | `LoadBalance(f)` uses ρ(x) from the caller | Signature is now `LoadBalance(f, ρ, kind)` (Alg. 1 line 15, Alg. 2) | Text |
| R2.m9 | Alg. 2: r(f) used before b is unpacked; stale entry deletion in prose | (a_b, p_b) ← b moved before its use; `delete T_rev[r_old(f)]` written symbolically | Text |

### D. Experimental design and results

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R2.11 | Macro-benchmarks bypass the load balancer (routed path only) | **VIP benchmark added.** A second service v' = 10.100.0.2:5202 (TCP+UDP, single backend s2) carries iperf3 TCP and 64-byte UDP through backend selection, NAT state and DNAT/SNAT. Table IV and Fig. 2 report both paths; §V-D defines them. The eBPF VIP path is at most 8.7% slower than its routed path | Code, Exp, Text |
| R2.12 | Microbenchmark: repeat loop keeps state cache-hot; single-shot overhead; whether DNAT is new or established; "forces all ten lookups" also at 0 rules | **All addressed.** (i) New cache-cold test: 60,000 flows in random order cost 682/679 ns vs. 124/137 ns for one flow (XDP/TC). (ii) Paths now distinguish DNAT of an established vs. a new connection (2.1–2.4 µs) and quantify the single-shot overhead (60–80 ns) by timing the pass path both ways. (iii) The data plane now skips unpopulated patterns (pattern mask in `dp_config`, maintained by the control plane; `test_mask_tracks_populated_patterns`), and Fig. 3 shows the real dependence: 74–100 ns with no populated pattern, 250–295 ns with all ten, ≈16–20 ns per pattern, flat in the number of rules. §V-D, §VI-E, Fig. 3, Table V | Code, Exp, Text |
| R2.13 | Sender/softirq co-location; daemon and ovs-vswitchd affinity; rule count during macro runs | **Fixed/stated.** `run_experiments.sh` pins ovs-vswitchd and the eBPF daemon to CPUs 1,3 (siblings of the traffic cores) and restores afterwards; §V-D states the affinity and that rule tables are empty (flood test: one rule). §VI-E contrasts the sender-limited flood rate with the in-kernel drop cost (62–67 ns ≈ 15–16 Mpps). Reaper cost now measured: 0.82 s per 180,000 entries | Code, Exp, Text |
| R2.14 | TC+FIB missing from Table II / Fig. 2; XDP+FIB not explained | **Fixed.** TC+FIB runs all Mininet scenarios and appears in Tables II and III; §V-A explains why XDP+FIB is not evaluated (veth XDP_REDIRECT requires an XDP program on the peer inside each host) | Exp, Text |
| R2.15 | Low power of N = 100; post-drain counts not reported | **Fixed.** Table III gives exact counts before and after draining, with χ²; the in-kernel test (f) uses 20,000 synthetic connections. Threats to validity mention the low power of T3 | Exp, Text |
| R2.16 | Version strings (Linux 7.2.15, Clang 23.1.3, OVS 4.0.0) look implausible | **Verified.** They are the versions on the test machine (rolling release, November 2026), recorded automatically by `benchmark.sh` in `results/rev2/environment.txt` from `uname -r`, `clang --version`, `ovs-vswitchd --version`; §V-B says so | Exp, Text |
| R2.m10 | "92 of 93" counts | Now "115 of the 116 automated unit and kernel tests pass and one is skipped; the Mininet checks are counted separately" (41 unit + 75 kernel) | Text |
| R2.m11 | χ² for OVS vs. bar heights in Fig. 2 | Distribution figure replaced by Table III with exact integer counts | Text |
| R2.m12 | Percentages vs. rounded table means | §VI opening note: percentages come from unrounded means | Text |
| R2.m13 | Missing comma before p | Fixed throughout §VI | Text |
| R2.m14 | n/a vs. – in tables | "n/a" used in all tables, defined in captions | Text |
| R2.m15 | Table IV super-headers | Table V now groups "Repeat loop" and "Single-shot (incl. timing overhead)" | Text |
| R2.cit | Citation checker | No reference flagged in Round 2; bibliography unchanged | — |

### E. How the results changed between Revision 1 and Revision 2

| Revision 1 | Revision 2 (`results/rev2/`) | Why |
|---|---|---|
| All eBPF configurations 10–19% below OVS-ct | TC and TC+FIB statistically indistinguishable from OVS-ct on routed and VIP paths (except TC+FIB +6.9% VIP pps, p = 0.011); XDP 13.1% below in packet rate | The pattern mask skips unpopulated rule patterns; macro-runs use empty rule tables (best case, stated in §VI-C and §VI-G) |
| eBPF TC ≈ nft+IPVS | Routed path: still ≈ (n.s.). VIP path: TC +12.8% TCP (p = 0.025), TC+FIB +17.5% TCP / +16.0% pps (p < 0.001) | New VIP benchmark compares the load balancers directly |
| Stateful cost vs. kernel 13–31% | 13.6–26.9% | — |
| 0.21–0.23 µs per admitted packet, flat | 74–100 ns with empty tables; 250–295 ns with all ten patterns populated; flat in rule and connection counts; 0.68 µs cache-cold | Pattern mask; new canonical-key/recovery logic adds work per probed pattern; new cache-cold test |
| Drop 145–151 ns | 62–67 ns | Pattern mask (one populated pattern in the path test) |
| FIB: no significant gain | Still no significant throughput gain; but 34% lower average RTT (p = 0.002) | — |

Note: about 40 comparisons are reported without multiple-comparison correction; §VI states that p-values between 0.01 and 0.05 are only suggestive.

### Summary of new evidence in Revision 2

- Automated tests: 116 (41 unit, 75 kernel = 37 cases × 2 hooks + 1 chain-equivalence test); 115 pass, 1 skipped (TC truncated frame).
- Functional scenarios (`results/rev2/scenarios/`): all seven configurations including TC+FIB pass every applicable check; χ² = 1.52–5.36 (p ≥ 0.15) before draining, ≤ 5.12 (2 dof) after.
- Benchmarks (`results/rev2/raw/`, 7 configurations × 10 interleaved rounds, routed and VIP paths). Note: `results/rev2/summary.json` was written by the root run; regenerate with `python3 -m testbed.aggregate results/rev2 …`.
- Microbenchmark (`results/rev2/microbench.json`): rules, conntrack, cache-cold, paths (incl. new connections), tail-call ablation, 20,000-connection uniformity, reaper sweep.
- Environment: `results/rev2/environment.txt`.
- Paper: `paper/versions/v2_revision2.pdf` (11 pages) and `.tex`.


---

## Round 3: review of Revision 2 (v2) → Revision 3 (v3)

Full reviewer output: `paper/revisions/round3_comments.md`

As before, comments about the implementation's behaviour were fixed in code
first, each with a regression test, and all experiments were re-run from
scratch (`results/rev3/`, 2026-11-18, 13 configurations × 10 interleaved
rounds). The user additionally asked for 12–14 supplementary figures with
95% confidence intervals; they form the new Appendix (Figs. 4–17, Table VI).

### A. Framing and conclusions

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R3.W1 / R3.E3 | TC+FIB (stack bypass) compared only with un-offloaded nft+IPVS; consider `nf_flow_table` | **New baseline nft-FT** (`testbed/gateways.py: NftFlowtableGateway`): nftables DNAT via jhash map + software flowtable for established TCP/UDP, drop rules before offload, conntrack flush on rule add. Result: nft-FT is the fastest stateful configuration; every eBPF configuration is 11–25% slower (TC+FIB −19.7±5.2% routed TCP, p<0.001). The paper now says the TC+FIB advantage over nft+IPVS comes mostly from bypassing the forwarding path. Related work, §V-A, §VI-C, §VI-F, abstract and conclusion updated | Code, Exp, Text |
| R3.W2 / R3.E4 | Tail-call ablation: mixed denominators, re-parsing not isolated, single-shot pass not measured, KFuse/Morpheus | **Second chained variant** (`bpf/chain.h`, `xdp_chainm_*`) shares the parse result through a per-CPU map; both variants measured repeat-loop and single-shot incl. pass; raw and harness-adjusted percentages reported. Result: no measurable chaining cost when hot; +46–67 ns (+30–31% raw, +38–40% adjusted) single-shot on pass/DNAT; sharing metadata is *slower* than re-parsing. The previous 33–47% claim is withdrawn. KFuse and Morpheus cited (§II) | Code, Exp, Text |
| R3.W3 / R3.E2 | Macro-benchmarks only with empty rule tables | **"+rules" configurations**: 1000 non-matching rules over all ten patterns in each system's idiomatic form (`testbed/rules.py`: BPF maps, nftables concatenated sets, OpenFlow ACL flows) for TC, TC+FIB, nft+IPVS, nft-FT, OVS-ct. Result: eBPF loses 11–16% routed TCP; nft+IPVS 31%; nft-FT and OVS-ct no measurable change, so eBPF falls 6–14% behind OVS-ct on most metrics. Discussion proposes a per-flow verdict cache | Code, Exp, Text |
| R3.F1 | "the latter" antecedent in abstract | Sentence rewritten; the abstract names each baseline explicitly | Text |
| R3.F2 | Rule- and connection-scaling claims merged | Abstract and conclusion separate them (connections measured with empty tables, rules with all patterns) | Text |
| R3.m1 | 25–32% savings vs 33–47% overhead | Both replaced by one, re-measured statement (30–40% cold, ~0 hot) | Text |
| R3.m2 | DOI consistency | DOIs added to all entries that have one (incl. [2], [13]); new references verified against Crossref | Text |

### B. Formal model and data-plane semantics

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R3.M1 | Forward vs reply direction in T_fw; directional rule semantics under κ | §III-D defines a reply for T_fw (LB REPLY or reverse-key hit), states that flags are a union, and that pattern rules on VIP traffic are connection predicates over the client-visible key | Text |
| R3.M2 | Backend replacement/removal vs LRU recovery | **Fixed in code.** Backends keep fixed slots when a service is redefined; removed/replaced backends have their state flushed (`conntrack.flush_backend`); replies are checked against the backend slot (`lb_slot_holds`) and a stale slot isolates the reply; recovery verifies `be_idx`. Tests: `test_replacing_a_service_keeps_backend_slots`, `test_removed_backend_state_is_flushed`, `test_reply_from_replaced_backend_slot_is_isolated` | Code, Text |
| R3.M3 | Signature of A(k) under ρ=0 | A(k,ρ) defined with shorthand A(k); I₄(ρ) introduced | Text |
| R3.m3–m6 | "drain flag" polarity; Table I 16×16 partition; r_b(f) undefined; χ² needs n_act ≥ 2 | α renamed "active flag"; caption "16 services × 16 slots"; r_b(f) defined in §III-F; n_act ≥ 2 stated | Text |
| R3.m7 | Fig. 1 does not show reply classification | Fig. 1 has a "Classify reply" stage | Text |

### C. Pipeline and control plane

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R3.P1 | Reply classification mutates state before firewall admission | **Fixed in code.** `lb_reply_lookup` is read-only; T_rev/L are refreshed or re-created by `lb_reverse_nat` only after admission. Test: `test_dropped_reply_creates_no_lb_state`. Alg. 1/2 rewritten accordingly | Code, Text |
| R3.P2 | Redundant overwrites on established hits | In-place refresh instead of full rewrites; `rev_store(..., fresh)` | Code, Text |
| R3.P3 | Fragments vs isolation, port DROP rules, PMTUD | **Fixed in code.** First fragments carry their ports (`first_frag`, `ff_sport/ff_dport`) and are dropped if they hit an isolated endpoint or a port DROP rule. Tests: `test_first_fragment_to_service_endpoint_is_dropped`, `test_first_fragment_obeys_port_drop_rules`. PMTUD/ICMP limitation stated in §IV-A | Code, Text |
| R3.P4 | Recovery loop on every new connection | **Fixed in code.** TCP SYNs never enter recovery (`tcp_opening`), so a reused client port cannot be captured by stale reverse state (`test_syn_does_not_rejoin_a_stale_reverse_entry`). New UDP flows still probe n entries; measured: new TCP 1.5–1.7 µs, new UDP 2.0–2.2 µs | Code, Exp, Text |
| R3.P5 | Reaper deletion ordering, L2/wildcard DROP flush | Reaper re-checks the partner T_rev entry before deleting it (`test_refreshed_reverse_entry_survives_its_partner`); §IV-E states the flush scope and active-list update ordering | Code, Text |
| R3.m8–m10 | UDP zero checksum in XDP path; Alg. 2 index bound; T_rev value notation | §IV-C note; `0 ≤ i < n`; T_rev[r_b(f)] ← (v, p_v, σ, j) | Text |

### D. Experimental design and results

| # | Reviewer comment (summary) | Response and changes | Type |
|---|---|---|---|
| R3.E1 | 60k-flow cache-cold test confounds cache misses with telemetry LRU eviction | Cold test now at 1k / 15k / 60k flows; 15k fits the 16,384-entry telemetry table. Result: 290 ns (TC) / 524 ns (XDP) already at 15k, so most of the rise is cache misses; eviction adds 145 ns at TC. Baselines stated as zero-rule | Exp, Text |
| R3.E5 | TC 78–82 ns vs 100 ns contradiction | Re-measured with a longer warm-up: TC 78 ns with empty tables in both sweeps for large tables, but 106/95 ns at 0/1k connections. Reported as transient interference; the paper states a ~30 ns reproducibility limit for repeated measurements | Exp, Text |
| R3.E6 | Unpaired tests on a paired design; reaper/SMT contention; E-cores | Paired t-tests on per-round relative differences are now primary (Welch for comparison; pairing changed no conclusion). §V-D states daemon/OVS affinity, E-cores enabled, softirq co-location, and that tables held at most 608 entries (sweep ≈ 3 ms) | Code, Exp, Text |
| R3.E7 | Identical TC/TC+FIB counts in T3 | T3 now records client ports. `testbed/verify_t3.py` replays them through an offline model of the hash: 375/375 eBPF choices reproduced. TC's uneven sample (χ²=12.16, p=0.007) is explained by its port sample; previous identical counts most likely from repeated port sequences (not verifiable). Paper notes the unseeded hash is predictable | Code, Exp, Text |
| R3.m11 | Table III post-drain p column | Added | Text |
| R3.m12 | "on the routed path" in hooks bullet | Bullet rewritten for both paths | Text |
| R3.m13 | OVS p ≤ 0.004 | Superseded by new data (paired p reported) | Text |
| R3.m14 | "CI as wide as its mean" | Sentence replaced (new data) | Text |
| R3.m15 | 3 × 65,536 = 196,608 | Stated in the reaper paragraph | Text |
| User | 12–14 figures with 95% CI at the end | Appendix A: 14 figures (Figs. 4–17), zoomed axes stated in each caption, Table VI index with unit, configurations and data file; generated by `paper/make_figures.py results/rev3` | Text |

### E. How the results changed between Revision 2 and Revision 3

| Revision 2 | Revision 3 (`results/rev3/`) | Why |
|---|---|---|
| TC+FIB 16–18% faster than nft+IPVS through the VIP | TC/TC+FIB +18% routed TCP vs nft+IPVS; VIP +7–11% TCP; but 11–25% slower than nft-FT | New flowtable baseline; re-run |
| eBPF ≈ OVS-ct (empty tables) | Unchanged with empty tables; 6–14% behind OVS-ct with 1000 rules | New populated-rule runs |
| Tail calls cost 33–47% | ~0 hot; 30–40% single-shot on pass/DNAT; shared metadata slower | Corrected denominators, new variant |
| 74–100 ns empty tables; 250–295 ns all patterns | 68–79 ns; 224–270 ns | Longer warm-up, re-run |
| 0.68 µs cold (60k) | 0.29–0.52 µs at 15k; 0.44–0.46 µs at 60k | New sizes separate eviction |
| TC+FIB −34% RTT vs TC (p=0.002) | −11.5±35.4% (p=0.48): not reproduced | Re-run |
| New connection 2.1–2.4 µs | TCP SYN 1.5–1.7 µs (no recovery probes); UDP 2.0–2.2 µs | SYN rule |
| Stateful cost vs kernel 13.6–26.9% | Kernel had an outlier round (5.5 Gbit/s); excluding it: eBPF 13.6–20.4%, OVS-ct 17.5%, nft+IPVS 25.8%; nft-FT ≈ kernel | Re-run; sensitivity check stated |

### Summary of new evidence in Revision 3

- Automated tests: 130 (45 unit, 85 kernel = 42 cases × 2 hooks + 1 chain-equivalence test for both chained variants); 129 pass, 1 skipped (TC truncated frame).
- Functional scenarios (`results/rev3/scenarios/`): all seven configurations incl. nft-FT pass every applicable check; client ports recorded; `python3 testbed/verify_t3.py results/rev3` reproduces 375/375 eBPF backend choices.
- Benchmarks (`results/rev3/raw/`): 8 configurations + 5 "+rules" variants × 10 interleaved rounds, routed and VIP paths, paired tests.
- Microbenchmark (`results/rev3/microbench.json`): rules, conntrack, cold (1/1k/15k/60k), paths incl. new TCP/UDP, two chained variants, uniformity, reaper.
- Environment: `results/rev3/environment.txt`.
- Paper: `paper/versions/v3_revision3.pdf` (16 pages incl. 4-page figure appendix) and `.tex` (+ `v3_revision3_appendix_figs.tex`).
