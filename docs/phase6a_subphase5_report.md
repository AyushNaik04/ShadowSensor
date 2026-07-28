# Phase 6A - Sub-Phase 5 Completion Report (RE-RUN following feature-extraction scoping fix)

**Date/time executed:** 2026-07-27
**Sub-phase goal (restated):** Report true, observed activation rates for every binary/count feature in the exported CSV - no invented thresholds, plain facts only, with explicit flagging of anything categorically inconsistent with a benign-only session.
**Context:** This SUPERSEDES the earlier Sub-Phase 5 analysis, which was run against a contaminated benign_baseline.csv (795 windows, all-time unscoped extraction mixing today's session with weeks of Phase 4A/4B attack-simulation data). scripts\run_feature_extraction.py has since been fixed to support --since/--until time-window scoping (see docs/scoping_fix_final_report.md). A VM-internal clock discrepancy was also discovered during re-extraction: logs\rule_hits.log timestamps and SQLite events.timestamp values are offset from each other by a confirmed +7 hours (verified by matching the live-observed WARP OpenProcess hit at rule_hits.log time 02:11:56 to its SQLite-stored timestamp 09:11:56.731641), separate from the previously-documented ~12h VM-vs-host drift (docs/vm_clock_drift_finding.md). Per Ayush's direction, rather than rely on an exact narrow window given the extra clock uncertainty, extraction was widened to an 8-hour same-day window: --since "2026-07-27 02:00:00" --until "2026-07-27 10:10:00", anchored against the database's confirmed max timestamp (2026-07-27 10:07:19.117870).

## What Was Completed
- Ran corrected extraction: python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --since "2026-07-27 02:00:00" --until "2026-07-27 10:10:00" --output data\features\benign_baseline.csv
- Extracted 621 process windows (down from the contaminated 795)
- Verified CSV structure: 31 header columns, 621 data rows, first column cmd_length, last column label
- Computed activation rates for all 18 binary features
- Computed summary stats (min/max/mean) for 11 numeric/count features
- Verified LOLBIN_NAMES set directly: rundll32.exe present, powershell.exe absent

## What's Working
Decontamination fully confirmed. All rule-hit-derived flags that were nonzero due to weeks-old Phase 4A/4B attack simulations are now correctly zero: has_encoded_command 7->0, has_download_keyword 8->0, is_known_suspicious_chain 33->0, has_powershell_rule_hit 44->0, has_lolbin_rule_hit 32->0, has_network_rule_hit 9->0, has_chain_rule_hit 36->0. is_off_hours also dropped to 0/621 (0.00%%), though this feature's reliability is separately caveated below given the clock discrepancy.

Remaining nonzero activations are all attributable to the already-logged Cloudflare WARP install/VPN session from Sub-Phase 2 (2026-07-27, rule_hits.log time 02:10:51-02:11:56), not new contamination:
- open_process_suspicious_access: 242/621 (38.97%%) - warp-svc.exe / wmiprvse.exe / svchost.exe -> winlogon.exe/lsass.exe pattern
- open_process_lsass_target: 6/621 (0.97%%)
- is_lolbin: 15/621 (2.42%%) - confirmed via direct LOLBIN_NAMES check to be rundll32.exe (present in the set), not powershell.exe (absent from the set) - consistent with the WARP installer's rundll32.exe usage
- unsigned_image_loaded: 21/621 (3.38%%)
- is_suspicious_parent: 6/621 (0.97%%)
- has_api_rule_hit: 9/621 (1.45%%) - consistent with the OpenProcess-category rule hits in the same cluster

Numeric feature stats all fall within plausible ranges for a long benign window: cmd_length mean 130.08 (max 1217), cmd_entropy mean 2.44 (max 5.29), dns_query_length mean 0.19 (max 23, no tunneling-length outliers), create_remote_thread_count min/max/mean all 0.00 (zero injection activity anywhere in the window), rule_hit_count max 7 / unique_rules_fired max 2 (small, consistent with the WARP cluster concentrating on a couple of process windows). open_process_count max 11011 is high but plausible for a long-lived system/background process accumulating routine handle opens over several hours.

## What's Not Working / Unexpected
A new, separate clock discrepancy was discovered during this re-run: logs\rule_hits.log and SQLite events.timestamp appear to be stamped ~7 hours apart from each other (confirmed via the WARP OpenProcess hit matched across both sources), independent of the already-documented ~12h VM-vs-host drift. This is not fixed or root-caused in this sub-phase - flagged for follow-up alongside the existing VM clock drift finding. Because of this, is_off_hours (0/621, 0.00%%) should be treated with caution until the VM's actual clock source(s) are reconciled - a 0.00%% off-hours rate for a session that included real off-hours-adjacent activity (per the human narrative) may reflect the wrong clock being used for the hour_of_day computation, not a genuine finding.

## Issues Log
1) NEW - VM internal clock discrepancy (rule_hits.log vs. SQLite events.timestamp), confirmed +7h offset, separate from the previously-documented ~12h VM-host drift. Not fixed here; recommend consolidating both clock findings into a single follow-up task before Phase 6B/7B rely on hour_of_day/is_off_hours.
2) CARRIED FORWARD, not new - open_process_suspicious_access activations and the wmiprvse.exe/svchost.exe -> winlogon/lsass pattern remain consistent with Phase 4B's previously-logged, still-open/inconclusive Issue 4. No new escalation warranted from this data alone.
3) CARRIED FORWARD, not new - all WARP-related rundll32.exe / OpenProcess activations already logged in docs/phase6a_subphase2_report.md (re-run version); no new occurrences beyond what was already captured live.

## Ready to Proceed?
Yes - Sub-Phase 5 re-run complete against decontaminated data. All previously-contaminated rule-hit-derived features confirmed at zero; remaining nonzero activations fully attributed to already-logged real session activity. Awaiting Ayush's go-ahead for Sub-Phase 6 (Dashboard Cross-Check).
