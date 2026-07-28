# Phase 6A — Final Consolidated Report

**Date range:** 2026-07-27
**Status:** Phase 6A COMPLETE — all 7 sub-phases closed.
**Purpose:** Single self-contained handoff document for Phase 6B (Codex/Cursor, Sonnet 4.6 medium-effort). No need to re-read prior sub-phase reports individually.

---

## 1. Collection Window

- **Original session (2026-07-27, ~11:05–12:23 host-local):** Clean, zero rule hits, but never persisted to SQLite due to a since-fixed silent write-path bug (see Section 3). Superseded.
- **Re-run session used for this baseline:** VM-local session bounded by `logs/rule_hits.log` markers `2026-07-27 01:38:21` (SESSION START) → `2026-07-27 03:07:19` (SESSION END), duration 1:28:58. Human/host-local narrative time was approx 14:00–15:38 IST; the discrepancy between these two framings is explained by the VM clock drift finding (Section 6).
- **Activities performed:** YouTube browsing/streaming, general web surfing, downloading and installing Cloudflare WARP, reading manga on asurascans.com, Edge browsing, Notepad opened, idle periods, periodic dashboard monitoring. No simulation scripts, no encoded commands, no LOLBin invocations, no Atomic Red Team techniques were run at any point.
- **Live-observed rule hits during the session:** Two clusters, both tied to the Cloudflare WARP install/VPN activity — not simulation-triggered:
  1. `API_LOLBIN_DLL_UNSIGNED_001` / `API_DLL_LOAD_SUSPICIOUS_PATH_001` on `rundll32.exe` (~30+ hits, 02:10:51–02:11:53 rule_hits.log time) — attributed to the WARP installer invoking rundll32.exe to load unsigned setup/network-driver DLLs.
  2. `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` (2 hits, 02:11:56) — `warp-svc.exe` opening handles to `winlogon.exe` and `lsass.exe`. Structurally similar to the previously-open, inconclusive Phase 4B Issue 4 (wmiprvse.exe/svchost.exe → winlogon/lsass pattern).
  - No RULE_HITs occurred outside this ~65-second window; the remaining ~1h37m of session activity produced zero rule fires.

---

## 2. Final Database State

Post-collection row counts (full cumulative database, all project history):

| Table | Sub-Phase 1 baseline | Post-collection | Delta |
|---|---:|---:|---:|
| events | 346 | 71,544 | +71,198 |
| rule_hits | 349 | 399 | +50 |
| alerts | 349 | 399 | +50 |
| model_scores | 0 | 0 | 0 |

Database spans 2026-07-01 10:52:30 through 2026-07-27 10:07:19 (SQLite-clock time), i.e. the full project history since early Phase 3/4 testing, not just this session.

Spot-check of most recent events confirmed sane, real data: varied event_type_id values (3, 7, 10), plausible image paths (lsass.exe, OneDrive.Sync.Service.exe, MsMpEng.exe, svchost.exe), sequential recent timestamps, plausible PIDs.

---

## 3. Blocker #1 — Silent SQLite Write-Path Failure (FIXED)

**Discovered:** Sub-Phase 3, original collection attempt.
**Root cause (three chained bugs):**
1. `scripts/run_pipeline.py`: an early `return` on `if not hits` skipped SQLite persistence entirely for benign zero-hit events — the majority of all real traffic.
2. `storage/storage_writer.py`: write functions caught all exceptions, logged a one-line warning, and returned `None` without re-raising — failures were invisible to the outer handler.
3. The outer exception handler in `run_pipeline.py` referenced an undefined `logger` variable, raising a `NameError` on any exception it did try to handle, further hiding failures.

**Effect:** No new events/rule_hits/alerts were written to SQLite between 2026-07-12 23:07:35 and the fix landing on 2026-07-27, despite the pipeline running normally and `logs/rule_hits.log` continuing to write correctly the entire time — an ~15-day silent gap across at least 8 separate sessions.

**Fix:** Removed the early-return gate (event always persisted; RULE_HIT console/log output remains hit-gated); added a `handle_persist_pipeline_event` wrapper that logs exceptions visibly without re-raising (collector stays up); changed `storage_writer.py`'s exception handlers to log with full traceback and re-raise, so failures are never silently swallowed again.

**Verification:** Full regression 506/506 passing (+4 new proof tests). Live reproduction on host confirmed real event counts climbing correctly (baseline 1 → 13,059 after live run → 19,048 after recovery test), including a deliberate negative test (invalid `SHADOWSENSOR_DB_DIR`) that now fails visibly instead of silently.

**Detail:** `docs/phase6a_blocker_report.md` (original finding), `docs/blocker_fix_final_report.md` (fix + verification).

---

## 4. Blocker #2 — Feature Extraction Time-Scoping Gap (FIXED)

**Discovered:** Sub-Phase 5, first activation-rate analysis.
**Root cause:** `scripts/run_feature_extraction.py` / `ml/features/pipeline.py` had no time-window filter — every extraction read the *entire* `events` table regardless of intent, mixing the current session with weeks of Phase 2B/4A/4B deliberate attack-simulation telemetry still present in the same cumulative database.

**Evidence:** A `--label 0` (benign) export immediately after a confirmed-clean live session still showed `has_encoded_command` 7/795, `has_download_keyword` 8/795, `has_powershell_rule_hit` 44/795, and several other rule-hit-derived features nonzero — all traceable to old Phase 4A/4B simulation data, not the actual session.

**Fix:** Added optional `--since`/`--until` CLI arguments (inclusive both ends, ISO-8601 or space-separated datetime formats accepted), threaded through `FeatureExtractionPipeline.run(time_from, time_to)`, applied consistently to both the `events` and `rule_hits` queries with `ORDER BY timestamp ASC` preserved. Fully backward-compatible — omitting both arguments preserves prior all-time behavior exactly.

**Verification:** Full regression 514/514 passing (+8 new scoping tests). Host-side mechanism proof showed a real 772→353 window delta with corresponding activation-rate shifts when scoped vs. unscoped on the same data.

**Detail:** `docs/phase6a_feature_extraction_scoping_issue.md` (original finding), `docs/scoping_fix_final_report.md` (fix + verification).

---

## 5. Feature Activation Rate Table — Final, Decontaminated Baseline

Extraction command used (final, corrected):
```
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --since "2026-07-27 02:00:00" --until "2026-07-27 10:10:00" --output data\features\benign_baseline.csv
```
(Window widened to 8 hours same-day per Ayush's direction, rather than the exact narrow session bound, due to the clock discrepancy described in Section 6 — anchored against the database's confirmed max timestamp `2026-07-27 10:07:19.117870`.)

**Result:** 621 process windows, 31 CSV columns (30 features + label), header/structure verified correct.

### Binary features (621 total windows)

| Feature | Count | Rate | Note |
|---|---:|---:|---|
| has_encoded_command | 0 | 0.00% | contamination cleared (was 7/795) |
| has_download_keyword | 0 | 0.00% | contamination cleared (was 8/795) |
| is_signed | 0 | 0.00% | expected — always 0 at EID-1 (schema gap, documented since Phase 5) |
| is_off_hours | 0 | 0.00% | **caveat — see Section 6, clock discrepancy** |
| is_lolbin | 15 | 2.42% | confirmed = rundll32.exe (WARP install), not powershell.exe |
| is_suspicious_parent | 6 | 0.97% | WARP-cluster related |
| is_known_suspicious_chain | 0 | 0.00% | contamination cleared (was 33/795) |
| parent_is_same_image | 116 | 18.68% | expected benign pattern |
| is_suspicious_port | 0 | 0.00% | — |
| is_external_ip | 31 | 4.99% | expected for normal browsing |
| unsigned_image_loaded | 21 | 3.38% | WARP-cluster related |
| open_process_lsass_target | 6 | 0.97% | WARP-cluster related |
| open_process_suspicious_access | 242 | 38.97% | WARP-cluster related — see caveat below |
| has_powershell_rule_hit | 0 | 0.00% | contamination cleared (was 44/795) |
| has_lolbin_rule_hit | 0 | 0.00% | contamination cleared (was 32/795) |
| has_network_rule_hit | 0 | 0.00% | contamination cleared (was 9/795) |
| has_api_rule_hit | 9 | 1.45% | WARP-cluster related (was 73/795) |
| has_chain_rule_hit | 0 | 0.00% | contamination cleared (was 36/795) |

### Numeric/count features

| Feature | Min | Max | Mean |
|---|---:|---:|---:|
| cmd_length | 0.00 | 1217.00 | 130.08 |
| cmd_entropy | 0.00 | 5.29 | 2.44 |
| parent_cmd_length | 0.00 | 619.00 | 40.76 |
| dns_query_length | 0.00 | 23.00 | 0.19 |
| dest_port | 0.00 | 443.00 | 19.78 |
| network_event_count | 0.00 | 433.00 | 1.28 |
| image_load_count | 0.00 | 331.00 | 41.61 |
| create_remote_thread_count | 0.00 | 0.00 | 0.00 |
| open_process_count | 0.00 | 11011.00 | 71.22 |
| rule_hit_count | 0.00 | 7.00 | 0.08 |
| unique_rules_fired | 0.00 | 2.00 | 0.02 |

**Key takeaway:** `create_remote_thread_count` is 0.00 across the entire window (min/max/mean) — zero injection-technique activity anywhere in this baseline, as expected for a genuinely benign session.

---

## 6. Open Caveat — VM Internal Clock Discrepancy (NOT FIXED, documentation only)

Two separate, independently-confirmed clock issues affect this dataset and future Phase 6A/7A collections:

1. **VM-vs-host drift (~12h)** — documented pre-existing finding, `docs/vm_clock_drift_finding.md`. The VM's OS clock is offset from host/human wall-clock framing.
2. **NEW — internal VM clock discrepancy (~7h), discovered during this phase's Sub-Phase 5 re-run.** `logs/rule_hits.log` and SQLite `events.timestamp` are stamped by what appear to be two different clock sources that disagree with each other. Confirmed precisely: the live WARP `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` hit, logged in `rule_hits.log` at `02:11:56`, is stored in SQLite at `09:11:56.731641` — a clean +7:00:00 offset (minute/second components match exactly).

**Practical impact:** `hour_of_day` and `is_off_hours` (2 of the 30 `FEATURE_REGISTRY` features) are derived from the SQLite-stored timestamp and may not reflect true real-world time-of-day until these clock sources are reconciled. This baseline's `is_off_hours` reading of 0/621 (0.00%) should be treated with caution rather than as a confirmed finding.

**Recommendation:** Consolidate both clock findings into a single follow-up task (VM clock correction) before Phase 6B/7B rely meaningfully on `hour_of_day`/`is_off_hours` as trained features. Not blocking for Isolation Forest training itself, since the other 28 features are unaffected and clean.

---

## 7. Open / Carried-Forward Issues (not new, not blocking)

- **Phase 4B Issue 4** (`API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` on wmiprvse.exe/svchost.exe → winlogon.exe/lsass.exe): left explicitly open/inconclusive at Phase 4B close. This session's WARP-related OpenProcess activations (242/621, 38.97%) are structurally similar but attributed to a different, identified source (warp-svc.exe / VPN client). Not escalated further from this data alone — noted as a real design consideration: `open_process_suspicious_access` at ~39% is a meaningfully high rate to bake into a benign baseline, even though explained. Worth being aware of if Isolation Forest training treats this as strongly "normal."
- **Dashboard UI/styling** (Sub-Phase 6): data table column truncation/non-resizable columns, and dated chart/graph visual styling. Purely cosmetic, no data-correctness impact. Explicitly deferred by Ayush to a dedicated UI overhaul pass before Phase 9 (Packaging) — not routed as a bug now.

---

## 8. File Locations

- **Benign baseline CSV (final, decontaminated):** `data\features\benign_baseline.csv` — 621 rows, 31 columns (30 features + label=0). Accessible from both VM (`Z:\filelessmalware\data\features\benign_baseline.csv`) and host (`E:\filelessmalware\data\features\benign_baseline.csv`) via the shared project tree — no copy/sync needed.
- **Database:** `C:\ShadowSensor\data\shadowsensor.db` (VM-local, not shared — 71,544 events / 399 rule_hits / 399 alerts as of this report).
- **Sub-phase reports:** `docs/phase6a_subphase1_report.md` through `docs/phase6a_subphase6_report.md`.
- **Blocker documentation:** `docs/phase6a_blocker_report.md`, `docs/blocker_fix_final_report.md`, `docs/phase6a_feature_extraction_scoping_issue.md`, `docs/scoping_fix_final_report.md`, `docs/vm_clock_drift_finding.md`.

---

## 9. Explicit Readiness Statement

**Is `benign_baseline.csv` ready for Phase 6B Isolation Forest training with no unresolved blockers?**

**Yes**, with two carried-forward, non-blocking caveats for Phase 6B to be aware of during training/evaluation:

1. `hour_of_day` / `is_off_hours` may carry unreliable signal until the VM's internal clock discrepancy (Section 6) is resolved — the other 28 features are unaffected.
2. `open_process_suspicious_access` (~39% activation rate) is baked into this "benign" baseline from an explained, real, but unusually concentrated event cluster (Cloudflare WARP installation) — Phase 6B may want to consider whether this over-represents that specific event class relative to typical steady-state benign activity, and whether a future, more varied benign collection session would strengthen the baseline.

Both caveats are documentation, not blockers — the CSV is structurally valid, decontaminated of all attack-simulation data, and reflects genuine benign process activity end-to-end.

Phase 6A is complete. Ayush may proceed to Phase 6B in Cursor/Codex with confidence, using the file and caveats above.
