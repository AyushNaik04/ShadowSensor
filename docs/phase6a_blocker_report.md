# ShadowSensor — Phase 6A Blocker Report: Silent SQLite Write Failure

**Status:** Phase 6A PAUSED pending fix. Not a Phase 6A defect — a dormant regression discovered during Phase 6A verification.
**Discovered:** 2026-07-27, during Sub-Phase 3 (Post-Collection Database Verification)
**Severity:** High — blocks all SQLite-backed data collection (Phase 6A, and by extension Phase 7A, 8A validation, and dashboard-based verification) until fixed.
**Affects:** Pipeline SQLite write path only. Does NOT affect rule detection, rule evaluation, or `logs/rule_hits.log` writes — those are confirmed still working correctly.

---

## Summary

The ShadowSensor pipeline's SQLite write path (`events`, `rule_hits`, `alerts` tables) silently stopped functioning at some point after Phase 4B closed. The pipeline continues to start cleanly, load all 49 rules, evaluate events, and correctly write to `logs/rule_hits.log` — but no new rows have been written to `C:\ShadowSensor\data\shadowsensor.db` since **2026-07-12 23:07:35**, despite the pipeline having been run in at least 8 separate sessions since then (07-13, 07-17 x3, 07-26, and a fresh 07-27 reproduction test), totaling several hours of runtime including sessions that logged confirmed `RULE_HIT` events to the log file.

**No exception, warning, or error of any kind is printed to stdout/stderr during any of these runs.** The pipeline reports normal startup (`Database initialized at C:\ShadowSensor\data\shadowsensor.db`, `Event collection pipeline started`) and normal shutdown (`Pipeline stopped. Rule hits written to logs/rule_hits.log`) in every case.

---

## Evidence

### 1. Database file mtime vs. current date
```
Last modified: 2026-07-12 23:07:36.077726
```
Current VM date at time of discovery: 2026-07-27. The file has not been touched in 15 days despite repeated pipeline runs.

### 2. Row counts unchanged across a clean, minimal reproduction test
Pre-test baseline (2026-07-27):
```
events: 346 rows
rule_hits: 349 rows
alerts: 349 rows
model_scores: 0 rows
```
Immediately after a fresh 2-minute pipeline run (clean bookmark, clean start, clean stop, no errors):
```
events: 346 rows
rule_hits: 349 rows
alerts: 349 rows
model_scores: 0 rows
```
Zero delta on all four tables.

### 3. `DB_PATH` resolves correctly
```
DB_PATH: C:\ShadowSensor\data\shadowsensor.db
```
Confirmed via direct import from `storage.database`, matching the path the pipeline reports initializing. This rules out a path-mismatch explanation.

### 4. `logs/rule_hits.log` write path is confirmed still working
Every session since 07-12 has correctly appended `=== SESSION START ===` / `=== SESSION END ===` markers to `logs/rule_hits.log`, and sessions that triggered rule fires (e.g. 07-13 Codex fix-pass validation sessions, 07-17) correctly logged `RULE_HIT` lines with full detail (rule name, technique, severity, image, cmdline, etc.) to that file. This confirms:
- The collector is receiving and processing Sysmon events
- The rule engine is evaluating correctly and firing rules
- Only the SQLite write step in the chain is failing

### 5. Full reproduction test transcript (2026-07-27)
```
Z:\filelessmalware>python_runtime\python.exe scripts\run_pipeline.py
============================================================
ShadowSensor Pipeline — Live Mode
Polling Microsoft-Windows-Sysmon/Operational every 2s
Rule hits -> stdout + logs/rule_hits.log
Press Ctrl+C to stop.
============================================================
Loaded 49 rules from rules\definitions
Event ID 10: 4 rule(s) loaded
Event ID 8: 1 rule(s) loaded
Event ID 7: 2 rule(s) loaded
Event ID 1: 34 rule(s) loaded
Event ID 22: 2 rule(s) loaded
Event ID 3: 6 rule(s) loaded
[INFO] Loaded 49 rules from rules/definitions/
Database initialized at C:\ShadowSensor\data\shadowsensor.db
Event collection pipeline started (thread: ShadowSensor-Collector)
[INFO] Pipeline stopped. Rule hits written to logs/rule_hits.log
```
No exceptions, no warnings, no stack traces at any point in stdout or stderr.

---

## Timing Analysis — Likely Introduction Point

Cross-referencing `logs/rule_hits.log` session timestamps against the database mtime:

- **Last session with confirmed DB writes:** 2026-07-12 22:49:29 → 23:07:35 (this is the Phase 4B Subphase 7 benign baseline session — DB mtime is 23:07:36, one second after this session's `SESSION END`)
- **First session after the gap:** 2026-07-13 13:19:10 (a short session, no RULE_HITs logged)
- Between these two sessions, the only recorded project activity was the **Codex Fix Pass (Subphases 1–6)**, completed 2026-07-13, which modified:
  - `rules/definitions/api_memory.yaml` (Subphase 1 — Issue 1 fix)
  - `rules/definitions/network.yaml` (Subphase 2 — Issue 3 fix)
  - `rules/definitions/parent_child.yaml` (Subphase 3 — Issue 9 two-rule split)
  - Read-only diagnosis of `normalizer/parser.py` and `normalizer/field_maps.py` (Subphase 4 — no code change stated)
  - Full regression suite run and rule-count confirmation (Subphase 6)

Per `status.md` and the Technical Flow document, `storage/`, `alerting/`, and `scripts/run_pipeline.py` were **not** listed as touched by the Fix Pass — but the timing strongly suggests something in or adjacent to that work introduced this regression, whether directly or as a side effect (e.g., a rule-loading change that altered a code path shared with the storage writer, or an untracked edit).

**This is a hypothesis for Codex to verify, not a confirmed root cause.** The regression could equally have been introduced by any commit between 2026-07-12 23:07 and 2026-07-13 13:19 that isn't reflected in the status.md changelog.

---

## What Is NOT the Problem

To save diagnosis time, ruling out:
- **Path misconfiguration** — `DB_PATH` resolves correctly and matches pipeline startup log output.
- **VMware shared-folder SQLite incompatibility** — this is a known, already-solved issue (DB lives on local NTFS at `C:\ShadowSensor\data\`, not the shared folder). Not the cause here.
- **Sysmon/collector failure** — `rule_hits.log` proves events are being collected and evaluated correctly.
- **Rule engine failure** — 49 rules load correctly every time; rule evaluation is demonstrably still firing (see 07-13/07-17 RULE_HIT entries in the log).
- **A visible crash or exception** — there is none. This is a silent failure.

---

## Diagnosis Targets for Codex

Recommend investigation focus, in priority order:
1. **`storage/storage_writer.py`** — the module responsible for actually writing events/rule_hits/alerts to SQLite. Look for any `try/except` block that could be silently swallowing a write exception (e.g., bare `except: pass`, or an `except Exception` that logs nothing or logs to a location not visible in this run).
2. **`alerting/alert_manager.py`** — the alert generation path that sits between rule hits and the `alerts` table.
3. **`scripts/run_pipeline.py`** — specifically the callback wiring between the collector/rule engine and the storage write calls, since this is the one file the project's own modification policy allows changes to, and is the most likely place for an additive change to have accidentally broken or bypassed a write call.
4. Confirm whether `git log` / file diff history (if available) shows any changes to these three files between 2026-07-12 23:07 and 2026-07-13 13:19, to narrow down or rule out the Fix Pass hypothesis above.
5. Check whether the SQLite connection/session used by the pipeline is being silently closed, rolled back, or never committed (e.g., a missing `.commit()`, or a connection opened in a scope that closes before the write executes).

---

## Recommended Fix Verification Steps (for whoever fixes this)

Once a fix is applied, verification must include:
1. Full regression suite still passing (502/502 baseline, adjusted for the fix's own new tests).
2. A fresh pipeline run reproducing this report's Step 5 reproduction test — confirm `events` row count now increases with normal benign activity.
3. A short encoded-command test (per `VM_RUN_GUIDE.md` Step 5) confirming a rule hit now correctly appears in BOTH `logs/rule_hits.log` AND the `rule_hits`/`alerts` SQLite tables.
4. Explicit confirmation that any exception in the storage write path now surfaces visibly (printed/logged), so a future regression of this kind cannot recur silently.

---

## Phase 6A Status

Phase 6A is paused at the end of Sub-Phase 3 (Post-Collection Database Verification). Sub-Phases 1 and 2 completed successfully and their reports (`docs/phase6a_subphase1_report.md`, `docs/phase6a_subphase2_report.md`) remain valid — the ~1h18m benign collection window on 2026-07-27 (11:05–12:23) itself was clean (zero rule hits), it simply wasn't persisted to SQLite due to this pre-existing bug. **The collection window will need to be re-run once the fix is verified**, since the events from that session were never written to the database and cannot be recovered from it. `logs/rule_hits.log` does retain a record that the session occurred and was clean, but not the underlying event data needed for Phase 5 feature extraction.

Sub-Phases 4–7 (feature extraction, activation analysis, dashboard cross-check, final consolidation) cannot proceed until this is resolved, since there is no new data to extract.

**Recommended next step:** route this report to Codex for diagnosis and fix, then re-run Phase 6A Sub-Phase 2 (collection window) once fixed and verified.
