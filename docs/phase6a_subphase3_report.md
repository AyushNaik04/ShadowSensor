# Phase 6A - Sub-Phase 3 Completion Report (RE-RUN following SQLite blocker fix)

**Date/time executed:** 2026-07-27
**Sub-phase goal (restated):** Confirm the collection window actually wrote new, sane data, before attempting feature extraction.
**Context:** This is a re-run following the SQLite write-path blocker fix (see docs/blocker_fix_final_report.md) and the Sub-Phase 2 re-run collection window (14:00-15:38, ~1h38m).

## What Was Completed
- Captured post-collection row counts and computed deltas against Sub-Phase 1 baseline (events: 346, rule_hits: 349, alerts: 349, model_scores: 0)
- Post-collection counts: events 71544, rule_hits 399, alerts 399, model_scores 0
- Deltas: events +71198, rule_hits +50, alerts +50, model_scores +0
- Spot-checked 10 most recent events for data sanity

## What's Working
Write path confirmed fully functional on real live data, not just the fix's own unit tests. events delta of +71198 over a ~1h38m session confirms benign zero-hit events are now persisting correctly (the core Fix 1 behavior). rule_hits/alerts delta of +50 is consistent with the ~35-50 RULE_HIT lines observed live during the WARP-install/OpenProcess cluster in Sub-Phase 2. model_scores correctly unchanged at 0 (no model trained yet). Spot-checked events show varied, correct event_type_id values (3, 7, 10) and sane real-world image paths (lsass.exe, OneDrive.Sync.Service.exe, MsMpEng.exe, svchost.exe) with sequential recent timestamps and plausible PIDs.

## What's Not Working / Unexpected
None. This is the first Phase 6A verification to run against the post-fix write path, and it passed cleanly on every check.

## Issues Log
None new. The two rule-hit clusters (WARP install / OpenProcess) already logged in the Sub-Phase 2 re-run report account for the rule_hits/alerts delta observed here; no discrepancy between live-observed hits and persisted counts.

## Ready to Proceed?
Yes - Sub-Phase 3 re-run complete. Write path fully verified end-to-end on real data. Awaiting Ayush's go-ahead for Sub-Phase 4 (Feature Extraction).
