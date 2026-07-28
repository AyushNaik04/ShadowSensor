# ShadowSensor — Feature Extraction Time-Scoping Gap

**Status:** New finding, not yet routed to Codex. Discovered during Phase 6A Sub-Phase 5 (Feature Activation Analysis).
**Severity:** Medium — does not block Phase 6A's ability to collect data, but blocks producing a *correctly scoped* benign baseline, and will independently block Phase 7A (labeled suspicious telemetry) for the same reason.
**Affects:** `scripts/run_feature_extraction.py` and the Phase 5 feature extraction pipeline it drives (`ml/features/pipeline.py`). Not related to the separate SQLite silent-write-failure bug already fixed (see `docs/blocker_fix_final_report.md`) — that fix is confirmed working correctly; this is a new, unrelated gap.

---

## Summary

`run_feature_extraction.py` reads the **entire** `events` table on every invocation, with no way to scope the extraction to a specific time window or session. The `events` table is cumulative across the whole project's history (currently spanning 2026-07-01 through present, ~71,500+ rows and counting) and includes deliberate attack-simulation events from Phase 2B, 4A, and 4B rule-validation work (encoded PowerShell commands, download cradles, LOLBin executions, Office→shell chains, OpenProcess-to-lsass/winlogon tests, etc.), alongside genuine benign activity from Phase 6A collection sessions.

Because there is no time filter, any CSV produced by this script — regardless of the `--label` flag passed — is a feature vector export of **all historical events**, not the specific session the label is meant to describe. This makes any `--label 0` ("benign") export inaccurate whenever the database contains prior rule-validation simulation data, which it currently does and will continue to.

---

## Evidence

### Database spans the full project history, not just the current session
```
min id: 1
max id: 71544
min timestamp: 2026-07-01 10:52:30.807569
max timestamp: 2026-07-27 10:07:19.117870
```

### A `--label 0` extraction run immediately after a clean ~1h38m benign-only collection window (2026-07-27, 14:00–15:38) still shows clearly attack-simulation-derived activations
Extraction command used:
```
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --output data\features\benign_baseline.csv
```
Result: 795 process windows extracted, all 71,544 events in the database. Activation rates from the exported CSV (should be ~0% for every line below in a genuinely benign-only session):
```
has_encoded_command: 7/795 (0.88%)
has_download_keyword: 8/795 (1.01%)
is_known_suspicious_chain: 33/795 (4.15%)
open_process_lsass_target: 13/795 (1.64%)
open_process_suspicious_access: 275/795 (34.59%)
has_powershell_rule_hit: 44/795 (5.53%)
has_lolbin_rule_hit: 32/795 (4.03%)
has_network_rule_hit: 9/795 (1.13%)
has_api_rule_hit: 73/795 (9.18%)
has_chain_rule_hit: 36/795 (4.53%)
```
None of this activity occurred during the actual 2026-07-27 14:00–15:38 benign session (confirmed clean via live Terminal 1 monitoring in that session — only two real rule-hit clusters occurred, both tied to a Cloudflare WARP install/VPN use, already logged separately). This confirms the 795 windows include process activity from weeks-old rule-validation simulations still present in the same `events` table.

---

## Root Cause

`ml/features/pipeline.py`'s `FeatureExtractionPipeline.run()` queries `events` (and the corresponding `rule_hits` join) with no `WHERE` clause on `timestamp`, `id`, or any other session-scoping field. Per `docs/phase5_schema_reference.md`, `events` has a flat, indexed `timestamp` column, so a time-range filter is straightforward to add without touching the underlying schema.

`scripts/run_feature_extraction.py`'s CLI currently exposes only `--label`, `--output`, and `--db` — no time-scoping argument exists at any layer.

---

## Why This Needs a Permanent Fix (Not a One-Off Workaround)

This is not unique to Phase 6A. **Phase 7A** (Generate Labeled Suspicious Telemetry) will hit the identical problem in reverse: it needs to export *only* the suspicious-simulation events from a controlled session, cleanly separated from all the benign activity (including this Phase 6A session and any future ones) sitting in the same accumulating `events` table. Without a scoping mechanism, every future labeled export (`--label 0` or `--label 1`) is at risk of the same contamination, growing worse as the database grows across the project's remaining phases.

---

## Requested Fix (for Codex)

Add time-window scoping to the feature extraction pipeline, surfaced as new CLI arguments on `scripts/run_feature_extraction.py`:

1. **New CLI arguments:** `--since` and `--until` (ISO-8601 or `YYYY-MM-DD HH:MM:SS` datetime strings), both optional. When provided, the underlying `events` query (and the corresponding `rule_hits` query, since both must stay consistent for the `event_fk` join per `docs/phase5_schema_reference.md`) filters on `timestamp >= since` and/or `timestamp <= until`. When omitted, current all-time behavior is preserved (no breaking change to existing usage or existing tests).
2. **Threading through `ml/features/pipeline.py`:** `FeatureExtractionPipeline` needs an optional `time_from`/`time_to` (or similar) parameter that both the `events` and `rule_hits` queries respect, consistent with the existing `ORDER BY timestamp ASC` requirement already in place for correct first-event resolution (per `docs/phase5_schema_reference.md`'s Subphase 4 ground truth — this ordering requirement must be preserved when a time filter is added).
3. **Validation:** if `--since`/`--until` are provided but malformed, fail with a clear error message before querying, rather than a silent no-op or a raw SQL/parsing exception.
4. **Tests:** new tests in `tests/test_phase5/test_pipeline.py` (or a new adjacent test file) covering: filtering with only `--since`, only `--until`, both, neither (regression — confirms unchanged all-time behavior), and a boundary case (event exactly at the `since`/`until` timestamp, to confirm inclusive vs. exclusive behavior is deliberate and documented either way).
5. **Documentation:** update `docs/phase5_schema_reference.md` or an adjacent doc with the new scoping behavior, since that file is the authoritative ground-truth reference for this pipeline going forward.

**Explicitly out of scope for this fix:** no changes to `FEATURE_REGISTRY`, the 30-feature spec, the aggregator's merge strategies, or the existing SQLite write path (already fixed separately). This is additive scoping only.

---

## Immediate Workaround Status

No workaround has been applied. `data\features\benign_baseline.csv` (795 rows, generated 2026-07-27) is **not** a clean benign-only dataset and should not be used as-is for Phase 6B (Isolation Forest) training. A corrected, properly time-scoped extraction is needed once this fix lands — re-running `run_feature_extraction.py --label 0 --since "2026-07-27 14:00:00" --output data\features\benign_baseline.csv` (once `--since` exists) against the same already-collected data would retroactively produce the correct file without needing a new collection window, since the underlying events from the 2026-07-27 14:00–15:38 session are already persisted correctly.

---

## Recommendation

Route this to Codex as a scoped, additive CLI/pipeline enhancement per the "Requested Fix" section above. Phase 6A Sub-Phase 5 (Feature Activation Analysis) should pause after this finding — the current `benign_baseline.csv` is not representative and further analysis of its activation rates would only be analyzing contaminated data. Once the fix lands, re-run extraction with the correct `--since` bound and resume Sub-Phase 5 against the corrected file.
