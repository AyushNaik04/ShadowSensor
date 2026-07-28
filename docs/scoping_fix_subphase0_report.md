# Scoping Fix — Sub-Phase 0 Completion Report

**Date/time executed:** 2026-07-27 16:23:51 +0530  
**Sub-phase goal (restated):** Establish complete, accurate context by reading every listed file in full, copying the trigger document into `docs/` if missing, and producing a factual 2–4 sentence summary of each — before any diagnostic, design, or code action.

## What Was Done

1. Read `phase6a_scoping_fix_task.md` in full (governing decisions, sub-phases, report template).
2. Verified `docs/phase6a_feature_extraction_scoping_issue.md` was **not** present in the repo; located the source at `C:\Users\AYUSH NAIK\Downloads\phase6a_feature_extraction_scoping_issue.md` (7726 bytes, mtime Jul 27 16:06).
3. Copied that file into `docs/phase6a_feature_extraction_scoping_issue.md` and verified an exact byte-for-byte match (`cmp -s` → match; identical SHA-256 `b046fb1856a5b5635dd6167c637fa0edf6a673e2ae349fe85d1f1ef6bc1e288e`).
4. Read in full every other Sub-Phase 0 listed file and wrote the factual summaries below.
5. Extracted the real collection-session boundary strings from `docs/phase6a_subphase2_report.md` for later Sub-Phase 5 use (quoted in Evidence; not approximated from memory).
6. No diagnostic queries, design, implementation, or test runs were performed.

## Evidence

### Trigger-doc copy verification
```
EXACT_MATCH: yes
 7726 /c/Users/AYUSH NAIK/Downloads/phase6a_feature_extraction_scoping_issue.md
 7726 E:/filelessmalware/docs/phase6a_feature_extraction_scoping_issue.md
b046fb1856a5b5635dd6167c637fa0edf6a673e2ae349fe85d1f1ef6bc1e288e */c/Users/AYUSH NAIK/Downloads/phase6a_feature_extraction_scoping_issue.md
b046fb1856a5b5635dd6167c637fa0edf6a673e2ae349fe85d1f1ef6bc1e288e *E:/filelessmalware/docs/phase6a_feature_extraction_scoping_issue.md
```

`git status --short` after copy:
```
?? docs/phase6a_feature_extraction_scoping_issue.md
```

### Per-file factual summaries

#### `docs/phase6a_feature_extraction_scoping_issue.md`
Documents that `run_feature_extraction.py` / `FeatureExtractionPipeline` read the entire cumulative `events` table with no time filter, so any `--label` export mixes the intended session with all prior history (including Phase 2B/4A/4B attack-simulation telemetry). Concrete evidence cited: DB span `2026-07-01 10:52:30.807569`–`2026-07-27 10:07:19.117870` (ids 1–71544), and a post-session `--label 0` run yielding 795 windows with non-zero activation on attack-like features (e.g. `has_encoded_command` 7/795, `open_process_suspicious_access` 275/795) despite a clean live benign session. Requested fix is additive `--since`/`--until` CLI args threaded into both `events` and `rule_hits` queries, with validation, tests, and schema-doc update; explicitly out of scope: `FEATURE_REGISTRY`, aggregator merge strategies, and the already-fixed SQLite write path. States `benign_baseline.csv` (795 rows) is not clean and should not be used for Phase 6B until a scoped re-extraction is done.

#### `docs/phase5_schema_reference.md`
Authoritative Phase 5 ground truth: `event_type_id` values are raw Sysmon EIDs; `events` flat columns include `id, event_type_id, timestamp, pid, image, raw_json, ingested_at`; rule hits join via `rule_hits.event_fk = events.id` (not timestamp-window matching). Documents field-name variance (`process_id` vs `source_process_id`), LOLBin prefix `LOLBIN_`, and EID-scoped first-event aggregation. Subphase 4 ground truth states both `events` and `rule_hits` queries use `ORDER BY timestamp ASC` (required for first-event resolution), and the CLI imports `DB_PATH` from `storage.database`.

#### `docs/blocker_fix_final_report.md`
Consolidated report for the **separate** SQLite write-path fix: Issue #1 early-return skipped all writes on zero-hit events; Issue #2 `StorageWriter` swallowed exceptions; Issue #3 undefined `logger` in the outer handler. Fixes landed in `scripts/run_pipeline.py` and `storage/storage_writer.py` (plus Phase 3 proof tests); final suite **506 passed**, live elevated pipeline proved writes. Explicit recommendation was to re-run Phase 6A Sub-Phase 2 collection on the VM (done separately). **No overlap with this scoping task:** this task must not touch those write-path files.

#### `scripts/run_feature_extraction.py`
CLI entrypoint: argparse exposes only `--label` (optional int), `--output` (default timestamped path under `data/features`), and `--db` (default `DB_PATH`). Instantiates `FeatureExtractionPipeline(db_path).run(label=args.label)` then `export_to_csv(...)`. No `--since`/`--until` (or any time-window) arguments exist; missing DB yields empty vectors with a warning.

#### `ml/features/pipeline.py`
`FeatureExtractionPipeline.__init__(db_path)` and `run(label=None)` select **all** rows from `events` (`SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at FROM events ORDER BY timestamp ASC`) and **all** from `rule_hits` (`SELECT id, event_fk, rule_id, timestamp FROM rule_hits ORDER BY timestamp ASC`) — neither query has a `WHERE` on `timestamp`. Groups by `(image, pid)`, maps rule hits via `event_fk`, extracts/aggregates per window, optionally stamps `label`. No time-scoping parameters exist on the class or `run()`.

#### `ml/features/exporter.py`
`export_to_csv(feature_vectors, output_path, label=None)` writes `FEATURE_NAMES` columns plus optional `label`, creating parent dirs as needed. `default_output_path()` returns `data/features/features_YYYYMMDD_HHMMSS.csv`. No time-window logic; exporter is label/CSV-only.

#### `ml/features/feature_spec.py`
Defines the frozen 30-feature `FEATURE_REGISTRY` / `FEATURE_NAMES`, `default_feature_vector()`, and constant sets (`LOLBIN_NAMES`, `SUSPICIOUS_PARENT_IMAGES`, `SUSPICIOUS_CHAINS`, `SUSPICIOUS_PORTS`). Per task decisions and the scoping issue, this file is additive-fix out-of-scope (no registry/spec changes expected).

#### `tests/test_phase5/test_pipeline.py`
In-memory SQLite helpers plus tests for empty DB, window grouping, label None/0/1, `event_fk` rule-hit join, unmatched FK skip, null pid, CSV export column counts (30 / 31), and nonexistent DB → `[]`. Helper `_run_pipeline_with_memory_db(..., label=None)` calls `pipeline.run(label=label)` only — **no time-window tests exist today**.

#### `docs/phase6a_subphase2_report.md` (most recent re-run collection session)
Re-run benign collection after the SQLite blocker fix. **Exact session boundary strings as written in the report** (needed for Sub-Phase 5 — do not approximate from memory):

| Field | Exact text from report |
|---|---|
| Date/time executed header | `2026-07-27, approx 14:00 - 15:38` |
| Pipeline start | `Started pipeline (Terminal 1) at approx 14:00` |
| Activity window | `approx 1h 38m (14:00 - 15:38)` |
| Pipeline stop | `Stopped pipeline via Ctrl+C at approx 15:38` |
| Superseded prior (non-persisted) session | `original 2026-07-27 11:05-12:23` |

Quoted start/stop lines:
```
- Started pipeline (Terminal 1) at approx 14:00 - "Loaded 49 rules from rules\definitions", collector thread started cleanly, DB initialized at C:\ShadowSensor\data\shadowsensor.db
...
- Stopped pipeline via Ctrl+C at approx 15:38 - clean shutdown: "[INFO] Pipeline stopped. Rule hits written to logs/rule_hits.log"
```

Also records two Cloudflare WARP–related rule-hit clusters at `2026-07-27 02:10:51-02:11:53` and `2026-07-27 02:11:56` (not session boundaries; logged for FP awareness). Session described as clean outside that ~65s window; ready for Sub-Phase 3 DB verification.

## Findings / Conclusions

1. The trigger document is now present at `docs/phase6a_feature_extraction_scoping_issue.md` and **exactly matches** the Downloads source (same size + SHA-256).
2. The contamination problem is in the **read/export** path (`run_feature_extraction.py` + `pipeline.py` all-table SELECTs), not the already-fixed write path — confirmed by comparing this task’s trigger doc and `blocker_fix_final_report.md`; no file-scope overlap.
3. Current CLI surface is `--label` / `--output` / `--db` only; pipeline SQL has no timestamp `WHERE`; existing Phase 5 pipeline tests do not cover time filtering.
4. For Sub-Phase 5, the session bounds available in `phase6a_subphase2_report.md` are explicitly labeled **approx** `14:00` start and **approx** `15:38` stop on `2026-07-27`. The scoping-issue doc’s suggested workaround uses `--since "2026-07-27 14:00:00"` (and the issue text cites the same 14:00–15:38 window). No second-precision start/stop timestamps appear in the Sub-Phase 2 report itself.
5. Design decisions already locked (inclusive both ends; no default lookback) match the trigger doc’s requested optional `--since`/`--until` additive behavior; Sub-Phase 0 did not re-litigate them.

## File-Change Scope (if applicable)

Only the intentional trigger-doc copy was added; no product code was modified.

```
?? docs/phase6a_feature_extraction_scoping_issue.md
```

(This completion report `docs/scoping_fix_subphase0_report.md` is also new as required by the task.)

## Anomalies / Uncertainties

1. **Session boundary precision:** `docs/phase6a_subphase2_report.md` records start/stop as **approx** 14:00 / 15:38, not second-precision wall-clock values. Sub-Phase 5 will need an explicit choice of exact `--since`/`--until` strings (e.g. `2026-07-27 14:00:00` / `2026-07-27 15:38:00` as implied by the scoping-issue workaround, or tighter bounds from live DB timestamps) — flagging now so it is not silently approximated later.
2. **Rule-hit clock vs session clock:** the same report lists WARP rule hits at `2026-07-27 02:10:51`–`02:11:56`, while the session narrative is 14:00–15:38. That offset is unexplained by this Sub-Phase 0 read alone (possible timezone / VM clock difference); not needed for Sub-Phase 0, but may matter when correlating DB timestamps in later sub-phases.

## Ready to Proceed?

**Yes** — Sub-Phase 0 context read and trigger-doc copy are complete. Awaiting explicit go-ahead before Sub-Phase 1 (Baseline and Reproduction).
