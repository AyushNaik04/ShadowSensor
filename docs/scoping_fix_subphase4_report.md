# Scoping Fix — Sub-Phase 4 Completion Report

**Date/time executed:** 2026-07-27 16:48:04 +0530  
**Sub-phase goal (restated):** Prove the new `--since`/`--until` scoping behavior with automated tests (including the whole-second `--until` padding proof), then confirm the full regression suite against the Sub-Phase 3 baseline of **506 passed**.

## What Was Done

1. Chose **`tests/test_phase5/test_pipeline.py`** (not a new adjacent file) — rationale below.
2. Extended `_run_pipeline_with_memory_db` to pass optional `time_from` / `time_to`.
3. Added eight new tests covering every required case from the task + SP2 review addition.
4. Ran `tests/test_phase5/test_pipeline.py` (23 passed), then full `tests/` suite.
5. No product implementation files changed in this sub-phase (tests + this report only).

## Evidence

### Where tests were added — and why

**File:** `tests/test_phase5/test_pipeline.py`

**Why not a new adjacent file:**  
Existing helpers (`create_test_db`, `_insert_event`, `_insert_rule_hit`, `_run_pipeline_with_memory_db`) and all prior pipeline orchestration tests already live here. Extending this file avoids duplicating fixtures, keeps time-scoping coverage next to the code under test’s existing suite, and matches the task’s preferred primary option (`test_pipeline.py` or adjacent).

### New tests added (8)

| Test | Requirement covered |
|---|---|
| `test_time_filter_since_only` | `--since` only |
| `test_time_filter_until_only` | `--until` only |
| `test_time_filter_both_since_and_until` | both together |
| `test_time_filter_neither_preserves_all_time_behavior` | neither (all-time regression) |
| `test_time_filter_inclusive_boundaries_include_exact_since_and_until` | exact `--since` / `--until` timestamps included |
| `test_whole_second_until_includes_same_second_excludes_next_second` | whole-second `--until` padding proof (include same-second micros; exclude next second); also asserts fractional `--until` is **not** padded |
| `test_cli_malformed_since_exits_2_before_pipeline_runs` | malformed `--since` → `[ERROR]`, exit **2**, no CSV written, no “Extracted” stdout |
| `test_cli_malformed_until_exits_2` | malformed `--until` → exit **2** |

### Targeted suite

```
============================= 23 passed in 2.04s ==============================
```

(15 prior pipeline tests + 8 new = 23)

### Full regression suite

```
====================== 514 passed, 34 warnings in 32.11s ======================
```

| Checkpoint | Result |
|---|---|
| Sub-Phase 3 baseline | **506 passed** |
| Sub-Phase 4 after new tests | **514 passed**, 0 failed |
| Delta | **+8** (exact match to new tests added) |

### File-change scope (this sub-phase)

```
 tests/test_phase5/test_pipeline.py | 219 ++++++++++++++++++++++++++++++++++++-
 1 file changed, 217 insertions(+), 2 deletions(-)
```

```
 M tests/test_phase5/test_pipeline.py
```

Plus this report: `docs/scoping_fix_subphase4_report.md`.

**Known unrelated dirty state (carry forward to Sub-Phase 6 cumulative scope):**  
`scripts/run_pipeline.py`, `storage/storage_writer.py`, `tests/test_phase3/test_storage.py` remain modified from the prior blocker-fix task — expected, explained, not part of this scoping fix.

## Findings / Conclusions

1. All required scoping behaviors are covered by automated tests, including the dedicated whole-second `--until` padding proof.
2. Full suite is **514 passed** vs Sub-Phase 3’s **506** — no regressions; +8 new tests only.
3. Malformed CLI input fails with exit code 2 and does not produce an output CSV.

## File-Change Scope (if applicable)

- `tests/test_phase5/test_pipeline.py` — new scoping tests (intended)
- `docs/scoping_fix_subphase4_report.md` — this report
- Product files from Sub-Phase 3 unchanged in this step: `ml/features/pipeline.py`, `scripts/run_feature_extraction.py`

## Anomalies / Uncertainties

None blocking. Initial double-run-on-same-connection test drafts hit `Cannot operate on a closed database` because `pipeline.run` closes the monkeypatched connection and subsequent `sqlite3.connect(":memory:")` was intercepted by that monkeypatch; fixed by pre-creating both in-memory DBs before any `run()` call. Final suite is green.

## Ready to Proceed?

**Yes** — Sub-Phase 4 testing complete at **514 passed**. Awaiting go-ahead before Sub-Phase 5 (mechanism-proof + VM handoff package split).
