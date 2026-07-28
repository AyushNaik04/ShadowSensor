# Scoping Fix — Sub-Phase 6 Completion Report

**Date/time executed:** 2026-07-27 16:51:52 +0530  
**Sub-phase goal (restated):** Final whole-project regression confirmation against the Sub-Phase 4 baseline (514), document `--since`/`--until` (including the intentional asymmetry) in `docs/phase5_schema_reference.md`, and produce a cumulative file-change scope report for the entire scoping-fix task.

## What Was Done

1. Ran full regression: `python_runtime\python.exe -m pytest tests\ -v --tb=short -q`.
2. Appended section **“Feature extraction time-window scoping (--since / --until)”** to `docs/phase5_schema_reference.md` covering inclusive bounds, no default lookback, CLI names/formats, and the `--since`/`--until` asymmetry rationale.
3. Captured cumulative `git status --short` and `git diff --stat`, separating scoping-fix product changes from pre-existing blocker-fix dirty files and other unrelated untracked docs.

## Evidence

### Step 6.1 — Final full regression suite

```
====================== 514 passed, 34 warnings in 50.34s ======================
```

| Checkpoint | Result |
|---|---|
| Sub-Phase 4 baseline | **514 passed** |
| Sub-Phase 6 final | **514 passed**, 0 failed |
| Delta | **0** (matches SP4 exactly) |

### Step 6.2 — Exact addition to `docs/phase5_schema_reference.md`

Quoted in full (lines 90–141 as written):

```markdown
## Feature extraction time-window scoping (--since / --until)

Additive CLI/pipeline filter on `scripts/run_feature_extraction.py` and
`ml/features/pipeline.py` (FeatureExtractionPipeline.run). Applies the
same bounds to both the `events` and `rule_hits` reads. `ORDER BY
timestamp ASC` is preserved on both queries.

### CLI arguments
- `--since` — optional inclusive lower bound on `timestamp`
- `--until` — optional inclusive upper bound on `timestamp`

Accepted input formats:
- `YYYY-MM-DD HH:MM:SS`
- `YYYY-MM-DD HH:MM:SS.ffffff` (fractional seconds)
- ISO-8601 with `T`: `YYYY-MM-DDTHH:MM:SS[.ffffff]`

Stored `events.timestamp` values are TEXT of the form
`YYYY-MM-DD HH:MM:SS.ffffff` (space separator, six-digit zero-padded
microseconds). CLI bounds with a `T` separator are normalized to a
space before binding so they remain lexicographically comparable to
stored rows.

### Boundary semantics
Inclusive on both ends: `timestamp >= since AND timestamp <= until`.
An event stamped exactly at either bound is included.

### No default lookback
`--since` and `--until` are optional. Omitting both preserves the prior
all-time behavior exactly (no automatic lookback window of any kind;
no silent narrowing of the no-argument case).

### --since / --until asymmetry (intentional)

`--until` is padded to `.999999` **only** when the user supplies a
whole-second value with **no** fractional/microsecond component (plain
`YYYY-MM-DD HH:MM:SS` or `...THH:MM:SS`). That padding makes inclusive
`timestamp <= until` include every stored event within that final
second under lexicographic TEXT comparison against microsecond-precision
rows (otherwise `...SS.123456` would sort after bare `...SS` and be
excluded).

If `--until` is given **with** an explicit fractional component, that
value is used as given (normalized to six-digit microseconds) — no
`.999999` padding.

`--since` needs **no** such padding: a bare second-precision lower bound
already naturally includes that whole second under lexicographic TEXT
comparison, because any `...SS.ffffff` row sorts greater than or equal
to bare `...SS`.

Malformed `--since` / `--until` values fail with a clear `[ERROR]` on
stderr and exit code 2 **before** any database query runs.
```

### Step 6.3 — Cumulative file-change scope

#### `git status --short` (verbatim)

```
 M docs/phase5_schema_reference.md
 M ml/features/pipeline.py
 M scripts/run_feature_extraction.py
 M scripts/run_pipeline.py
 M storage/storage_writer.py
 M tests/test_phase3/test_storage.py
 M tests/test_phase5/test_pipeline.py
?? Git_Upload_Commands_Log.md
?? ShadowSensor_Git_Upload_Prompt.md
?? docs/blocker_fix_final_report.md
?? docs/blocker_fix_subphase0_report.md
?? docs/blocker_fix_subphase1_report.md
?? docs/blocker_fix_subphase2_report.md
?? docs/blocker_fix_subphase3_report.md
?? docs/blocker_fix_subphase4_fix1_report.md
?? docs/blocker_fix_subphase4_fix2_report.md
?? docs/blocker_fix_subphase5_report.md
?? docs/blocker_fix_subphase6_report.md
?? docs/phase6a_blocker_report.md
?? docs/phase6a_feature_extraction_scoping_issue.md
?? docs/phase6a_subphase1_report.md
?? docs/phase6a_subphase2_report.md
?? docs/phase6a_subphase3_report.md
?? docs/phase6a_subphase4_report.md
?? docs/scoping_fix_subphase0_report.md
?? docs/scoping_fix_subphase1_report.md
?? docs/scoping_fix_subphase2_report.md
?? docs/scoping_fix_subphase3_report.md
?? docs/scoping_fix_subphase4_report.md
?? docs/scoping_fix_subphase5_report.md
?? docs/vm_clock_drift_finding.md
?? phase6a_blocker_fix_task.md
?? phase6a_scoping_fix_task.md
?? tests/test_phase3/test_pipeline_event_persistence.py
?? tests/test_phase3/test_pipeline_persist_visibility.py
```

(After this report is saved, `docs/scoping_fix_subphase6_report.md` is also new/untracked.)

#### `git diff --stat` (all modified tracked files)

```
 docs/phase5_schema_reference.md    |  54 +++++++++
 ml/features/pipeline.py            |  98 +++++++++++++++--
 scripts/run_feature_extraction.py  |  40 ++++++-
 scripts/run_pipeline.py            |  68 +++++++++---
 storage/storage_writer.py          |  50 +++++++---
 tests/test_phase3/test_storage.py  |  11 +-
 tests/test_phase5/test_pipeline.py | 219 ++++++++++++++++++++++++++++++++++++-
 7 files changed, 495 insertions(+), 45 deletions(-)
```

#### Scoping-fix product tracked diffs only

```
 docs/phase5_schema_reference.md    |  54 +++++++++
 ml/features/pipeline.py            |  98 +++++++++++++++--
 scripts/run_feature_extraction.py  |  40 ++++++-
 tests/test_phase5/test_pipeline.py | 219 ++++++++++++++++++++++++++++++++++++-
 4 files changed, 396 insertions(+), 15 deletions(-)
```

#### Pre-existing blocker-fix dirty files (known, unrelated to this task)

```
 scripts/run_pipeline.py           | 68 ++++++++++++++++++++++++++++++---------
 storage/storage_writer.py         | 50 ++++++++++++++++++++--------
 tests/test_phase3/test_storage.py | 11 +++++--
 3 files changed, 99 insertions(+), 30 deletions(-)
```

Also untracked from that prior blocker-fix task (not scoping):  
`tests/test_phase3/test_pipeline_event_persistence.py`,  
`tests/test_phase3/test_pipeline_persist_visibility.py`,  
plus blocker/phase6a process docs and `phase6a_blocker_fix_task.md`.

#### Scoping-fix file map (explained)

| File | Role in this task |
|---|---|
| `ml/features/pipeline.py` | SP3 implementation (`parse_time_bound`, filtered queries) |
| `scripts/run_feature_extraction.py` | SP3 CLI `--since`/`--until` |
| `tests/test_phase5/test_pipeline.py` | SP4 new scoping tests (+8) |
| `docs/phase5_schema_reference.md` | SP6 schema documentation |
| `docs/phase6a_feature_extraction_scoping_issue.md` | SP0 trigger-doc copy |
| `docs/vm_clock_drift_finding.md` | SP2 docs-only clock-drift finding |
| `docs/scoping_fix_subphase0_report.md` … `subphase6_report.md` | This task’s completion reports |
| `phase6a_scoping_fix_task.md` | Task brief (present in tree) |

**Generated proof CSVs (not source; optional artifacts):**  
`data/features/baseline_reproduction_check.csv`, `backward_compat_check.csv`, `sp5_host_unscoped.csv`, `sp5_host_scoped.csv`.

**Unrelated untracked (not this task):**  
`Git_Upload_Commands_Log.md`, `ShadowSensor_Git_Upload_Prompt.md`, Phase 6A subphase reports, blocker-fix docs/task.

## Findings / Conclusions

1. Final regression matches Sub-Phase 4 exactly: **514 passed**.
2. Schema reference now documents inclusive scoping, no default lookback, accepted formats, and the intentional `--until`-only whole-second `.999999` padding asymmetry.
3. Cumulative scope is clean for the scoping fix: four intended tracked product/doc files + task docs. Blocker-fix dirty files remain present and are explicitly segregated as unrelated.

## File-Change Scope (if applicable)

See Evidence Step 6.3. No unexpected product files were modified by the scoping-fix task beyond the four listed tracked diffs.

## Anomalies / Uncertainties

None blocking. `benign_baseline.csv` real-data correction remains pending the VM handoff command from Sub-Phase 5 (not part of SP6).

## Ready to Proceed?

**Yes** — Sub-Phase 6 complete. Awaiting go-ahead for Sub-Phase 7 (final consolidated report). Note: the consolidated report’s yes/no on a “genuinely clean `benign_baseline.csv`” must remain **no** until the VM command is run, per the SP5 split.
