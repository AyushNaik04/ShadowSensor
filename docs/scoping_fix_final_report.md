# Scoping Fix — Final Consolidated Report

**Date/time executed:** 2026-07-27 16:53:31 +0530  
**Task:** ShadowSensor feature extraction time-scoping (`phase6a_scoping_fix_task.md`)  
**Status:** Complete pending Ayush’s review. No Phase 6A / 6B / other phase work started in this session.

---

## Confirmed design (Sub-Phase 2) and exact diff applied (Sub-Phase 3)

### Locked design decisions (not re-litigated)

1. **Inclusive both ends:** `timestamp >= since AND timestamp <= until`.
2. **No default lookback:** omitting `--since` and `--until` preserves exact prior all-time behavior.
3. **Additive only:** same filter on `events` and `rule_hits`; `ORDER BY timestamp ASC` preserved; no changes to `FEATURE_REGISTRY`, aggregator, `run_pipeline.py`, or `storage_writer.py`.

### CLI / pipeline

- New optional CLI args: `--since`, `--until`
- Accepted formats: `YYYY-MM-DD HH:MM:SS[.ffffff]` or ISO-8601 with `T`
- Stored timestamps confirmed as TEXT `YYYY-MM-DD HH:MM:SS.ffffff` (6-digit micros)
- `FeatureExtractionPipeline.run(label=None, time_from=None, time_to=None)`
- Malformed input → stderr `[ERROR]…`, exit **2**, before any query
- **`--until` asymmetry:** pad to `.999999` **only** when no fractional component is supplied; explicit fractional `--until` used as given; `--since` never padded

### Exact product diff applied (Sub-Phase 3 + tests/docs)

```
 docs/phase5_schema_reference.md    |  54 +++++++++
 ml/features/pipeline.py            |  98 +++++++++++++++--
 scripts/run_feature_extraction.py  |  40 ++++++-
 tests/test_phase5/test_pipeline.py | 219 ++++++++++++++++++++++++++++++++++++-
 4 files changed, 396 insertions(+), 15 deletions(-)
```

Core implementation files from SP3:

- `ml/features/pipeline.py` — `parse_time_bound`, `_time_filter_sql`, optional `WHERE` on both queries
- `scripts/run_feature_extraction.py` — `--since` / `--until` argparse, validation, threading into `run()`

---

## Full regression counts

| Checkpoint | Result |
|---|---|
| Sub-Phase 1 baseline | **506 passed**, 0 failed |
| After Sub-Phase 3 implementation | **506 passed**, 0 failed |
| After Sub-Phase 4 new tests | **514 passed**, 0 failed (+8) |
| Sub-Phase 6 final | **514 passed**, 0 failed |

Rule count throughout: **49**.

---

## Sub-Phase 5 Part A — Host mechanism proof (not the real correction)

Host DB: `C:\ShadowSensor\data\shadowsensor.db` (29687 events; blocker-fix host data — **not** the VM’s 71544-row collection DB).

| Export | Command window | Process windows |
|---|---|---:|
| Unscoped | `--label 0` (all-time) | **772** |
| Scoped | `--since "2026-07-27 07:58:00" --until "2026-07-27 08:00:00"` | **353** |

**Delta: −419 windows.** Absolute activation shifts on the same host data included e.g. `open_process_suspicious_access` 305→129, `has_powershell_rule_hit` 9→4, `has_encoded_command` 44→43.

This proves the mechanism changes real extraction output end-to-end. It does **not** produce a corrected Phase 6A `benign_baseline.csv`.

Artifacts: `data/features/sp5_host_unscoped.csv`, `data/features/sp5_host_scoped.csv`.

---

## Sub-Phase 5 Part B — VM handoff command (**not yet run**)

**Must be run on the VM** against VM-local `C:\ShadowSensor\data\shadowsensor.db` (71544-row collection database). Shared project tree means no separate code sync once this fix is present.

```bat
cd /d E:\filelessmalware
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --since "2026-07-27 01:38:21" --until "2026-07-27 03:07:19" --output data\features\benign_baseline.csv
```

**`data/features/benign_baseline.csv` has not been corrected by this task.** The contaminated all-time export (795 windows in `docs/phase6a_feature_extraction_scoping_issue.md`) remains until the command above is executed on the VM.

---

## Real session boundaries

Quoted from `logs/rule_hits.log` (exact markers; not the rounded human narrative):

```
[2026-07-27 01:38:21] === SESSION START ===
[2026-07-27 03:07:19] === SESSION END ===
```

Duration: `1:28:58`. These are the correct, internally consistent bounds for filtering the VM DB.

**Why they look unusual vs “approx 14:00–15:38”:** the Lab Win10 VM clock is offset by ~12 hours relative to the host/human narrative. See `docs/vm_clock_drift_finding.md` (documentation-only; **not fixed** in this task). Do not “correct” these bounds by adding 12 hours when querying VM-stamped events. Note: `hour_of_day` / `is_off_hours` from VM-collected data may be systematically shifted until a future clock correction / separate task.

---

## Complete file list — this scoping-fix task

### In scope — product / docs / tests for this task

| File | Role |
|---|---|
| `ml/features/pipeline.py` | Implementation |
| `scripts/run_feature_extraction.py` | CLI |
| `tests/test_phase5/test_pipeline.py` | New scoping tests |
| `docs/phase5_schema_reference.md` | Schema reference update |
| `docs/phase6a_feature_extraction_scoping_issue.md` | Trigger doc copy (SP0) |
| `docs/vm_clock_drift_finding.md` | Clock-drift finding (docs-only) |
| `phase6a_scoping_fix_task.md` | Task brief |
| `docs/scoping_fix_subphase0_report.md` … `subphase6_report.md` | Sub-phase reports |
| `docs/scoping_fix_final_report.md` | This file |

Optional generated proof CSVs: `data/features/baseline_reproduction_check.csv`, `backward_compat_check.csv`, `sp5_host_unscoped.csv`, `sp5_host_scoped.csv`.

### Out of scope — pre-existing blocker-fix dirty files (unrelated)

| File | Note |
|---|---|
| `scripts/run_pipeline.py` | Prior SQLite write-path fix — not touched by scoping |
| `storage/storage_writer.py` | Prior SQLite write-path fix — not touched by scoping |
| `tests/test_phase3/test_storage.py` | Prior blocker-fix contract update |
| `tests/test_phase3/test_pipeline_event_persistence.py` | Prior blocker-fix proof tests (untracked) |
| `tests/test_phase3/test_pipeline_persist_visibility.py` | Prior blocker-fix proof tests (untracked) |

Also unrelated untracked: `Git_Upload_Commands_Log.md`, `ShadowSensor_Git_Upload_Prompt.md`, blocker-fix / Phase 6A process docs.

---

## `phase5_schema_reference.md` documentation addition (quoted)

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

---

## Final verification statement

**Is the feature extraction time-scoping fix complete and verified, with the mechanism proven correct — pending only the VM-side execution of the handoff command to produce the actual corrected benign_baseline.csv?**

**Yes.**

---

## Explicit next step

The VM handoff command (Part B above) **must be run** (by Ayush or the Builder Claude account) against the real **71544-row** VM database before Phase 6A Sub-Phase 5 (Feature Activation Analysis) can resume against corrected data.

**No new VM collection window is needed** — the underlying benign-session events are already correctly persisted; only a scoped re-extraction is required.

After that VM run: confirm row count is below the contaminated all-time export, recompute activation rates (WARP-related residuals from the in-session rule-hit cluster may remain; weeks-old simulation contamination should be gone), then resume Phase 6A Sub-Phase 5 against the corrected `benign_baseline.csv`.

---

## Ready to Proceed?

**No further agent action in this session.** This scoping-fix task is complete pending Ayush’s review. Do not begin any Phase 6A, Phase 6B, or other phase work until explicitly instructed.
