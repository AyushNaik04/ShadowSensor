# Scoping Fix — Sub-Phase 3 Completion Report

**Date/time executed:** 2026-07-27 16:44:01 +0530  
**Sub-phase goal (restated):** Apply exactly the Sub-Phase 2 design as approved, including the three required additions (conditional `--until` padding, SP4 padding-proof test requirement noted, pre-implementation timestamp-format verification); confirm file-change scope and all-time backward compatibility.

## What Was Done

1. **Pre-implementation timestamp-format verification** on host `C:\ShadowSensor\data\shadowsensor.db` (all stored `events.timestamp` values).
2. Stated and applied the final confirmed design to:
   - `ml/features/pipeline.py`
   - `scripts/run_feature_extraction.py`
3. Encoded the **exact conditional padding rule** in `parse_time_bound` docstring + implementation comments.
4. Ran file-change scope check (`git status` / `git diff --stat`).
5. Ran no-argument backward-compat extraction → `data/features/backward_compat_check.csv`; compared row count to Sub-Phase 1 reproduction (772).
6. Ran full regression suite against Sub-Phase 1 baseline (506).
7. Spot-checked malformed `--since` → exit 2 before query; spot-checked padding asserts.
8. **Did not** write Sub-Phase 4 tests yet (next sub-phase). **Did not** update `phase5_schema_reference.md` yet (Sub-Phase 6 — must document `--since`/`--until` asymmetry there).

## Evidence

### Addition 3 — Timestamp consistency check (before finalizing implementation)

```
total_events: 29687
length_distribution: [(26, 29687)]
no_fractional_part_count: 0
glob_bad_sample: []
regex_mismatched_count: 0
regex_mismatch_examples: []
```

Regex used: `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$`  
**Result:** All **29687** host `events.timestamp` values consistently use full **6-digit zero-padded** microseconds (length 26). No rows with fewer digits or missing fractional parts. Padding logic’s assumption holds on the reachable host DB.

(Note: the VM’s 71544-row DB was not reachable from this host; same storage writer path produces these timestamps, but VM re-check remains part of the Sub-Phase 5 handoff if desired.)

### Addition 1 — Padding rule as implemented

From `parse_time_bound` (applied code):

- `--until` **without** fractional/microsecond component → pad to `.999999`
- `--until` **with** explicit fractional component → use exactly as parsed (six-digit `%f`); **no** padding
- `--since` → never padded

Assert spot-check:
```
until_whole: 2026-07-27 03:07:19.999999
until_frac: 2026-07-27 03:07:19.123456
until_T_whole: 2026-07-27 03:07:19.999999
since_whole: 2026-07-27 01:38:21
since_frac: 2026-07-27 01:38:21.500000
parse_time_bound asserts OK
```

### Addition 2 — Required Sub-Phase 4 test (not implemented yet; tracked)

Beyond the SP4 cases already listed in `phase6a_scoping_fix_task.md`, Sub-Phase 4 **must** include:

> An `--until` given **without** fractional seconds must correctly **INCLUDE** an event later within that same second (nonzero microseconds), and correctly **EXCLUDE** an event in the very next second.

This proves the `.999999` padding behavior directly (not covered by the general inclusive-boundary test alone).

### Addition for Sub-Phase 6 (tracked, not done here)

`docs/phase5_schema_reference.md` must document the `--since`/`--until` asymmetry and explain why only whole-second `--until` is padded — so it does not read as an inconsistency.

### Final applied diff (SP3 product files only)

```
 ml/features/pipeline.py           | 98 ++++++++++++++++++++++++++++++++++-----
 scripts/run_feature_extraction.py | 40 +++++++++++++++-
 2 files changed, 125 insertions(+), 13 deletions(-)
```

Full diff as applied (verbatim from `git diff -- ml/features/pipeline.py scripts/run_feature_extraction.py`):

```diff
diff --git a/ml/features/pipeline.py b/ml/features/pipeline.py
index 7d2ffe4..bb42700 100644
--- a/ml/features/pipeline.py
+++ b/ml/features/pipeline.py
@@ -3,6 +3,7 @@
 from __future__ import annotations
 
 import sqlite3
+from datetime import datetime
 from pathlib import Path
 ...
+def parse_time_bound(raw: str, *, bound_name: str) -> str:
+    """... Padding rule (asymmetry is intentional):
+    - --until WITHOUT fractional → .999999
+    - --until WITH fractional → exact, no padding
+    - --since never padded
+    """
 ...
+def _time_filter_sql(...) -> tuple[str, tuple[str, ...]]:
 ...
-    def run(self, label: int | None = None) -> list[dict]:
+    def run(self, label=None, time_from=None, time_to=None) -> list[dict]:
 ...
+                events_where, events_params = _time_filter_sql(time_from, time_to)
                 event_rows = conn.execute(
-                    """ SELECT ... FROM events ORDER BY timestamp ASC """
+                    "SELECT ... FROM events" f"{events_where}\n" "ORDER BY timestamp ASC",
+                    events_params,
                 )
 ...
+                hits_where, hits_params = _time_filter_sql(time_from, time_to)
                 rule_hit_rows = conn.execute(
-                    """ SELECT ... FROM rule_hits ORDER BY timestamp ASC """
+                    "SELECT ... FROM rule_hits" f"{hits_where}\n" "ORDER BY timestamp ASC",
+                    hits_params,
                 )
```

```diff
diff --git a/scripts/run_feature_extraction.py b/scripts/run_feature_extraction.py
--- a/scripts/run_feature_extraction.py
+++ b/scripts/run_feature_extraction.py
-from ml.features.pipeline import FeatureExtractionPipeline
+from ml.features.pipeline import FeatureExtractionPipeline, parse_time_bound
+    # --since / --until argparse
+    # validate via parse_time_bound; since>until rejected; exit 2 on ValueError
-        vectors = FeatureExtractionPipeline(db_path).run(label=args.label)
+        vectors = FeatureExtractionPipeline(db_path).run(
+            label=args.label, time_from=time_from, time_to=time_to,
+        )
```

(Complete unified diff was captured in the agent session via `git diff`; summary above matches the applied files.)

### Step 3.2 — File-change scope check

`git status --short` (relevant product lines):
```
 M ml/features/pipeline.py
 M scripts/run_feature_extraction.py
 M scripts/run_pipeline.py
 M storage/storage_writer.py
 M tests/test_phase3/test_storage.py
```

`git diff --stat` (working tree vs HEAD, all modified tracked files):
```
 ml/features/pipeline.py           | 98 ++++++++++++++++++++++++++++++++++-----
 scripts/run_feature_extraction.py | 40 +++++++++++++++-
 scripts/run_pipeline.py           | 68 +++++++++++++++++++++------
 storage/storage_writer.py         | 50 ++++++++++++++------
 tests/test_phase3/test_storage.py | 11 ++++-
 5 files changed, 224 insertions(+), 43 deletions(-)
```

**SP3-only product changes** (`git diff --stat -- ml/features/pipeline.py scripts/run_feature_extraction.py`):
```
 ml/features/pipeline.py           | 98 ++++++++++++++++++++++++++++++++++-----
 scripts/run_feature_extraction.py | 40 +++++++++++++++-
 2 files changed, 125 insertions(+), 13 deletions(-)
```

**Flag:** `scripts/run_pipeline.py`, `storage/storage_writer.py`, and `tests/test_phase3/test_storage.py` appear modified in the working tree but are **pre-existing uncommitted blocker-fix changes**, not touched by this Sub-Phase 3 implementation. Confirmed by limiting the SP3 diff to the two feature-extraction files only. Out-of-scope for this task; not reverted.

### Step 3.3 — Backward compatibility (no time args)

```
[INFO] Reading from: C:\ShadowSensor\data\shadowsensor.db
[INFO] Extracted 772 process windows
[INFO] Exported to: E:\filelessmalware\data\features\backward_compat_check.csv
[INFO] Features per row: 31
baseline_rows=772 backward_compat_rows=772 match=True
```

Matches Sub-Phase 1 reproduction row count exactly (**772**).

### Malformed input (exit 2) spot-check

```
[ERROR] Invalid --since value 'not-a-date': expected YYYY-MM-DD HH:MM:SS[.ffffff] or YYYY-MM-DDTHH:MM:SS[.ffffff]
EXIT:2
```

### Full regression suite (post-implementation)

```
====================== 506 passed, 34 warnings in 40.84s ======================
```

Matches Sub-Phase 1 baseline (**506 passed**, 0 failed).

## Findings / Conclusions

1. Implementation matches the approved design: optional inclusive `time_from`/`time_to`, both queries filtered identically, `ORDER BY timestamp ASC` preserved, no-arg path unchanged (772 == 772).
2. `--until` padding is **conditional only** when no fractional component is supplied; explicit fractional `--until` is used as given.
3. Host DB timestamps are uniformly 6-digit microsecond TEXT — padding assumption verified on 29687/29687 rows.
4. Regression baseline unchanged at 506; new scoping tests deferred to Sub-Phase 4 (including the required whole-second `--until` include/exclude proof).
5. Pre-existing blocker-fix dirty files remain in the tree and are **not** part of this fix.

## File-Change Scope (if applicable)

**Intended SP3 product files changed:**  
- `ml/features/pipeline.py`  
- `scripts/run_feature_extraction.py`

**Also present but not from SP3:** `scripts/run_pipeline.py`, `storage/storage_writer.py`, `tests/test_phase3/test_storage.py` (blocker-fix).  

**New report:** `docs/scoping_fix_subphase3_report.md`

## Anomalies / Uncertainties

1. Timestamp consistency verified on **host** DB only; VM 71544-row DB not queried (unreachable). Low risk given shared writer code path, but not directly proven on VM rows.
2. Working-tree noise from prior blocker-fix remains; flagged above, not cleaned in this sub-phase.

## Ready to Proceed?

**Yes** — Sub-Phase 3 implementation is complete, backward-compatible, and regression-clean at 506. Awaiting go-ahead for Sub-Phase 4 (tests), which must include the dedicated whole-second `--until` padding proof test.
