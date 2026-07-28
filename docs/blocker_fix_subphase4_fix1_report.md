# Blocker Fix — Sub-Phase 4.Fix1 Completion Report

**Date/time executed:** 2026-07-27 13:22:31 +0530
**Sub-phase goal (restated):** Apply Fix 1 only — remove the `if not hits: return` gate so `write_event` always runs for every evaluated event (including benign zero-hit events). Do not change exception-handling code. Verify with scope check, full regression, and a targeted proof test.

## What Was Done

### Step 4.1.1 — Stated fix (before apply)
Intended change to `scripts/run_pipeline.py` only:
- Replace `if not hits: return` + unconditional hit-log loop with `if hits:` log loop
- Ensure SQLite `write_event` always executes after evaluation
- Leave the `except` / `logger.warning(...)` block untouched

### Step 4.1.2 — Applied
Applied the early-return removal as stated, plus a small extract of the persistence body into module-level `persist_pipeline_event(...)` so the previously broken path is directly unit-testable. Exception-handling code was not modified (same `try`/`except` / `logger.warning` lines remain).

### Step 4.1.3 — File-change scope check
Ran `git status` / `git diff --stat`.

### Step 4.1.4 — Full regression suite
Ran `python_runtime\python.exe -m pytest tests\ -v --tb=short -q`.

### Step 4.1.5 — Targeted proof test
Added and ran `tests/test_phase3/test_pipeline_event_persistence.py` proving a zero-hit event still creates an `events` row (and does not create rule_hit/alert rows).

## Evidence

### Exact applied diff (`scripts/run_pipeline.py`)
```diff
+def persist_pipeline_event(
+    event: Any,
+    hits: list[Any],
+    storage_writer: StorageWriter,
+    alert_manager: AlertManager,
+) -> int | None:
+    """Always persist the event; persist rule hits/alerts only when hits exist.
+    ...
+    """
+    event_db_id = storage_writer.write_event(event)
+    for hit in hits:
+        hit_db_id = storage_writer.write_rule_hit(hit, event_db_id)
+        alert_manager.process_hit(hit, hit_db_id, event_db_id, event)
+    return event_db_id

-        if not hits:
-            return
-
-        for hit in hits:
-            line = _format_hit(hit, event)
-            print(line)
-            log_file.write(line + "\n")
-            log_file.flush()
-
-        # Phase 3 — persist to SQLite (additive; does not affect pipeline behaviour)
-        try:
-            _event_db_id = _storage_writer.write_event(event)
-            for _hit in hits:
-                _hit_db_id = _storage_writer.write_rule_hit(_hit, _event_db_id)
-                _alert_manager.process_hit(_hit, _hit_db_id, _event_db_id, event)
-        except Exception as _exc:
-            logger.warning("SQLite persistence failed (non-fatal): %s", _exc)
+        if hits:
+            for hit in hits:
+                line = _format_hit(hit, event)
+                print(line)
+                log_file.write(line + "\n")
+                log_file.flush()
+
+        # Phase 3 — persist to SQLite (additive; does not affect pipeline behaviour)
+        # Always write the event, including benign zero-hit events needed for Phase 6A.
+        try:
+            persist_pipeline_event(event, hits, _storage_writer, _alert_manager)
+        except Exception as _exc:
+            logger.warning("SQLite persistence failed (non-fatal): %s", _exc)
```

Exception-handling lines unchanged.

### Step 4.1.3 — Scope check output
```
On branch main
Changes not staged for commit:
	modified:   scripts/run_pipeline.py

Untracked files:
	... (prior docs/task artifacts) ...
	tests/test_phase3/test_pipeline_event_persistence.py

 scripts/run_pipeline.py | 38 ++++++++++++++++++++++++++------------
 1 file changed, 26 insertions(+), 12 deletions(-)
```

Fix-intended files only: `scripts/run_pipeline.py` (modified) and `tests/test_phase3/test_pipeline_event_persistence.py` (new). No frozen-tree (`collector/`, `normalizer/`, `rules/`) changes. No `storage/` or `alerting/` changes.

### Step 4.1.5 — Targeted proof test (code + result)
Test file exercises `persist_pipeline_event` (the fixed path now called from `on_event`) with `hits=[]`:

```
tests/test_phase3/test_pipeline_event_persistence.py::test_zero_hit_event_still_writes_events_row PASSED
tests/test_phase3/test_pipeline_event_persistence.py::test_nonempty_hits_still_write_event_and_rule_hit PASSED
============================== 2 passed in 0.96s ==============================
```

Zero-hit assertions: `events` count == 1, `rule_hits` == 0, `alerts` == 0, returned id > 0.

### Step 4.1.4 — Full regression vs Sub-Phase 1 baseline
Sub-Phase 1 baseline: **502 passed, 0 failed**

Fix 1 result:
```
====================== 504 passed, 34 warnings in 29.70s ======================
```

**504 = 502 baseline + 2 new proof tests. Zero failures.**

## Findings / Conclusions

1. Issue #1 is fixed in `scripts/run_pipeline.py`: zero-hit events no longer early-return before persistence; `write_event` always runs via `persist_pipeline_event`.
2. Exception-handling code was not modified in this fix.
3. Targeted proof confirms a zero-hit benign event creates an `events` row without rule_hit/alert rows.
4. Full suite is green at 504/504.

## File-Change Scope (if applicable)

Intended Fix 1 files:
- `scripts/run_pipeline.py` — early-return removal + `persist_pipeline_event` helper
- `tests/test_phase3/test_pipeline_event_persistence.py` — new proof tests

No unexpected source changes. Pre-existing untracked docs/task files from earlier sub-phases remain untracked and were not part of this fix.

## Anomalies / Uncertainties

1. The stated Step 4.1.1 preview described an inline-only restructuring; the applied change also extracted `persist_pipeline_event` for direct proof-test access. Behavior matches the stated intent; exception handling remains untouched.
2. Issues #2 / #3 (StorageWriter swallow; undefined `logger`) are intentionally **not** addressed in Fix 1.

## Ready to Proceed?

**No — hard stop after Fix 1.** Awaiting explicit go-ahead before Fix 2 (exception-handling path / Issues #2–#3).
