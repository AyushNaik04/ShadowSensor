# Blocker Fix — Sub-Phase 4.Fix2 Completion Report

**Date/time executed:** 2026-07-27 13:27:00 +0530
**Sub-phase goal (restated):** Fix Issues #2 and #3 together — stop silent SQLite write swallows, replace the undefined `logger` reference with a correct logger, and ensure failures are logged with diagnostic detail without killing the collector thread.

## What Was Done

### Step 4.2.1 — Stated fix (before apply)
- Confirmed from code that `run_pipeline.py` only defined `_corr_logger` (corroboration). Correct SQLite logger: new `logger = logging.getLogger(__name__)`, not reuse of `_corr_logger`.
- Design choice confirmed: pipeline boundary logs failures and does **not** re-raise (collector stays alive). `StorageWriter` must **re-raise** persistence errors so the pipeline handler can see them (previously `return None` meant the outer except never ran).
- Stated diffs for `scripts/run_pipeline.py` and `storage/storage_writer.py` before applying.

### Step 4.2.2 — Applied
Applied as stated: module `logger`, `handle_persist_pipeline_event` (visible log, non-fatal), StorageWriter DB except blocks log with `exc_info=True` then `raise`. Updated storage unit test that previously expected `return None` on DB failure.

### Step 4.2.3 — File-change scope check
### Step 4.2.4 — Full regression suite
### Step 4.2.5 — Targeted proof tests for visible non-fatal failure

## Evidence

### Logger name confirmation (from code before/after)
Before Fix 2, only:
```python
_corr_logger = logging.getLogger("shadowsensor.corroboration")
```
and the broken call site used undefined `logger`. After Fix 2:
```python
logger = logging.getLogger(__name__)
_corr_logger = logging.getLogger("shadowsensor.corroboration")
```

### Key applied behavior (`scripts/run_pipeline.py`)
```python
def handle_persist_pipeline_event(...) -> bool:
    try:
        persist_pipeline_event(event, hits, storage_writer, alert_manager)
        return True
    except Exception as exc:
        logger.error(
            "SQLite persistence failed (non-fatal) [%s]: %s",
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return False
```
`on_event` calls `handle_persist_pipeline_event(...)` — no re-raise at pipeline boundary.

### Key applied behavior (`storage/storage_writer.py`)
Each of `write_event` / `write_rule_hit` / `write_alert_from_hit` DB failure paths:
```python
        except Exception as exc:
            logger.error(
                "Failed to write event to SQLite [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            raise
```
Validation soft-fails (`non-dataclass` / missing `event_type_id` → `return None`) unchanged.

### Step 4.2.3 — Scope check
```
modified:   scripts/run_pipeline.py
modified:   storage/storage_writer.py
modified:   tests/test_phase3/test_storage.py
untracked:  tests/test_phase3/test_pipeline_persist_visibility.py
```
(`run_pipeline.py` also still contains Fix 1 changes from the prior hard-stop; no frozen-tree edits.)

### Step 4.2.5 — Targeted proof results
```
tests/test_phase3/test_pipeline_persist_visibility.py::test_write_failure_is_logged_visibly_without_raising PASSED
tests/test_phase3/test_pipeline_persist_visibility.py::test_pipeline_continues_after_logged_write_failure PASSED
tests/test_phase3/test_storage.py::test_write_event_db_exception_is_logged_and_reraised PASSED
tests/test_phase3/test_pipeline_event_persistence.py::... PASSED (Fix 1 still green)
============================== 5 passed in 0.85s ==============================
```

Forced failure injection (`RuntimeError: DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_FIX2`) asserts:
- `handle_persist_pipeline_event` returns `False` (does not raise to caller)
- caplog contains `SQLite persistence failed (non-fatal)`, `RuntimeError`, the injected message, and `Traceback`
- a subsequent healthy persist still succeeds (pipeline continues)

### Step 4.2.4 — Full regression vs baselines
- Sub-Phase 1 baseline: **502 passed**
- After Fix 1: **504 passed**
- After Fix 2:
```
====================== 506 passed, 34 warnings in 25.04s ======================
```
**506 = 502 + 2 (Fix 1 proofs) + 2 (Fix 2 proofs).** Storage test was replaced in place (same count). Zero failures.

## Findings / Conclusions

1. Issue #3 fixed: undefined `logger` replaced with `logging.getLogger(__name__)`.
2. Issue #2 fixed: StorageWriter no longer silently `return None` on persistence exceptions; it logs with type/message/traceback and re-raises to the pipeline boundary.
3. Pipeline boundary logs the failure with type/message/`exc_info` and does **not** re-raise — collector thread remains up. This design choice is confirmed reasonable for a telemetry agent.
4. `_corr_logger` left exclusively for corroboration (not reused for SQLite errors).

## File-Change Scope (if applicable)

Fix 2 intended files:
- `scripts/run_pipeline.py`
- `storage/storage_writer.py`
- `tests/test_phase3/test_storage.py` (contract update)
- `tests/test_phase3/test_pipeline_persist_visibility.py` (new)

No unexpected product-code files. `alerting/alert_manager.py` untouched (Issue #4 deferred).

## Anomalies / Uncertainties

1. A failed write currently produces **two** ERROR log records (StorageWriter then `handle_persist_pipeline_event`) because both layers log before the pipeline swallows. Visible by design; slightly redundant but acceptable.
2. `AlertManager.process_hit` still has its own defensive `except` (Issue #4, not in scope). Alert-path failures raised by `write_alert_from_hit` are caught there first; event/rule_hit path visibility is covered by Fix 2.

## Ready to Proceed?

**No — hard stop after Fix 2.** Awaiting explicit go-ahead before Sub-Phase 5 (live end-to-end reproduction).
