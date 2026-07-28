# Blocker Fix — Sub-Phase 3 Completion Report

**Date/time executed:** 2026-07-27 13:16:07 +0530
**Sub-phase goal (restated):** Convert Issues #1, #2, and #3 into proven root-cause statements with literal captured evidence (reproduction + instrumentation only — no fix applied).

## What Was Done

1. Confirmed Issue #1 from the live `run_pipeline.py` control-flow order (code quote) and from a runtime reproduction that evaluated a benign notepad event (0 hits) and an encoded-command event (`PS_ENCODED_CMD_001`).
2. Added temporary, clearly marked `DIAG_TEMP` instrumentation to `storage/storage_writer.py` and `scripts/run_pipeline.py` to surface swallowed exceptions and observe the undefined-`logger` outer handler.
3. Attempted a live Sysmon pipeline run on the host: non-elevated `EvtQuery` failed with Access Denied; Windows `sudo` is disabled; elevated `Start-Process -Verb RunAs` launched but stdout/stderr redirection from the elevated process could not be reliably captured in this environment.
4. Because Sysmon channel access requires elevation that this non-admin agent shell cannot hold, ran an equivalent callback-path reproduction using the **real** `RuleEngine` + `StorageWriter` + `AlertManager` and the **same control-flow order** as `on_event` in `run_pipeline.py` (log-equivalent step → SQLite try → broken `logger.warning` except). Encoded-command rule hit: `PS_ENCODED_CMD_001`.
5. For Issue #2, observed the natural hit-path write result, then injected a session failure to force and capture a literal swallowed exception through the real `StorageWriter.write_event` except block.
6. For Issue #3, forced the outer `except` to run once (after successful SQLite calls) and captured the literal `NameError` from `logger.warning(...)`.
7. Removed all `DIAG_TEMP` instrumentation from source files; deleted temporary helper scripts/bats. Left `logs/diag_sp3_capture.txt` as the raw capture artifact. No fix was applied (`logger` remains undefined; early-return gate unchanged; StorageWriter still swallows).

## Evidence

### Issue #1 — Does the early return skip `events` writes too?

**Code proof (current `scripts/run_pipeline.py`):** `write_event` is inside the block that is only reachable after the `if not hits: return` gate. Therefore the early return skips **`write_event` (events table), `write_rule_hit`, and `process_hit`** — not merely rule_hit/alert writes.

```131:147:scripts/run_pipeline.py
        if not hits:
            return

        for hit in hits:
            line = _format_hit(hit, event)
            print(line)
            log_file.write(line + "\n")
            log_file.flush()

        # Phase 3 — persist to SQLite (additive; does not affect pipeline behaviour)
        try:
            _event_db_id = _storage_writer.write_event(event)
            for _hit in hits:
                _hit_db_id = _storage_writer.write_rule_hit(_hit, _event_db_id)
                _alert_manager.process_hit(_hit, _hit_db_id, _event_db_id, event)
        except Exception as _exc:
            logger.warning("SQLite persistence failed (non-fatal): %s", _exc)
```

**Runtime proof (callback repro, same gate logic):**
```
[DIAG_TEMP Issue#1] benign hits=0 rule_ids=[]
[DIAG_TEMP Issue#1] early return path TAKEN — write_event NOT called (same gate as run_pipeline.py lines if not hits: return BEFORE write_event)
[DIAG_TEMP] encoded hits=1 rule_ids=['PS_ENCODED_CMD_001']
[DIAG_TEMP Issue#1] entering SQLite block — calling write_event
```

**Phase 6A implication (directly from the above):** a clean benign window with zero rule hits never calls `write_event`, so `events` cannot gain process-window population for feature extraction.

### Issue #2 — StorageWriter catch-all: natural hit path + forced swallowed exception

**Natural hit path (encoded command → `PS_ENCODED_CMD_001`): writes succeeded; nothing was swallowed.**
```
[DIAG_TEMP Issue#2] write_event returned: 1
[DIAG_TEMP Issue#2] write_rule_hit('PS_ENCODED_CMD_001') returned: 1
[DIAG_TEMP] DB events: 1 rows
[DIAG_TEMP] DB rule_hits: 1 rows
[DIAG_TEMP] DB alerts: 1 rows
[DIAG_TEMP] latest rule_hits rows: [(1, 'PS_ENCODED_CMD_001')]
```

**Forced failure through the real instrumented `write_event` except (session raise injected): literal swallowed exception:**
```
[DIAG_TEMP Issue#2] write_event SWALLOWED exception: RuntimeError: RuntimeError('DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_ISSUE2')
[DIAG_TEMP Issue#2] write_event full traceback follows:
Traceback (most recent call last):
  File "E:\filelessmalware\storage\storage_writer.py", line 90, in write_event
    with get_session() as session:
         ~~~~~~~~~~~^^
  File "E:\filelessmalware\logs\diag_sp3_callback_repro.py", line 134, in _boom_session
    raise RuntimeError("DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_ISSUE2")
RuntimeError: DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_ISSUE2

Failed to write event to SQLite (non-fatal): DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_ISSUE2
[DIAG_TEMP Issue#2] after injected failure write_event returned: None
```

Observed behavior of Issue #2’s contract: exception is logged via `logger.warning`, **not re-raised**, caller receives `None`, pipeline continues.

### Issue #3 — What happens when the undefined `logger` line executes?

After SQLite calls completed, the outer `except` was entered with an intentional `RuntimeError`. Executing the production statement `logger.warning(...)` then raised:

```
[DIAG_TEMP Issue#3] outer except ENTERED with: RuntimeError: RuntimeError('DIAG_TEMP_FORCE_OUTER_EXCEPT_FOR_ISSUE3 (intentional — after SQLite calls completed)')
[DIAG_TEMP Issue#3] CONFIRMED NameError on logger.warning: NameError: NameError("name 'logger' is not defined")
[DIAG_TEMP Issue#3] NameError traceback follows:
Traceback (most recent call last):
  File "E:\filelessmalware\logs\diag_sp3_callback_repro.py", line 111, in main
    raise RuntimeError(
    ...<2 lines>...
    )
RuntimeError: DIAG_TEMP_FORCE_OUTER_EXCEPT_FOR_ISSUE3 (intentional — after SQLite calls completed)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "E:\filelessmalware\logs\diag_sp3_callback_repro.py", line 118, in main
    logger.warning("SQLite persistence failed (non-fatal): %s", exc)  # noqa: F821
    ^^^^^^
NameError: name 'logger' is not defined
```

**Chain behavior (evidence-based):**
1. Something raises inside the SQLite `try` in `on_event`.
2. Outer `except` runs and attempts `logger.warning(...)`.
3. That raises `NameError: name 'logger' is not defined` (module only defines `_corr_logger`).
4. In production `run_pipeline.py` there is **no** wrapper around that `NameError`. Collector callback invocation in `collector/poller.py` / `collector/runner.py` has **no** try/except around the user callback, so this `NameError` propagates on the collector thread (would not be a “clean warning”; it would abort that thread). This is **not** a silent swallow of the original SQLite error — it **replaces** it with an uncaught `NameError`.

**Why long clean pipeline sessions can still exist with #3 present:** Issue #2’s non-raising contract normally prevents the outer `except` from ever running. #3 is dead/latent unless something outside StorageWriter’s swallow raises in that `try` body.

### Live Sysmon pipeline attempt (host)

Non-elevated `scripts/run_pipeline.py`:
```
Exception in thread ShadowSensor-Collector:
...
pywintypes.error: (5, 'EvtQuery', 'Access is denied.')
...
RuntimeError: Sysmon channel not found. Is Sysmon installed and running?
```

Also confirmed: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational` → `UnauthorizedAccessException` for the current non-admin user; `sudo` reports disabled. Elevated launches were attempted; reliable live Sysmon + encoded-command capture under this agent session was not obtained. Callback-path reproduction above used the same rule/storage code paths with `PS_ENCODED_CMD_001`.

### Post-repro host DB state (side effect of reproduction writes)
```
events 1
rule_hits 1
alerts 1
[(1, 'PS_ENCODED_CMD_001')]
```

## Findings / Conclusions

**Confirmed root cause(s):**

1. **Issue #1 — CONFIRMED primary cause of zero SQLite growth during zero-hit / benign collection:** `on_event` returns before `write_event` when `not hits`. This skips **events, rule_hits, and alerts** persistence for every non-matching event. This is incompatible with Phase 6A’s need to persist full benign process-window telemetry.

2. **Issue #2 — CONFIRMED silencing mechanism, NOT confirmed as an active natural failure on the host hit path in this reproduction:** When an exception occurs inside `StorageWriter`, it is swallowed (`warning` + `return None`). On the encoded-command hit path here, writes **succeeded** (event/rule_hit/alert ids returned; rows present). No natural swallowed exception was observed during the successful write. A forced injected failure produced the literal `RuntimeError: DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_ISSUE2` and returned `None`.

3. **Issue #3 — CONFIRMED defect in the outer handler:** `logger` is undefined; executing that line raises `NameError: name 'logger' is not defined`. It does **not** silently succeed. It does **not** by itself explain clean multi-hour runs with only StorageWriter failures, because Issue #2 prevents those failures from reaching this handler. When the outer handler *does* run, the NameError is worse than a warning: it can kill the collector thread.

**Failure-chain reading supported by evidence:** #1 explains Phase 6A benign empty DB. #2 hides StorageWriter failures from the outer handler (and from crashing the pipeline). #3 is a broken fallback that only matters if something raises past #2 — and then it fails loudly via NameError rather than logging cleanly.

## File-Change Scope (if applicable)

Temporary instrumentation was applied then **fully removed** from:
- `scripts/run_pipeline.py`
- `storage/storage_writer.py`

`git diff --stat` on those two files after cleanup: empty (restored).

Artifacts retained for evidence (not product code):
- `logs/diag_sp3_capture.txt` — raw DIAG capture from the reproduction

Temporary helpers deleted:
- `logs/diag_sp3_callback_repro.py`
- `logs/diag_sp3_run_elevated.bat`

No fix applied.

## Anomalies / Uncertainties

1. **Live Sysmon encoded-command pipeline on this host agent session was blocked by Access Denied** (non-admin). Evidence for #1/#2/#3 therefore comes from code quotes + a same-path callback reproduction with real RuleEngine/StorageWriter, not from an elevated live Sysmon poll loop in this session.
2. **Host hit-path SQLite writes succeeded** in this reproduction. That does **not** prove the VM’s post-2026-07-12 hit sessions wrote successfully; it does show that with current shared code on this host, the writer path works when invoked. The blocker report’s “RULE_HIT sessions also wrote nothing” remains **not re-proven on the VM DB in this sub-phase**.
3. Host DB now contains the 1/1/1 reproduction rows (`PS_ENCODED_CMD_001`) as a side effect of Sub-Phase 3 evidence gathering.

## Ready to Proceed?

**No — hard stop.** Sub-Phase 3 complete. Awaiting your review of the captured evidence and explicit authorization before any Sub-Phase 4 fix.
