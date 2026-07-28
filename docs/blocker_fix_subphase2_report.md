# Blocker Fix — Sub-Phase 2 Completion Report

**Date/time executed:** 2026-07-27 13:03:53 +0530
**Sub-phase goal (restated):** Build a complete, evidence-backed ranked Issues List of every candidate root cause for the silent SQLite write failure — read-only investigation only; no fixes applied.

## What Was Done

1. Full read of `storage/storage_writer.py` — every `try`/`except` quoted and characterized.
2. Full read of `alerting/alert_manager.py` — same treatment.
3. Full read of `scripts/run_pipeline.py` — traced callback wiring from collection → evaluation → log write → SQLite write; identified how log write can succeed while SQLite is skipped or fails silently.
4. Full read of `storage/database.py` — session/connection lifecycle, commit/rollback/close.
5. Cross-checked Fix Pass YAML files `rules/definitions/api_memory.yaml`, `network.yaml`, `parent_child.yaml` for field/severity/rule-id shapes that could break the storage write path (including programmatic severity validation against the DB check-constraint set).
6. Confirmed via AST that `logger` is referenced but never bound in `run_pipeline.py`.
7. Read collector callback wiring (`collector/runner.py`, `collector/poller.py`) only enough to characterize whether callback exceptions are swallowed (read-only; frozen tree not modified).
8. Produced the ranked Issues List below. **No fix was selected or applied.**

## Evidence

### Step 2.1 — `storage/storage_writer.py` exception blocks

**Block A — `_coerce_datetime` (lines 55–58)**
```55:58:storage/storage_writer.py
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                return None
```
Characterization: Catches `ValueError` only; returns `None` (fallback path). Does not log. Not a silent SQLite-write swallow by itself.

**Block B — `write_event` (lines 68–103)**
```68:103:storage/storage_writer.py
        try:
            if not dataclasses.is_dataclass(event):
                logger.warning("write_event received non-dataclass event: %r", type(event))
                return None
            # ... build EventRecord, session.add, session.flush, return record.id ...
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write event to SQLite (non-fatal): %s", exc)
            return None
```
Characterization: Catches **all** `Exception`s; logs a warning via module `logger`; returns `None`. Does **not** re-raise. Explicit non-raising contract.

**Block C — `write_rule_hit` (lines 107–136)**
```107:136:storage/storage_writer.py
        try:
            # ... build RuleHitRecord, session.add, session.flush, return record.id ...
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write rule hit to SQLite (non-fatal): %s", exc)
            return None
```
Characterization: Same as Block B — catch-all, warning log, return `None`, no re-raise.

**Block D — `write_alert_from_hit` (lines 146–187)**
```146:187:storage/storage_writer.py
        try:
            # ... build AlertRecord, session.add, session.flush, return record.id ...
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write alert to SQLite (non-fatal): %s", exc)
            return None
```
Characterization: Same as Blocks B/C — catch-all, warning log, return `None`, no re-raise.

### Step 2.2 — `alerting/alert_manager.py` exception blocks

**Block E — `process_hit` (lines 27–30)**
```27:30:alerting/alert_manager.py
        try:
            self._writer.write_alert_from_hit(hit, rule_hit_id, event_id, raw_event)
        except Exception as exc:  # pragma: no cover - defensive contract
            logger.warning("AlertManager failed to process hit (non-fatal): %s", exc)
```
Characterization: Catch-all; logs warning; does not re-raise; returns `None` implicitly. Note: `write_alert_from_hit` already never raises per its own contract, so this handler is defensive/redundant under current writer behavior.

### Step 2.3 — `scripts/run_pipeline.py` callback wiring

**Startup / wiring (relevant):**
```119:121:scripts/run_pipeline.py
    init_db()
    _storage_writer = StorageWriter()
    _alert_manager = AlertManager(_storage_writer)
```
```150:155:scripts/run_pipeline.py
        poller = run_collector(
            callback=on_event,
            poll_interval=2,
            bookmark_path=Path("logs/.shadowsensor_bookmark.xml"),
        )
```

**`on_event` full control flow (quoted):**
```123:147:scripts/run_pipeline.py
    def on_event(event: Any) -> None:
        hits = engine.evaluate(event)

        # Secondary corroboration (hash + decoded-content) — never produces rule_hit
        corr: CorroborationResult = corroborate_event(event)
        if corr.has_findings:
            log_corroboration(event, hits, corr, log=_corr_logger)

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

**Order of operations (factual):**
1. `engine.evaluate(event)` → `hits`
2. Optional corroboration logging (does not create rule hits / does not write SQLite)
3. **If `hits` is empty → `return` immediately** — no log `RULE_HIT` line, **and no SQLite calls**
4. If `hits` non-empty → write each hit to stdout + `logs/rule_hits.log` (flush)
5. **Only after log writes** → SQLite: `write_event` → per-hit `write_rule_hit` → `process_hit`

**How log write can succeed while SQLite is skipped or fails silently:**
- **Skipped entirely:** lines 131–132 early-return when `not hits`. Session START/END markers still append to `logs/rule_hits.log` (lines 100–101, 161–162) even when no SQLite writes occur. Any event with zero rule hits never reaches `write_event`.
- **Log succeeds, SQLite fails without aborting pipeline:** log writes (134–138) happen **before** and **outside** the SQLite `try` block (141–147). StorageWriter methods catch exceptions internally and return `None`, so the outer `try` typically completes without raising even when DB writes fail.
- **Outer handler itself is broken if reached:** line 147 references `logger`, but the only logging name bound in this module is `_corr_logger` (line 24). AST confirmation: `logger_in_bound_names: False`.

**Collector exception behavior (read-only context):**
```37:40:collector/runner.py
    def _inner_callback(xml: str, event_id: int) -> None:
        result = parse_event(xml)
        if result is not None:
            callback(result)
```
```73:74:collector/poller.py
                for xml, event_id in results:
                    callback(xml, event_id)
```
No `try`/`except` around the user callback in these paths. An exception escaping `on_event` would propagate on the collector thread (not silently swallowed there).

### Step 2.4 — `storage/database.py` session lifecycle

```73:84:storage/database.py
@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a committed-or-rolled-back SQLAlchemy session."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

Factual observations:
- **`.commit()` is present** (line 79), executed after a successful `yield` (including when the caller `return`s from inside the `with` block — context manager `__exit__` still runs).
- On exception: `rollback()` then **re-raise** (not swallowed here).
- `finally`: always `session.close()`.
- Engine is created at import time (`engine = create_db_engine()`, line 69) with `DB_PATH = C:\ShadowSensor\data\shadowsensor.db` unless `SHADOWSENSOR_DB_DIR` overrides.
- PRAGMA failures on connect are caught, logged as warnings, and skipped (lines 56–63) — they do not abort engine creation.

**Missing-commit hypothesis from the blocker report: not supported by this code.** Commit exists and is on the success path.

### Step 2.5 — Fix Pass YAML cross-check

Files read / validated: `rules/definitions/api_memory.yaml`, `network.yaml`, `parent_child.yaml`.

Observed Fix Pass–related content still present:
- `api_memory.yaml`: `API_AV_PROCESS_ACCESS_001` exclusions include `csrss.exe`, `conhost.exe`, `svchost.exe`, `lsass.exe`, `winlogon.exe`, `wininit.exe`
- `network.yaml`: `NET_DNS_LONG_QUERY_001` exclusions include `SearchApp.exe`
- `parent_child.yaml`: `CHAIN_SCHEDULED_TASK_SCRIPT_001` (legacy scheduler parents) + sibling `CHAIN_SCHEDULED_TASK_SVCHOST_001` (`svchost.exe` + `-s Schedule`)

Severity validation against DB check-constraint set `{'Low','Medium','High','Critical'}`:
```
=== api_memory.yaml: 7 rules ===
  ... all severities in {Critical, High} ...
  invalid_severity: none
=== network.yaml: 8 rules ===
  ... all severities in {High, Medium} ...
  invalid_severity: none
=== parent_child.yaml: 10 rules ===
  ... all severities in {High, Medium} ...
  invalid_severity: none
```

Rule IDs are ordinary uppercase underscore strings (including `CHAIN_SCHEDULED_TASK_SVCHOST_001`). No field-name / severity / rule-id shape was found that would uniquely break `StorageWriter` / ORM constraints.

**Cross-check result: EMPTY** for indirect storage-write-path breakage via these three YAML files.

## Findings / Conclusions

### Ranked Issues List

#### Issue 1 — SQLite persistence is gated behind non-empty `hits` (early return)

- **File/lines:** `scripts/run_pipeline.py` 131–132 (gate); SQLite calls only at 141–145
- **Quoted code:**
```131:145:scripts/run_pipeline.py
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
```
- **Why plausible:** Directly explains zero DB delta on runs with no `RULE_HIT` lines (Phase 6A Sub-Phase 2 benign window; blocker report’s 2026-07-27 2-minute reproduction transcript also shows no `RULE_HIT`). Session START/END still update `logs/rule_hits.log`, matching “log works, DB unchanged.” By code, **benign-only events are never written to `events` at all.**
- **Confidence:** **Confirmed** as actual control-flow behavior for the no-hit case. **Does not by itself prove** the separate claim that sessions *with* logged `RULE_HIT`s also failed to write (that requires Issue 2+ and Sub-Phase 3 reproduction).

#### Issue 2 — `StorageWriter` catch-all handlers convert write failures into `None` (non-raising)

- **File/lines:** `storage/storage_writer.py` 101–103, 134–136, 185–187
- **Quoted code:**
```101:103:storage/storage_writer.py
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write event to SQLite (non-fatal): %s", exc)
            return None
```
```134:136:storage/storage_writer.py
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write rule hit to SQLite (non-fatal): %s", exc)
            return None
```
```185:187:storage/storage_writer.py
        except Exception as exc:  # pragma: no cover - explicit non-raising contract
            logger.warning("Failed to write alert to SQLite (non-fatal): %s", exc)
            return None
```
- **Why plausible:** Matches the symptom class “pipeline continues; no crash; SQLite rows don’t appear.” Log writes occur before/outside these calls. If an underlying DB/ORM error occurs on the hit path, these blocks prevent it from aborting the pipeline.
- **Confidence:** **Strong candidate** for hit-path silent failure. Tension with blocker report’s “zero visible warnings”: these paths *do* call `logger.warning`, which should be visible under `logging.basicConfig(level=logging.INFO, ...)` in `run_pipeline.py` unless the failure mode produces no exception, warnings were missed on stderr, or writes are never attempted (Issue 1). **Not Confirmed** without a captured exception (Sub-Phase 3).

#### Issue 3 — Outer SQLite `except` in `run_pipeline.py` references undefined `logger`

- **File/lines:** `scripts/run_pipeline.py` 146–147 (use); contrast line 24 (`_corr_logger` only)
- **Quoted code:**
```22:24:scripts/run_pipeline.py
import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
_corr_logger = logging.getLogger("shadowsensor.corroboration")
```
```146:147:scripts/run_pipeline.py
        except Exception as _exc:
            logger.warning("SQLite persistence failed (non-fatal): %s", _exc)
```
- **AST evidence:** `logger_in_bound_names: False`; only usage of bare `logger` is line 147.
- **Why plausible:** If any exception escapes the StorageWriter/AlertManager non-raising contracts into this `except`, handling itself raises `NameError: name 'logger' is not defined`. That secondary exception would leave the outer handler, and the collector callback path does not catch it — risking collector-thread failure rather than a clean warning. Also means this intended “surface the SQLite failure” path cannot work as written.
- **Confidence:** **Confirmed** as a code defect (undefined name). **Possible** as the *primary* explanation of the historical silent no-write symptom, because under current StorageWriter contracts the outer `except` normally never runs; long sessions with continued `RULE_HIT` logging argue against frequent uncaught callback crashes.

#### Issue 4 — `AlertManager.process_hit` catch-all (alerts-only)

- **File/lines:** `alerting/alert_manager.py` 27–30
- **Quoted code:** see Block E above
- **Why plausible:** Could hide alert-write failures. Cannot alone explain `events` and `rule_hits` also freezing, because those are written before/outside this method’s responsibility (`write_event` / `write_rule_hit`).
- **Confidence:** **Possible** (partial / secondary only).

#### Issue 5 — Timezone-aware timestamps written into naive `DateTime` columns

- **File/lines:** `storage/storage_writer.py` 62–64 (`datetime.now(UTC)`), 79/113/163 (timestamp assignment); models use `mapped_column(DateTime, ...)` without `timezone=True` in `storage/models.py`
- **Quoted code:**
```62:64:storage/storage_writer.py
    def _utc_now() -> datetime:
        """Return current UTC datetime."""
        return datetime.now(UTC)
```
- **Why plausible:** Aware datetimes into timezone-naive SQLAlchemy `DateTime` columns can raise or warn depending on SQLAlchemy/SQLite binding behavior; any raise would be swallowed by Issue 2. Host runtime is Python 3.13.5 (Sub-Phase 1). No direct proof this is failing in live runs.
- **Confidence:** **Possible** — worth ruling out in Sub-Phase 3; not proven by static read alone.

#### Issue 6 — Fix Pass YAML indirect breakage

- **Result:** **Empty.** No candidate raised. Severities and rule IDs are compatible with storage constraints; YAML changes affect matching only, not the writer API shape.

#### Explicitly investigated / not raised as a candidate

- **Missing `session.commit()`:** Not found. `get_session()` commits on success (database.py:79).
- **Premature close without commit on success path:** Not found; `close()` is in `finally` after commit/rollback.

## File-Change Scope (if applicable)

No source files modified. Only this report created: `docs/blocker_fix_subphase2_report.md`.

## Anomalies / Uncertainties

1. **Issue 1 vs blocker “RULE_HIT sessions also wrote no DB rows”:** Issue 1 is proven for no-hit runs. The stronger claim (hit sessions after 2026-07-12 also left DB mtime frozen) is **not yet proven on this host** and is not fully explained by Issue 1 alone. Sub-Phase 3 must reproduce with an intentional rule hit and capture whether StorageWriter warns / raises / writes.
2. **Issue 2 vs “no visible warnings”:** If writes fail via Issue 2, warnings are expected. Their absence in the blocker transcript is unresolved — possible stderr-not-captured, no exception occurring, or writes not attempted.
3. **No fix selected.** Per task rules, Sub-Phase 3 must confirm root cause with captured evidence before any code change.

## Ready to Proceed?

**No — hard stop.** Sub-Phase 2 complete. Issues List is ready for your review. Awaiting explicit confirmation of which issue(s) to pursue in Sub-Phase 3 before any instrumentation or fix.
