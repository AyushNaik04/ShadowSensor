# Blocker Fix — Sub-Phase 5 Completion Report

**Date/time executed:** 2026-07-27 13:28:21–13:34:42 +0530
**Sub-phase goal (restated):** Prove Fixes 1 and 2 end-to-end against real Sysmon telemetry on the host (elevated), including benign zero-hit event persistence and visible failure when `SHADOWSENSOR_DB_DIR` is invalid; then confirm recovery writes to the correct DB again.

## What Was Done

1. Deleted `logs/.shadowsensor_bookmark.xml`; captured pre-run DB baseline.
2. Launched `scripts/run_pipeline.py` via elevated (`RunAs`) helper bat with `PYTHONUNBUFFERED=1` and file-captured stdout/stderr.
3. Generated real activity (Explorer, Notepad open/close) and the standard encoded-command trigger; confirmed live `PS_ENCODED_CMD_001`.
4. Stopped the elevated pipeline; verified `logs/rule_hits.log` and SQLite table deltas, including benign Notepad/Explorer events and zero-hit event population (Fix 1).
5. Ran Step 5.4 negative test with `SHADOWSENSOR_DB_DIR=Z:\this_path_does_not_exist`; captured visible failure output.
6. Cleared `SHADOWSENSOR_DB_DIR`, re-ran elevated pipeline against default `C:\ShadowSensor\data\shadowsensor.db`, confirmed positive event delta; stopped pipeline.

## Evidence

### Step 5.1 — Bookmark clean + baseline
```
BOOKMARK_EXISTS=no
events: 1 rows
rule_hits: 1 rows
alerts: 1 rows
model_scores: 0 rows
```
(Pre-existing 1/1/1 rows were from Sub-Phase 3 synthetic reproduction.)

### Step 5.2 — Elevated live pipeline start (no Access Denied)
```
[INFO] Loaded 49 rules from rules/definitions/
Database initialized at C:\ShadowSensor\data\shadowsensor.db
Event collection pipeline started (thread: ShadowSensor-Collector)
```
Elevated process observed (`python` PID 1808 / later recovery PID 27228). No `EvtQuery Access Denied`.

### Live `PS_ENCODED_CMD_001` (stdout + log)
Deliberate encoded-command child (exact trigger):
```
[2026-07-27 13:29:27] RULE_HIT | rule='PowerShell Encoded Command' | id=PS_ENCODED_CMD_001 | ...
cmdline='"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -EncodedCommand JABjAG0AZAAgACcAVABlAHMAdAAnAA== ' | parent='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
```
Also present in `logs/rule_hits.log` under session start `[2026-07-27 13:28:35] === SESSION START ===`.

### Step 5.3 — DB deltas after live run (vs baseline 1/1/1)
Captured mid/post live (pipeline still draining Sysmon backlog briefly):
```
events: 13059 rows
rule_hits: 8 rows
alerts: 8 rows
```
**Deltas vs Step 5.1 baseline:** events **+13058**, rule_hits **+7**, alerts **+7**.

`PS_ENCODED_CMD_001` rows in `rule_hits`:
```
(4, 'PS_ENCODED_CMD_001', 3699, ...)
(5, 'PS_ENCODED_CMD_001', 6322, ...)   # deliberate encoded child → event 6322
```
Linked event 6322: `event_type_id=1`, image `...\powershell.exe`, raw_json contains the encoded-command process.

### Fix 1 live proof — benign / zero-hit events persisted
EID 1 ProcessCreate for Notepad (Store app path used on this host):
```
(4573, 1, 9960, '...\\Notepad\\Notepad.exe')
(4659, 1, 27584, '...\\Notepad\\Notepad.exe')
(5212, 1, 4920, '...\\Notepad\\Notepad.exe')
(5303, 1, 20980, '...\\Notepad\\Notepad.exe')
```
EID 1 ProcessCreate for Explorer:
```
(3888, 1, 23036, 'C:\\Windows\\explorer.exe')
```
Zero-hit population (events with no matching `rule_hits.event_fk`):
```
events_without_rule_hits: 13051
total_events: 13059
total_rule_hits: 8
```
Vast majority of new rows are non-hit events — Fix 1 behavior confirmed live, not only in unit tests.

### Step 5.4 — Negative test (`SHADOWSENSOR_DB_DIR=Z:\this_path_does_not_exist`)
Command used (env set before process start):
```
SHADOWSENSOR_DB_DIR=Z:\this_path_does_not_exist
python_runtime\python.exe -u scripts\run_pipeline.py
EXIT:1
```
**Visible failure (stderr), verbatim:**
```
Traceback (most recent call last):
  File "E:\filelessmalware\python_runtime\Lib\pathlib\_local.py", line 722, in mkdir
    os.mkdir(self, mode)
FileNotFoundError: [WinError 3] The system cannot find the path specified: 'Z:\\this_path_does_not_exist'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "E:\filelessmalware\scripts\run_pipeline.py", line 18, in <module>
    from storage.database import init_db
  File "E:\filelessmalware\storage\database.py", line 69, in <module>
    engine = create_db_engine()
  File "E:\filelessmalware\storage\database.py", line 32, in create_db_engine
    DB_DIR.mkdir(parents=True, exist_ok=True)
  ...
FileNotFoundError: [WinError 3] The system cannot find the path specified: 'Z:\\'
```
Row counts unchanged after negative attempt:
```
AFTER_NEGATIVE
events: 13059
rule_hits: 8
alerts: 8
```

### Recovery — env cleared, normal elevated write path
```
DB_PATH C:\ShadowSensor\data\shadowsensor.db
Database initialized at C:\ShadowSensor\data\shadowsensor.db
Event collection pipeline started (thread: ShadowSensor-Collector)
```
After brief Notepad activity:
```
RECOVERY_COUNTS
events: 19048
rule_hits: 9
alerts: 9
delta_events_from_13059: 5989
```
Positive delta on the correct local DB path confirmed. Pipeline then stopped (no remaining `python` processes).

## Findings / Conclusions

1. **Elevated live Sysmon path works** — collector started without Access Denied; real events streamed.
2. **Fix 1 verified live:** benign Notepad/Explorer ProcessCreate events are in `events`; thousands of zero-hit events persisted (`13051` without rule_hit FKs) while only `8` rule_hits existed at that checkpoint.
3. **Hit path verified live:** `PS_ENCODED_CMD_001` appeared in stdout and `logs/rule_hits.log`, and corresponding `rule_hits`/`alerts` rows were written with matching event FK content.
4. **Invalid `SHADOWSENSOR_DB_DIR` fails visibly** with a full traceback (exit code 1); no silent continue. Recovery with cleared env writes again to `C:\ShadowSensor\data\shadowsensor.db`.

## File-Change Scope (if applicable)

No product source changes in Sub-Phase 5. Helper/evidence artifacts under `logs/`:
- `sp5_run_elevated.bat`, `sp5_negative_elevated.bat`, `sp5_recovery_elevated.bat`
- `sp5_pipeline_stdout.txt` / `sp5_pipeline_stderr.txt`
- `sp5_negative_stdout.txt` / `sp5_negative_stderr.txt`
- `sp5_recovery_stdout.txt` / `sp5_recovery_stderr.txt`

## Anomalies / Uncertainties

1. **Negative-test failure layer:** With `Z:\this_path_does_not_exist`, failure occurs at `storage.database.create_db_engine()` / `DB_DIR.mkdir` **before** `handle_persist_pipeline_event` runs. Visibility requirement is met (full traceback), but this is not the StorageWriter/`handle_persist` ERROR-log path exercised by Fix 2’s unit proof. Flagged for clarity, not as a failed Step 5.4.
2. **Elevated UAC `Start-Process -Verb RunAs` for the negative bat** did not produce output files in one attempt (likely UAC deferral); the required negative command was therefore executed successfully in-process with the env var set (Sysmon not required for this DB-init failure). Live positive runs were elevated.
3. **High event volume:** Clearing the bookmark caused a large Sysmon backlog ingest (10k+ events in minutes), dominated by ImageLoad/OpenProcess noise plus intentional activity. This strengthens Fix 1 proof but is noisier than a short warm bookmark window.
4. An additional `PS_ENCODED_CMD_001` fired on the parent wrapper PowerShell whose command line *contained* the `-EncodedCommand` string; the deliberate child at 13:29:27 is the intended trigger evidence.

## Ready to Proceed?

**No — hard stop.** Sub-Phase 5 complete pending your review. Awaiting explicit go-ahead before Sub-Phase 6.
