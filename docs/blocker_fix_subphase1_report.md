# Blocker Fix — Sub-Phase 1 Completion Report

**Date/time executed:** 2026-07-27 13:01:18 +0530
**Sub-phase goal (restated):** Establish an evidence-backed host environment baseline before any diagnostic or code change — repo/runtime, Sysmon, rule count, full regression suite, DB row counts, `DB_PATH`, git history depth, and host/VM shared-folder relationship.

## What Was Done

### Pre-step (per go-ahead instructions)
Copied `C:\Users\AYUSH NAIK\Downloads\phase6a_blocker_report.md` → `E:\filelessmalware\docs\phase6a_blocker_report.md` (copy, not move). Verified original still present and byte-for-byte identical via `cmp -s`.

### Step 1.1 — Repo path and Python runtime
Confirmed `scripts/run_pipeline.py` exists under `E:\filelessmalware` and recorded `python_runtime\python.exe --version`.

### Step 1.2 — Sysmon
Ran `sc query Sysmon64`.

### Step 1.3 — Rule count
Loaded rules via `rules.loader.load_rules_from_directory(Path('rules'))`.

### Step 1.4 — Baseline full regression suite
Ran `python_runtime\python.exe -m pytest tests\ -v --tb=short -q`.

### Step 1.5 — Baseline database row counts
Counted rows in `events`, `rule_hits`, `alerts`, `model_scores` at `C:\ShadowSensor\data\shadowsensor.db`.

### Step 1.6 — `DB_PATH` resolution
Imported and printed `storage.database.DB_PATH`.

### Step 1.7 — Git history depth
Ran `git log --oneline` (and dated format for the single commit).

### Step 1.8 — Host/VM shared-folder relationship
Checked `git remote -v`, path attributes / reparse-point status for `E:\filelessmalware`, and the ShadowSensor lab VMX shared-folder settings.

`status.md` was not modified (per explicit instruction).

## Evidence

### Pre-step — blocker report copy
```
ORIGINAL_STILL_PRESENT=yes
CONTENT_MATCH=exact
 9486 C:/Users/AYUSH NAIK/Downloads/phase6a_blocker_report.md
 9486 e:/filelessmalware/docs/phase6a_blocker_report.md
```
Re-check after Sub-Phase 1 work:
```
COPY_STILL_EXACT=yes
```

### Step 1.1 — Repo path and Python runtime
```
-rwxr-xr-x 1 AYUSH NAIK 197121 5777 Jul 20 10:21 scripts/run_pipeline.py*
Python 3.13.5
```

### Step 1.2 — Sysmon
```
SERVICE_NAME: Sysmon64
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Step 1.3 — Rule count
```
Total rules loaded: 49
```
Matches expected value of 49.

### Step 1.4 — Baseline full regression suite
```
====================== 502 passed, 34 warnings in 36.53s ======================
```
**Baseline for later comparison: 502 passed, 0 failed.**

### Step 1.5 — Baseline database row counts (host PC)
```
events: 0 rows
rule_hits: 0 rows
alerts: 0 rows
model_scores: 0 rows
```
Host DB file metadata:
```
-rw-r--r-- 1 AYUSH NAIK 197121 73728 Jul 17 10:58 C:/ShadowSensor/data/shadowsensor.db
2026-07-17T10:58:32.3851085+05:30
```

### Step 1.6 — `DB_PATH` resolution
```
C:\ShadowSensor\data\shadowsensor.db
```

### Step 1.7 — Git history depth
```
b39290a feat: initial commit — Phases 0-5 complete
```
Dated form:
```
b39290a 2026-07-20T11:19:58+05:30 feat: initial commit — Phases 0-5 complete
```
**Git history is a single commit — no diff-based timeline analysis is possible.**

That single commit date (2026-07-20) is **after** the blocker report's 2026-07-12 23:07 → 2026-07-13 13:19 window; with only one commit present, there is no per-file timeline for that window in git.

### Step 1.8 — Host/VM shared-folder relationship
`git remote -v`:
```
origin	https://github.com/AyushNaik04/ShadowSensor.git (fetch)
origin	https://github.com/AyushNaik04/ShadowSensor.git (push)
```
`git rev-parse --show-toplevel`:
```
E:/filelessmalware
```
Path attributes (`Get-Item E:\filelessmalware`):
```
FullName=E:\filelessmalware
Attributes=Directory
LinkType=[]
Target=[]
Parent=Microsoft.PowerShell.Core\FileSystem::E:\
```
`fsutil reparsepoint query "E:\filelessmalware"`:
```
Error 4390: The file or directory is not a reparse point.
```
Drive listing includes `E:` labeled `STORAGE` (ordinary host volume; not presented as a guest mount).

VMware Workstation is installed on this host. Lab VMX file:
`E:\WINDOWS 10 VIRTUAL MACHINE\ShadowSensor-Lab-Win10.vmx`

Quoted shared-folder lines from that VMX:
```
isolation.tools.hgfs.disable = "FALSE"
sharedFolder0.present = "TRUE"
sharedFolder0.enabled = "TRUE"
sharedFolder0.readAccess = "TRUE"
sharedFolder0.writeAccess = "TRUE"
sharedFolder0.hostPath = "E:\filelessmalware"
sharedFolder0.guestName = "filelessmalware"
sharedFolder0.expiration = "never"
sharedFolder.maxNum = "1"
```

## Findings / Conclusions

1. **Pre-step complete:** Blocker report is now at `docs/phase6a_blocker_report.md` and matches the Downloads original exactly; Downloads original was not deleted.
2. **Host runtime is ready:** `run_pipeline.py` present; Python 3.13.5; Sysmon64 RUNNING; 49 rules load.
3. **Regression baseline is 502 passed / 0 failed** (34 warnings). This is the comparison number for later sub-phases.
4. **Host SQLite baseline is empty (0/0/0/0)** at `C:\ShadowSensor\data\shadowsensor.db`, last modified 2026-07-17. This differs from the blocker report / Phase 6A Sub-Phase 1 VM baseline (346/349/349/0). That difference is consistent with the DB living on each machine's local `C:\ShadowSensor\data\` path, not on the shared project folder.
5. **`DB_PATH` resolves correctly** to `C:\ShadowSensor\data\shadowsensor.db`.
6. **Git history is a single commit** (`b39290a`, 2026-07-20) — no diff-based timeline analysis for the 2026-07-12/13 regression window is possible via git.
7. **Host and VM share the same project files:** VMX configures a shared folder with `hostPath = E:\filelessmalware` and `guestName = filelessmalware`. Therefore a code fix applied under `E:\filelessmalware` is the same tree the VM sees (typically as `\\vmware-host\Shared Folders\filelessmalware` / `Z:\filelessmalware` per prior VM transcripts). **No separate repo sync step is required for code.** The SQLite database itself remains per-machine local NTFS and is not shared by that folder mapping.

## File-Change Scope (if applicable)

No source/code changes. Files added/present relative to Sub-Phase 1 work:
- `docs/phase6a_blocker_report.md` — newly copied into the repo (requested pre-step)
- `docs/blocker_fix_subphase1_report.md` — this report

`status.md` was not modified.

## Anomalies / Uncertainties

1. **Host DB row counts (0/0/0/0) ≠ blocker-report VM counts (346/349/349/0).** Not treated as a contradiction: both resolve `DB_PATH` to `C:\ShadowSensor\data\shadowsensor.db`, which is machine-local. Host DB mtime is 2026-07-17; blocker report's last successful write was 2026-07-12 on the VM DB. Later live verification on this host must use the host baseline (0/0/0/0), not the VM numbers.
2. **Python version is 3.13.5**, not 3.11 as `docs/DEPENDENCIES.md` / `DEV_STANDARDS.md` describe as the project target. Observed fact only; suite still passed 502/502.
3. Guest drive letter for the shared folder (e.g. `Z:`) is not re-verified from inside the guest in this sub-phase; host-side VMX evidence is sufficient to conclude the shared project tree identity.

## Ready to Proceed?

**No — hard stop.** Sub-Phase 1 is complete pending your review. Awaiting explicit go-ahead before Sub-Phase 2 (Static Code Investigation, read-only).
