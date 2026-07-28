# Scoping Fix — Sub-Phase 1 Completion Report

**Date/time executed:** 2026-07-27 16:33–16:36 +0530 (approx; suite finished 2026-07-27T11:05:36Z)  
**Sub-phase goal (restated):** Confirm current broken (unscoped) behavior with fresh evidence, and establish the regression/test baseline this fix will be measured against.

## What Was Done

1. Confirmed rule count via `load_rules_from_directory(Path('rules'))`.
2. Ran the full regression suite: `python_runtime\python.exe -m pytest tests\ -v --tb=short -q`.
3. Captured current CLI surface via `scripts\run_feature_extraction.py --help`.
4. Re-ran the unscoped extraction command from the scoping issue report, writing `data\features\baseline_reproduction_check.csv`, then computed activation rates for the same categorically-suspicious features named in that report.
5. Queried `C:\ShadowSensor\data\shadowsensor.db` for `MIN(id), MAX(id), MIN(timestamp), MAX(timestamp), COUNT(*)` on `events`.
6. No product code was changed. Did **not** proceed to Sub-Phase 2. Did **not** yet write `docs/vm_clock_drift_finding.md` (deferred until Sub-Phase 2 per instruction).

## Evidence

### Step 1.1 — Rule count
```
Total rules loaded: 49
```

### Step 1.1 — Full regression suite (baseline)
```
================= 506 passed, 34 warnings in 64.71s (0:01:04) =================
```
(Warnings are pre-existing Starlette/FastAPI/`datetime.utcnow` deprecations; 0 failed.)

**Baseline for this task:** **506 passed**, 0 failed; **49** rules.

### Step 1.2 — Current CLI argument surface
```
usage: run_feature_extraction.py [-h] [--label LABEL] [--output OUTPUT]
                                 [--db DB]

Extract process-window features from SQLite.

options:
  -h, --help       show this help message and exit
  --label LABEL    Optional label to append to every row.
  --output OUTPUT  Output CSV path.
  --db DB          SQLite database path.
```
Confirmed: only `--label`, `--output`, and `--db` exist today. No `--since` / `--until`.

### Step 1.3 — Contamination reproduction
Command (exact form from task / scoping issue):
```
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --output data\features\baseline_reproduction_check.csv
```
Stdout:
```
[INFO] Reading from: C:\ShadowSensor\data\shadowsensor.db
[INFO] Extracted 772 process windows
[INFO] Exported to: E:\filelessmalware\data\features\baseline_reproduction_check.csv
[INFO] Features per row: 31
```

Activation rates on `data\features\baseline_reproduction_check.csv` (same feature set as the scoping issue report):
```
rows=772
columns=31
has_label_col=True
has_encoded_command: 44/772 (5.70%)
has_download_keyword: 0/772 (0.00%)
is_known_suspicious_chain: 0/772 (0.00%)
open_process_lsass_target: 0/772 (0.00%)
open_process_suspicious_access: 305/772 (39.51%)
has_powershell_rule_hit: 9/772 (1.17%)
has_lolbin_rule_hit: 0/772 (0.00%)
has_network_rule_hit: 0/772 (0.00%)
has_api_rule_hit: 1/772 (0.13%)
has_chain_rule_hit: 0/772 (0.00%)
```

Reference rates from `docs/phase6a_feature_extraction_scoping_issue.md` (VM DB, 795 windows / 71544 events) for comparison only:
```
has_encoded_command: 7/795 (0.88%)
has_download_keyword: 8/795 (1.01%)
is_known_suspicious_chain: 33/795 (4.15%)
open_process_lsass_target: 13/795 (1.64%)
open_process_suspicious_access: 275/795 (34.59%)
has_powershell_rule_hit: 44/795 (5.53%)
has_lolbin_rule_hit: 32/795 (4.03%)
has_network_rule_hit: 9/795 (1.13%)
has_api_rule_hit: 73/795 (9.18%)
has_chain_rule_hit: 36/795 (4.53%)
```

### Step 1.4 — Host events table timestamp range
```
(1, 29687, '2026-07-27 07:44:11.805780', '2026-07-27 08:04:33.863806', 29687)
```
i.e. `MIN(id)=1`, `MAX(id)=29687`, `MIN(timestamp)='2026-07-27 07:44:11.805780'`, `MAX(timestamp)='2026-07-27 08:04:33.863806'`, `COUNT(*)=29687`.

## Findings / Conclusions

1. **Regression baseline established:** 49 rules; **506 passed** / 0 failed. Later suite runs in this task compare against this count.
2. **CLI gap confirmed:** no time-scoping arguments exist; surface is `--label` / `--output` / `--db` only.
3. **Unscoped extraction still mixes sessions on this host:** the default DB path resolved to host `C:\ShadowSensor\data\shadowsensor.db` and produced **772** labeled windows. Non-zero rates for `has_encoded_command` (44/772), `open_process_suspicious_access` (305/772), `has_powershell_rule_hit` (9/772), and `has_api_rule_hit` (1/772) show attack-/diagnostic-derived activations present in an all-time `--label 0` export — the same class of contamination the scoping issue describes, even though this host DB is **not** the VM’s 71544-row collection DB.
4. **Host DB ≠ VM collection DB (material for later sub-phases):** host events span only `2026-07-27 07:44:11.805780`–`08:04:33.863806` (29687 rows) — consistent with the blocker-fix live/recovery window on this machine, not the Phase 6A benign session (`logs/rule_hits.log` markers `2026-07-27 01:38:21` → `03:07:19`). The scoping issue’s 795-window / 71544-event numbers are therefore **not** reproducible from this host; Sub-Phase 1 proves the unscoped-CLI problem against the reachable host DB, not against the VM’s cumulative history.
5. **Forward flags (not acted on in this sub-phase):**
   - VM clock drift (~12h) → document in `docs/vm_clock_drift_finding.md` during Sub-Phase 2 (documentation-only; no fix).
   - Confirmed session bounds for Sub-Phase 5 remain `2026-07-27 01:38:21` / `2026-07-27 03:07:19` (internally consistent with VM clock; no further adjustment).
   - **Sub-Phase 5 must be split** into (a) host mechanism-proof and (b) a VM handoff package for the real 71544-row DB, which is unreachable from this host.

## File-Change Scope (if applicable)

No product source files modified. New/updated artifacts from this sub-phase:

- `data/features/baseline_reproduction_check.csv` (generated by Step 1.3)
- `docs/scoping_fix_subphase1_report.md` (this report)

`git status --short` was not required by the Step 1.x commands; no implementation diffs exist.

## Anomalies / Uncertainties

1. Host reproduction row count (**772**) and activation profile differ from the scoping issue’s VM numbers (**795** / broader non-zero set). Expected: different databases. Contamination class is still demonstrated on host via non-zero `has_encoded_command` and `open_process_suspicious_access`.
2. Several features that were non-zero on the VM (`has_download_keyword`, `is_known_suspicious_chain`, `open_process_lsass_target`, `has_lolbin_rule_hit`, `has_network_rule_hit`, `has_chain_rule_hit`) are **0/772** on this host DB — consistent with this DB being blocker-fix diagnostics rather than full multi-week rule-validation history.
3. Sub-Phase 5 real-data correction against the benign session **cannot** be completed on this host alone; requires the planned VM handoff split.

## Ready to Proceed?

**Yes** — Sub-Phase 1 baseline and host-side contamination reproduction are complete with evidence. Awaiting explicit go-ahead before Sub-Phase 2 (Design Confirmation), at which point `docs/vm_clock_drift_finding.md` will be written as a documentation-only finding.
