# Scoping Fix — Sub-Phase 5 Completion Report

**Label:** Mechanism proof + VM handoff package — **not** a completed real-data correction  
**Date/time executed:** 2026-07-27 16:49:49 +0530  
**Sub-phase goal (restated):** Prove `--since`/`--until` changes real extraction output end-to-end on host-reachable data, and package the exact VM command to correct `benign_baseline.csv` later — without claiming that correction has been done.

---

## What Was Done

### Part A — Host mechanism proof
1. Ran an **unscoped** `--label 0` extraction against host `C:\ShadowSensor\data\shadowsensor.db` (29687 events; same DB as Sub-Phase 1/3).
2. Ran a **scoped** extraction on the same DB with `--since "2026-07-27 07:58:00" --until "2026-07-27 08:00:00"` (a real sub-window inside the host DB’s span).
3. Compared process-window row counts and activation rates for the same feature set used in Sub-Phase 1 / the scoping issue report.

### Part B — VM handoff package
4. Documented the exact ready-to-run VM command using confirmed session boundaries `2026-07-27 01:38:21` / `2026-07-27 03:07:19`.
5. Explicitly stated where it must run, what DB it must use, and that `benign_baseline.csv` is **not** corrected by this sub-phase.

**Not done (by design):** No query against the VM’s 71544-row collection DB; no overwrite/replacement of `data/features/benign_baseline.csv` as a clean benign baseline.

---

## Evidence

### Part A — Host DB context

```
db_range: ('2026-07-27 07:44:11.805780', '2026-07-27 08:04:33.863806', 29687)
events_in_full: 29687
events_in_07:58-08:00: 13058
```

### Part A — Unscoped extraction (before)

```
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --output data\features\sp5_host_unscoped.csv
```

```
[INFO] Reading from: C:\ShadowSensor\data\shadowsensor.db
[INFO] Extracted 772 process windows
[INFO] Exported to: E:\filelessmalware\data\features\sp5_host_unscoped.csv
[INFO] Features per row: 31
```

Activation rates:
```
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

### Part A — Scoped extraction (after)

```
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --since "2026-07-27 07:58:00" --until "2026-07-27 08:00:00" --output data\features\sp5_host_scoped.csv
```

```
[INFO] Reading from: C:\ShadowSensor\data\shadowsensor.db
[INFO] Extracted 353 process windows
[INFO] Exported to: E:\filelessmalware\data\features\sp5_host_scoped.csv
[INFO] Features per row: 31
```

Activation rates:
```
has_encoded_command: 43/353 (12.18%)
has_download_keyword: 0/353 (0.00%)
is_known_suspicious_chain: 0/353 (0.00%)
open_process_lsass_target: 0/353 (0.00%)
open_process_suspicious_access: 305/772 → 129/353 (39.51% → 36.54%)
has_powershell_rule_hit: 9/772 → 4/353 (1.17% → 1.13%)
has_lolbin_rule_hit: 0/353 (0.00%)
has_network_rule_hit: 0/353 (0.00%)
has_api_rule_hit: 1/353 (0.28%)
has_chain_rule_hit: 0/353 (0.00%)
```

(Full scoped block for the same features:)
```
has_encoded_command: 43/353 (12.18%)
has_download_keyword: 0/353 (0.00%)
is_known_suspicious_chain: 0/353 (0.00%)
open_process_lsass_target: 0/353 (0.00%)
open_process_suspicious_access: 129/353 (36.54%)
has_powershell_rule_hit: 4/353 (1.13%)
has_lolbin_rule_hit: 0/353 (0.00%)
has_network_rule_hit: 0/353 (0.00%)
has_api_rule_hit: 1/353 (0.28%)
has_chain_rule_hit: 0/353 (0.00%)
```

### Part A — Before/after delta (mechanism proof)

| Metric | Unscoped | Scoped (`07:58:00`–`08:00:00`) | Delta |
|---|---:|---:|---:|
| Process windows | **772** | **353** | **−419** |
| Events in window (SQL) | 29687 | 13058 | −16629 |
| `has_encoded_command` (abs) | 44 | 43 | −1 |
| `open_process_suspicious_access` (abs) | 305 | 129 | −176 |
| `has_powershell_rule_hit` (abs) | 9 | 4 | −5 |

CLI surface now includes the new args:
```
usage: run_feature_extraction.py [-h] [--label LABEL] [--output OUTPUT]
                                 [--db DB] [--since SINCE] [--until UNTIL]
```

### Part B — Exact VM handoff command

**Run this on the VM only**, against the VM-local collection database  
`C:\ShadowSensor\data\shadowsensor.db` (**71544** events per Phase 6A Sub-Phases 3/4 — **not** the host’s 29687-row blocker-fix DB):

```bat
cd /d E:\filelessmalware
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --since "2026-07-27 01:38:21" --until "2026-07-27 03:07:19" --output data\features\benign_baseline.csv
```

(If the shared project is mounted as a different drive letter inside the guest, `cd` to that guest path first; default `--db` already resolves to `C:\ShadowSensor\data\shadowsensor.db` via `storage.database.DB_PATH`.)

**Session boundaries used (confirmed earlier; VM-clock-consistent):**
- `SESSION START`: `2026-07-27 01:38:21`
- `SESSION END`: `2026-07-27 03:07:19`

**Code sync:** The project tree is shared host↔VM (confirmed in `docs/blocker_fix_final_report.md`). Once this scoping fix is present in the shared tree, the VM already has the code — **no separate repo sync**. Only the command above needs to be executed on the VM.

**After the VM run (operator checklist, not performed here):**
1. Confirm extracted row count is **smaller than** the contaminated all-time export (795 in the scoping issue; current unscoped VM history may differ if the DB grew).
2. Recompute activation rates for the contaminated feature set; expect WARP-related residuals possible (50 rule hits logged in-session), not weeks-old simulation contamination.
3. Only then treat `data\features\benign_baseline.csv` as the corrected benign baseline for Phase 6A Sub-Phase 5 / 6B.

---

## Findings / Conclusions

1. **Mechanism works end-to-end on host data:** same DB, unscoped **772** windows → scoped **353** windows (−419), with absolute activation counts changing (e.g. `open_process_suspicious_access` 305 → 129). This is not unit-test-only proof.
2. **`benign_baseline.csv` has NOT been corrected** in this sub-phase. The host proof used a different DB and a different time window than the Phase 6A benign session.
3. **Real correction remains a VM operator step** using the Part B command against the 71544-row VM database.

## File-Change Scope (if applicable)

No product source changes in Sub-Phase 5. Artifacts produced:
- `data/features/sp5_host_unscoped.csv` (mechanism proof)
- `data/features/sp5_host_scoped.csv` (mechanism proof)
- `docs/scoping_fix_subphase5_report.md` (this report)

Unrelated blocker-fix dirty files unchanged/carry-forward for Sub-Phase 6.

## Anomalies / Uncertainties

1. Host scoped window still shows non-zero `has_encoded_command` / `open_process_suspicious_access` — expected for blocker-fix diagnostic data inside `07:58–08:00`; the proof is that scoping **changes** the export, not that this host window is a clean benign baseline.
2. Percent rates can rise while absolute counts fall (e.g. encoded_command 5.70% → 12.18%) because the denominator shrinks; absolute counts and window counts are the primary mechanism-proof signals.

## Ready to Proceed?

**Yes** — mechanism proof + VM handoff package complete. **`benign_baseline.csv` remains uncorrected until the Part B command is run on the VM.** Awaiting go-ahead for Sub-Phase 6 (final regression, schema-doc update including `--since`/`--until` asymmetry, cumulative scope report).
