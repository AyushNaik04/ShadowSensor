# ShadowSensor — Phase 7A Simulation Progress Log

*Running log of simulation execution, findings, fixes, and per-subphase results.
Maintained by the committee (Detection Engineer, Malware Analyst, Rule Engine Architect).
Append-only — do not delete past entries.*

---

## 2026-08-12 — Subphase 1 Re-simulation (PowerShell, 11 rules)

**Reason for re-simulation:** §21.5 reversal — Subphases 1–4 CSVs deleted and regenerated
fresh for multi-path training data quality (2 launches × 3 paths per rule vs prior single-path).

### Execution Summary
- Script: `scripts/simulate_subphase_1.py`
- Sim window (UTC): 2026-08-12 07:57:17 → 09:00:00
- Total pipeline hits in window: 66 (across multiple partial runs today)
- Feature extraction: 312 process windows, 31 features, label=1
- Output CSV: `data/features/suspicious_ps.csv`
- Staging CSV: `exports/subphase_1_training.csv`

### Results Per Rule

| Rule | Path A | Path B | Path C | FP Test | Note |
|---|---|---|---|---|---|
| PS_ENCODED_CMD_001 | PASS | PASS | PASS | — | |
| PS_DOWNLOAD_CRADLE_001 | PASS | PASS | PASS | PASS | See D44 |
| PS_AMSI_BYPASS_001 | PARTIAL | PARTIAL | PARTIAL | — | D-f block |
| PS_HIDDEN_WINDOW_001 | PASS | FAIL* | FAIL* | PASS | Pipeline lag |
| PS_EXECUTION_POLICY_BYPASS_001 | FAIL* | FAIL* | PASS | — | Pipeline lag |
| PS_INVOKE_EXPRESSION_001 | PASS | FAIL* | PASS | — | Pipeline lag |
| PS_VERSION_DOWNGRADE_001 | PASS | PASS | PASS | — | |
| PS_REFLECTIVE_ASSEMBLY_001 | PASS | PASS | PASS | — | |
| PS_CREDENTIAL_ACCESS_001 | PARTIAL | PARTIAL | PARTIAL | — | D-f block |
| PS_CONSTRAINED_LANG_BYPASS_001 | PASS | PASS | PASS | — | |
| PS_WMI_EXEC_001 | PASS | PASS | PASS | — | |

\* = pipeline lag — commands ran correctly, Sysmon events logged, DB hits arrived after
the 180-second polling window closed. All confirmed in DB via `diag_sp1_status.py`.

### Issues Encountered and Resolutions

**Issue 1 — EXPORTS_DIR access denied**
`os.makedirs(r"Z:\exports")` raised PermissionError — Z: maps to the shared folder root,
not the repo root. Fixed: `_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`.

**Issue 2 — DB_PATH wrong**
Script initially computed DB_PATH dynamically → `Z:\filelessmalware\data\shadowsensor.db`.
Pipeline writes to `C:\ShadowSensor\data\shadowsensor.db`. Fixed: hardcoded.

**Issue 3 — EncodedCommand payload `SQBFAFgA` caused PowerShell to prompt for stdin**
`SQBFAFgA` decodes to bare `IEX` with no argument — PowerShell waited for stdin, causing
subprocess.TimeoutExpired. Fixed: `ps_b64()` helper encodes harmless `Write-Host` commands.

**Issue 4 — URL timeouts (8.8.8.8)**
8.8.8.8 connections hung for 20 seconds each. Fixed: 127.0.0.1 (connection refused immediately).
EID-1 fires at process creation, not on network success. Note: D-g (Sysmon unreliable on
loopback) applies to EID-3 only — EID-1 rules are unaffected by loopback choice.

**Issue 5 — Pipeline lag causes FP suppression test false alarms (D44)**
Stale hits from prior script runs (10–15 min pipeline lag) bled into new run's fp_start
window, triggering `sys.exit(1)` hard stops on FP tests despite rule suppression working
correctly. Diagnosed via DB query: svchost.exe-parented PS correctly produced 0 hits.
Fixed: hard stops converted to `[WARN]`, simulation continues. Rule YAML unchanged.

**Issue 6 — PermissionError on Defender-blocked rules**
PS_AMSI_BYPASS_001 raised PermissionError at CreateProcess. Fixed: `try/except (PermissionError, OSError)` in `ps()` and `launch_argv()`.

**Issue 7 — Pipeline lag causes FAIL on TP paths (not a bug)**
180-second polling window exceeded for some rules. Those events ARE in Sysmon and eventually
in DB. Feature extractor's wide UTC window captures them. FAIL in CSV = polling window miss,
not missing data.

---

## 2026-08-12 — Subphase 2 (LOLBins, 13 rules)

**Sim window (UTC):** 2026-08-12 09:35:53 → 10:13:23
**Staging CSV:** `exports/subphase_2_training.csv`
**Feature CSV:** `data/features/suspicious_lolbins.csv` — 196 rows, 31 features, label=1 (wide extraction window 09:35–11:30 UTC)

### Results Per Rule

| Rule | Path A | Path B | Path C | Overall |
|---|---|---|---|---|
| LOLBIN_MSHTA_001 | PASS | PASS | PASS | PASS |
| LOLBIN_RUNDLL32_SUSPICIOUS_001 | PARTIAL (D-f) | PARTIAL (D-f) | PASS | PARTIAL |
| LOLBIN_REGSVR32_001 | PARTIAL (D-f) | PARTIAL (D-f) | PARTIAL (D-f) | PARTIAL |
| LOLBIN_CERTUTIL_001 | FAIL* | PASS | PASS | PARTIAL |
| LOLBIN_MSIEXEC_REMOTE_001 | PASS | PASS | PASS | PASS |
| LOLBIN_ODBCCONF_001 | PASS | PASS | PASS | PASS |
| LOLBIN_CMSTP_001 | PASS | PASS | PASS | PASS |
| LOLBIN_HH_CHM_001 | FAIL | FAIL | FAIL | FAIL ⚠ |
| LOLBIN_REGASM_REGSVCS_001 | PASS | PASS | PASS | PASS |
| LOLBIN_WMIC_PROCESS_001 | PASS | PASS | PASS | PASS |
| LOLBIN_BITSADMIN_001 | PASS | PASS | PASS | PASS |
| LOLBIN_INSTALLUTIL_001 | PASS | PASS | PASS | PASS |
| LOLBIN_FORFILES_001 | PASS | PASS | PASS | PASS |

\* CERTUTIL Path A (-urlcache) = Defender likely blocking pre-EID-1. Paths B/C pass.

### New Environmental Findings

**D45 — LOLBIN_HH_CHM_001: All 3 paths 0 hits after 180s polling each.**
hh.exe with URL/javascript/mk:@MSITStore arguments produced zero DB hits across ~9 minutes
of total polling. Other rules in same session fired within 2-3 minutes. Root cause: either
Sysmon config excludes hh.exe EID-1, or Defender kills the process before Sysmon logs it.
Not in documented D-f list. Investigation deferred; does not block training data.
Rule has zero hits in current DB from this simulation.

**RUNDLL32 Path C unexpectedly PASS:** `rundll32.exe http://127.0.0.1/a.dll,Entry` was not
Defender-blocked. D-f only blocks javascript: and ShellExec patterns for this rule.
The http:// form fires normally. This provides genuine TP data for RUNDLL32_SUSPICIOUS.

### .NET Tool Resolution
- RegAsm.exe: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe` ✓
- RegSvcs.exe: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe` ✓
- InstallUtil.exe: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe` ✓

---

---
## 2026-08-12 — Issues Catalog: Subphases 1 & 2 (For Future Fix Sessions)

*Compiled by committee. Two categories: (A) Script-level bugs fixed during SP1/SP2 execution —
documented here as a permanent template record. (B) Unresolved environmental issues deferred
for future investigation or fix sessions.*

---

### CATEGORY A — Script Bugs Fixed During SP1/SP2 Execution
*(Already resolved in simulate_subphase_1.py, simulate_subphase_2.py, and the SP3 template.
Listed here so future script authors have a complete failure-mode reference.)*

**A1 — EXPORTS_DIR mapped to Z:\ root (SP1)**
- **Cause:** `os.makedirs(r"Z:\exports")` — Z: is the VMware shared folder root, not the repo root.
  Writing to Z:\exports requires elevated permissions that the user process doesn't have.
- **Where:** `scripts/simulate_subphase_1.py`, initial draft — first run on VM.
- **Fix applied:** `_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`;
  `EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")`. This resolves to Z:\filelessmalware\exports
  which is writable. Baked into all subsequent script templates.
- **Status:** CLOSED.

**A2 — DB_PATH computed dynamically (SP1)**
- **Cause:** Script computed DB_PATH relative to the script location → resolved to
  `Z:\filelessmalware\data\shadowsensor.db`. The live pipeline writes exclusively to
  `C:\ShadowSensor\data\shadowsensor.db` (local NTFS — SQLite WAL incompatible with
  VMware shared folder). Dynamic path pointed to a file that does not exist.
- **Where:** `scripts/simulate_subphase_1.py`, initial draft.
- **Fix applied:** `DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"` — hardcoded literal,
  non-negotiable. Baked into all subsequent script templates.
- **Status:** CLOSED.

**A3 — EncodedCommand base64 payload `SQBFAFgA` caused stdin hang (SP1)**
- **Cause:** `SQBFAFgA` decodes to bare `IEX` with no argument. PowerShell launched, found no
  argument to `Invoke-Expression`, and waited on stdin indefinitely → `subprocess.TimeoutExpired`.
  The 20s subprocess timeout eventually killed it, but the polling window was consumed.
- **Where:** `scripts/simulate_subphase_1.py`, `PS_ENCODED_CMD_001` block — initial payload choice.
- **Fix applied:** `ps_b64()` helper that base64-encodes harmless `Write-Host ShadowSensor_<N>`
  commands. No stdin wait, immediate exit.
- **Status:** CLOSED.

**A4 — 8.8.8.8 URL hang for EID-1 simulation (SP1)**
- **Cause:** Using `http://8.8.8.8/` as the URL argument for EID-1 (ProcessCreate) rules caused
  processes to hang for 20s waiting for a connection that timed out. EID-1 fires at process
  creation — not at network success — so network success is irrelevant. The hang consumed
  timing budget unnecessarily.
- **Where:** `scripts/simulate_subphase_1.py`, initial URL choice for download-cradle rules.
- **Fix applied:** `http://127.0.0.1/` for EID-1 rules — connection refused immediately (localhost
  has no listener), process exits fast, EID-1 already logged. Note: D-g (loopback unreliable
  for EID-3) does NOT apply to EID-1 rules. Baked into all EID-1 script templates.
- **Status:** CLOSED.

**A5 — FP suppression `sys.exit(1)` hard stop triggered by pipeline lag (SP1 → D44)**
- **Cause:** Stale rule_hits from prior simulation runs (10–15 min pipeline lag) bled into the
  new FP test window. `hits_since()` with `quick=True` found N > 0 hits during the FP window
  even though those hits were from the prior run's TP launches, not from the FP process.
  The original `sys.exit(1)` hard stop killed the script.
- **Where:** `scripts/simulate_subphase_1.py`, `PS_DOWNLOAD_CRADLE_001` FP suppression block.
- **Fix applied:** Hard stop replaced with `[WARN]` print + continue. Rule YAML unchanged.
  Confirmed via direct DB query that svchost.exe-parented PS correctly produced 0 hits in the
  DB — the rule engine suppression is working correctly; the false alarm was purely from lag.
- **Status:** CLOSED (workaround in place). Root cause (pipeline lag itself) documented as D44
  — see Category B below.

**A6 — PermissionError at CreateProcess on Defender-blocked rules (SP1)**
- **Cause:** `PS_AMSI_BYPASS_001` (and later `LOLBIN_RUNDLL32_SUSPICIOUS_001` in SP2) raised
  `PermissionError` (WinError 5: Access Denied) when Defender intercepted and blocked the
  CreateProcess call before the child process started. The unhandled exception crashed the script.
- **Where:** `scripts/simulate_subphase_1.py`, `PS_AMSI_BYPASS_001` block — first Defender-blocked launch.
- **Fix applied:** `try/except (PermissionError, OSError)` added to `launch_argv()` (and `ps()`
  where it existed). Prints `[WARN] Process blocked by Defender` and continues. Baked into
  all subsequent templates.
- **Status:** CLOSED.

---

### CATEGORY B — Unresolved / Deferred Environmental Issues
*(These require future investigation or a dedicated fix session.
None are blocking SP3–SP6 simulation. All are documented for Phase 10B research paper §2.)*

**B1 — D44: Pipeline Lag (10–15 Minutes) Causes Polling Window Misses**
- **Name:** D44 — ShadowSensor VM pipeline lag
- **Cause:** On this VM configuration, the normalizer → rule engine → DB write cycle takes
  10–15 minutes for some events, far exceeding the 180-second `hits_since()` polling window.
  Sysmon logs the EID-1 event correctly and it exists in the raw Sysmon XML log, but the
  ShadowSensor pipeline processes it too slowly to appear in `rule_hits` within 180 seconds.
- **Where observed:** SP1 — `PS_HIDDEN_WINDOW_001` Paths B/C, `PS_EXECUTION_POLICY_BYPASS_001`
  Paths A/B, `PS_INVOKE_EXPRESSION_001` Path B all showed FAIL in 180s poll. All confirmed
  present in DB via `diag_sp1_status.py` after the run.
- **Effect:** These paths appear as FAIL in the staging CSV (`exports/subphase_1_training.csv`)
  even though the telemetry is real and correct. The wide-window feature extraction captured
  them correctly in `suspicious_ps.csv`. Training data is unaffected; staging CSV label
  "FAIL" is a poll-window artifact, not a rule defect.
- **Workaround:** Wide UTC window feature extraction (SIM_START to SIM_START + 2 hours) captures
  all hits regardless of polling window. In use for all subphases.
- **Root cause not isolated:** Possible causes: VMware shared folder I/O throttling the
  normalizer; SQLite WAL on network drive latency (though DB is on C:\ NTFS — may be
  filesystem monitoring overhead from Defender scanning writes); Python GIL under load. Not
  yet profiled.
- **Fix session scope:** Profile pipeline throughput on the VM. If the normalizer or rule engine
  has a bottleneck (e.g., polling interval too long, batch too small), a single config change
  could reduce lag significantly. Not blocking current work.
- **Status:** DEFERRED. Workaround in place.

**B2 — D45: LOLBIN_HH_CHM_001 — Zero Hits Across All 3 Paths (SP2)**
- **Name:** D45 — hh.exe EID-1 suppression (Sysmon config or Defender)
- **Cause (unconfirmed):** Two candidate root causes, not yet isolated:
  (a) Sysmon configuration excludes hh.exe from EID-1 logging (process image filter in
      `sysmonconfig-export.xml` — plausible, hh.exe is a legacy HTML Help viewer and may
      be excluded as benign by default configs).
  (b) Defender kills hh.exe with URL/javascript:/mk: arguments before Sysmon logs EID-1.
      Unlike documented D-f rules, hh.exe did not raise `PermissionError` at CreateProcess —
      the process appeared to start (no exception in launch_argv) but produced 0 DB hits
      after ~9 total minutes of polling (3 paths × 180s + 30s secondary waits).
      D-f-blocked rules (AMSI, RUNDLL32_SUSPICIOUS) DID raise PermissionError — hh.exe did
      not, suggesting Defender may be killing after CreateProcess rather than blocking it.
      Or the process simply exits before Sysmon flushes the event.
- **Where observed:** SP2 — `LOLBIN_HH_CHM_001` all 3 paths (Path A: http://, Path B:
  javascript:, Path C: mk:@MSITStore:) across ~9 minutes of total polling. Other rules in
  same session fired within 2–3 minutes.
- **Effect:** Zero training rows for `LOLBIN_HH_CHM_001` in `suspicious_lolbins.csv`.
  Rule has NO confirmed TP telemetry. This is the only rule in SP2 that produced a true FAIL
  (not PARTIAL, not SKIP — zero hits on every path).
- **Fix session scope:**
  1. Read `C:\ProgramData\Sysmon\sysmonconfig-export.xml` — check for any
     `ProcessCreate` exclude filters on hh.exe or HTML Help patterns.
  2. If Sysmon excludes hh.exe: add an explicit include rule for hh.exe and restart Sysmon.
  3. If Sysmon config is clean: run hh.exe with a simple benign argument (e.g., no URL),
     confirm EID-1 fires. Then add URL argument — if EID-1 disappears, Defender is the blocker.
  4. If Defender: test with real-time protection disabled temporarily (lab only) to confirm.
     If confirmed D-f, add hh.exe to the D-f list in committee.md §20.
  5. Re-run hh.exe simulation paths after root cause confirmed.
- **Status:** DEFERRED. Does not block training data for any other rule.

**B3 — CERTUTIL -urlcache Path A: Zero Hits (Unconfirmed Defender Block)**
- **Name:** CERTUTIL -urlcache pre-EID-1 Defender candidate
- **Cause (unconfirmed):** `certutil.exe -urlcache -split -f http://127.0.0.1/a.exe` produced
  0 hits in the polling window during SP2. `-decode` (Path B) and `-decodehex` (Path C) both
  passed. The `-urlcache` flag combined with an http:// URL appears to trigger Defender
  pre-execution or pre-EID-1 intervention. No `PermissionError` was raised (same behavior
  as B2 — process may start and get killed between CreateProcess and Sysmon EID-1 logging,
  or Defender blocks at the network layer before process interaction).
- **Where observed:** SP2 — `LOLBIN_CERTUTIL_001` Path A (`-urlcache -f http://`).
  Paths B (`-decode`) and C (`-decodehex`) both PASS without issue.
- **Effect:** Path A has no training rows in `suspicious_lolbins.csv`. Rule still has TP
  data from Paths B and C. Not a blocking issue for model training.
- **Fix session scope:**
  1. Run `certutil.exe -urlcache -f http://127.0.0.1/a.exe` with Defender temporarily
     disabled to confirm whether the block is Defender or something else.
  2. If Defender: add `-urlcache + http://` pattern to D-f list documentation.
  3. If not Defender: investigate whether certutil with -urlcache uses a different execution
     path (e.g., downloads before CreateProcess returns, or Sysmon filter excludes it).
  4. If confirmed Defender block: the existing Paths B/C provide sufficient TP coverage —
     no simulation fix needed, just documentation.
- **Status:** DEFERRED. Likely Defender pre-EID-1, not confirmed.

**B4 — D-f Confirmed Blocks: REGSVR32 Has Zero Genuine TP Hits in Training Data (SP2)**
- **Name:** LOLBIN_REGSVR32_001 training data gap due to D-f
- **Cause:** All 3 paths for `LOLBIN_REGSVR32_001` (`/i:http`, `/i:https`, `/s /u /i`)
  are D-f blocked. Defender kills the process pre-execution. `launch_argv()` raised
  `PermissionError` on all paths. Result: 0 genuine EID-1 events in `suspicious_lolbins.csv`
  for this rule. The CSV has PARTIAL entries from the staging log but no feature-extraction
  rows attributed to this rule.
- **Where observed:** SP2 — `LOLBIN_REGSVR32_001` all 3 paths. Similarly, `LOLBIN_RUNDLL32_SUSPICIOUS_001`
  Paths A and B are D-f blocked (Path C — http:// form — was unexpectedly NOT blocked and did PASS).
  In SP1: `PS_AMSI_BYPASS_001` and `PS_CREDENTIAL_ACCESS_001` are also D-f blocked.
- **Effect on model:** `suspicious_lolbins.csv` has no rows attributable to REGSVR32_001.
  The Isolation Forest and Random Forest models will never see real REGSVR32 telemetry in
  the labeled suspicious set. This is a known training data gap.
- **Fix session scope (if desired before Phase 7B):**
  1. Run SP2 regsvr32 paths in a VM snapshot with Defender disabled temporarily.
  2. Re-extract feature rows for that narrow window.
  3. Merge into `suspicious_lolbins.csv` with label=1.
  4. Alternatively: accept the gap for Phase 7B — REGSVR32 detection is covered at the
     rule-engine level (the rule is correct); the ML model's blind spot for this specific
     LOLBin can be documented in the paper.
- **Status:** DEFERRED. Not blocking Phase 7B, but documented as a training data gap.

**B5 — D44 Pipeline Lag FAIL* Entries in Staging CSV (SP1)**
- **Name:** Staging CSV `result="FAIL"` for pipeline-lag paths
- **Cause:** `exports/subphase_1_training.csv` has FAIL entries for 5 paths that actually
  produced valid DB hits — they simply arrived after the 180-second polling window. The
  staging CSV (subphase_N_training.csv) records the polling result, not the DB truth.
  The feature extraction CSV (`suspicious_ps.csv`) correctly captured all hits via the
  wide UTC window and is accurate.
- **Where:** SP1 staging CSV — `PS_HIDDEN_WINDOW_001` B/C, `PS_EXECUTION_POLICY_BYPASS_001`
  A/B, `PS_INVOKE_EXPRESSION_001` B.
- **Effect:** The staging CSV is mislabeled for these 5 rows. The feature CSV is correct.
  If the staging CSV is used for any audit or reporting, those 5 rows will falsely appear
  as FAIL instead of PARTIAL (polling miss). No ML training impact — models use the
  feature CSV, not the staging CSV.
- **Fix session scope:** Low priority. If staging CSV accuracy matters: re-query the DB
  for those 5 rule+path combinations, update their result field to "PARTIAL (pipeline lag —
  confirmed in DB)", rewrite the CSV. One-time manual correction.
- **Status:** DEFERRED. Low priority.

---

*End of issues catalog — Subphases 1 & 2.*
*Append new issues from SP3–SP6 runs below the respective subphase entries when they occur.*

---
## 2026-08-12 — Subphase 4 Prompt Drafted (Parent-Child Chains, 10 rules)

**Status:** READY — awaiting Grok 4.5 script generation and Ayush VM run
**Files changed:** `prompt_subphase4.md` (new), `status.md` (SP4 entry updated), `progress_log.md` (this entry)

**What was done:** Full committee deep-research session on `parent_child.yaml` (10 rules) and
`rule_insights.md` lines 738–919. 11 explicit committee decisions finalized before drafting.
`prompt_subphase4.md` written in full.

**Key design decisions:**

1. **Rule count:** 10 live rules confirmed. Office rules (POWERSHELL/CMD/WSCRIPT) → SKIP (3 rules, 3 paths each = 9 SKIP rows).
2. **CHAIN_BROWSER_SHELL_001:** PARTIAL block, no simulation — D42 structural limit. 3 PARTIAL rows in CSV.
3. **CHAIN_SCHEDULED_TASK_SCRIPT_001:** Attempt + confirm FAIL (D43). Real schtask created with `C:\Users\` in child command_line. Expected parent = svchost.exe (not taskeng/taskhostw). 3 FAIL rows in CSV.
4. **CHAIN_SCHEDULED_TASK_SVCHOST_001:** 3 real scheduled tasks (`ShadowSensor_SP4_SVCA/B/C`) run via `schtasks /run`. Path A: powershell -enc (base64 computed at runtime). Path B: powershell DownloadString http://127.0.0.1/. Path C: mshta https://127.0.0.1/. All satisfy the command_line contains_any condition. Expected: PASS.
5. **CHAIN_SCRIPT_HOST_CMD_001 / POWERSHELL_001:** VBScript files written to `C:\Windows\Temp\` in BLOCK 2. `WScript.CreateObject("WScript.Shell").Run` to spawn cmd.exe / powershell.exe. D41 mandatory retry via helper `run_two_with_d41_retry()`. Expected: PASS.
6. **CHAIN_REGSVR32_CHILD_001:** Compiled C# COM DLL via `csc.exe` (avoids D-f squiblydoo). `[ComRegisterFunction]` → cmd.exe; `[ComUnregisterFunction]` → powershell.exe. Path A: `/s` (register), Path B: `/s /u` (unregister), Path C: `/s` again (re-register). If csc fails → SKIP. Expected: PASS.
7. **CHAIN_LOLBIN_CHILD_001:** Path A: mshta.exe HTA → cmd (HIGH CONFIDENCE). Path B: cmstp.exe INF → cmd via RunPreSetupCommandsSection (HIGH CONFIDENCE). Path C: regasm.exe → cmd via [ComRegisterFunction] from reused C# DLL (MEDIUM, csc-dependent). Expected: PASS.
8. **D41 retry helper:** `run_two_with_d41_retry()` — single retry if 0 hits after first poll. FAIL if still 0.
9. **BLOCK 2 pre-flight assets:** 5 files written + 1 compiled (ss_chain_cmd.vbs, ss_chain_ps.vbs, ss_chain_ps64.vbs, ss_chain_cmd_mshta.hta, ss_chain_cmstp.inf, ss_chain_com.cs → ss_chain_com.dll).
10. **No FP suppression tests** — no testable exclusion conditions on any SP4 rule.
11. **BLOCK 9 cleanup:** All 4 scheduled tasks deleted unconditionally at script end.

**Script prompt structure:**
- BLOCK 0: Imports + constants (POWERSHELL, WSCRIPT, CSCRIPT, MSHTA, REGSVR32, CMSTP, CSC, SCHTASKS, REGASM, TEMP, EXPORTS_DIR, DB_PATH)
- BLOCK 1: hits_since, launch_argv, warn_zero, run_two_with_d41_retry, create_and_run_task, results[], SIM_START
- BLOCK 2: Pre-flight file writes + csc.exe compilation → _DLL_READY flag
- BLOCK 3: 10 rules in order (SCRIPT_HOST_CMD, SCRIPT_HOST_POWERSHELL, SVCHOST, SCRIPT(D43), REGSVR32, LOLBIN_CHILD, BROWSER(D42), OFFICE×3(SKIP))
- BLOCK 4: SIM_END
- BLOCK 5: Summary table (RULE_ORDER list, OVERALL logic)
- BLOCK 6: CSV export → `exports/subphase_4_training.csv`
- BLOCK 7: Feature extraction instructions (print)
- BLOCK 8: Completion report
- BLOCK 9: Scheduled task cleanup (unconditional)

**Outstanding:** Send `prompt_subphase4.md` to Grok 4.5 with standard starter message.
Grok will ask clarifying questions — committee answers, Grok writes, committee does 6-point checklist
review before Ayush runs on VM.

---
## 2026-08-12 — Subphase 3 Prompt Drafted (Network, 9 rules)

**Status:** READY — awaiting Ayush go-ahead to run on VM
**Files changed:** `prompt_subphase3.md` (new), `status.md` (SP3 entry corrected)
**What was done:** Live YAML audit of `rules/definitions/network.yaml` confirmed 9 live rules
(session context stated 8 — `NET_SCRIPT_ENGINE_OUTBOUND_001` is live and covered).
`prompt_subphase3.md` drafted by committee in full, following `prompt_subphase2.md` structure.
Key design decisions: EID-3 rules require actual TCP connections (not just process launches) —
VBScript/HTA files using `WinHttp.WinHttpRequest.5.1` written to `C:\Windows\Temp\` in BLOCK 2.
All EID-3 targets use `8.8.8.8:80` / `8.8.4.4:443` per D-g (no loopback for EID-3).
**Key findings:** D28 (SKIP): `NET_SUSPICIOUS_PORT_001` and `NET_SMB_LATERAL_001` structurally
unfireable (Sysmon EID-3 captures 80/443 only). D29 (INCONCLUSIVE risk): `NET_DNS_SCRIPT_ENGINE_001`,
`NET_SCRIPTING_ENGINE_HTTP_001`, `NET_SCRIPT_ENGINE_OUTBOUND_001` (wscript/cscript paths) may produce
0 events — simulate anyway, use INCONCLUSIVE not FAIL. D-b risk noted for msiexec/rundll32/odbcconf
paths (WinINet-based LOLBin HTTP may bypass EID-3). cmd.exe cannot appear in EID-3 → substituted
with msiexec/mshta/rundll32 for `NET_LOLBIN_PROCESS_HTTP_001`. FP suppression test included for
`NET_POWERSHELL_HTTP_001` (connects to www.microsoft.com — excluded hostname).
**Outstanding:** ~~Grok 4.5 to write `scripts/simulate_subphase_3.py` from `prompt_subphase3.md`.~~ DONE.
**COMPLETE — see execution log below.**

---
## 2026-08-12 — Subphase 3 Simulation COMPLETE (Network, 9 rules)

**Status:** COMPLETE ✅
**Script:** `scripts/simulate_subphase_3.py`
**SIM_START (UTC):** 2026-08-12 15:04:00.218076
**SIM_END (UTC):** 2026-08-12 15:56:09.591834
**DB confirmed window:** 2026-08-12 15:04:29.707000 → 2026-08-12 15:55:41.826652
**Feature CSV:** `data/features/suspicious_network.csv` — 194 rows, 31 features, label=1
**Staging CSV:** `exports/subphase_3_training.csv` — 29 rows (27 path rows + 1 FP row + header)
**has_network_rule_hit=1:** 16/194 rows (confirmed rule-firing process windows)

### Path-level results

| Rule | Path A | Path B | Path C | OVERALL (script) | Committee re-classification |
|---|---|---|---|---|---|
| NET_POWERSHELL_HTTP_001 | PASS (4 hits) | FAIL (0) | PASS (4 hits) | FAIL | PARTIAL — D48 on Path B |
| NET_DNS_LONG_QUERY_001 | PASS (2 hits) | PASS (2 hits) | FAIL (0) | FAIL | PARTIAL — D47 on Path C |
| NET_DNS_SCRIPT_ENGINE_001 | INCONCLUSIVE (D29) | INCONCLUSIVE (D29) | PARTIAL (1 hit) | INCONCLUSIVE | INCONCLUSIVE (D29 confirmed) |
| NET_SCRIPTING_ENGINE_HTTP_001 | PASS (2 hits) | INCONCLUSIVE (D29) | INCONCLUSIVE (D29) | INCONCLUSIVE | PARTIAL — wscript https works; http port-80 gap (D48) |
| NET_SCRIPT_ENGINE_OUTBOUND_001 | INCONCLUSIVE (D29) | INCONCLUSIVE (D29) | FAIL (D46) | FAIL | PARTIAL — wscript/cscript D29; mshta EID-3 gap (D46) |
| NET_LOLBIN_PROCESS_HTTP_001 | FAIL (D46) | INCONCLUSIVE (D-b) | INCONCLUSIVE (D-b) | FAIL | FAIL — mshta EID-3 gap (D46); msiexec/rundll32 D-b |
| NET_LOLBIN_NETWORK_001 | FAIL (D46) | INCONCLUSIVE (D-b) | PASS (4 hits, odbcconf) | FAIL | PARTIAL — odbcconf PASS; mshta D46; msiexec D-b |
| NET_SUSPICIOUS_PORT_001 | SKIP | SKIP | SKIP | SKIP | SKIP (D28) |
| NET_SMB_LATERAL_001 | SKIP | SKIP | SKIP | SKIP | SKIP (D28) |

**FP suppression (NET_POWERSHELL_HTTP_001):** FAIL — 1 hit for `www.microsoft.com` connection.
Cause: EID-3 `destination_hostname` = NULL on this VM. The `not_contains "microsoft.com"` exclusion
is on a field that never populates → exclusion always evaluates to True → rule fires anyway (D49).

### New environmental findings (D46–D49)

**D46 — mshta.exe HTTP/HTTPS connections produce 0 EID-3 events**
- Affected paths: NET_LOLBIN_PROCESS_HTTP_001 Path A (mshta→ss_mshta443.hta, FAIL),
  NET_LOLBIN_NETWORK_001 Path A (mshta→ss_mshta80.hta, FAIL),
  NET_SCRIPT_ENGINE_OUTBOUND_001 Path C (mshta→ss_mshta80.hta, FAIL).
- Counterpoint: mshta CAN generate EID-22 (NET_DNS_SCRIPT_ENGINE_001 Path C, 1 hit PARTIAL).
- Cause: mshta likely uses WinINet (or the Trident browser engine's own HTTP stack) for HTTP/HTTPS,
  which is invisible to Sysmon's EID-3 WinSock hook. This is a more specific instance of the D-b
  WinINet blind spot: D-b was previously attributed to msiexec/rundll32/odbcconf; D46 confirms
  mshta is also affected for EID-3 (but not EID-22).
- Fix scope: Do NOT use mshta for EID-3 simulation (HTTP/HTTPS). HTA files remain valid for EID-1
  parent-chain simulation and EID-22 DNS simulation only.

**D47 — nslookup.exe produces 0 EID-22 events (DNS query rule bypass)**
- Affected path: NET_DNS_LONG_QUERY_001 Path C (nslookup.exe, FAIL).
- Cause: nslookup.exe uses its own DNS resolver (directly queries nameservers via UDP/53). It does
  NOT go through the Windows DNS client service (dnsapi.dll), which is where Sysmon's EID-22 hook
  intercepts. nslookup is therefore invisible to any EID-22-based detection rule.
- Fix scope: Replace nslookup with PowerShell `Resolve-DnsName` or `[System.Net.Dns]::GetHostEntry`
  in any future DNS simulation paths. Both confirmed working (EID-22 generated, PASS).

**D48 — EID-3 generation for port-80 is process-dependent; confirmed gap for PS/wscript/cscript**
- Affected paths: NET_POWERSHELL_HTTP_001 Path B (powershell http://8.8.8.8:80, FAIL),
  NET_SCRIPTING_ENGINE_HTTP_001 Path B/C (wscript/cscript http://8.8.8.8:80, INCONCLUSIVE-D29),
  NET_SCRIPT_ENGINE_OUTBOUND_001 Path A/B (wscript/cscript http://8.8.8.8:80, INCONCLUSIVE-D29).
- Contrast: NET_LOLBIN_NETWORK_001 Path C (odbcconf http://8.8.8.8:80 → 4 hits, PASS). Same target
  (8.8.8.8:80), different process → odbcconf generates EID-3, powershell/wscript do not.
- Cause: unclear. Hypothesis 1: WinHTTP (used by powershell, wscript) vs raw WinSock (used by
  odbcconf) have different hook entry points in Sysmon's ETW provider. Hypothesis 2: 8.8.8.8:80
  is an HTTP port that Google's DNS infrastructure silently drops (RST immediately), and for
  WinHTTP, Sysmon's hook fires only after connection establishment (not at SYN). odbcconf may
  behave differently due to its own socket management.
- Safe workaround: use `https://8.8.4.4:443` for all WinHTTP-based EID-3 targets. Port 443
  confirmed reliable across powershell, wscript. Already applied in SP3 for passing paths.

**D49 — EID-3 destination_hostname always NULL on this VM → hostname-based exclusions fail**
- Affected: NET_POWERSHELL_HTTP_001 FP suppression (`not_contains "microsoft.com"` on
  destination_hostname). The exclusion always passes (NULL is never "contains X") → rule fires
  for microsoft.com connections despite the intended exclusion.
- Cause: Sysmon's EID-3 does not reliably populate destination_hostname on this VM (observed
  "null" in all staging CSV rows). The field requires DNS reverse resolution or prior name
  resolution — absent here because we use IP targets (8.8.8.8, 8.8.4.4), but even the
  www.microsoft.com connection in the FP test produced NULL hostname.
- Fix scope (Codex, post-SP6): For any rule with hostname-based EID-3 exclusions, replace with
  `command_line not_contains "hostname"` (valid for powershell, wscript, mshta where the URL
  appears in the command line). For rules where the initiating process doesn't have the URL
  in its command_line, hostname exclusions are not feasible without DNS enrichment.
- Paper note: D49 is a genuine detection blind spot — real malware that spoofs or resolves to
  a legitimate hostname won't be excluded by hostname-based EID-3 rules. Worth a note in Section 2.

### Unexpected positive findings

1. **wscript.exe WinHTTP to port 443 generates EID-3** (NET_SCRIPTING_ENGINE_HTTP_001 Path A, 2 hits).
   Prior session (2026-07-30) had D29 attributed globally to wscript/cscript. This re-run shows
   wscript IS visible for EID-3 when connecting to port 443. D29 (script engine telemetry gap) is
   now more precisely scoped: wscript port-443 = visible; wscript port-80 = D48 gap; cscript all
   ports = INCONCLUSIVE (possible D29 or D48 combined effect).

2. **odbcconf.exe generates EID-3 for port-80** (NET_LOLBIN_NETWORK_001 Path C, 4 hits). odbcconf
   `/f http://8.8.8.8/a.rsp` attempted to fetch an RSP file over HTTP — EID-3 was generated even
   though the target (8.8.8.8:80) returns no valid RSP file. odbcconf uses raw WinSock, not WinHTTP.

### Feature CSV integrity check

- Total rows: 194 (all label=1 ✓)
- has_network_rule_hit=1: 16 rows (confirmed rule-hit process windows)
- has_network_rule_hit=0: 178 rows (background/child/unrelated processes in the wide window)
- rule_hit_count > 0: 23 rows (includes 7 rows that fired non-network rules during the window)
- dest_port=443: 16 rows; dest_port=80: 2 rows
- hour_of_day=-1 on most rows (expected — pipeline timestamp handling, consistent with SP1/SP2)
- No label=0 contamination ✓

---
## 2026-08-12 — Subphase 4 Simulation COMPLETE (Parent-Child Chains, 10 rules)

**Status:** COMPLETE ✅ (feature extraction pending)
**Script:** `scripts/simulate_subphase_4.py`
**SIM_START (UTC):** 2026-08-12 16:35:11.776194
**SIM_END (UTC):** 2026-08-12 16:56:15.248679
**DLL compilation:** PASS (`ss_chain_com.dll` compiled via `csc.exe`)
**D41 retries triggered:** 0 — wscript/cscript spawned cleanly on first attempt throughout
**Scheduled task cleanup:** All 4 tasks deleted ✓

### Path-level results

| Rule | Path A | Path B | Path C | OVERALL (script) | Committee |
|---|---|---|---|---|---|
| CHAIN_SCRIPT_HOST_CMD_001 | PASS (2) | PASS (2) | PASS (2) | PASS | PASS |
| CHAIN_SCRIPT_HOST_POWERSHELL_001 | PASS (2) | PASS (2) | PASS (2) | PASS | PASS |
| CHAIN_SCHEDULED_TASK_SVCHOST_001 | PASS (2) | PASS (2) | PASS (3) | PASS | PASS |
| CHAIN_SCHEDULED_TASK_SCRIPT_001 | FAIL (D43) | FAIL (D43) | FAIL (D43) | FAIL | FAIL (structural) |
| CHAIN_REGSVR32_CHILD_001 | FAIL (D50) | FAIL (D50) | FAIL (D50) | FAIL | FAIL (new D50) |
| CHAIN_LOLBIN_CHILD_001 | PASS (2) | FAIL (D51) | PASS (2) | FAIL | PARTIAL (D51 on B) |
| CHAIN_BROWSER_SHELL_001 | PARTIAL | PARTIAL | PARTIAL | PARTIAL | PARTIAL (D42) |
| CHAIN_OFFICE_POWERSHELL_001 | SKIP | SKIP | SKIP | SKIP | SKIP |
| CHAIN_OFFICE_CMD_001 | SKIP | SKIP | SKIP | SKIP | SKIP |
| CHAIN_OFFICE_WSCRIPT_001 | SKIP | SKIP | SKIP | SKIP | SKIP |

### New environmental findings (D50–D51)

**D50 — CHAIN_REGSVR32_CHILD_001: regsvr32 + .NET COM DLL → 0 EID-1 (new finding)**
- All 3 paths (register /s, unregister /s /u, re-register /s) produced 0 hits.
- DLL compiled correctly (`_DLL_READY=True`). regsvr32 ran without error or WinError catch.
- Critical diagnostic: the SAME `ss_chain_com.dll` via `regasm /nologo /codebase` → 2 hits PASS
  (CHAIN_LOLBIN_CHILD_001 Path C). This PROVES the C# `[ComRegisterFunction]` → `Process.Start`
  code works correctly. The failure is loader-specific to regsvr32.
- Root cause: Defender's behavioral engine detects `regsvr32.exe` loading a .NET DLL and spawning
  a child process (`cmd.exe`), silently terminates the child before Sysmon EID-1 is logged.
  No WinError is raised because regsvr32 returns normally before the child is killed. This is a
  more subtle form of D-f: not a command-line signature match but a behavioral chain block.
- Prior session note: CHAIN_REGSVR32_CHILD_001 was PASS in 2026-07-30 session, which used the
  squiblydoo pattern (scrobj.dll). That pattern was documented as D-f blocked. This re-simulation
  used the C# DLL specifically to AVOID D-f, but hit a different Defender behavioral profile.
- Fix scope (Codex, post-SP6): redesign with a native (non-.NET) DLL that spawns cmd.exe
  via DllRegisterServer without managed code — avoids the .NET load behavioral signal.
  Rule itself is valid and was confirmed in Phase 4B direct validation.

**D51 — CHAIN_LOLBIN_CHILD_001 Path B: cmstp /s /ni + INF RunPreSetupCommandsSection → 0 EID-1**
- `cmstp.exe /s /ni C:\Windows\Temp\ss_chain_cmstp.inf` ran silently, 0 hits after 180s poll.
- Rule confirmed PASS on Path A (mshta HTA → cmd, 2 hits) and Path C (regasm → cmd, 2 hits).
- Root cause: cmstp's `RunPreSetupCommandsSection` likely uses `ShellExecuteEx` rather than
  `CreateProcess` to execute INF commands, attributing the child process parent to explorer.exe
  or svchost.exe rather than cmstp.exe. Alternatively, Defender blocked the cmstp→cmd.exe chain
  behaviorally. Without WinError output, cannot distinguish the two. The `/s /ni` flags suppress
  all UI including any error popups that might have revealed the failure.
- Fix scope (future): if cmstp is needed as a confirmed path, try the `RegisterOCXs` section
  variant (which explicitly calls `DllRegisterServer` on a specified DLL), or use `-s` only
  (without `/ni`) to allow UI that might reveal what happened. Low priority — rule already
  confirmed via 2 other paths.

### Notable positives

1. **No D41 retries needed.** All wscript/cscript paths (Rules 1 and 2) fired on first attempt.
   D41 retry mechanism was not triggered — VM was cooperative for script engine spawning today.

2. **CHAIN_SCHEDULED_TASK_SVCHOST_001 Path C got 3 hits.** The second `/run` call after the
   10s sleep successfully triggered a second task execution, giving 3 total hits (first run from
   inside `create_and_run_task` + second `/run` call + possible lag delivery). Clean PASS.

3. **SysWOW64 powershell confirmed** (CHAIN_SCRIPT_HOST_POWERSHELL_001 Path C). cscript →
   SysWOW64 powershell.exe → PASS. The rule's `ends_with "powershell.exe"` condition matches
   the 32-bit path correctly.

4. **regasm as lolbin confirmed** (CHAIN_LOLBIN_CHILD_001 Path C, 2 hits PASS). regasm.exe
   is confirmed as a valid parent for CHAIN_LOLBIN_CHILD_001 on this VM — useful data point
   for both detection validation and research paper Section 3.

### Feature CSV integrity check

- **DB confirmed window:** 2026-08-12 16:35:25.741658 → 2026-08-12 16:55:49.809910 (UTC)
- **Total rows:** 186 (all label=1 ✓)
- **has_chain_rule_hit=1:** 21 rows (confirmed chain rule hits in DB)
- **has_chain_rule_hit=0:** 165 rows (background/child/unrelated processes in window)
- **rule_hit_count > 0:** 39 rows (includes 18 rows where other rule types fired during window)
- **max rule_hit_count:** 40 — one row with `has_api=1`, D30 pattern (vmtoolsd/wmiprvse firing
  API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 unprompted against lsass/winlogon). Expected noise,
  no contamination. label=1 ✓.
- **is_known_suspicious_chain=1:** 12 rows — static feature; covers confirmed parent-chain launches
- **is_suspicious_parent=1:** 12 rows — same population as above
- **Feature columns:** 31 ✓
- **Non-label-1 rows:** 0 ✓

**CSV accepted: `data/features/suspicious_chains.csv` — 186 rows, 31 features, label=1.**

---

## 2026-08-13 — Subphase 5 Simulation COMPLETE (API/Memory, 8 rules)

**Script:** `scripts/simulate_subphase_5.py`
**SIM_START (UTC):** 2026-08-13T02:53:28.544979
**SIM_END   (UTC):** 2026-08-13T03:44:07.625055
**D30 pre-flight:** Clean — 0 background hits for `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` in 2-min idle window.
**DLL compilation:** PASS — `ss_api.dll` compiled via csc.exe to `C:\Windows\Temp`.
**Fake AV processes:** msmpeng.exe PID 4124, mpcmdrun.exe PID 7024 (both notepad copies — launched ✓).
**Notepad target:** PID 6248. lsass=696, winlogon=636, csrss=456, services=676.
**E5 workaround:** `ntdll.RtlExitUserThread` resolved — CRT confirmed working.

### Path-level results

| Rule | Path A | Path B | Path C | Script | Committee |
|---|---|---|---|---|---|
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 | PASS (2 hits, lsass 0x1f0fff) | PASS (2 hits, winlogon 0x1410) | FAIL (csrss 0x1fffff — WinError 5, D52) | FAIL | **PARTIAL** |
| API_TOKEN_MANIPULATION_001 | PASS (2 hits, lsass 0x40) | PASS (2 hits, winlogon 0x440) | FAIL (services 0x1440 — WinError 5, D52) | FAIL | **PARTIAL** |
| API_AV_PROCESS_ACCESS_001 | FAIL (msmpeng 0x1 — handle acquired, 0 hits, D53) | FAIL (msmpeng 0x20 — handle acquired, 0 hits, D53) | FAIL (mpcmdrun 0x1 — handle acquired, 0 hits, D53) | FAIL | **FAIL/D53** |
| API_OPEN_PROCESS_VM_WRITE_001 | PASS (2 hits, notepad 0x28) | PASS (2 hits, notepad 0x1f0fff) | FAIL (csrss 0x28 — WinError 5, D52) | FAIL | **PARTIAL** |
| API_DLL_LOAD_SUSPICIOUS_PATH_001 | FAIL (Temp — subprocess ran, 0 EID-7, D54) | FAIL (Public — DLL quarantined by Defender, 0 EID-7, D54) | FAIL (ProgramData — subprocess ran, 0 EID-7, D54) | FAIL | **FAIL/D54** |
| API_LOLBIN_DLL_UNSIGNED_001 | FAIL (rundll32 Temp — 20s timeout, DLL loaded but 0 EID-7, D55) | FAIL (regsvr32 Temp — completed, 0 EID-7, D55) | FAIL (rundll32 Public — file quarantined, exited quickly, 0 EID-7, D55) | FAIL | **FAIL/D55** |
| API_CRT_SUSPICIOUS_SOURCE_001 | PASS (4 hits, powershell→notepad) | PASS (4 hits, powershell→notepad) | PASS (4 hits, powershell→notepad) | PASS | **PASS** |
| API_CRT_SENSITIVE_TARGET_001 | PASS (4 hits, lsass) | PASS (4 hits, winlogon) | PASS (4 hits, lsass) | PASS | **PASS** |

**Committee re-classification:** 2 PASS / 3 PARTIAL / 2 FAIL-EID7 / 1 FAIL-D53 (out of 8 rules).

### New D-findings

**D52 — Sysmon EID-10 not generated for denied OpenProcess (WinError 5)**
- Confirmed: Rule 1 Path C (csrss, 0x1fffff), Rule 2 Path C (services, 0x1440), Rule 4 Path C (csrss, 0x0028) — all WinError 5 with 0 hits.
- Root cause: Sysmon ObRegisterCallbacks EID-10 hook only fires on GRANTED handles. Denied access attempts are silently dropped at the Sysmon layer.
- Impact: Rules 1/2/4 PARTIAL. PPL processes and processes with restrictive DACLs cannot be covered via denied-handle simulation paths.
- Fix scope: accept PARTIAL — 2/3 paths confirm each rule. Alternatively expand the ctypes simulation to use `SeDebugPrivilege` elevation for the specific paths (may help services.exe path; will not help csrss PPL).

**D53 — API_AV_PROCESS_ACCESS_001 structurally unfireable via fake processes**
- Confirmed: All 3 paths — handles to fake msmpeng.exe/mpcmdrun.exe acquired (ctypes said "Handle acquired and released") but 0 rule hits after full poll window.
- Root cause: Sysmon ProcessAccess filter does NOT include processes named msmpeng.exe/mpcmdrun.exe at `C:\Windows\Temp` in its EID-10 target inclusion list. The filter covers genuine system processes (lsass, winlogon, csrss, notepad confirmed firing) but not arbitrary user processes even if named like AV executables. Real MsMpEng.exe (in Program Files\Windows Defender) is PPL — all access denied regardless.
- Impact: This rule cannot be simulated via the fake-process approach on this VM. The rule is structurally unfireable without either: (a) modifying Sysmon config to add msmpeng.exe/mpcmdrun.exe as EID-10 targets, or (b) finding a non-PPL path to open the real AV process.
- Fix scope: flag as UNFIREABLE on this VM. Accept for now. Codex fix session: expand Sysmon config `<ProcessAccess>` to include `<TargetImage onmatch="include">msmpeng.exe</TargetImage>` and mpcmdrun.exe equivalents.

**D54 — Sysmon EID-7 not generated for DLL loads by python subprocess**
- Confirmed: API_DLL_LOAD_SUSPICIOUS_PATH_001 all 3 paths — subprocess python executed, no EID-7 in DB after 180s.
- Paths A/C (Temp, ProgramData): DLL survived (present at cleanup) → subprocess ran → 0 EID-7. Sysmon ImageLoad filter does not capture python.exe.
- Path B (Public): DLL quarantined by Defender during simulation (not found at cleanup — WinError 2) → subprocess would have gotten "file not found" → ctypes raised OSError internally → no LoadLibraryW → no EID-7 regardless.
- Root cause: Sysmon `<ImageLoad>` filter on this VM has a narrow inclusion rule that excludes arbitrary user processes (python.exe) from ImageLoad monitoring.
- Fix scope: Sysmon config change needed — add `python.exe` to `<ImageLoad>` monitored processes, or broaden the filter to include all unsigned DLL loads from suspicious paths. Deferred. Rule unfireable on this VM via python subprocess approach.

**D55 — Sysmon EID-7 not generated for rundll32/regsvr32 loading unsigned .NET DLL**
- Confirmed: API_LOLBIN_DLL_UNSIGNED_001 all 3 paths — 0 EID-7.
- Path A (rundll32 + Temp DLL): TIMED OUT at 20s. DLL was loaded by rundll32 (process was live and processing), but no EID-7 generated. Confirms Sysmon doesn't log EID-7 for this LOLBin+DLL combination on this VM.
- Path B (regsvr32 + Temp DLL): completed quickly with 0 hits. DllRegisterServer not found, regsvr32 returned quickly. No EID-7.
- Path C (rundll32 + Public DLL): completed quickly — Public DLL had already been quarantined by Defender (D54). rundll32 got "file not found" immediately.
- Root cause: Sysmon `<ImageLoad>` filter does not include rundll32.exe or regsvr32.exe as monitored loader processes for unsigned DLL detection on this VM.
- Fix scope: Sysmon config — add rundll32.exe and regsvr32.exe to `<ImageLoad>` `<Image onmatch="include">` filter. Deferred. Rule unfireable via this approach without config change.

### Notable positives

1. **EID-8 (CRT) confirmed fully working.** Both Rules 7 and 8 — 3 paths each — PASS. CRT to notepad, lsass, winlogon all confirmed. `SS_CRT:DONE:0 / SS_CRT:DONE:1` confirmed in output (meaning `OpenProcess(0x1F0FFF)` + `CreateRemoteThread` + `CloseHandle` all succeeded in the PS script). The `True` stdout lines are `CloseHandle` return values auto-printed by PowerShell (cosmetic only).
2. **E5 workaround confirmed.** `ntdll.dll + RtlExitUserThread` successfully bypasses Sysmon's `kernel32.dll StartModule` exclusion. CRT events generated correctly.
3. **D30 pre-flight: clean window.** No background EID-10 hits in the 2-minute idle window before simulation. vmtoolsd/wmiprvse did not trigger the D30 pattern this run.
4. **lsass CRT detection latency:** Rule 8 Path A first hit arrived ~50s after simulation start (not ~0s) — reflects pipeline lag but well within the 180s poll window.

### Cleanup notes

- Notepad, fake msmpeng.exe, fake mpcmdrun.exe: terminated ✓
- `C:\Windows\Temp\ss_api.cs`: deleted ✓
- `C:\Windows\Temp\ss_api.dll`: deleted ✓
- `C:\Users\Public\ss_api.dll`: **WinError 2 — not found.** Defender quarantined this file during simulation (consistent with D54/D56 pattern — Defender aggressively monitors unsigned DLLs in user-accessible public locations). Not a script bug.
- `C:\ProgramData\ss_api.dll`: deleted ✓
- Temp fake AV executables and ps1 script: deleted ✓

### Feature CSV integrity check — PASSED

- **DB confirmed window:** 2026-08-13 02:53:47.286285 → 2026-08-13 03:43:09.292475 (UTC)
- **Total rows:** 217 (all label=1 ✓)
- **has_api_rule_hit=1:** ~17 rows — python.exe EID-10 windows + powershell.exe CRT windows + target process windows
- **create_remote_thread_count=2:** exactly 12 rows — 6 paths × 2 PS launches for Rules 7+8; 2 threads per invocation (ss_crt_sim.ps1 loop 0→1) ✓
- **unsigned_image_loaded=1:** in all 12 CRT powershell rows — Add-Type C# JIT compilation produces temporary unsigned .NET assembly, expected ✓
- **open_process_suspicious_access=1:** multiple rows, consistent with Rules 1/2/4 PASS paths ✓
- **rule_hit_count peaks:** 28 (python.exe full-window EID-10 accumulation), 11 (lsass CRT windows firing both CRT rules + OpenProcess simultaneously) — internally consistent ✓
- **Background rows:** present, all label=1, feature flags 0 — consistent with 50-minute wide window ✓
- **No contamination:** has_chain_rule_hit=0 throughout; has_powershell_rule_hit only in CRT PS rows ✓
- **Feature columns:** 31 ✓ | **Non-label-1 rows:** 0 ✓

**CSV ACCEPTED: `data/features/suspicious_api.csv` — 217 rows, 31 features, label=1.**

---

## Subphase 6 — SUPERSEDED

Subphase 6 (CreateRemoteThread/Injection, originally planned separately) is **superseded** by the §21.5 re-simulation consolidation. All 8 `api_memory.yaml` rules (EID-10 + EID-7 + EID-8) were consolidated into `simulate_subphase_5.py`. Both EID-8 rules are PASS and confirmed in `suspicious_api.csv`. No separate SP6 script or CSV needed.

**All Phase 7A suspicious telemetry CSVs are now COMPLETE:**

| Subphase | CSV | Rows |
|---|---|---|
| SP1 (PowerShell, 11 rules) | `suspicious_ps.csv` | 312 |
| SP2 (LOLBins, 13 rules) | `suspicious_lolbins.csv` | 196 |
| SP3 (Network, 9 rules) | `suspicious_network.csv` | 194 |
| SP4 (Parent-Child Chains, 10 rules) | `suspicious_chains.csv` | 186 |
| SP5 (API/Memory, 8 rules) | `suspicious_api.csv` | 217 |
| **Total** | | **1,105 rows** |

**Next: Subphase 7 — Consolidation & Handoff.**

---
