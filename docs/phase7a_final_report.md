# Phase 7A Final Report — Labeled Suspicious Telemetry Generation

**Phase:** 7A — Generate Labeled Suspicious Telemetry via Sandbox Simulation
**Status:** COMPLETE ✅
**Dates:** 2026-08-12 (SP1–SP4) and 2026-08-13 (SP5 + SP7 Consolidation)
**Author:** ShadowSensor Committee (Detection Engineer, Malware Analyst, Rule Engine Architect)
**Depends on:** Phase 6B COMPLETE — Isolation Forest trained, `model_scores` live

---

## 1. Summary

Phase 7A generated 1,105 labeled (label=1) suspicious process windows across five simulation subphases, covering all five rule YAML files in `rules/definitions/`. All simulations ran in the isolated Windows 10 Pro VMware sandbox VM with the ShadowSensor pipeline active. Feature extraction used the same `run_feature_extraction.py` pipeline as Phase 6A, maintaining identical feature schema (31 columns including `label`).

| Metric | Value |
|---|---|
| Combined output file | `data/features/suspicious.csv` |
| Total rows (label=1) | **1,105** |
| Total columns | **31** (30 features + label) |
| Contamination check | **PASSED** — all rows `label=1` |
| Subphases completed | 5 (SP6 superseded — see §3) |
| Rule files covered | `powershell.yaml`, `lolbins.yaml`, `network.yaml`, `parent_child.yaml`, `api_memory.yaml` |
| New environmental findings documented | D44–D55 |

---

## 2. Simulation Windows (UTC)

| Subphase | YAML File | SIM START (UTC) | SIM END (UTC) | Rows |
|---|---|---|---|---|
| 1 — PowerShell | powershell.yaml | 2026-08-12 07:57 | 2026-08-12 09:00 | 312 |
| 2 — LOLBins | lolbins.yaml | 2026-08-12 09:35 | 2026-08-12 11:30 | 196 |
| 3 — Network | network.yaml | 2026-08-12 15:04 | 2026-08-12 15:56 | 194 |
| 4 — Parent-Child | parent_child.yaml | 2026-08-12 16:35:25 | 2026-08-12 16:55:49 | 186 |
| 5 — API/Memory | api_memory.yaml | 2026-08-13 02:53:28 | 2026-08-13 03:44:07 | 217 |

All timestamps are UTC. VM displays IST (UTC+5:30). All `--since`/`--until` extraction bounds were derived from DB-queried UTC timestamps, not console wall-clock output. (See D8 in `docs/decisions_log.md` Entry 008.)

---

## 3. Subphase 6 — SUPERSEDED

Subphase 6 was originally planned for `CreateRemoteThread` (EID-8) rules: `API_CRT_SUSPICIOUS_SOURCE_001` and `API_CRT_SENSITIVE_TARGET_001`. During SP5 design, all 8 `api_memory.yaml` rules (EID-10, EID-7, AND EID-8) were consolidated into `simulate_subphase_5.py` using the E5 workaround (`ntdll.RtlExitUserThread`). Both CRT rules **PASS** with full 3-path / 2-launch coverage. No SP6 CSV was needed.

Note: `injection.yaml` was listed in early documentation but this file does not exist. No SP6 simulation was needed.

---

## 4. Rule-Hit Confirmation Table

### Subphase 1 — powershell.yaml (11 live rules)

| Rule ID | Result | Notes |
|---|---|---|
| PS_ENCODED_COMMAND_001 | ✅ PASS | 3 paths |
| PS_EXECUTION_POLICY_BYPASS_001 | ⚠ PARTIAL | Pipeline lag D44; DB confirmed |
| PS_HIDDEN_WINDOW_001 | ⚠ PARTIAL | Pipeline lag D44; DB confirmed |
| PS_INVOKE_EXPRESSION_001 | ⚠ PARTIAL | Pipeline lag D44; DB confirmed |
| PS_DOWNLOAD_CRADLE_001 | ✅ PASS | |
| PS_AMSI_BYPASS_001 | ⚠ PARTIAL | D-f: Defender blocks pre-EID-1; not a rule defect |
| PS_CREDENTIAL_ACCESS_001 | ⚠ PARTIAL | D-f: Defender blocks pre-EID-1; not a rule defect |
| PS_REFLECTIVE_ASSEMBLY_001 | ✅ PASS | ID renamed from PS_REFLECTION_ASSEMBLY_001 (D2) |
| PS_CONSTRAINED_LANG_BYPASS_001 | ✅ PASS | Mechanism differs from docs: `__PSLockdownPolicy` env var (D4) |
| PS_VERSION_DOWNGRADE_001 | ✅ PASS | Undocumented live rule (D5) |
| PS_WMI_EXEC_001 | ✅ PASS | Undocumented live rule (D6) |
| PS_NOPROFILE_NONINTERACTIVE_001 | ⏭ SKIP | Does not exist in live YAML (D1) |
| PS_OBFUSCATION_001 | ⏭ SKIP | Does not exist in live YAML (D1) |

### Subphase 2 — lolbins.yaml (13 live rules)

| Rule ID | Result | Notes |
|---|---|---|
| LOLBIN_MSHTA_001 | ✅ PASS | |
| LOLBIN_RUNDLL32_SUSPICIOUS_001 | ⚠ PARTIAL | D-f Defender; Path C (http://) unexpectedly PASS |
| LOLBIN_REGSVR32_001 | ⚠ PARTIAL | D-f Defender |
| LOLBIN_CERTUTIL_001 | ⚠ PARTIAL | Path A (-urlcache) Defender-blocked; Paths B/C PASS |
| LOLBIN_MSIEXEC_001 | ✅ PASS | |
| LOLBIN_ODBCCONF_001 | ✅ PASS | |
| LOLBIN_CMSTP_001 | ✅ PASS | |
| LOLBIN_HH_CHM_001 | ❌ FAIL | D45: Sysmon or Defender prevents EID-1 for hh.exe on this VM |
| LOLBIN_REGASM_001 | ✅ PASS | .NET Framework64\v4.0.30319 path confirmed |
| LOLBIN_REGSVCS_001 | ✅ PASS | |
| LOLBIN_INSTALLUTIL_001 | ✅ PASS | |
| LOLBIN_WMIC_001 | ✅ PASS | |
| LOLBIN_BITSADMIN_001 | ✅ PASS | |
| LOLBIN_FINDSTR_001 | ⏭ SKIP | Does not exist in live YAML (D13) |

### Subphase 3 — network.yaml (9 live rules)

| Rule ID | Result | Notes |
|---|---|---|
| NET_POWERSHELL_HTTP_001 | ✅ PASS | Paths A/C; Path B FAIL D48 |
| NET_DNS_LONG_QUERY_001 | ✅ PASS | Paths A/B; Path C FAIL D47 |
| NET_DNS_SCRIPT_ENGINE_001 | ❓ INCONCLUSIVE | D29: cscript HTTPS → zero Sysmon events; mshta Path C 1 hit |
| NET_SCRIPTING_ENGINE_HTTP_001 | ⚠ PARTIAL | wscript https PASS; cscript/mshta INCONCLUSIVE D29 |
| NET_SCRIPT_ENGINE_OUTBOUND_001 | ⚠ PARTIAL | D29/D46 dominant; odbcconf Path C confirmed |
| NET_LOLBIN_PROCESS_HTTP_001 | ❓ INCONCLUSIVE | D46/D-b |
| NET_LOLBIN_NETWORK_001 | ✅ PASS | odbcconf Path C confirmed |
| NET_SUSPICIOUS_PORT_001 | ⏭ SKIP | D28: EID-3 filter ports 80/443 only — structurally unfireable |
| NET_SMB_LATERAL_001 | ⏭ SKIP | D28: same reason |

### Subphase 4 — parent_child.yaml (10 live rules)

| Rule ID | Result | Notes |
|---|---|---|
| CHAIN_SCRIPT_HOST_CMD_001 | ✅ PASS | 3 paths; required 1 retry (D41) |
| CHAIN_SCRIPT_HOST_POWERSHELL_001 | ✅ PASS | SysWOW64 path confirmed |
| CHAIN_SCHEDULED_TASK_SVCHOST_001 | ✅ PASS | 3 command-line variants confirmed |
| CHAIN_SCHEDULED_TASK_SCRIPT_001 | ❌ FAIL | D43: schtasks.exe never true parent; real parent svchost -s Schedule |
| CHAIN_REGSVR32_CHILD_001 | ❌ FAIL | D50: Defender terminates child before Sysmon EID-1; regasm works |
| CHAIN_LOLBIN_CHILD_001 | ⚠ PARTIAL | mshta PASS, regasm PASS; cmstp FAIL D51 |
| CHAIN_BROWSER_SHELL_001 | ⚠ PARTIAL | D42: Edge protocol-handler requires in-browser trigger |
| CHAIN_OFFICE_POWERSHELL_001 | ⏭ SKIP | Office not installed on sandbox VM |
| CHAIN_OFFICE_CMD_001 | ⏭ SKIP | Office not installed on sandbox VM |
| CHAIN_OFFICE_WSCRIPT_001 | ⏭ SKIP | Office not installed on sandbox VM |

### Subphase 5 — api_memory.yaml (8 live rules)

| Rule ID | EID | Result | Notes |
|---|---|---|---|
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 | 10 | ⚠ PARTIAL | Paths A/B PASS; Path C FAIL D52 (PPL csrss denied, EID-10 not logged) |
| API_TOKEN_MANIPULATION_001 | 10 | ⚠ PARTIAL | Paths A/B PASS; Path C FAIL D52 (PPL services.exe) |
| API_AV_PROCESS_ACCESS_001 | 10 | ❌ FAIL | D53: Sysmon ProcessAccess filter excludes fake msmpeng in Temp; real MsMpEng PPL |
| API_OPEN_PROCESS_VM_WRITE_001 | 10 | ⚠ PARTIAL | Paths A/B PASS; Path C FAIL D52 (PPL csrss) |
| API_DLL_LOAD_SUSPICIOUS_PATH_001 | 7 | ❌ FAIL | D54: Sysmon ImageLoad filter excludes python.exe; Defender quarantined Public DLL |
| API_LOLBIN_DLL_UNSIGNED_001 | 7 | ❌ FAIL | D55: Sysmon ImageLoad filter excludes rundll32/regsvr32 DLL loads on this VM |
| API_CRT_SUSPICIOUS_SOURCE_001 | 8 | ✅ PASS | E5 workaround (ntdll.RtlExitUserThread); powershell→notepad/lsass/winlogon |
| API_CRT_SENSITIVE_TARGET_001 | 8 | ✅ PASS | E5 workaround; lsass/winlogon confirmed sensitive targets |

---

## 5. Family Enrichment Log

| Rule ID | Technique Simulated | Primary Family Reference |
|---|---|---|
| PS_ENCODED_COMMAND_001 | PowerShell -EncodedCommand execution | APT29 / Cobalt Strike — base64-encoded payloads standard C2 mechanism |
| PS_EXECUTION_POLICY_BYPASS_001 | -ExecutionPolicy Bypass flag | Generic commodity malware; Emotet dropper documented by Picus Security |
| PS_HIDDEN_WINDOW_001 | -WindowStyle Hidden flag | QakBot / TrickBot PowerShell loaders |
| PS_INVOKE_EXPRESSION_001 | IEX (Invoke-Expression) remote download | Emotet / Dridex PowerShell stages (Picus Security analysis) |
| PS_DOWNLOAD_CRADLE_001 | (New-Object Net.WebClient).DownloadString IEX | APT29 NOBELIUM — documented download cradle pattern |
| PS_AMSI_BYPASS_001 | amsiInitFailed reflection bypass | Red team technique; widely attributed to GreyEnergy group (ESET) |
| PS_CREDENTIAL_ACCESS_001 | Mimikatz-style credential dumping script | Lazarus Group / APT38 — PowerShell-based lsass access |
| PS_REFLECTIVE_ASSEMBLY_001 | [Reflection.Assembly]::LoadWithPartialName | APT41 — reflective loading of .NET assemblies in-memory |
| PS_CONSTRAINED_LANG_BYPASS_001 | __PSLockdownPolicy env var bypass | Generic red team / WannaCry delivery mechanism |
| PS_VERSION_DOWNGRADE_001 | PowerShell -Version 2 downgrade | FIN7 documented by FireEye — AMSI and CLM bypass via PS v2 |
| PS_WMI_EXEC_001 | Invoke-WmiMethod Win32_Process::Create | APT29 / WMI-based lateral movement (Mandiant M-Trends) |
| LOLBIN_MSHTA_001 | mshta.exe executing VBScript / HTA | Uroburos / APT28 — mshta.exe VBScript execution |
| LOLBIN_RUNDLL32_SUSPICIOUS_001 | rundll32.exe loading inline script | Cobalt Strike beacon delivery |
| LOLBIN_REGSVR32_001 | regsvr32 /s /u /i: squiblydoo technique | APT19 (DeputyDog) — documented by Carbon Black |
| LOLBIN_CERTUTIL_001 | certutil -decode / -urlcache download | APT41 — certutil used for payload delivery (FireEye) |
| LOLBIN_MSIEXEC_001 | msiexec /q /i http:// | Emotet — remote MSI execution for module loading |
| LOLBIN_ODBCCONF_001 | odbcconf.exe /A {REGSVR ...} | FIN7 — documented by Mandiant (odbcconf.exe abuse) |
| LOLBIN_CMSTP_001 | cmstp.exe INF with RunPreSetupCommands | MuddyWater — documented by ClearSky/Symantec |
| LOLBIN_HH_CHM_001 | hh.exe executing CHM with embedded VBScript | Lazarus Group — CHM-based delivery (CISA advisory) — **FAIL D45** |
| LOLBIN_REGASM_001 | regasm.exe /U loading .NET assembly | APT32 (OceanLotus) — regasm.exe proxy execution |
| LOLBIN_REGSVCS_001 | regsvcs.exe loading COM+ assembly | Generic red team — analogous to regasm abuse |
| LOLBIN_INSTALLUTIL_001 | installutil.exe /logfile= /U | TURLA — .NET InstallUtil proxy execution |
| LOLBIN_WMIC_001 | wmic.exe process call create | APT29 — WMIC lateral movement |
| LOLBIN_BITSADMIN_001 | bitsadmin /transfer download | APT10 — BITS job as download mechanism |
| NET_POWERSHELL_HTTP_001 | PS WebClient/Invoke-WebRequest outbound HTTP | Cobalt Strike C2 beacon over HTTP |
| NET_DNS_LONG_QUERY_001 | Long DNS query hostname via Resolve-DnsName | DNSMessenger / POWERSOURCE — DNS C2 exfiltration (Talos) |
| NET_DNS_SCRIPT_ENGINE_001 | cscript/wscript DNS query for C2 resolution | Generic script-engine-based DNS C2 |
| NET_SCRIPTING_ENGINE_HTTP_001 | wscript.exe HTTPS outbound | QakBot delivery via wscript |
| NET_SCRIPT_ENGINE_OUTBOUND_001 | Script engine HTTP outbound via various LOLBins | Generic download-cradle pattern |
| NET_LOLBIN_PROCESS_HTTP_001 | LOLBin HTTP connection (mshta, odbcconf) | APT28 — LOLBin-based C2 channels |
| NET_LOLBIN_NETWORK_001 | odbcconf.exe outbound network connection | FIN7 documented network channel via odbcconf |
| NET_SUSPICIOUS_PORT_001 | Non-standard port network connection | Generic C2; Cobalt Strike custom port malleable profiles — **SKIP D28** |
| NET_SMB_LATERAL_001 | SMB lateral movement | NotPetya / EternalBlue-based lateral movement — **SKIP D28** |
| CHAIN_SCRIPT_HOST_CMD_001 | wscript.exe → cmd.exe | QakBot — wscript→cmd documented chain (myspybot.com) |
| CHAIN_SCRIPT_HOST_POWERSHELL_001 | wscript.exe → powershell.exe | QakBot — wscript→PowerShell variant |
| CHAIN_SCHEDULED_TASK_SVCHOST_001 | svchost -s Schedule spawning scripts | IcedID — scheduled task persistence (FortiGuard) |
| CHAIN_SCHEDULED_TASK_SCRIPT_001 | Legacy scheduler parents → scripts | IcedID — **FAIL D43**: schtasks.exe never true parent |
| CHAIN_REGSVR32_CHILD_001 | regsvr32 spawning child via [ComRegisterFunction] | APT19 — **FAIL D50**: Defender terminates child pre-EID-1 |
| CHAIN_LOLBIN_CHILD_001 | mshta/regasm spawning child process | APT32 — HTA-based child process spawning |
| CHAIN_BROWSER_SHELL_001 | Browser spawning shell process | Generic phishing chain — **PARTIAL D42** |
| CHAIN_OFFICE_POWERSHELL_001 | Word macro → powershell.exe | TrickBot/QakBot — **SKIP**: Office not installed |
| CHAIN_OFFICE_CMD_001 | Word macro → cmd.exe | TrickBot — **SKIP**: Office not installed |
| CHAIN_OFFICE_WSCRIPT_001 | Word macro → wscript.exe | QakBot — **SKIP**: Office not installed |
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 | OpenProcess PROCESS_ALL_ACCESS on lsass/winlogon | Mimikatz credential harvesting — PARTIAL (D52 PPL) |
| API_TOKEN_MANIPULATION_001 | OpenProcess PROCESS_DUP_HANDLE on lsass/winlogon | Token impersonation — generic red team; PARTIAL (D52 PPL) |
| API_AV_PROCESS_ACCESS_001 | OpenProcess on AV processes (MsMpEng) | Lazarus Group AV enumeration — **FAIL D53** |
| API_OPEN_PROCESS_VM_WRITE_001 | OpenProcess PROCESS_VM_WRITE/OPERATION on target | Process hollowing prep — generic injection — PARTIAL (D52 PPL) |
| API_DLL_LOAD_SUSPICIOUS_PATH_001 | DLL loaded from Temp/Public/ProgramData | Cobalt Strike — staged DLL delivery — **FAIL D54** |
| API_LOLBIN_DLL_UNSIGNED_001 | rundll32/regsvr32 loading unsigned DLL | APT41 — LOLBin-based unsigned DLL execution — **FAIL D55** |
| API_CRT_SUSPICIOUS_SOURCE_001 | CreateRemoteThread from PowerShell to target | Cobalt Strike inject-dll — CRT from non-standard process ✅ |
| API_CRT_SENSITIVE_TARGET_001 | CreateRemoteThread into lsass/winlogon | Mimikatz / Cobalt Strike privilege escalation injection ✅ |

---

## 6. Combined suspicious.csv Statistics

| Metric | Value |
|---|---|
| File path | `data/features/suspicious.csv` |
| Total rows | **1,105** |
| Columns | **31** (30 features + `label`) |
| First column | `cmd_length` |
| Last column | `label` |
| All `label=1` | **True** |
| Contamination | **None** — assertion passed |

### Rule-Hit Feature Activation (across combined 1,105 rows)

| Feature | Rows Activated | % |
|---|---|---|
| `has_powershell_rule_hit` | 79 / 1105 | 7.1% |
| `has_lolbin_rule_hit` | 74 / 1105 | 6.7% |
| `has_network_rule_hit` | 16 / 1105 | 1.4% |
| `has_api_rule_hit` | 53 / 1105 | 4.8% |
| `has_chain_rule_hit` | 22 / 1105 | 2.0% |

All five rule-hit features have activation — confirming each subphase's simulation data is represented in the combined dataset.

The low activation percentages (1–7%) are expected: the feature extraction pipeline generates one process window per process event, not one per rule hit. Most simulated suspicious processes generate multiple process windows (parent + children), but only the specific window that triggers the rule carries `has_*_rule_hit = 1`. The remaining windows still carry `label=1` because they were captured within the simulation window and carry the correct behavioral features.

---

## 7. Isolation Forest Score Distribution

The trained Isolation Forest model (`ml/models/isolation_forest.joblib`) was applied to both the suspicious and benign datasets for calibration.

| Metric | Suspicious (N=1,105) | Benign (N=621) | Delta |
|---|---|---|---|
| Min | 0.0000 | 0.0000 | — |
| Max | 0.8393 | 1.0000 | — |
| **Mean** | **0.2152** | **0.1394** | **+0.0758** |
| **Median** | **0.1294** | **0.0912** | **+0.0382** |
| > 0.5 (anomalous) | **162 / 1105 (14.7%)** | 31 / 621 (5.0%) | +9.7 pp |
| > 0.3 (elevated) | 376 / 1105 (34.0%) | 104 / 621 (16.7%) | +17.3 pp |

**Interpretation for Phase 7B:**

The IF model — trained only on benign data — shows a modest but consistent positive separation: suspicious data scores ~7.6% higher on average (mean delta +0.0758) and the anomalous rate (>0.5) is nearly **3× higher** (14.7% vs 5.0%).

However, 85.3% of suspicious data does NOT score as anomalous to the IF model. This is expected: the IF was trained on process-level feature statistics, not on rule semantics. Many suspicious process windows are structurally similar to normal processes at the feature-statistics layer (e.g., a PowerShell window that runs one encoded command looks nearly identical to a benign PS window in its process metrics).

The critical implication for Phase 7B: the Random Forest must learn from **behavioral/categorical features** (rule hit flags, command-line patterns, parent-child structure) rather than relying on IF anomaly scores as a proxy. The RF will need the full 30-feature input to achieve high separability. The IF provides a weak prior signal but is not sufficient as a standalone binary classifier.

**Caution flags from Phase 6B (still active):**
- `open_process_suspicious_access` (~39% benign activation during Phase 6A) was flagged as disproportionately influential in IF training. Phase 7B should evaluate whether to drop/re-weight.
- `hour_of_day` / `is_off_hours` — VM clock drift issue was resolved before Phase 7A, but carry this flag into Phase 7B for awareness.

---

## 8. Coverage Gaps and Skipped Rules

The following rules could **not** generate confirmed suspicious telemetry on this sandbox VM. Phase 7B should be aware that these rules are absent from the label=1 training set.

| Rule ID | Reason | D-Finding | Recommended Action |
|---|---|---|---|
| PS_NOPROFILE_NONINTERACTIVE_001 | Rule does not exist in live YAML | D1 | Documentation cleanup — Codex |
| PS_OBFUSCATION_001 | Rule does not exist in live YAML | D1 | Documentation cleanup — Codex |
| LOLBIN_FINDSTR_001 | Rule does not exist in live YAML | D13 | Documentation cleanup — Codex |
| LOLBIN_HH_CHM_001 | Sysmon/Defender prevents EID-1 for hh.exe | D45 | Sysmon config or Defender exclusion needed |
| NET_SUSPICIOUS_PORT_001 | EID-3 filter captures ports 80/443 only | D28 | Sysmon config expansion — Codex/config task |
| NET_SMB_LATERAL_001 | Same as D28 | D28 | Same |
| NET_DNS_SCRIPT_ENGINE_001 | cscript HTTPS → 0 Sysmon events | D29 | Telemetry visibility gap — research paper §2 |
| CHAIN_OFFICE_POWERSHELL_001 | Office not installed on sandbox VM | — | Install Office, or document as known coverage gap |
| CHAIN_OFFICE_CMD_001 | Office not installed on sandbox VM | — | Same |
| CHAIN_OFFICE_WSCRIPT_001 | Office not installed on sandbox VM | — | Same |
| CHAIN_SCHEDULED_TASK_SCRIPT_001 | schtasks.exe never true parent | D43 | Rule deprecation or legacy-only notation — Codex |
| CHAIN_REGSVR32_CHILD_001 | Defender terminates child before EID-1 | D50 | Native DLL needed (not .NET) |
| API_AV_PROCESS_ACCESS_001 | Sysmon ProcessAccess filter excludes arbitrary Temp processes | D53 | Sysmon config expansion |
| API_DLL_LOAD_SUSPICIOUS_PATH_001 | Sysmon ImageLoad filter excludes python.exe | D54 | Sysmon config expansion |
| API_LOLBIN_DLL_UNSIGNED_001 | Sysmon ImageLoad filter excludes rundll32/regsvr32 DLL loads | D55 | Sysmon config expansion |

---

## 9. Environmental Findings Summary (D44–D55, new this phase)

| ID | Finding | Impact |
|---|---|---|
| D44 | VM pipeline lag 10–15 min; stale hit bleed from prior runs | FP hard-stops converted to [WARN]; affects SP1 |
| D45 | hh.exe EID-1 not logged by Sysmon on this VM | LOLBIN_HH_CHM_001 unfireable |
| D46 | mshta.exe HTTP/HTTPS → 0 EID-3; can produce EID-22 only | Affects SP3 network rules |
| D47 | nslookup.exe bypasses Windows DNS resolver → 0 EID-22 | Use Resolve-DnsName instead |
| D48 | EID-3 generation process-dependent at port 80; odbcconf PASS, PS/wscript FAIL | Affects SP3; workaround: use https://8.8.4.4:443 |
| D49 | EID-3 `destination_hostname` always NULL; hostname-exclusions structurally ineffective | FP suppression for NET_POWERSHELL_HTTP_001 non-functional |
| D50 | regsvr32 + .NET DLL: Defender terminates child before Sysmon EID-1 | CHAIN_REGSVR32_CHILD_001 unfireable via .NET DLL |
| D51 | cmstp INF RunPreSetupCommands → 0 EID-1 | CHAIN_LOLBIN_CHILD_001 Path B fails |
| D52 | EID-10 not logged for denied OpenProcess (WinError 5 / PPL) | EID-10 rules only partially fireable; PPL-protected targets excluded |
| D53 | Fake AV processes in Temp not in Sysmon ProcessAccess filter | API_AV_PROCESS_ACCESS_001 unfireable |
| D54 | python.exe DLL loads not captured by Sysmon ImageLoad filter | API_DLL_LOAD_SUSPICIOUS_PATH_001 unfireable |
| D55 | rundll32/regsvr32 DLL loads not captured by Sysmon ImageLoad filter; Defender quarantine | API_LOLBIN_DLL_UNSIGNED_001 unfireable |

---

## 10. Phase 7B Readiness Statement

**`data/features/suspicious.csv` is ready for Phase 7B Random Forest training.**

Confirmed:
- 1,105 rows, all `label=1`, zero contamination
- 30 features + `label`, identical schema to `data/features/benign_baseline.csv` (621 rows, all `label=0`)
- Combined training set: 1,726 rows (1,105 suspicious + 621 benign)
- IF score distribution confirms modest but consistent separation; RF needed for high-quality classification
- All rule-hit features have positive activation — no silent zero-columns

**Known gaps Phase 7B must account for:**
1. 15 rules from the gap table above have no confirmed label=1 representation — the RF will not learn to detect these patterns from the current training set.
2. Office-dependent rules (3) are structurally absent — document as "Office not installed" in Phase 10B paper.
3. `open_process_suspicious_access` and `hour_of_day` remain caution-flagged features from Phase 6B — evaluate before RF training.

**What Phase 7B needs:**
- `data/features/suspicious.csv` — this file ✅
- `data/features/benign_baseline.csv` — exists at this path from Phase 6A ✅
- Family enrichment log — Section 5 of this document ✅
- IF score distribution on suspicious data — Section 7 of this document ✅
- Coverage gaps and skipped rules — Section 8 of this document ✅

---

*Report authored by ShadowSensor Committee. Reviewed and accepted 2026-08-13.*
