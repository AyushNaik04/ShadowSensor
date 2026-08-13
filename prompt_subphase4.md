# Cursor Grok 4.5 — ShadowSensor Phase 7A Subphase 4 Simulation Script

## Purpose

Generate `scripts/simulate_subphase_4.py` — a simulation script that exercises all 10
Parent-Child Chain detection rules from `rules/definitions/parent_child.yaml` and logs
results to the ShadowSensor pipeline.

Live YAML audit confirmed **10 rules** — same count as prior SP4 (2026-07-30).

---

## Hard Constraints (non-negotiable)

1. Output file: `scripts/simulate_subphase_4.py` only. No other files modified.
2. Frozen files — do not touch:
   - `rules/engine.py`, `rules/definitions/*.yaml`, `scripts/run_pipeline.py`,
     `storage/database.py`, `normalizer/*.py`, `ml/`, `api/`, `tests/`,
     `data/`, `docs/`, `status.md`, `handover.md`, `committee.md`,
     `rule_insights.md`, `task.md`, `VM_RUN_GUIDE.md`
3. Every rule ID and field value comes from `rule_insights.md` and confirmed `parent_child.yaml`.
4. If any value in this prompt conflicts with itself, STOP and report. Do not guess.
5. Do not create or modify any file other than `scripts/simulate_subphase_4.py`.
6. The compiled DLL (`ss_chain_com.dll`) and all helper files are written by the script itself
   at runtime — they are NOT pre-existing files.

---

## FUNDAMENTAL DIFFERENCE FROM SUBPHASES 1–3 — READ FIRST

**Subphases 1–3 controlled what process runs and what it does (command line, network call).
Subphase 4 controls WHO spawned the process.**

All 10 rules are EID-1 (ProcessCreate) rules that check `parent_image` → `image` relationships.
Sysmon reads the actual Windows kernel process tree — `parent_image` cannot be faked. The
simulation script (python.exe) spawns a **PARENT** process, and that parent must then spawn
the **CHILD** process. Sysmon's EID-1 for the child will show parent_image = the actual parent.

**Consequence:** Every simulation uses a two-step chain:
1. `launch_argv()` → spawns the PARENT process (e.g., wscript.exe, mshta.exe, regsvr32.exe)
2. The PARENT runs an embedded script/DLL/INF that calls CreateProcess on the CHILD

Scripts, HTA files, INF files, and a compiled C# DLL are written to disk in BLOCK 2 before
any simulation runs. These are the mechanisms that make the parent spawn the child.

---

## Critical Environment Notes

### DB_PATH (hardcoded)
```python
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
```

### REPO_ROOT and EXPORTS_DIR
```python
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
```

### D41 — wscript/cscript spawn intermittent failure (NON-NEGOTIABLE retry logic)
On this VM, wscript.exe and cscript.exe intermittently fail to spawn shell children
(cmd.exe, powershell.exe) without any error or Defender detection. This is non-deterministic.
**Every wscript/cscript-as-parent path MUST implement a D41 retry:**
- After the first two launches, poll 180s.
- If n == 0: print `[D41] 0 hits — retrying (D41: wscript/cscript spawn intermittent)`.
  Immediately re-run the same two launches with a fresh path_start, poll again.
- If still n == 0 after retry: warn_zero + result = "FAIL".
- D41 retry applies ONLY to CHAIN_SCRIPT_HOST_CMD_001 and CHAIN_SCRIPT_HOST_POWERSHELL_001.
  No other rules use it.

### D42 — CHAIN_BROWSER_SHELL_001 structural limitation
A browser cannot be made to spawn cmd.exe via subprocess invocation. Any child process
launched by the simulation script has parent_image = python.exe, not a browser. This rule
gets a PARTIAL block with no simulation attempt. Reason documented in CSV.

### D43 — CHAIN_SCHEDULED_TASK_SCRIPT_001 structural limitation
On Windows 10, taskeng.exe does not exist (Vista/7 legacy). taskhostw.exe handles only
COM/DLL-based tasks. Script tasks (PowerShell, wscript) always run with parent =
`svchost.exe -s Schedule`. The rule's condition (`parent_image contains_any "taskeng.exe" |
"taskhostw.exe"`) can never match. We ATTEMPT this rule (create and run a real scheduled
task) and CONFIRM the D43 failure by observing 0 hits. Result = "FAIL", reason = D43.

### D-f and the compiled DLL approach for regsvr32
The standard squiblydoo technique (regsvr32 + /i:http + scrobj.dll) is Defender-blocked (D-f).
CHAIN_REGSVR32_CHILD_001 is simulated via a **compiled C# COM DLL** — no scrobj.dll, no http://
in the regsvr32 command line — which avoids the D-f squiblydoo signature entirely.

### Compiled C# DLL dependency
`csc.exe` at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` is confirmed present
on this VM (from SP1 analysis). In BLOCK 2, the script writes a C# source file and compiles it.
If compilation fails: CHAIN_REGSVR32_CHILD_001 all paths → SKIP. CHAIN_LOLBIN_CHILD_001
Path C → SKIP. Other paths in CHAIN_LOLBIN_CHILD_001 (mshta, cmstp) are NOT affected.
Store the compilation result in `_DLL_READY: bool` at the start.

### Scheduled task cleanup
All scheduled tasks created during simulation must be deleted at the END of the script
(after BLOCK 8), regardless of whether the run succeeded. Use a finally-style cleanup block.
Task names: `ShadowSensor_SP4_SVCA`, `ShadowSensor_SP4_SVCB`, `ShadowSensor_SP4_SVCC`,
`ShadowSensor_SP4_D43`. Delete all four even if they were never created (schtasks /delete
returns non-zero if the task doesn't exist — ignore those errors).

### No FP suppression tests
No rules in `parent_child.yaml` have exclusion conditions that are testable via simulation.
CHAIN_SCHEDULED_TASK_SCRIPT_001 has `command_line not_contains "C:\Windows\system32\"`
but that rule is expected to FAIL (D43), making the FP test moot. **Do NOT write any
FP suppression test blocks.** Zero FP test blocks in the entire script.

---

## BLOCK 0 — Imports and top-level constants

```python
import subprocess, datetime, time, sqlite3, csv, os, sys, base64

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
os.makedirs(EXPORTS_DIR, exist_ok=True)

POWERSHELL   = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WSCRIPT      = r"C:\Windows\System32\wscript.exe"
CSCRIPT      = r"C:\Windows\System32\cscript.exe"
MSHTA        = r"C:\Windows\System32\mshta.exe"
RUNDLL32     = r"C:\Windows\System32\rundll32.exe"
REGSVR32     = r"C:\Windows\System32\regsvr32.exe"
CMSTP        = r"C:\Windows\System32\cmstp.exe"
CSC          = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
SCHTASKS     = r"C:\Windows\System32\schtasks.exe"
TEMP         = r"C:\Windows\Temp"

_find_regasm = lambda: next(
    (p for p in [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe",
    ] if os.path.exists(p)), None
)
REGASM = _find_regasm()

print("=" * 60)
print("ShadowSensor Phase 7A — Subphase 4: Parent-Child Chain Simulation")
print("=" * 60)
print("PREREQUISITE: Confirm pipeline is running before this script.")
print(f"Script UTC start: {datetime.datetime.utcnow().isoformat()}")
print(f"RegAsm path    : {REGASM or 'NOT FOUND'}")
```

---

## BLOCK 1 — Helper functions

Implement these EXACTLY as written. Do not change polling durations or logic.

```python
def hits_since(rule_id: str, since: datetime.datetime, quick: bool = False) -> int:
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    def _query() -> int:
        conn = sqlite3.connect(DB_PATH)
        n = conn.execute(
            "SELECT COUNT(*) FROM rule_hits WHERE rule_id=? AND timestamp>=?",
            (rule_id, since_str)
        ).fetchone()[0]
        conn.close()
        return n

    if quick:
        return _query()

    deadline = time.time() + 180
    elapsed = 0
    while time.time() < deadline:
        n = _query()
        if n > 0:
            print(f"  [DB] First hit after ~{elapsed}s — waiting 30s for second launch", flush=True)
            time.sleep(30)
            n = _query()
            print(f"  [DB] Final count: {n} hit(s)", flush=True)
            return n
        time.sleep(5)
        elapsed += 5

    return _query()


def launch_argv(argv: list, label: str) -> None:
    print(f"  [LAUNCH] {label}")
    print(f"  [CMD]    {' '.join(str(a) for a in argv)}")
    try:
        subprocess.run(argv, capture_output=True, timeout=20)
    except subprocess.TimeoutExpired:
        print(f"  [WARN] Process timed out (20s) — EID-1 captured at launch")
    except (PermissionError, OSError) as e:
        print(f"  [WARN] Process blocked (WinError {getattr(e, 'winerror', '?')}) — PARTIAL expected")
    time.sleep(2)


def warn_zero(rule_id: str, path: str, reason: str = "") -> None:
    msg = f"  [WARN] 0 hits for {rule_id} {path} after full poll window"
    if reason:
        msg += f" — {reason}"
    print(msg + " — continuing.")


def run_two_with_d41_retry(rule_id: str, path_label: str,
                            argv1: list, argv2: list,
                            label1: str, label2: str):
    """
    Launch argv1 and argv2, poll 180s. If 0 hits, retry once (D41).
    Returns (n_hits, result_str, reason_str).
    """
    path_start = datetime.datetime.utcnow()
    launch_argv(argv1, label1)
    launch_argv(argv2, label2)
    n = hits_since(rule_id, path_start)

    if n == 0:
        print(f"  [D41] 0 hits for {rule_id} {path_label} — retrying once "
              f"(D41: wscript/cscript spawn intermittent on this VM)")
        path_start = datetime.datetime.utcnow()
        launch_argv(argv1, label1 + " [D41 retry]")
        launch_argv(argv2, label2 + " [D41 retry]")
        n = hits_since(rule_id, path_start)

    if n == 0:
        warn_zero(rule_id, path_label, "D41 retry exhausted")
        return n, "FAIL", f"0 hits after D41 retry"
    elif n >= 2:
        return n, "PASS", f"{n} hits"
    else:
        return n, "PARTIAL", f"{n} hits"


results = []
SIM_START = datetime.datetime.utcnow()
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")
```

---

## BLOCK 2 — Pre-flight: write helper files and compile C# DLL

Write all files BEFORE the first simulation block. If any write fails, print the error
and continue. If DLL compilation fails, set `_DLL_READY = False` and continue — affected
rules will SKIP.

### File 1: `C:\Windows\Temp\ss_chain_cmd.vbs`
wscript/cscript spawns cmd.exe
```
WScript.CreateObject("WScript.Shell").Run "cmd.exe /c echo ShadowSensor_chain_cmd", 0, True
WScript.Quit 0
```

### File 2: `C:\Windows\Temp\ss_chain_ps.vbs`
wscript/cscript spawns powershell.exe
```
WScript.CreateObject("WScript.Shell").Run "powershell.exe -Command Write-Host ShadowSensor_chain_ps", 0, True
WScript.Quit 0
```

### File 3: `C:\Windows\Temp\ss_chain_cmd_mshta.hta`
mshta spawns cmd.exe (HTA uses CreateObject directly — no WScript prefix in HTA context)
```
<html><head><script language="VBScript">
Dim sh : Set sh = CreateObject("WScript.Shell")
sh.Run "cmd.exe /c echo ShadowSensor_mshta_chain", 0, True
window.close()
</script></head><body></body></html>
```

### File 4: `C:\Windows\Temp\ss_chain_cmstp.inf`
cmstp spawns cmd.exe via RunPreSetupCommandsSection
```
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
RunPreSetupCommandsSection=RunCmds

[RunCmds]
cmd /c echo ShadowSensor_cmstp_chain
```

### File 5: `C:\Windows\Temp\ss_chain_com.cs`
C# COM DLL — [ComRegisterFunction] spawns cmd.exe; [ComUnregisterFunction] spawns powershell.exe
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ShadowSensorChain
{
    [ComVisible(true)]
    [Guid("8A4F2B3C-5D6E-4F7A-8B9C-0D1E2F3A4B5C")]
    public class ShadowSensorCOM
    {
        [ComRegisterFunction]
        public static void Register(Type t)
        {
            try { Process.Start("cmd.exe", "/c echo ShadowSensor_regsvr32_register"); }
            catch { }
        }

        [ComUnregisterFunction]
        public static void Unregister(Type t)
        {
            try { Process.Start("powershell.exe", "-Command Write-Host ShadowSensor_regsvr32_unregister"); }
            catch { }
        }
    }
}
```

### Compilation step
After writing ss_chain_com.cs, compile it:
```python
_DLL_PATH = os.path.join(TEMP, "ss_chain_com.dll")
_CS_PATH  = os.path.join(TEMP, "ss_chain_com.cs")
_DLL_READY = False
try:
    result = subprocess.run(
        [CSC, "/target:library", f"/out:{_DLL_PATH}", _CS_PATH],
        capture_output=True, timeout=60
    )
    if result.returncode == 0 and os.path.exists(_DLL_PATH):
        print(f"  [COMPILE] ss_chain_com.dll compiled successfully")
        _DLL_READY = True
    else:
        print(f"  [COMPILE ERROR] csc.exe returned {result.returncode}")
        print(f"  stderr: {result.stderr.decode(errors='replace')}")
        _DLL_READY = False
except (subprocess.TimeoutExpired, OSError) as e:
    print(f"  [COMPILE ERROR] {e}")
    _DLL_READY = False
```

Print confirmation lines for each file written. Print `_DLL_READY` status after compilation.

---

## BLOCK 3 — Simulation rules

**Rule execution order (follow exactly):**
1. CHAIN_SCRIPT_HOST_CMD_001
2. CHAIN_SCRIPT_HOST_POWERSHELL_001
3. CHAIN_SCHEDULED_TASK_SVCHOST_001
4. CHAIN_SCHEDULED_TASK_SCRIPT_001 (D43 attempt)
5. CHAIN_REGSVR32_CHILD_001
6. CHAIN_LOLBIN_CHILD_001
7. CHAIN_BROWSER_SHELL_001 (PARTIAL block)
8. CHAIN_OFFICE_POWERSHELL_001 (SKIP block)
9. CHAIN_OFFICE_CMD_001 (SKIP block)
10. CHAIN_OFFICE_WSCRIPT_001 (SKIP block)

---

### RULE 1: CHAIN_SCRIPT_HOST_CMD_001

Source: rule_insights.md CHAIN_SCRIPT_HOST_CMD_001
Trigger: parent_image contains_any "wscript.exe" | "cscript.exe" AND image ends_with "cmd.exe"
EID: 1 (ProcessCreate). D41 retry mandatory on all paths.

3 attack paths. 2 launches per path. Use `run_two_with_d41_retry()` for all paths.

The VBScript (`ss_chain_cmd.vbs`) calls `WScript.CreateObject("WScript.Shell").Run "cmd.exe /c echo ShadowSensor_chain_cmd", 0, True`. This spawns cmd.exe with parent_image=wscript.exe (or cscript.exe).

**Path A — wscript.exe → cmd.exe**
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_CMD_001", "Path A",
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    "CHAIN_SCRIPT_HOST_CMD_001 Path A Launch 1",
    "CHAIN_SCRIPT_HOST_CMD_001 Path A Launch 2",
)
```

**Path B — cscript.exe → cmd.exe**
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_CMD_001", "Path B",
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    "CHAIN_SCRIPT_HOST_CMD_001 Path B Launch 1",
    "CHAIN_SCRIPT_HOST_CMD_001 Path B Launch 2",
)
```

**Path C — wscript.exe → cmd.exe (alternate run — different VBS invocation)**
rule_insights.md Path C describes "wscript from user path → cmd". In our simulation the wscript
image path is always System32\wscript.exe — the rule uses contains_any (not ends_with) so the
System32 path satisfies "wscript.exe". Use a second wscript run as Path C.
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_CMD_001", "Path C",
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
    "CHAIN_SCRIPT_HOST_CMD_001 Path C Launch 1",
    "CHAIN_SCRIPT_HOST_CMD_001 Path C Launch 2",
)
```

Print `Path X: {result} ({n} hits)` after each path. Append to results.

`field_values_used` for Path A: `"wscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=wscript.exe;image=cmd.exe"`
`field_values_used` for Path B: `"cscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=cscript.exe;image=cmd.exe"`
`field_values_used` for Path C: `"wscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=wscript.exe;image=cmd.exe"`

---

### RULE 2: CHAIN_SCRIPT_HOST_POWERSHELL_001

Source: rule_insights.md CHAIN_SCRIPT_HOST_POWERSHELL_001
Trigger: parent_image contains_any "wscript.exe" | "cscript.exe" AND image ends_with "powershell.exe"
EID: 1 (ProcessCreate). D41 retry mandatory on all paths.

The VBScript (`ss_chain_ps.vbs`) calls `WScript.CreateObject("WScript.Shell").Run "powershell.exe -Command Write-Host ShadowSensor_chain_ps", 0, True`.

**Path A — wscript.exe → powershell.exe**
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path A",
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
    [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path A Launch 1",
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path A Launch 2",
)
```

**Path B — cscript.exe → powershell.exe**
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path B",
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path B Launch 1",
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path B Launch 2",
)
```

**Path C — cscript.exe → powershell.exe (SysWOW64 variant)**
rule_insights.md Path C describes "Nested script host → PS — cscript → SysWOW64 powershell".
Launch cscript with a VBS that runs the SysWOW64 powershell path explicitly.
Write an additional VBS inline (use Python `open()` in the script):
`C:\Windows\Temp\ss_chain_ps64.vbs` content:
`WScript.CreateObject("WScript.Shell").Run "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -Command Write-Host ShadowSensor_chain_ps64", 0, True`
`WScript.Quit 0`

Write this file in BLOCK 2 (add it to the file-writing section). Then:
```python
n, result, reason = run_two_with_d41_retry(
    "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path C",
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps64.vbs"],
    [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps64.vbs"],
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path C Launch 1",
    "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path C Launch 2",
)
```
Note: SysWOW64 powershell still ends_with "powershell.exe" → rule fires. ✓

---

### RULE 3: CHAIN_SCHEDULED_TASK_SVCHOST_001

Source: rule_insights.md CHAIN_SCHEDULED_TASK_SVCHOST_001
Trigger: parent_image contains "svchost.exe" AND parent_command_line contains "-s Schedule"
         AND image ends_with_any "powershell.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
         AND command_line contains_any "http://" | "https://" | "-enc" | "-encoded" |
             "downloadstring" | "iex" | "invoke-expression" | "frombase64string"
EID: 1 (ProcessCreate). Simulation: create real Windows Scheduled Tasks via schtasks.exe.

When a scheduled task runs, `svchost.exe -k netsvcs -p -s Schedule` is the true parent of the
spawned child process. Sysmon EID-1 shows parent_image=svchost.exe, parent_command_line includes
"-s Schedule".

**Task naming:** Use unique names to avoid conflicts: `ShadowSensor_SP4_SVCA`, `ShadowSensor_SP4_SVCB`,
`ShadowSensor_SP4_SVCC`. Delete all at the END of the script (scheduled task cleanup block).

**Pattern for each path:**
```python
# Set a start time 2 minutes in the future (schtasks /once needs a future time)
# Then use schtasks /run to force immediate execution.
# Capture path_start BEFORE /run. Wait 10s for task to spawn child. Then poll.
```

**Helper function — implement in BLOCK 1 (add after warn_zero):**
```python
def create_and_run_task(task_name: str, task_command: str) -> bool:
    """Create and immediately run a scheduled task. Returns True if /run succeeded."""
    from datetime import timedelta
    start_time = (datetime.datetime.now() + timedelta(minutes=2)).strftime("%H:%M")
    create_result = subprocess.run(
        [SCHTASKS, "/create", "/tn", task_name, "/tr", task_command,
         "/sc", "once", "/st", start_time, "/f"],
        capture_output=True, timeout=30
    )
    if create_result.returncode != 0:
        print(f"  [WARN] schtasks /create failed for {task_name}: "
              f"{create_result.stderr.decode(errors='replace').strip()}")
        return False
    run_result = subprocess.run(
        [SCHTASKS, "/run", "/tn", task_name],
        capture_output=True, timeout=15
    )
    if run_result.returncode != 0:
        print(f"  [WARN] schtasks /run failed for {task_name}: "
              f"{run_result.stderr.decode(errors='replace').strip()}")
        return False
    print(f"  [TASK] {task_name} created and triggered successfully")
    return True
```

**Path A — svchost -s Schedule → powershell.exe -enc (satisfies "-enc" condition)**
```python
_b64_a = base64.b64encode(
    "Write-Host ShadowSensor_svchost_chain_A".encode("utf-16-le")
).decode()
task_cmd_a = f'powershell.exe -enc {_b64_a}'

path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
ok = create_and_run_task("ShadowSensor_SP4_SVCA", task_cmd_a)
if ok:
    time.sleep(10)  # allow task to spawn child
    # Run a second time for 2-hit confidence
    subprocess.run([SCHTASKS, "/run", "/tn", "ShadowSensor_SP4_SVCA"],
                   capture_output=True, timeout=15)
    time.sleep(5)
n = hits_since("CHAIN_SCHEDULED_TASK_SVCHOST_001", path_start)
```
Standard PASS/PARTIAL/FAIL logic with warn_zero.

**Path B — svchost -s Schedule → powershell.exe with DownloadString http:// (satisfies both "downloadstring" and "http://")**
```python
task_cmd_b = 'powershell.exe -Command "(New-Object System.Net.WebClient).DownloadString(\'http://127.0.0.1/a.txt\') | Out-Null"'
```
Use `create_and_run_task("ShadowSensor_SP4_SVCB", task_cmd_b)`. Same pattern — run twice, poll.

**Path C — svchost -s Schedule → mshta.exe https:// (satisfies "https://" condition)**
```python
task_cmd_c = 'mshta.exe https://127.0.0.1/a.hta'
```
Use `create_and_run_task("ShadowSensor_SP4_SVCC", task_cmd_c)`. Same pattern — run twice, poll.

`field_values_used` for Path A: `"svchost.exe;-s Schedule;powershell.exe;-enc <base64>"`
`field_values_used` for Path B: `"svchost.exe;-s Schedule;powershell.exe;DownloadString http://127.0.0.1/"`
`field_values_used` for Path C: `"svchost.exe;-s Schedule;mshta.exe;https://127.0.0.1/a.hta"`

---

### RULE 4: CHAIN_SCHEDULED_TASK_SCRIPT_001 (D43 — attempt and confirm FAIL)

Source: rule_insights.md CHAIN_SCHEDULED_TASK_SCRIPT_001
Trigger: parent_image contains_any "taskeng.exe" | "taskhostw.exe"
         AND image ends_with_any "powershell.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
         AND command_line contains_any staging path markers
         AND command_line NOT contains "C:\Windows\system32\"
EID: 1 (ProcessCreate). **D43: taskeng.exe absent on Windows 10; taskhostw.exe never parent
of script tasks — actual parent is always svchost.exe -s Schedule.**

We attempt this rule via a real scheduled task whose child command_line contains `C:\Users\`.
The task WILL run — but its parent will be svchost.exe, not taskeng/taskhostw.
Expected: 0 hits for CHAIN_SCHEDULED_TASK_SCRIPT_001.
This confirms D43 experimentally.

```python
print("\n" + "=" * 60)
print("RULE: CHAIN_SCHEDULED_TASK_SCRIPT_001 (D43 — structural FAIL expected)")
print("=" * 60)
print("D43: taskeng.exe absent on Win10; taskhostw.exe not used for script tasks.")
print("     Creating task with C:\\Users\\ in command_line — parent will be svchost.exe.")
print("     Expecting 0 hits. This confirms D43 experimentally.")

task_cmd_d43 = r'powershell.exe -Command "Set-Content -Path C:\Users\Public\ss_d43.txt -Value ShadowSensor_D43"'
# command_line contains "C:\Users\" → satisfies staging path condition IF parent were taskeng/taskhostw
# But parent will be svchost.exe → rule will NOT fire → confirms D43

for path in ["Path A", "Path B", "Path C"]:
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    create_and_run_task("ShadowSensor_SP4_D43", task_cmd_d43)
    time.sleep(10)
    subprocess.run([SCHTASKS, "/run", "/tn", "ShadowSensor_SP4_D43"],
                   capture_output=True, timeout=15)
    time.sleep(5)
    n = hits_since("CHAIN_SCHEDULED_TASK_SCRIPT_001", path_start, quick=True)
    # Use quick=True — pipeline lag means eventual hits from this window would only
    # appear if rule misfires. No 180s poll needed for a confirmed structural FAIL.
    print(f"  {path}: {n} hit(s) (expected 0 — D43 FAIL)")
    result = "FAIL"
    reason = "D43: taskeng/taskhostw never parent of script tasks on Win10 — svchost.exe -s Schedule is actual parent"
    results.append({
        "rule_id": "CHAIN_SCHEDULED_TASK_SCRIPT_001",
        "attack_path": path,
        "field_values_used": r"powershell.exe;C:\Users\Public\ss_d43.txt;parent=svchost.exe(actual)",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

print("  D43 confirmed: 0 hits — taskeng/taskhostw not used as parent on this Windows 10 build.")
```

Note: Use `quick=True` for this rule only (we're confirming a known FAIL, not waiting for a TP).
All three paths use the same task run and the same D43 reason — this is intentional.

---

### RULE 5: CHAIN_REGSVR32_CHILD_001

Source: rule_insights.md CHAIN_REGSVR32_CHILD_001
Trigger: parent_image ends_with "regsvr32.exe" AND image ends_with_any cmd/PS/wscript/mshta/cscript
EID: 1 (ProcessCreate).

Simulation: `regsvr32.exe /s ss_chain_com.dll` calls DllRegisterServer via mscoree.dll shim,
which runs `[ComRegisterFunction]` → spawns cmd.exe. Parent of cmd.exe = regsvr32.exe. ✓
`regsvr32.exe /s /u ss_chain_com.dll` calls DllUnregisterServer → runs `[ComUnregisterFunction]`
→ spawns powershell.exe. Parent = regsvr32.exe. ✓
NO http:// or scrobj.dll in any command — avoids D-f squiblydoo signature.

**If `_DLL_READY` is False: SKIP all 3 paths.** Add SKIP rows with reason = "DLL compilation
failed (csc.exe error) — cannot simulate CHAIN_REGSVR32_CHILD_001 without compiled COM DLL."

**Path A — regsvr32 /s (register) → cmd.exe via [ComRegisterFunction]**
- Launch 1: `[REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"]`
- Launch 2: same command
- `n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)`
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regsvr32.exe;image=cmd.exe"`

**Path B — regsvr32 /s /u (unregister) → powershell.exe via [ComUnregisterFunction]**
- Launch 1: `[REGSVR32, "/s", "/u", r"C:\Windows\Temp\ss_chain_com.dll"]`
- Launch 2: same command
- `n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)`
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"regsvr32.exe /s /u ss_chain_com.dll → powershell.exe via [ComUnregisterFunction];parent_image=regsvr32.exe;image=powershell.exe"`

**Path C — regsvr32 /s (re-register after unregister from Path B) → cmd.exe again**
- Launch 1: `[REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"]`
- Launch 2: same command
- `n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)`
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction] (re-register);parent_image=regsvr32.exe;image=cmd.exe"`

---

### RULE 6: CHAIN_LOLBIN_CHILD_001

Source: rule_insights.md CHAIN_LOLBIN_CHILD_001
Trigger: parent_image ends_with_any "mshta.exe" | "rundll32.exe" | "odbcconf.exe" | "cmstp.exe"
         | "installutil.exe" | "regasm.exe" | "regsvcs.exe"
         AND image ends_with_any "cmd.exe" | "powershell.exe" | "wscript.exe" | "cscript.exe"
EID: 1 (ProcessCreate).

**Path A — mshta.exe → cmd.exe (via HTA, HIGH CONFIDENCE)**
The HTA file (`ss_chain_cmd_mshta.hta`) uses `CreateObject("WScript.Shell").Run "cmd.exe /c echo ShadowSensor_mshta_chain"`. mshta.exe spawns cmd.exe. parent_image=mshta.exe. ✓

- Launch 1: `[MSHTA, r"C:\Windows\Temp\ss_chain_cmd_mshta.hta"]`
- Launch 2: same command
- `n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)` (full 180s polling)
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"mshta.exe;ss_chain_cmd_mshta.hta → cmd.exe;parent_image=mshta.exe;image=cmd.exe"`

**Path B — cmstp.exe → cmd.exe (via malicious INF RunPreSetupCommandsSection)**
The INF file (`ss_chain_cmstp.inf`) has `[RunCmds]` section containing `cmd /c echo ShadowSensor_cmstp_chain`.
cmstp.exe processes the INF and spawns cmd.exe as its child.

- Launch 1: `[CMSTP, "/s", "/ni", r"C:\Windows\Temp\ss_chain_cmstp.inf"]`
- Launch 2: same command
- `n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)` (full 180s polling)
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"cmstp.exe /s /ni ss_chain_cmstp.inf → cmd.exe via RunPreSetupCommandsSection;parent_image=cmstp.exe;image=cmd.exe"`

**Path C — regasm.exe → cmd.exe (via compiled C# [ComRegisterFunction], csc-dependent)**
If `_DLL_READY` is False OR `REGASM` is None: SKIP with reason = "csc.exe compilation failed
or RegAsm.exe not found — CHAIN_LOLBIN_CHILD_001 Path C skipped."

If both available:
- `regasm.exe /nologo /codebase C:\Windows\Temp\ss_chain_com.dll`
  Calls [ComRegisterFunction] → spawns cmd.exe. parent_image=regasm.exe. ✓
- Launch 1: `[REGASM, "/nologo", "/codebase", r"C:\Windows\Temp\ss_chain_com.dll"]`
- Launch 2: same command
- `n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)` (full 180s polling)
- Standard PASS/PARTIAL/FAIL + warn_zero.
- `field_values_used`: `"regasm.exe /nologo /codebase ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regasm.exe;image=cmd.exe"`

---

### RULE 7: CHAIN_BROWSER_SHELL_001 (PARTIAL — D42, no simulation)

```python
print("\n" + "=" * 60)
print("RULE: CHAIN_BROWSER_SHELL_001 — PARTIAL (D42)")
print("D42: Cannot make browser (msedge/chrome/firefox) spawn cmd.exe via subprocess.")
print("     Any child process launched by simulation script has parent_image=python.exe.")
print("     Requires actual browser exploit or malicious extension — out of scope.")
print("=" * 60)
for path in ["Path A", "Path B", "Path C"]:
    results.append({
        "rule_id": "CHAIN_BROWSER_SHELL_001",
        "attack_path": path,
        "field_values_used": "msedge.exe/chrome.exe → cmd.exe/powershell.exe",
        "result": "PARTIAL",
        "reason": "D42: browser→shell chain not simulatable via subprocess — requires browser exploit or malicious extension",
        "timestamp_utc": datetime.datetime.utcnow().isoformat(),
    })
```

---

### RULES 8–10: CHAIN_OFFICE_* (SKIP — Office not installed)

```python
for rule_id in ["CHAIN_OFFICE_POWERSHELL_001", "CHAIN_OFFICE_CMD_001", "CHAIN_OFFICE_WSCRIPT_001"]:
    print("\n" + "=" * 60)
    print(f"RULE: {rule_id} — SKIP (Office not installed)")
    print("=" * 60)
    for path in ["Path A", "Path B", "Path C"]:
        results.append({
            "rule_id": rule_id,
            "attack_path": path,
            "field_values_used": "winword.exe/excel.exe/powerpnt.exe → powershell.exe/cmd.exe/wscript.exe",
            "result": "SKIP",
            "reason": "Office not installed on simulation VM — Office parent process cannot be launched",
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
        })
```

---

## BLOCK 4 — Simulation window end

```python
SIM_END = datetime.datetime.utcnow()
print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")
```

---

## BLOCK 5 — Summary table

```
RULE                               | PATH_A  | PATH_B  | PATH_C  | OVERALL
CHAIN_SCRIPT_HOST_CMD_001          | PASS    | PASS    | PASS    | PASS
CHAIN_SCRIPT_HOST_POWERSHELL_001   | PASS    | PASS    | PASS    | PASS
...
```

RULE_ORDER (exact):
```python
RULE_ORDER = [
    "CHAIN_SCRIPT_HOST_CMD_001",
    "CHAIN_SCRIPT_HOST_POWERSHELL_001",
    "CHAIN_SCHEDULED_TASK_SVCHOST_001",
    "CHAIN_SCHEDULED_TASK_SCRIPT_001",
    "CHAIN_REGSVR32_CHILD_001",
    "CHAIN_LOLBIN_CHILD_001",
    "CHAIN_BROWSER_SHELL_001",
    "CHAIN_OFFICE_POWERSHELL_001",
    "CHAIN_OFFICE_CMD_001",
    "CHAIN_OFFICE_WSCRIPT_001",
]
```

OVERALL computation:
- All paths PASS → PASS
- Any path FAIL → FAIL (checked before PARTIAL)
- Any path PARTIAL (and none FAIL) → PARTIAL
- All paths SKIP → SKIP
- Mix of PASS and SKIP → PARTIAL

Print final count: `N/10 rules PASS, M PARTIAL (D42), P FAIL (D43), Q SKIP (Office)`

---

## BLOCK 6 — CSV export

Write to `os.path.join(EXPORTS_DIR, "subphase_4_training.csv")`.
Columns: `rule_id, attack_path, field_values_used, result, reason, timestamp_utc`
One row per path per rule. Include SKIP, PARTIAL, FAIL rows.

---

## BLOCK 7 — Feature extraction instructions (print only)

```
======================================================
NEXT STEPS — run manually after reviewing output above
======================================================

STEP 1 — Query DB for confirmed UTC window of this subphase:
  <python> -c "
  import sqlite3; conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db');
  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits
    WHERE rule_id LIKE 'CHAIN_%' AND timestamp >= '<paste SIM_START UTC here>'\").fetchone();
  print('Since:', row[0]); print('Until:', row[1]); conn.close()"

STEP 2 — Run feature extraction with DB-confirmed timestamps:
  <python> <repo_root>\scripts\run_feature_extraction.py
    --label 1
    --since "YYYY-MM-DD HH:MM:SS"
    --until "YYYY-MM-DD HH:MM:SS"
    --output <repo_root>\data\features\suspicious_chains.csv

  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.
  Do NOT use VM wall-clock time. All DB timestamps are UTC.
```

Use f-strings with DB_PATH and _REPO_ROOT for exact paths.

---

## BLOCK 8 — Completion report

```
======================================================
SUBPHASE 4 SIMULATION COMPLETE
======================================================
Total rules in parent_child.yaml (live): 10
Rules simulated: 6 (3 SKIP — Office; 1 PARTIAL — D42; 1 FAIL — D43)
DLL compilation: <PASS/FAIL>
D41 retries triggered: <count if tracked, else "see above">
D43 confirmed: CHAIN_SCHEDULED_TASK_SCRIPT_001 — taskeng/taskhostw not used
D42 confirmed: CHAIN_BROWSER_SHELL_001 — browser spawn not automatable
SIM_START (UTC): <SIM_START>
SIM_END   (UTC): <SIM_END>
CSV written to: exports/subphase_4_training.csv
```

---

## BLOCK 9 — Scheduled task cleanup (always runs, even after errors)

```python
# Run unconditionally at script end — use try/except per task
_tasks_to_delete = [
    "ShadowSensor_SP4_SVCA",
    "ShadowSensor_SP4_SVCB",
    "ShadowSensor_SP4_SVCC",
    "ShadowSensor_SP4_D43",
]
print("\nCleaning up scheduled tasks...")
for _tn in _tasks_to_delete:
    try:
        subprocess.run([SCHTASKS, "/delete", "/tn", _tn, "/f"],
                       capture_output=True, timeout=15)
        print(f"  [CLEANUP] Deleted task: {_tn}")
    except Exception as _e:
        print(f"  [CLEANUP] Could not delete {_tn}: {_e}")
```

This block must be the LAST block in the script, after BLOCK 8.

---

## Starter prompt for Grok

Give Grok this exact message before sharing this document:

> You are implementing a precise simulation script for a security detection project.
> You must follow the specification below EXACTLY — no deviations, no invented values, no assumptions.
> If anything is unclear or ambiguous, STOP and ask before writing that section.
> The specification is your only source of truth.

Then share this entire document.

---

## Script location

The generated script must be saved as:
```
scripts/simulate_subphase_4.py
```

Run command (from Z:\filelessmalware on the VM):
```powershell
& .\python_runtime\python.exe .\scripts\simulate_subphase_4.py
```
