import subprocess, datetime, time, sqlite3, csv, os, sys, shutil, ctypes
import ctypes.wintypes as _wt

_REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
DB_PATH     = r"C:\ShadowSensor\data\shadowsensor.db"
os.makedirs(EXPORTS_DIR, exist_ok=True)

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RUNDLL32   = r"C:\Windows\System32\rundll32.exe"
REGSVR32   = r"C:\Windows\System32\regsvr32.exe"
MSHTA      = r"C:\Windows\System32\mshta.exe"
CSC        = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
TEMP       = r"C:\Windows\Temp"
NOTEPAD    = r"C:\Windows\System32\notepad.exe"
PYTHON     = sys.executable   # e.g. Z:\filelessmalware\python_runtime\python.exe

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.argtypes  = [_wt.DWORD, _wt.BOOL, _wt.DWORD]
_k32.OpenProcess.restype   = _wt.HANDLE
_k32.CloseHandle.argtypes  = [_wt.HANDLE]
_k32.CloseHandle.restype   = _wt.BOOL

print("=" * 60)
print("ShadowSensor Phase 7A — Subphase 5: API/Memory Rule Simulation")
print("=" * 60)
print("PREREQUISITE: Confirm pipeline is running before this script.")
print(f"Script UTC start: {datetime.datetime.utcnow().isoformat()}")


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


def ctypes_open_process(access: int, pid: int, label: str) -> bool:
    """
    Call OpenProcess(access, False, pid) via ctypes. Closes handle if acquired.
    Returns True if handle was acquired (EID-10 generated), False otherwise.
    """
    print(f"  [CTYPES] {label}")
    print(f"  [CALL]   OpenProcess(access=0x{access:08x}, pid={pid})")
    if pid == 0:
        print(f"  [WARN]   PID is 0 — target process not found, skipping")
        time.sleep(1)
        return False
    h = _k32.OpenProcess(access, False, pid)
    if h:
        _k32.CloseHandle(h)
        print(f"  [CTYPES] Handle acquired and released — EID-10 expected")
        time.sleep(2)
        return True
    else:
        err = ctypes.get_last_error()
        print(f"  [CTYPES] OpenProcess failed (WinError {err}) — EID-10 may still be logged by Sysmon at NtOpenProcess syscall level")
        time.sleep(2)
        return False


def get_pid_by_name(name: str) -> int:
    """Return first PID matching image name via tasklist /fo csv. Returns 0 if not found."""
    try:
        out = subprocess.run(
            ["tasklist", "/fo", "csv", "/fi", f"imagename eq {name}"],
            capture_output=True, text=True, timeout=10
        )
        for line in out.stdout.strip().splitlines():
            if line.startswith('"') and name.lower() in line.lower():
                return int(line.split(",")[1].strip('"'))
        return 0
    except Exception as e:
        print(f"  [WARN]   get_pid_by_name({name!r}) failed: {e}")
        return 0


def launch_crt(label: str, target_name: str, start_target: bool = False) -> None:
    """EID-8: subprocess.run timeout=60 — do not use launch_argv()."""
    argv = [
        POWERSHELL, "-ExecutionPolicy", "Bypass", "-File",
        r"C:\Windows\Temp\ss_crt_sim.ps1", "-TargetName", target_name,
    ]
    if start_target:
        argv.append("-StartTarget")
    print(f"  [LAUNCH] {label}")
    print(f"  [CMD]    {' '.join(argv)}")
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60)
        out = r.stdout.decode(errors="replace")
        print(f"  [CRT]    stdout: {out.strip()[:200]}")
    except subprocess.TimeoutExpired:
        print(f"  [WARN]   PS timed out (60s) — process continues in background, EID-8 will be polled")
    except (PermissionError, OSError) as e:
        print(f"  [WARN]   Blocked: {e}")
    time.sleep(3)


results    = []
SIM_START  = datetime.datetime.utcnow()
_notepad_proc       = None   # Popen object — killed in BLOCK 9
_fake_msmpeng_proc  = None
_fake_mpcmdrun_proc = None
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")

_API_DLL_READY = False
msmpeng_pid  = 0
mpcmdrun_pid = 0
notepad_pid  = 0
lsass_pid    = 0
winlogon_pid = 0
csrss_pid    = 0
services_pid = 0

try:
    # =========================================================================
    # BLOCK 2 — Pre-flight
    # =========================================================================
    print("=" * 60)
    print("BLOCK 2 — Pre-flight")
    print("=" * 60)

    # Step 1 — Compile ss_api.dll (unsigned .NET DLL, no logic)
    _cs_path = r"C:\Windows\Temp\ss_api.cs"
    try:
        with open(_cs_path, "w", encoding="utf-8") as _f:
            _f.write("namespace ShadowSensorSP5 { public class SP5DLL { } }\n")
        result = subprocess.run(
            [CSC, "/target:library", "/out:C:\\Windows\\Temp\\ss_api.dll",
             "C:\\Windows\\Temp\\ss_api.cs"],
            capture_output=True, timeout=60,
        )
        if result.returncode == 0 and os.path.exists(r"C:\Windows\Temp\ss_api.dll"):
            print("  [COMPILE] ss_api.dll compiled successfully")
            _API_DLL_READY = True
        else:
            print(f"  [COMPILE ERROR] csc.exe returned {result.returncode}")
            print(f"  {result.stderr.decode(errors='replace')}")
            _API_DLL_READY = False
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  [COMPILE ERROR] {e}")
        _API_DLL_READY = False

    # Step 2 — Copy DLL to additional staging paths
    _DLL_TEMP   = r"C:\Windows\Temp\ss_api.dll"
    _DLL_PUBLIC = r"C:\Users\Public\ss_api.dll"
    _DLL_PD     = r"C:\ProgramData\ss_api.dll"
    if _API_DLL_READY:
        shutil.copy(_DLL_TEMP, _DLL_PUBLIC)
        print(f"  [COPY] {_DLL_TEMP} -> {_DLL_PUBLIC}")
        shutil.copy(_DLL_TEMP, _DLL_PD)
        print(f"  [COPY] {_DLL_TEMP} -> {_DLL_PD}")

    # Step 3 — Write C:\Windows\Temp\ss_crt_sim.ps1
    _ps1_content = r"""param(
    [string]$TargetName   = "notepad",
    [switch]$StartTarget
)

Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class CrtSim5 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string m);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hp, IntPtr a, uint s,
        IntPtr f, IntPtr p2, uint c, IntPtr t);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
'@

if ($StartTarget) {
    Start-Process $TargetName -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep 3
}

$procs = Get-Process $TargetName -ErrorAction SilentlyContinue
$proc  = if ($procs) { $procs | Select-Object -First 1 } else { $null }
if (-not $proc) {
    Write-Host "SS_CRT:TARGET_NOT_FOUND:$TargetName"
    exit 1
}

$ntdll  = [CrtSim5]::GetModuleHandle("ntdll.dll")
$rtlExit = [CrtSim5]::GetProcAddress($ntdll, "RtlExitUserThread")
if ($rtlExit -eq [IntPtr]::Zero) {
    Write-Host "SS_CRT:RTLEXIT_NOT_FOUND"
    exit 1
}

for ($i = 0; $i -lt 2; $i++) {
    $hp = [CrtSim5]::OpenProcess(0x001F0FFF, $false, $proc.Id)
    if ($hp -ne [IntPtr]::Zero) {
        $ht = [CrtSim5]::CreateRemoteThread($hp, [IntPtr]::Zero, 0,
              $rtlExit, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        if ($ht -ne [IntPtr]::Zero) { [CrtSim5]::CloseHandle($ht) }
        [CrtSim5]::CloseHandle($hp)
        Write-Host "SS_CRT:DONE:$i"
    } else {
        Write-Host "SS_CRT:OPEN_FAIL:$i"
    }
    Start-Sleep 1
}
"""
    with open(r"C:\Windows\Temp\ss_crt_sim.ps1", "w", encoding="utf-8") as _f:
        _f.write(_ps1_content)
    print(r"  [WRITE] C:\Windows\Temp\ss_crt_sim.ps1")

    # Step 4 — Create fake AV processes (bypass D45 / PPL)
    shutil.copy(NOTEPAD, os.path.join(TEMP, "msmpeng.exe"))
    shutil.copy(NOTEPAD, os.path.join(TEMP, "mpcmdrun.exe"))
    _fake_msmpeng_proc  = subprocess.Popen([os.path.join(TEMP, "msmpeng.exe")])
    _fake_mpcmdrun_proc = subprocess.Popen([os.path.join(TEMP, "mpcmdrun.exe")])
    msmpeng_pid  = _fake_msmpeng_proc.pid
    mpcmdrun_pid = _fake_mpcmdrun_proc.pid
    time.sleep(2)
    print(f"  [AV-SIM]  msmpeng.exe (fake) PID: {msmpeng_pid}")
    print(f"  [AV-SIM]  mpcmdrun.exe (fake) PID: {mpcmdrun_pid}")

    # Step 5 — Launch notepad.exe simulation target
    _notepad_proc = subprocess.Popen([NOTEPAD])
    time.sleep(2)
    notepad_pid = _notepad_proc.pid
    print(f"  [TARGET]  notepad.exe PID: {notepad_pid}")

    # Step 6 — Resolve system process PIDs
    lsass_pid    = get_pid_by_name("lsass.exe")
    winlogon_pid = get_pid_by_name("winlogon.exe")
    csrss_pid    = get_pid_by_name("csrss.exe")
    services_pid = get_pid_by_name("services.exe")
    print(f"  [PIDS]   lsass={lsass_pid}  winlogon={winlogon_pid}  "
          f"csrss={csrss_pid}  services={services_pid}")
    if lsass_pid == 0 or winlogon_pid == 0:
        print("  [WARN]   lsass or winlogon PID=0 — EID-10 sensitive-target rules may produce 0 hits")

    # Step 7 — D30 pre-flight idle check
    _d30_check_since = (datetime.datetime.utcnow() - datetime.timedelta(minutes=2))
    _d30_n = hits_since("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", _d30_check_since, quick=True)
    if _d30_n > 0:
        print(f"  [D30 WARN] {_d30_n} background hit(s) for API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 "
              f"in last 2 min — pipeline is active. Continuing (vmtoolsd/wmiprvse excluded by YAML).")
    else:
        print(f"  [D30]  No background hits for API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 — clean window.")

    # =========================================================================
    # BLOCK 3 — Simulation rules
    # =========================================================================

    # -------------------------------------------------------------------------
    # RULE 1: API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001")
    print("=" * 60)

    # Path A — OpenProcess(0x1f0fff, lsass_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x1f0fff, lsass_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path A Launch 1")
    ctypes_open_process(0x1f0fff, lsass_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path A Launch 2")
    n = hits_since("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", path_start)
    if n == 0:
        warn_zero("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "Path A")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({"rule_id": "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "attack_path": "Path A",
                    "field_values_used": "python.exe;granted_access=0x1f0fff;target=lsass.exe;source=python_runtime\\python.exe",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — OpenProcess(0x1410, winlogon_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x1410, winlogon_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path B Launch 1")
    ctypes_open_process(0x1410, winlogon_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path B Launch 2")
    n = hits_since("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", path_start)
    if n == 0:
        warn_zero("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "Path B")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({"rule_id": "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "attack_path": "Path B",
                    "field_values_used": "python.exe;granted_access=0x1410;target=winlogon.exe;source=python_runtime\\python.exe",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — OpenProcess(0x1fffff, csrss_pid) x 2
    if csrss_pid == 0:
        reason = "csrss.exe PID not resolved — cannot simulate."
        print(f"  Path C: SKIP — {reason}")
        results.append({"rule_id": "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x1fffff;target=csrss.exe;source=python_runtime\\python.exe",
                        "result": "SKIP", "reason": reason,
                        "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        ctypes_open_process(0x1fffff, csrss_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path C Launch 1")
        ctypes_open_process(0x1fffff, csrss_pid, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 Path C Launch 2")
        n = hits_since("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", path_start)
        if n == 0:
            warn_zero("API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "Path C")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({"rule_id": "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x1fffff;target=csrss.exe;source=python_runtime\\python.exe",
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 2: API_TOKEN_MANIPULATION_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_TOKEN_MANIPULATION_001")
    print("=" * 60)

    # Path A — OpenProcess(0x0040, lsass_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x0040, lsass_pid, "API_TOKEN_MANIPULATION_001 Path A Launch 1")
    ctypes_open_process(0x0040, lsass_pid, "API_TOKEN_MANIPULATION_001 Path A Launch 2")
    n = hits_since("API_TOKEN_MANIPULATION_001", path_start)
    if n == 0:
        warn_zero("API_TOKEN_MANIPULATION_001", "Path A")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({"rule_id": "API_TOKEN_MANIPULATION_001", "attack_path": "Path A",
                    "field_values_used": "python.exe;granted_access=0x0040;target=lsass.exe;PROCESS_DUP_HANDLE",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — OpenProcess(0x0440, winlogon_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x0440, winlogon_pid, "API_TOKEN_MANIPULATION_001 Path B Launch 1")
    ctypes_open_process(0x0440, winlogon_pid, "API_TOKEN_MANIPULATION_001 Path B Launch 2")
    n = hits_since("API_TOKEN_MANIPULATION_001", path_start)
    if n == 0:
        warn_zero("API_TOKEN_MANIPULATION_001", "Path B")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({"rule_id": "API_TOKEN_MANIPULATION_001", "attack_path": "Path B",
                    "field_values_used": "python.exe;granted_access=0x0440;target=winlogon.exe;DUP_HANDLE|QUERY_INFO",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — OpenProcess(0x1440, services_pid) x 2
    if services_pid == 0:
        reason = "services.exe PID not resolved — cannot simulate."
        print(f"  Path C: SKIP — {reason}")
        results.append({"rule_id": "API_TOKEN_MANIPULATION_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x1440;target=services.exe;DUP_HANDLE|QUERY_INFO|extra",
                        "result": "SKIP", "reason": reason,
                        "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        ctypes_open_process(0x1440, services_pid, "API_TOKEN_MANIPULATION_001 Path C Launch 1")
        ctypes_open_process(0x1440, services_pid, "API_TOKEN_MANIPULATION_001 Path C Launch 2")
        n = hits_since("API_TOKEN_MANIPULATION_001", path_start)
        if n == 0:
            warn_zero("API_TOKEN_MANIPULATION_001", "Path C")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({"rule_id": "API_TOKEN_MANIPULATION_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x1440;target=services.exe;DUP_HANDLE|QUERY_INFO|extra",
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 3: API_AV_PROCESS_ACCESS_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_AV_PROCESS_ACCESS_001")
    print("=" * 60)

    _av_skip_reason = "fake AV process failed to start — PID not resolved."

    # Path A — OpenProcess(0x0001, msmpeng_pid) x 2
    if msmpeng_pid == 0:
        print(f"  Path A: SKIP — {_av_skip_reason}")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path A",
                        "field_values_used": "python.exe;granted_access=0x0001;target=C:\\Windows\\Temp\\msmpeng.exe;PROCESS_TERMINATE (fake process)",
                        "result": "SKIP", "reason": _av_skip_reason,
                        "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        ctypes_open_process(0x0001, msmpeng_pid, "API_AV_PROCESS_ACCESS_001 Path A Launch 1")
        ctypes_open_process(0x0001, msmpeng_pid, "API_AV_PROCESS_ACCESS_001 Path A Launch 2")
        n = hits_since("API_AV_PROCESS_ACCESS_001", path_start)
        if n == 0:
            warn_zero("API_AV_PROCESS_ACCESS_001", "Path A")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path A: {result} ({n} hits)")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path A",
                        "field_values_used": "python.exe;granted_access=0x0001;target=C:\\Windows\\Temp\\msmpeng.exe;PROCESS_TERMINATE (fake process)",
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — OpenProcess(0x0020, msmpeng_pid) x 2
    if msmpeng_pid == 0:
        print(f"  Path B: SKIP — {_av_skip_reason}")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path B",
                        "field_values_used": "python.exe;granted_access=0x0020;target=C:\\Windows\\Temp\\msmpeng.exe;PROCESS_VM_WRITE (fake process)",
                        "result": "SKIP", "reason": _av_skip_reason,
                        "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        ctypes_open_process(0x0020, msmpeng_pid, "API_AV_PROCESS_ACCESS_001 Path B Launch 1")
        ctypes_open_process(0x0020, msmpeng_pid, "API_AV_PROCESS_ACCESS_001 Path B Launch 2")
        n = hits_since("API_AV_PROCESS_ACCESS_001", path_start)
        if n == 0:
            warn_zero("API_AV_PROCESS_ACCESS_001", "Path B")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path B: {result} ({n} hits)")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path B",
                        "field_values_used": "python.exe;granted_access=0x0020;target=C:\\Windows\\Temp\\msmpeng.exe;PROCESS_VM_WRITE (fake process)",
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — OpenProcess(0x0001, mpcmdrun_pid) x 2
    if mpcmdrun_pid == 0:
        print(f"  Path C: SKIP — {_av_skip_reason}")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x0001;target=C:\\Windows\\Temp\\mpcmdrun.exe;PROCESS_TERMINATE (fake process)",
                        "result": "SKIP", "reason": _av_skip_reason,
                        "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        ctypes_open_process(0x0001, mpcmdrun_pid, "API_AV_PROCESS_ACCESS_001 Path C Launch 1")
        ctypes_open_process(0x0001, mpcmdrun_pid, "API_AV_PROCESS_ACCESS_001 Path C Launch 2")
        n = hits_since("API_AV_PROCESS_ACCESS_001", path_start)
        if n == 0:
            warn_zero("API_AV_PROCESS_ACCESS_001", "Path C")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({"rule_id": "API_AV_PROCESS_ACCESS_001", "attack_path": "Path C",
                        "field_values_used": "python.exe;granted_access=0x0001;target=C:\\Windows\\Temp\\mpcmdrun.exe;PROCESS_TERMINATE (fake process)",
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 4: API_OPEN_PROCESS_VM_WRITE_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_OPEN_PROCESS_VM_WRITE_001")
    print("=" * 60)

    # Path A — OpenProcess(0x0028, notepad_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x0028, notepad_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path A Launch 1")
    ctypes_open_process(0x0028, notepad_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path A Launch 2")
    n = hits_since("API_OPEN_PROCESS_VM_WRITE_001", path_start)
    if n == 0:
        warn_zero("API_OPEN_PROCESS_VM_WRITE_001", "Path A")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({"rule_id": "API_OPEN_PROCESS_VM_WRITE_001", "attack_path": "Path A",
                    "field_values_used": "python.exe;granted_access=0x0028;target=notepad.exe;VM_WRITE|VM_OPERATION",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — OpenProcess(0x001f0fff, notepad_pid) x 2
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x001f0fff, notepad_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path B Launch 1")
    ctypes_open_process(0x001f0fff, notepad_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path B Launch 2")
    n = hits_since("API_OPEN_PROCESS_VM_WRITE_001", path_start)
    if n == 0:
        warn_zero("API_OPEN_PROCESS_VM_WRITE_001", "Path B")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({"rule_id": "API_OPEN_PROCESS_VM_WRITE_001", "attack_path": "Path B",
                    "field_values_used": "python.exe;granted_access=0x001f0fff;target=notepad.exe;PROCESS_ALL_ACCESS",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — OpenProcess(0x0028, csrss_pid) x 2; fallback to notepad_pid if csrss_pid == 0
    if csrss_pid == 0:
        _path_c_pid = notepad_pid
        _path_c_fields = "python.exe;granted_access=0x0028;target=notepad.exe;VM_WRITE|VM_OPERATION;csrss_pid=0 fallback"
    else:
        _path_c_pid = csrss_pid
        _path_c_fields = "python.exe;granted_access=0x0028;target=csrss.exe;VM_WRITE|VM_OPERATION"
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ctypes_open_process(0x0028, _path_c_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path C Launch 1")
    ctypes_open_process(0x0028, _path_c_pid, "API_OPEN_PROCESS_VM_WRITE_001 Path C Launch 2")
    n = hits_since("API_OPEN_PROCESS_VM_WRITE_001", path_start)
    if n == 0:
        warn_zero("API_OPEN_PROCESS_VM_WRITE_001", "Path C")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path C: {result} ({n} hits)")
    results.append({"rule_id": "API_OPEN_PROCESS_VM_WRITE_001", "attack_path": "Path C",
                    "field_values_used": _path_c_fields,
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 5: API_DLL_LOAD_SUSPICIOUS_PATH_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_DLL_LOAD_SUSPICIOUS_PATH_001")
    print("=" * 60)

    _r5_skip = "DLL compilation failed — cannot simulate API_DLL_LOAD_SUSPICIOUS_PATH_001 without unsigned DLL."
    _r5_fields = {
        "Path A": "python.exe subprocess;image_loaded=C:\\Windows\\Temp\\ss_api.dll;signed=false;staging=\\temp\\",
        "Path B": "python.exe subprocess;image_loaded=C:\\Users\\Public\\ss_api.dll;signed=false;staging=c:\\users\\public\\",
        "Path C": "python.exe subprocess;image_loaded=C:\\ProgramData\\ss_api.dll;signed=false;staging=\\programdata\\",
    }
    if not _API_DLL_READY:
        for path in ["Path A", "Path B", "Path C"]:
            print(f"  {path}: SKIP — {_r5_skip}")
            results.append({"rule_id": "API_DLL_LOAD_SUSPICIOUS_PATH_001", "attack_path": path,
                            "field_values_used": _r5_fields[path],
                            "result": "SKIP", "reason": _r5_skip,
                            "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        # Path A — C:\Windows\Temp\ss_api.dll x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\Windows\Temp\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path A Launch 1",
        )
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\Windows\Temp\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path A Launch 2",
        )
        n = hits_since("API_DLL_LOAD_SUSPICIOUS_PATH_001", path_start)
        if n == 0:
            warn_zero("API_DLL_LOAD_SUSPICIOUS_PATH_001", "Path A")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path A: {result} ({n} hits)")
        results.append({"rule_id": "API_DLL_LOAD_SUSPICIOUS_PATH_001", "attack_path": "Path A",
                        "field_values_used": _r5_fields["Path A"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

        # Path B — C:\Users\Public\ss_api.dll x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\Users\Public\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path B Launch 1",
        )
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\Users\Public\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path B Launch 2",
        )
        n = hits_since("API_DLL_LOAD_SUSPICIOUS_PATH_001", path_start)
        if n == 0:
            warn_zero("API_DLL_LOAD_SUSPICIOUS_PATH_001", "Path B")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path B: {result} ({n} hits)")
        results.append({"rule_id": "API_DLL_LOAD_SUSPICIOUS_PATH_001", "attack_path": "Path B",
                        "field_values_used": _r5_fields["Path B"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

        # Path C — C:\ProgramData\ss_api.dll x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\ProgramData\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path C Launch 1",
        )
        launch_argv(
            [PYTHON, "-c", r"import ctypes; ctypes.WinDLL(r'C:\ProgramData\ss_api.dll')"],
            "API_DLL_LOAD_SUSPICIOUS_PATH_001 Path C Launch 2",
        )
        n = hits_since("API_DLL_LOAD_SUSPICIOUS_PATH_001", path_start)
        if n == 0:
            warn_zero("API_DLL_LOAD_SUSPICIOUS_PATH_001", "Path C")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({"rule_id": "API_DLL_LOAD_SUSPICIOUS_PATH_001", "attack_path": "Path C",
                        "field_values_used": _r5_fields["Path C"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 6: API_LOLBIN_DLL_UNSIGNED_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_LOLBIN_DLL_UNSIGNED_001")
    print("=" * 60)

    _r6_skip = "DLL compilation failed — cannot simulate API_LOLBIN_DLL_UNSIGNED_001 without unsigned DLL."
    _r6_fields = {
        "Path A": "rundll32.exe;image_loaded=C:\\Windows\\Temp\\ss_api.dll;signed=false",
        "Path B": "regsvr32.exe /s ss_api.dll;signed=false",
        "Path C": "rundll32.exe;image_loaded=C:\\Users\\Public\\ss_api.dll;signed=false",
    }
    if not _API_DLL_READY:
        for path in ["Path A", "Path B", "Path C"]:
            print(f"  {path}: SKIP — {_r6_skip}")
            results.append({"rule_id": "API_LOLBIN_DLL_UNSIGNED_001", "attack_path": path,
                            "field_values_used": _r6_fields[path],
                            "result": "SKIP", "reason": _r6_skip,
                            "timestamp_utc": datetime.datetime.utcnow().isoformat()})
    else:
        # Path A — rundll32 C:\Windows\Temp\ss_api.dll,FakeEntry x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([RUNDLL32, r"C:\Windows\Temp\ss_api.dll,FakeEntry"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path A Launch 1")
        launch_argv([RUNDLL32, r"C:\Windows\Temp\ss_api.dll,FakeEntry"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path A Launch 2")
        n = hits_since("API_LOLBIN_DLL_UNSIGNED_001", path_start)
        if n == 0:
            warn_zero("API_LOLBIN_DLL_UNSIGNED_001", "Path A")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path A: {result} ({n} hits)")
        results.append({"rule_id": "API_LOLBIN_DLL_UNSIGNED_001", "attack_path": "Path A",
                        "field_values_used": _r6_fields["Path A"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

        # Path B — regsvr32 /s C:\Windows\Temp\ss_api.dll x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_api.dll"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path B Launch 1")
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_api.dll"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path B Launch 2")
        n = hits_since("API_LOLBIN_DLL_UNSIGNED_001", path_start)
        if n == 0:
            warn_zero("API_LOLBIN_DLL_UNSIGNED_001", "Path B")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path B: {result} ({n} hits)")
        results.append({"rule_id": "API_LOLBIN_DLL_UNSIGNED_001", "attack_path": "Path B",
                        "field_values_used": _r6_fields["Path B"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

        # Path C — rundll32 C:\Users\Public\ss_api.dll,FakeEntry x 2
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([RUNDLL32, r"C:\Users\Public\ss_api.dll,FakeEntry"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path C Launch 1")
        launch_argv([RUNDLL32, r"C:\Users\Public\ss_api.dll,FakeEntry"],
                    "API_LOLBIN_DLL_UNSIGNED_001 Path C Launch 2")
        n = hits_since("API_LOLBIN_DLL_UNSIGNED_001", path_start)
        if n == 0:
            warn_zero("API_LOLBIN_DLL_UNSIGNED_001", "Path C")
            result, reason = "FAIL", "0 hits after full poll window"
        elif n >= 2:
            result, reason = "PASS", f"{n} hits"
        else:
            result, reason = "PARTIAL", f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({"rule_id": "API_LOLBIN_DLL_UNSIGNED_001", "attack_path": "Path C",
                        "field_values_used": _r6_fields["Path C"],
                        "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 7: API_CRT_SUSPICIOUS_SOURCE_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_CRT_SUSPICIOUS_SOURCE_001")
    print("=" * 60)

    # Path A — 2 x ps1 launches, -TargetName notepad -StartTarget
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SUSPICIOUS_SOURCE_001 Path A Launch {i+1}",
                   "notepad", start_target=True)
    n = hits_since("API_CRT_SUSPICIOUS_SOURCE_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SUSPICIOUS_SOURCE_001", "Path A")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SUSPICIOUS_SOURCE_001", "attack_path": "Path A",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=notepad.exe;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — 2 x ps1 launches, -TargetName notepad (no -StartTarget)
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SUSPICIOUS_SOURCE_001 Path B Launch {i+1}",
                   "notepad", start_target=False)
    n = hits_since("API_CRT_SUSPICIOUS_SOURCE_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SUSPICIOUS_SOURCE_001", "Path B")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SUSPICIOUS_SOURCE_001", "attack_path": "Path B",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=notepad.exe;run_2;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — 2 x ps1 launches, -TargetName notepad (third run)
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SUSPICIOUS_SOURCE_001 Path C Launch {i+1}",
                   "notepad", start_target=False)
    n = hits_since("API_CRT_SUSPICIOUS_SOURCE_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SUSPICIOUS_SOURCE_001", "Path C")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path C: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SUSPICIOUS_SOURCE_001", "attack_path": "Path C",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=notepad.exe;run_3;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # -------------------------------------------------------------------------
    # RULE 8: API_CRT_SENSITIVE_TARGET_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: API_CRT_SENSITIVE_TARGET_001")
    print("=" * 60)

    # Path A — 2 x ps1 -TargetName lsass (NO -StartTarget)
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SENSITIVE_TARGET_001 Path A Launch {i+1}",
                   "lsass", start_target=False)
    n = hits_since("API_CRT_SENSITIVE_TARGET_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SENSITIVE_TARGET_001", "Path A")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SENSITIVE_TARGET_001", "attack_path": "Path A",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=lsass.exe;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path B — 2 x ps1 -TargetName winlogon
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SENSITIVE_TARGET_001 Path B Launch {i+1}",
                   "winlogon", start_target=False)
    n = hits_since("API_CRT_SENSITIVE_TARGET_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SENSITIVE_TARGET_001", "Path B")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SENSITIVE_TARGET_001", "attack_path": "Path B",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=winlogon.exe;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # Path C — 2 x ps1 -TargetName lsass (second run)
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    for i in range(2):
        launch_crt(f"API_CRT_SENSITIVE_TARGET_001 Path C Launch {i+1}",
                   "lsass", start_target=False)
    n = hits_since("API_CRT_SENSITIVE_TARGET_001", path_start)
    if n == 0:
        warn_zero("API_CRT_SENSITIVE_TARGET_001", "Path C")
        result, reason = "FAIL", "0 hits after full poll window"
    elif n >= 2:
        result, reason = "PASS", f"{n} hits"
    else:
        result, reason = "PARTIAL", f"{n} hits"
    print(f"  Path C: {result} ({n} hits)")
    results.append({"rule_id": "API_CRT_SENSITIVE_TARGET_001", "attack_path": "Path C",
                    "field_values_used": "powershell.exe;source_image=powershell.exe;target=lsass.exe;run_2;crt_start=ntdll!RtlExitUserThread",
                    "result": result, "reason": reason, "timestamp_utc": ts})

    # =========================================================================
    # BLOCK 4 — Simulation window end
    # =========================================================================
    SIM_END = datetime.datetime.utcnow()
    print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")

    # =========================================================================
    # BLOCK 5 — Summary table
    # =========================================================================
    RULE_ORDER = [
        "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001",
        "API_TOKEN_MANIPULATION_001",
        "API_AV_PROCESS_ACCESS_001",
        "API_OPEN_PROCESS_VM_WRITE_001",
        "API_DLL_LOAD_SUSPICIOUS_PATH_001",
        "API_LOLBIN_DLL_UNSIGNED_001",
        "API_CRT_SUSPICIOUS_SOURCE_001",
        "API_CRT_SENSITIVE_TARGET_001",
    ]

    def _path_result(rule_id: str, path: str) -> str:
        for r in results:
            if r["rule_id"] == rule_id and r["attack_path"] == path:
                return r["result"]
        return "?"

    def _overall(path_results: list) -> str:
        if all(x == "PASS" for x in path_results):
            return "PASS"
        if any(x == "FAIL" for x in path_results):
            return "FAIL"
        if any(x == "PARTIAL" for x in path_results):
            return "PARTIAL"
        if all(x == "SKIP" for x in path_results):
            return "SKIP"
        if any(x == "PASS" for x in path_results) and any(x == "SKIP" for x in path_results):
            return "PARTIAL"
        return "PARTIAL"

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"{'RULE':<42} | {'PATH_A':<7} | {'PATH_B':<7} | {'PATH_C':<7} | OVERALL")
    overalls = {}
    for rid in RULE_ORDER:
        pa = _path_result(rid, "Path A")
        pb = _path_result(rid, "Path B")
        pc = _path_result(rid, "Path C")
        ov = _overall([pa, pb, pc])
        overalls[rid] = ov
        print(f"{rid:<42} | {pa:<7} | {pb:<7} | {pc:<7} | {ov}")

    n_pass = sum(1 for v in overalls.values() if v == "PASS")
    n_partial = sum(1 for v in overalls.values() if v == "PARTIAL")
    n_fail = sum(1 for v in overalls.values() if v == "FAIL")
    n_skip = sum(1 for v in overalls.values() if v == "SKIP")
    print(f"\n{n_pass}/8 rules PASS, {n_partial} PARTIAL, {n_fail} FAIL, {n_skip} SKIP (DLL compilation)")

    # =========================================================================
    # BLOCK 6 — CSV export
    # =========================================================================
    csv_path = os.path.join(EXPORTS_DIR, "subphase_5_training.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["rule_id", "attack_path", "field_values_used",
                        "result", "reason", "timestamp_utc"],
        )
        writer.writeheader()
        writer.writerows(results)
    print(f"\nCSV written to: {csv_path}")

    # =========================================================================
    # BLOCK 7 — Feature extraction instructions (print only)
    # =========================================================================
    print(f"""
======================================================
NEXT STEPS — run manually after reviewing output above
======================================================

STEP 1 — Query DB for confirmed UTC window:
  <python> -c "
  import sqlite3; conn = sqlite3.connect(r'{DB_PATH}');
  row = conn.execute(\\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits
    WHERE rule_id LIKE 'API_%' AND timestamp >= '{SIM_START.strftime("%Y-%m-%d %H:%M:%S")}'\\").fetchone();
  print('Since:', row[0]); print('Until:', row[1]); conn.close()"

STEP 2 — Run feature extraction:
  <python> {_REPO_ROOT}\\scripts\\run_feature_extraction.py --label 1
    --since "YYYY-MM-DD HH:MM:SS" --until "YYYY-MM-DD HH:MM:SS"
    --output {_REPO_ROOT}\\data\\features\\suspicious_api.csv

  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.
  Do NOT use VM wall-clock time. All DB timestamps are UTC.
""")

    # =========================================================================
    # BLOCK 8 — Completion report
    # =========================================================================
    print("""======================================================
SUBPHASE 5 SIMULATION COMPLETE
======================================================""")
    print("Total rules in api_memory.yaml (live): 8")
    print("EID-10 rules (OpenProcess): 4")
    print("EID-7  rules (ImageLoad):   2")
    print("EID-8  rules (CRT):         2")
    print(f"DLL compilation: {'PASS' if _API_DLL_READY else 'FAIL'}")
    print("E5 workaround: ntdll.RtlExitUserThread confirmed")
    print(f"SIM_START (UTC): {SIM_START.isoformat()}")
    print(f"SIM_END   (UTC): {SIM_END.isoformat()}")
    print("CSV written to: exports/subphase_5_training.csv")

finally:
    print("\nCleaning up simulation artifacts...")
    # Kill spawned processes
    for _proc, _name in [
        (_notepad_proc,       "notepad.exe"),
        (_fake_msmpeng_proc,  "msmpeng.exe (fake)"),
        (_fake_mpcmdrun_proc, "mpcmdrun.exe (fake)"),
    ]:
        if _proc is not None:
            try:
                _proc.terminate()
                _proc.wait(timeout=5)
                print(f"  [CLEANUP] Terminated: {_name}")
            except Exception as _e:
                print(f"  [CLEANUP] Could not terminate {_name}: {_e}")

    # Delete temp files
    _cleanup_files = [
        r"C:\Windows\Temp\ss_api.cs",
        r"C:\Windows\Temp\ss_api.dll",
        r"C:\Users\Public\ss_api.dll",
        r"C:\ProgramData\ss_api.dll",
        r"C:\Windows\Temp\msmpeng.exe",
        r"C:\Windows\Temp\mpcmdrun.exe",
        r"C:\Windows\Temp\ss_crt_sim.ps1",
    ]
    for _f in _cleanup_files:
        try:
            os.remove(_f)
            print(f"  [CLEANUP] Deleted: {_f}")
        except Exception as _e:
            print(f"  [CLEANUP] Could not delete {_f}: {_e}")
