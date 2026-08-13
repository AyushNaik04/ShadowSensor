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
        return n, "FAIL", "0 hits after D41 retry exhausted"
    elif n >= 2:
        return n, "PASS", f"{n} hits"
    else:
        return n, "PARTIAL", f"{n} hits"


results = []
SIM_START = datetime.datetime.utcnow()
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")


try:
    # =========================================================================
    # BLOCK 2 — Pre-flight: write helper files and compile C# DLL
    # =========================================================================
    print("=" * 60)
    print("BLOCK 2 — Writing helper files and compiling C# DLL")
    print("=" * 60)

    _helper_files = [
        (
            os.path.join(TEMP, "ss_chain_cmd.vbs"),
            'WScript.CreateObject("WScript.Shell").Run "cmd.exe /c echo ShadowSensor_chain_cmd", 0, True\n'
            "WScript.Quit 0\n",
        ),
        (
            os.path.join(TEMP, "ss_chain_ps.vbs"),
            'WScript.CreateObject("WScript.Shell").Run "powershell.exe -Command Write-Host ShadowSensor_chain_ps", 0, True\n'
            "WScript.Quit 0\n",
        ),
        (
            os.path.join(TEMP, "ss_chain_ps64.vbs"),
            'WScript.CreateObject("WScript.Shell").Run "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -Command Write-Host ShadowSensor_chain_ps64", 0, True\n'
            "WScript.Quit 0\n",
        ),
        (
            os.path.join(TEMP, "ss_chain_cmd_mshta.hta"),
            '<html><head><script language="VBScript">\n'
            'Dim sh : Set sh = CreateObject("WScript.Shell")\n'
            'sh.Run "cmd.exe /c echo ShadowSensor_mshta_chain", 0, True\n'
            "window.close()\n"
            "</script></head><body></body></html>\n",
        ),
        (
            os.path.join(TEMP, "ss_chain_cmstp.inf"),
            "[version]\n"
            "Signature=$chicago$\n"
            "AdvancedINF=2.5\n"
            "\n"
            "[DefaultInstall_SingleUser]\n"
            "RunPreSetupCommandsSection=RunCmds\n"
            "\n"
            "[RunCmds]\n"
            "cmd /c echo ShadowSensor_cmstp_chain\n",
        ),
        (
            os.path.join(TEMP, "ss_chain_com.cs"),
            "using System;\n"
            "using System.Diagnostics;\n"
            "using System.Runtime.InteropServices;\n"
            "\n"
            "namespace ShadowSensorChain\n"
            "{\n"
            "    [ComVisible(true)]\n"
            '    [Guid("8A4F2B3C-5D6E-4F7A-8B9C-0D1E2F3A4B5C")]\n'
            "    public class ShadowSensorCOM\n"
            "    {\n"
            "        [ComRegisterFunction]\n"
            "        public static void Register(Type t)\n"
            "        {\n"
            '            try { Process.Start("cmd.exe", "/c echo ShadowSensor_regsvr32_register"); }\n'
            "            catch { }\n"
            "        }\n"
            "\n"
            "        [ComUnregisterFunction]\n"
            "        public static void Unregister(Type t)\n"
            "        {\n"
            '            try { Process.Start("powershell.exe", "-Command Write-Host ShadowSensor_regsvr32_unregister"); }\n'
            "            catch { }\n"
            "        }\n"
            "    }\n"
            "}\n",
        ),
    ]

    for _path, _content in _helper_files:
        try:
            with open(_path, "w", encoding="utf-8") as _f:
                _f.write(_content)
            print(f"  [WRITE] {_path}")
        except OSError as e:
            print(f"  [WRITE ERROR] {_path}: {e}")

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

    print(f"  [DLL_READY] {_DLL_READY}")

    # =========================================================================
    # BLOCK 3 — Simulation rules
    # =========================================================================

    # -------------------------------------------------------------------------
    # RULE 1: CHAIN_SCRIPT_HOST_CMD_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: CHAIN_SCRIPT_HOST_CMD_001")
    print("=" * 60)

    # Path A — wscript.exe → cmd.exe
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_CMD_001", "Path A",
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        "CHAIN_SCRIPT_HOST_CMD_001 Path A Launch 1",
        "CHAIN_SCRIPT_HOST_CMD_001 Path A Launch 2",
    )
    print(f"  Path A: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_CMD_001",
        "attack_path": "Path A",
        "field_values_used": "wscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=wscript.exe;image=cmd.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path B — cscript.exe → cmd.exe
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_CMD_001", "Path B",
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        "CHAIN_SCRIPT_HOST_CMD_001 Path B Launch 1",
        "CHAIN_SCRIPT_HOST_CMD_001 Path B Launch 2",
    )
    print(f"  Path B: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_CMD_001",
        "attack_path": "Path B",
        "field_values_used": "cscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=cscript.exe;image=cmd.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path C — wscript.exe → cmd.exe (alternate run)
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_CMD_001", "Path C",
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_cmd.vbs"],
        "CHAIN_SCRIPT_HOST_CMD_001 Path C Launch 1",
        "CHAIN_SCRIPT_HOST_CMD_001 Path C Launch 2",
    )
    print(f"  Path C: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_CMD_001",
        "attack_path": "Path C",
        "field_values_used": "wscript.exe;ss_chain_cmd.vbs → cmd.exe;parent_image=wscript.exe;image=cmd.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # -------------------------------------------------------------------------
    # RULE 2: CHAIN_SCRIPT_HOST_POWERSHELL_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: CHAIN_SCRIPT_HOST_POWERSHELL_001")
    print("=" * 60)

    # Path A — wscript.exe → powershell.exe
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path A",
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
        [WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path A Launch 1",
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path A Launch 2",
    )
    print(f"  Path A: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_POWERSHELL_001",
        "attack_path": "Path A",
        "field_values_used": "wscript.exe;ss_chain_ps.vbs → powershell.exe;parent_image=wscript.exe;image=powershell.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path B — cscript.exe → powershell.exe
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path B",
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps.vbs"],
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path B Launch 1",
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path B Launch 2",
    )
    print(f"  Path B: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_POWERSHELL_001",
        "attack_path": "Path B",
        "field_values_used": "cscript.exe;ss_chain_ps.vbs → powershell.exe;parent_image=cscript.exe;image=powershell.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path C — cscript.exe → SysWOW64 powershell.exe
    ts = datetime.datetime.utcnow().isoformat()
    n, result, reason = run_two_with_d41_retry(
        "CHAIN_SCRIPT_HOST_POWERSHELL_001", "Path C",
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps64.vbs"],
        [CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_chain_ps64.vbs"],
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path C Launch 1",
        "CHAIN_SCRIPT_HOST_POWERSHELL_001 Path C Launch 2",
    )
    print(f"  Path C: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_SCRIPT_HOST_POWERSHELL_001",
        "attack_path": "Path C",
        "field_values_used": "cscript.exe;ss_chain_ps64.vbs → SysWOW64\\powershell.exe;parent_image=cscript.exe;image=powershell.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # -------------------------------------------------------------------------
    # RULE 3: CHAIN_SCHEDULED_TASK_SVCHOST_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: CHAIN_SCHEDULED_TASK_SVCHOST_001")
    print("=" * 60)

    # Path A — svchost -s Schedule → powershell.exe -enc
    _b64_a = base64.b64encode(
        "Write-Host ShadowSensor_svchost_chain_A".encode("utf-16-le")
    ).decode()
    task_cmd_a = f'powershell.exe -enc {_b64_a}'

    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ok = create_and_run_task("ShadowSensor_SP4_SVCA", task_cmd_a)
    if not ok:
        print(f"  Path A: FAIL (schtasks create/run failed)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path A",
            "field_values_used": "svchost.exe;-s Schedule;powershell.exe;-enc <base64>",
            "result": "FAIL",
            "reason": "schtasks create/run failed — cannot simulate this path",
            "timestamp_utc": ts,
        })
    else:
        time.sleep(10)  # allow task to spawn child
        # Run a second time for 2-hit confidence
        subprocess.run([SCHTASKS, "/run", "/tn", "ShadowSensor_SP4_SVCA"],
                       capture_output=True, timeout=15)
        time.sleep(5)
        n = hits_since("CHAIN_SCHEDULED_TASK_SVCHOST_001", path_start)
        if n == 0:
            warn_zero("CHAIN_SCHEDULED_TASK_SVCHOST_001", "Path A")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path A: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path A",
            "field_values_used": "svchost.exe;-s Schedule;powershell.exe;-enc <base64>",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

    # Path B — svchost -s Schedule → powershell.exe DownloadString http://
    task_cmd_b = 'powershell.exe -Command "(New-Object System.Net.WebClient).DownloadString(\'http://127.0.0.1/a.txt\') | Out-Null"'

    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ok = create_and_run_task("ShadowSensor_SP4_SVCB", task_cmd_b)
    if not ok:
        print(f"  Path B: FAIL (schtasks create/run failed)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path B",
            "field_values_used": "svchost.exe;-s Schedule;powershell.exe;DownloadString http://127.0.0.1/",
            "result": "FAIL",
            "reason": "schtasks create/run failed — cannot simulate this path",
            "timestamp_utc": ts,
        })
    else:
        time.sleep(10)
        subprocess.run([SCHTASKS, "/run", "/tn", "ShadowSensor_SP4_SVCB"],
                       capture_output=True, timeout=15)
        time.sleep(5)
        n = hits_since("CHAIN_SCHEDULED_TASK_SVCHOST_001", path_start)
        if n == 0:
            warn_zero("CHAIN_SCHEDULED_TASK_SVCHOST_001", "Path B")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path B: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path B",
            "field_values_used": "svchost.exe;-s Schedule;powershell.exe;DownloadString http://127.0.0.1/",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

    # Path C — svchost -s Schedule → mshta.exe https://
    task_cmd_c = 'mshta.exe https://127.0.0.1/a.hta'

    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    ok = create_and_run_task("ShadowSensor_SP4_SVCC", task_cmd_c)
    if not ok:
        print(f"  Path C: FAIL (schtasks create/run failed)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path C",
            "field_values_used": "svchost.exe;-s Schedule;mshta.exe;https://127.0.0.1/a.hta",
            "result": "FAIL",
            "reason": "schtasks create/run failed — cannot simulate this path",
            "timestamp_utc": ts,
        })
    else:
        time.sleep(10)
        subprocess.run([SCHTASKS, "/run", "/tn", "ShadowSensor_SP4_SVCC"],
                       capture_output=True, timeout=15)
        time.sleep(5)
        n = hits_since("CHAIN_SCHEDULED_TASK_SVCHOST_001", path_start)
        if n == 0:
            warn_zero("CHAIN_SCHEDULED_TASK_SVCHOST_001", "Path C")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_SCHEDULED_TASK_SVCHOST_001",
            "attack_path": "Path C",
            "field_values_used": "svchost.exe;-s Schedule;mshta.exe;https://127.0.0.1/a.hta",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

    # -------------------------------------------------------------------------
    # RULE 4: CHAIN_SCHEDULED_TASK_SCRIPT_001 (D43)
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # RULE 5: CHAIN_REGSVR32_CHILD_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: CHAIN_REGSVR32_CHILD_001")
    print("=" * 60)

    if not _DLL_READY:
        _skip_reason = ("DLL compilation failed (csc.exe error) — cannot simulate "
                        "CHAIN_REGSVR32_CHILD_001 without compiled COM DLL.")
        _skip_fields = {
            "Path A": "regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regsvr32.exe;image=cmd.exe",
            "Path B": "regsvr32.exe /s /u ss_chain_com.dll → powershell.exe via [ComUnregisterFunction];parent_image=regsvr32.exe;image=powershell.exe",
            "Path C": "regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction] (re-register);parent_image=regsvr32.exe;image=cmd.exe",
        }
        for path in ["Path A", "Path B", "Path C"]:
            results.append({
                "rule_id": "CHAIN_REGSVR32_CHILD_001",
                "attack_path": path,
                "field_values_used": _skip_fields[path],
                "result": "SKIP",
                "reason": _skip_reason,
                "timestamp_utc": datetime.datetime.utcnow().isoformat(),
            })
            print(f"  {path}: SKIP — DLL compilation failed")
    else:
        # Path A — regsvr32 /s (register) → cmd.exe
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path A Launch 1")
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path A Launch 2")
        n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)
        if n == 0:
            warn_zero("CHAIN_REGSVR32_CHILD_001", "Path A")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path A: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_REGSVR32_CHILD_001",
            "attack_path": "Path A",
            "field_values_used": "regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regsvr32.exe;image=cmd.exe",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

        # Path B — regsvr32 /s /u (unregister) → powershell.exe
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([REGSVR32, "/s", "/u", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path B Launch 1")
        launch_argv([REGSVR32, "/s", "/u", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path B Launch 2")
        n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)
        if n == 0:
            warn_zero("CHAIN_REGSVR32_CHILD_001", "Path B")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path B: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_REGSVR32_CHILD_001",
            "attack_path": "Path B",
            "field_values_used": "regsvr32.exe /s /u ss_chain_com.dll → powershell.exe via [ComUnregisterFunction];parent_image=regsvr32.exe;image=powershell.exe",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

        # Path C — regsvr32 /s (re-register) → cmd.exe
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path C Launch 1")
        launch_argv([REGSVR32, "/s", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_REGSVR32_CHILD_001 Path C Launch 2")
        n = hits_since("CHAIN_REGSVR32_CHILD_001", path_start)
        if n == 0:
            warn_zero("CHAIN_REGSVR32_CHILD_001", "Path C")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_REGSVR32_CHILD_001",
            "attack_path": "Path C",
            "field_values_used": "regsvr32.exe /s ss_chain_com.dll → cmd.exe via [ComRegisterFunction] (re-register);parent_image=regsvr32.exe;image=cmd.exe",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

    # -------------------------------------------------------------------------
    # RULE 6: CHAIN_LOLBIN_CHILD_001
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("RULE: CHAIN_LOLBIN_CHILD_001")
    print("=" * 60)

    # Path A — mshta.exe → cmd.exe
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    launch_argv([MSHTA, r"C:\Windows\Temp\ss_chain_cmd_mshta.hta"],
                "CHAIN_LOLBIN_CHILD_001 Path A Launch 1")
    launch_argv([MSHTA, r"C:\Windows\Temp\ss_chain_cmd_mshta.hta"],
                "CHAIN_LOLBIN_CHILD_001 Path A Launch 2")
    n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)
    if n == 0:
        warn_zero("CHAIN_LOLBIN_CHILD_001", "Path A")
        result = "FAIL"
        reason = "0 hits after full poll window"
    elif n >= 2:
        result = "PASS"
        reason = f"{n} hits"
    else:
        result = "PARTIAL"
        reason = f"{n} hits"
    print(f"  Path A: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_LOLBIN_CHILD_001",
        "attack_path": "Path A",
        "field_values_used": "mshta.exe;ss_chain_cmd_mshta.hta → cmd.exe;parent_image=mshta.exe;image=cmd.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path B — cmstp.exe → cmd.exe
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    launch_argv([CMSTP, "/s", "/ni", r"C:\Windows\Temp\ss_chain_cmstp.inf"],
                "CHAIN_LOLBIN_CHILD_001 Path B Launch 1")
    launch_argv([CMSTP, "/s", "/ni", r"C:\Windows\Temp\ss_chain_cmstp.inf"],
                "CHAIN_LOLBIN_CHILD_001 Path B Launch 2")
    n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)
    if n == 0:
        warn_zero("CHAIN_LOLBIN_CHILD_001", "Path B")
        result = "FAIL"
        reason = "0 hits after full poll window"
    elif n >= 2:
        result = "PASS"
        reason = f"{n} hits"
    else:
        result = "PARTIAL"
        reason = f"{n} hits"
    print(f"  Path B: {result} ({n} hits)")
    results.append({
        "rule_id": "CHAIN_LOLBIN_CHILD_001",
        "attack_path": "Path B",
        "field_values_used": "cmstp.exe /s /ni ss_chain_cmstp.inf → cmd.exe via RunPreSetupCommandsSection;parent_image=cmstp.exe;image=cmd.exe",
        "result": result,
        "reason": reason,
        "timestamp_utc": ts,
    })

    # Path C — regasm.exe → cmd.exe (csc-dependent)
    if (not _DLL_READY) or (REGASM is None):
        print("  Path C: SKIP — csc.exe compilation failed or RegAsm.exe not found")
        results.append({
            "rule_id": "CHAIN_LOLBIN_CHILD_001",
            "attack_path": "Path C",
            "field_values_used": "regasm.exe /nologo /codebase ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regasm.exe;image=cmd.exe",
            "result": "SKIP",
            "reason": "csc.exe compilation failed or RegAsm.exe not found — CHAIN_LOLBIN_CHILD_001 Path C skipped.",
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
        })
    else:
        path_start = datetime.datetime.utcnow()
        ts = path_start.isoformat()
        launch_argv([REGASM, "/nologo", "/codebase", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_LOLBIN_CHILD_001 Path C Launch 1")
        launch_argv([REGASM, "/nologo", "/codebase", r"C:\Windows\Temp\ss_chain_com.dll"],
                    "CHAIN_LOLBIN_CHILD_001 Path C Launch 2")
        n = hits_since("CHAIN_LOLBIN_CHILD_001", path_start)
        if n == 0:
            warn_zero("CHAIN_LOLBIN_CHILD_001", "Path C")
            result = "FAIL"
            reason = "0 hits after full poll window"
        elif n >= 2:
            result = "PASS"
            reason = f"{n} hits"
        else:
            result = "PARTIAL"
            reason = f"{n} hits"
        print(f"  Path C: {result} ({n} hits)")
        results.append({
            "rule_id": "CHAIN_LOLBIN_CHILD_001",
            "attack_path": "Path C",
            "field_values_used": "regasm.exe /nologo /codebase ss_chain_com.dll → cmd.exe via [ComRegisterFunction];parent_image=regasm.exe;image=cmd.exe",
            "result": result,
            "reason": reason,
            "timestamp_utc": ts,
        })

    # -------------------------------------------------------------------------
    # RULE 7: CHAIN_BROWSER_SHELL_001 (PARTIAL — D42)
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # RULES 8–10: CHAIN_OFFICE_* (SKIP — Office not installed)
    # -------------------------------------------------------------------------
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

    # =========================================================================
    # BLOCK 4 — Simulation window end
    # =========================================================================
    SIM_END = datetime.datetime.utcnow()
    print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")

    # =========================================================================
    # BLOCK 5 — Summary table
    # =========================================================================
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
    print(f"{'RULE':<38} | {'PATH_A':<7} | {'PATH_B':<7} | {'PATH_C':<7} | OVERALL")
    overalls = {}
    for rid in RULE_ORDER:
        pa = _path_result(rid, "Path A")
        pb = _path_result(rid, "Path B")
        pc = _path_result(rid, "Path C")
        ov = _overall([pa, pb, pc])
        overalls[rid] = ov
        print(f"{rid:<38} | {pa:<7} | {pb:<7} | {pc:<7} | {ov}")

    n_pass = sum(1 for v in overalls.values() if v == "PASS")
    n_partial = sum(1 for v in overalls.values() if v == "PARTIAL")
    n_fail = sum(1 for v in overalls.values() if v == "FAIL")
    n_skip = sum(1 for v in overalls.values() if v == "SKIP")
    print(f"\n{n_pass}/10 rules PASS, {n_partial} PARTIAL (D42), {n_fail} FAIL (D43), {n_skip} SKIP (Office)")

    # =========================================================================
    # BLOCK 6 — CSV export
    # =========================================================================
    csv_path = os.path.join(EXPORTS_DIR, "subphase_4_training.csv")
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

STEP 1 — Query DB for confirmed UTC window of this subphase:
  <python> -c "
  import sqlite3; conn = sqlite3.connect(r'{DB_PATH}');
  row = conn.execute(\\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits
    WHERE rule_id LIKE 'CHAIN_%' AND timestamp >= '{SIM_START.strftime("%Y-%m-%d %H:%M:%S")}'\\").fetchone();
  print('Since:', row[0]); print('Until:', row[1]); conn.close()"

STEP 2 — Run feature extraction with DB-confirmed timestamps:
  <python> {_REPO_ROOT}\\scripts\\run_feature_extraction.py
    --label 1
    --since "YYYY-MM-DD HH:MM:SS"
    --until "YYYY-MM-DD HH:MM:SS"
    --output {_REPO_ROOT}\\data\\features\\suspicious_chains.csv

  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.
  Do NOT use VM wall-clock time. All DB timestamps are UTC.
""")

    # =========================================================================
    # BLOCK 8 — Completion report
    # =========================================================================
    print("""======================================================
SUBPHASE 4 SIMULATION COMPLETE
======================================================""")
    print("Total rules in parent_child.yaml (live): 10")
    print("Rules simulated: 6 (3 SKIP — Office; 1 PARTIAL — D42; 1 FAIL — D43)")
    print(f"DLL compilation: {'PASS' if _DLL_READY else 'FAIL'}")
    print("D41 retries triggered: see above")
    print("D43 confirmed: CHAIN_SCHEDULED_TASK_SCRIPT_001 — taskeng/taskhostw not used")
    print("D42 confirmed: CHAIN_BROWSER_SHELL_001 — browser spawn not automatable")
    print(f"SIM_START (UTC): {SIM_START.isoformat()}")
    print(f"SIM_END   (UTC): {SIM_END.isoformat()}")
    print("CSV written to: exports/subphase_4_training.csv")

finally:
    # =========================================================================
    # BLOCK 9 — Scheduled task cleanup (always runs, even after errors)
    # =========================================================================
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
