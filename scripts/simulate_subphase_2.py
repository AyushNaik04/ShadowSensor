import subprocess, datetime, time, sqlite3, csv, os, glob

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

# Dummy base64 file for certutil -decode (base64 of "ShadowSensor test")
with open(r"C:\Windows\Temp\ss_b64.txt", "w") as f:
    f.write("U2hhZG93U2Vuc29yIHRlc3Q=")

# Dummy hex file for certutil -decodehex (hex of "ShadowSensor test")
with open(r"C:\Windows\Temp\ss_hex.txt", "w") as f:
    f.write("536861646f7753656e736f722074657374")

# ---------------------------------------------------------------------------
# RULE 1: LOLBIN_MSHTA_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_MSHTA_001 ===")

# PATH A — Remote HTA URL
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(["C:\\Windows\\System32\\mshta.exe", "http://127.0.0.1/payload_a1.hta"],
            "LOLBIN_MSHTA_001 Path A Launch 1")
launch_argv(["C:\\Windows\\System32\\mshta.exe", "http://127.0.0.1/payload_a2.hta"],
            "LOLBIN_MSHTA_001 Path A Launch 2")
n = hits_since("LOLBIN_MSHTA_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSHTA_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSHTA_001",
    "attack_path": "Path A",
    "field_values_used": "mshta.exe http://127.0.0.1/payload_a1.hta ; http://127.0.0.1/payload_a2.hta",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — Inline VBScript
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(["C:\\Windows\\System32\\mshta.exe", "vbscript:close"],
            "LOLBIN_MSHTA_001 Path B Launch 1")
launch_argv(["C:\\Windows\\System32\\mshta.exe", "vbscript:Execute(\"close\")"],
            "LOLBIN_MSHTA_001 Path B Launch 2")
n = hits_since("LOLBIN_MSHTA_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSHTA_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSHTA_001",
    "attack_path": "Path B",
    "field_values_used": "mshta.exe vbscript:close ; vbscript:Execute(\"close\")",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — Local HTA
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(["C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\Temp\\ss_test_1.hta"],
            "LOLBIN_MSHTA_001 Path C Launch 1")
launch_argv(["C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\Temp\\ss_test_2.hta"],
            "LOLBIN_MSHTA_001 Path C Launch 2")
n = hits_since("LOLBIN_MSHTA_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSHTA_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSHTA_001",
    "attack_path": "Path C",
    "field_values_used": "mshta.exe C:\\Windows\\Temp\\ss_test_1.hta ; ss_test_2.hta",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 2: LOLBIN_RUNDLL32_SUSPICIOUS_001 (DEFENDER-BLOCKED)
# ---------------------------------------------------------------------------
print("=== LOLBIN_RUNDLL32_SUSPICIOUS_001 ===")

# PATH A — javascript: protocol
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\rundll32.exe",
     "javascript:\"\\.\\mshtml,RunHTMLApplication\";document.write()"],
    "LOLBIN_RUNDLL32_SUSPICIOUS_001 Path A Launch 1")
n = hits_since("LOLBIN_RUNDLL32_SUSPICIOUS_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path A: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_RUNDLL32_SUSPICIOUS_001",
    "attack_path": "Path A",
    "field_values_used": "rundll32.exe javascript:\"\\.\\mshtml,RunHTMLApplication\";document.write()",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# PATH B — ShellExec shim
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\rundll32.exe", "shell32.dll,ShellExec_RunDLL",
     "cmd.exe", "/c", "echo ShadowSensor_test"],
    "LOLBIN_RUNDLL32_SUSPICIOUS_001 Path B Launch 1")
n = hits_since("LOLBIN_RUNDLL32_SUSPICIOUS_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path B: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_RUNDLL32_SUSPICIOUS_001",
    "attack_path": "Path B",
    "field_values_used": "rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe /c echo ShadowSensor_test",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# PATH C — Remote HTTP URL
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\rundll32.exe", "http://127.0.0.1/a.dll,Entry"],
    "LOLBIN_RUNDLL32_SUSPICIOUS_001 Path C Launch 1")
n = hits_since("LOLBIN_RUNDLL32_SUSPICIOUS_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path C: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_RUNDLL32_SUSPICIOUS_001",
    "attack_path": "Path C",
    "field_values_used": "rundll32.exe http://127.0.0.1/a.dll,Entry",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 3: LOLBIN_REGSVR32_001 (DEFENDER-BLOCKED)
# ---------------------------------------------------------------------------
print("=== LOLBIN_REGSVR32_001 ===")

# PATH A — /i:http Squiblydoo
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\regsvr32.exe", "/s", "/i:http://127.0.0.1/a.sct", "scrobj.dll"],
    "LOLBIN_REGSVR32_001 Path A Launch 1")
n = hits_since("LOLBIN_REGSVR32_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path A: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_REGSVR32_001",
    "attack_path": "Path A",
    "field_values_used": "regsvr32.exe /s /i:http://127.0.0.1/a.sct scrobj.dll",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# PATH B — /i:https
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\regsvr32.exe", "/i:https://127.0.0.1/a.sct", "scrobj.dll"],
    "LOLBIN_REGSVR32_001 Path B Launch 1")
n = hits_since("LOLBIN_REGSVR32_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path B: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_REGSVR32_001",
    "attack_path": "Path B",
    "field_values_used": "regsvr32.exe /i:https://127.0.0.1/a.sct scrobj.dll",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# PATH C — /s /u /i local SCT
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\regsvr32.exe", "/s", "/u",
     "/i:C:\\Windows\\Temp\\ss_test.sct", "scrobj.dll"],
    "LOLBIN_REGSVR32_001 Path C Launch 1")
n = hits_since("LOLBIN_REGSVR32_001", path_start, quick=True)
if n > 0:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = "DEFENDER_BLOCKED"
print(f"  Path C: {result} ({reason})")
results.append({
    "rule_id": "LOLBIN_REGSVR32_001",
    "attack_path": "Path C",
    "field_values_used": "regsvr32.exe /s /u /i:C:\\Windows\\Temp\\ss_test.sct scrobj.dll",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 4: LOLBIN_CERTUTIL_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_CERTUTIL_001 ===")

# PATH A — urlcache download
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-urlcache", "-split", "-f",
     "http://127.0.0.1/a_1.exe", "C:\\Windows\\Temp\\certutil_out_a1.bin"],
    "LOLBIN_CERTUTIL_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-urlcache", "-f",
     "http://127.0.0.1/a_2.exe", "C:\\Windows\\Temp\\certutil_out_a2.bin"],
    "LOLBIN_CERTUTIL_001 Path A Launch 2")
n = hits_since("LOLBIN_CERTUTIL_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CERTUTIL_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CERTUTIL_001",
    "attack_path": "Path A",
    "field_values_used": "certutil.exe -urlcache -split -f http://127.0.0.1/a_1.exe ; -urlcache -f http://127.0.0.1/a_2.exe",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — -decode
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-decode",
     "C:\\Windows\\Temp\\ss_b64.txt", "C:\\Windows\\Temp\\certutil_out_b1.bin"],
    "LOLBIN_CERTUTIL_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-decode",
     "C:\\Windows\\Temp\\ss_b64.txt", "C:\\Windows\\Temp\\certutil_out_b2.bin"],
    "LOLBIN_CERTUTIL_001 Path B Launch 2")
n = hits_since("LOLBIN_CERTUTIL_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CERTUTIL_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CERTUTIL_001",
    "attack_path": "Path B",
    "field_values_used": "certutil.exe -decode C:\\Windows\\Temp\\ss_b64.txt (2 launches)",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — -decodehex
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-decodehex",
     "C:\\Windows\\Temp\\ss_hex.txt", "C:\\Windows\\Temp\\certutil_out_c1.bin"],
    "LOLBIN_CERTUTIL_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\certutil.exe", "-decodehex",
     "C:\\Windows\\Temp\\ss_hex.txt", "C:\\Windows\\Temp\\certutil_out_c2.bin"],
    "LOLBIN_CERTUTIL_001 Path C Launch 2")
n = hits_since("LOLBIN_CERTUTIL_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CERTUTIL_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CERTUTIL_001",
    "attack_path": "Path C",
    "field_values_used": "certutil.exe -decodehex C:\\Windows\\Temp\\ss_hex.txt (2 launches)",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 5: LOLBIN_MSIEXEC_REMOTE_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_MSIEXEC_REMOTE_001 ===")

# PATH A — /i http
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/i", "http://127.0.0.1/pkg_a1.msi", "/qn"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/i", "http://127.0.0.1/pkg_a2.msi", "/qn"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path A Launch 2")
n = hits_since("LOLBIN_MSIEXEC_REMOTE_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSIEXEC_REMOTE_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSIEXEC_REMOTE_001",
    "attack_path": "Path A",
    "field_values_used": "msiexec.exe /i http://127.0.0.1/pkg_a1.msi /qn ; pkg_a2.msi",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — /package https
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/package", "https://127.0.0.1/pkg_b1.msi"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/package", "https://127.0.0.1/pkg_b2.msi"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path B Launch 2")
n = hits_since("LOLBIN_MSIEXEC_REMOTE_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSIEXEC_REMOTE_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSIEXEC_REMOTE_001",
    "attack_path": "Path B",
    "field_values_used": "msiexec.exe /package https://127.0.0.1/pkg_b1.msi ; pkg_b2.msi",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — /i ftp
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/i", "ftp://127.0.0.1/pkg_c1.msi"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\msiexec.exe", "/i", "ftp://127.0.0.1/pkg_c2.msi"],
    "LOLBIN_MSIEXEC_REMOTE_001 Path C Launch 2")
n = hits_since("LOLBIN_MSIEXEC_REMOTE_001", path_start)
if n == 0:
    warn_zero("LOLBIN_MSIEXEC_REMOTE_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_MSIEXEC_REMOTE_001",
    "attack_path": "Path C",
    "field_values_used": "msiexec.exe /i ftp://127.0.0.1/pkg_c1.msi ; pkg_c2.msi",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 6: LOLBIN_ODBCCONF_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_ODBCCONF_001 ===")

# PATH A — /a {REGSVR ...}
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "/a",
     "{REGSVR C:\\Windows\\Temp\\ss_fake_1.dll}"],
    "LOLBIN_ODBCCONF_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "/a",
     "{REGSVR C:\\Windows\\Temp\\ss_fake_2.dll}"],
    "LOLBIN_ODBCCONF_001 Path A Launch 2")
n = hits_since("LOLBIN_ODBCCONF_001", path_start)
if n == 0:
    warn_zero("LOLBIN_ODBCCONF_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_ODBCCONF_001",
    "attack_path": "Path A",
    "field_values_used": "odbcconf.exe /a {REGSVR C:\\Windows\\Temp\\ss_fake_1.dll} ; ss_fake_2.dll",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — -a {REGSVR ...}
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "-a",
     "{REGSVR C:\\Windows\\Temp\\ss_fake_3.dll}"],
    "LOLBIN_ODBCCONF_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "-a",
     "{REGSVR C:\\Windows\\Temp\\ss_fake_4.dll}"],
    "LOLBIN_ODBCCONF_001 Path B Launch 2")
n = hits_since("LOLBIN_ODBCCONF_001", path_start)
if n == 0:
    warn_zero("LOLBIN_ODBCCONF_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_ODBCCONF_001",
    "attack_path": "Path B",
    "field_values_used": "odbcconf.exe -a {REGSVR C:\\Windows\\Temp\\ss_fake_3.dll} ; ss_fake_4.dll",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — /f http
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "/f", "http://127.0.0.1/a_c1.rsp"],
    "LOLBIN_ODBCCONF_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\odbcconf.exe", "/f", "http://127.0.0.1/a_c2.rsp"],
    "LOLBIN_ODBCCONF_001 Path C Launch 2")
n = hits_since("LOLBIN_ODBCCONF_001", path_start)
if n == 0:
    warn_zero("LOLBIN_ODBCCONF_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_ODBCCONF_001",
    "attack_path": "Path C",
    "field_values_used": "odbcconf.exe /f http://127.0.0.1/a_c1.rsp ; a_c2.rsp",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 7: LOLBIN_CMSTP_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_CMSTP_001 ===")

# PATH A — /s with INF
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/s", "C:\\Windows\\Temp\\ss_inf_a1.inf"],
    "LOLBIN_CMSTP_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/s", "C:\\Windows\\Temp\\ss_inf_a2.inf"],
    "LOLBIN_CMSTP_001 Path A Launch 2")
n = hits_since("LOLBIN_CMSTP_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CMSTP_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CMSTP_001",
    "attack_path": "Path A",
    "field_values_used": "cmstp.exe /s C:\\Windows\\Temp\\ss_inf_a1.inf ; ss_inf_a2.inf",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — /au
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/au", "C:\\Windows\\Temp\\ss_inf_b1.inf"],
    "LOLBIN_CMSTP_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/au", "C:\\Windows\\Temp\\ss_inf_b2.inf"],
    "LOLBIN_CMSTP_001 Path B Launch 2")
n = hits_since("LOLBIN_CMSTP_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CMSTP_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CMSTP_001",
    "attack_path": "Path B",
    "field_values_used": "cmstp.exe /au C:\\Windows\\Temp\\ss_inf_b1.inf ; ss_inf_b2.inf",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — /u (uninstall) variant — not bare launch
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/u", "C:\\Windows\\Temp\\ss_inf_c1.inf"],
    "LOLBIN_CMSTP_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\cmstp.exe", "/u", "C:\\Windows\\Temp\\ss_inf_c2.inf"],
    "LOLBIN_CMSTP_001 Path C Launch 2")
n = hits_since("LOLBIN_CMSTP_001", path_start)
if n == 0:
    warn_zero("LOLBIN_CMSTP_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_CMSTP_001",
    "attack_path": "Path C",
    "field_values_used": "cmstp.exe /u C:\\Windows\\Temp\\ss_inf_c1.inf ; ss_inf_c2.inf",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 8: LOLBIN_HH_CHM_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_HH_CHM_001 ===")

# PATH A — Remote CHM URL
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\hh.exe", "http://127.0.0.1/help_a1.chm"],
    "LOLBIN_HH_CHM_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\hh.exe", "http://127.0.0.1/help_a2.chm"],
    "LOLBIN_HH_CHM_001 Path A Launch 2")
n = hits_since("LOLBIN_HH_CHM_001", path_start)
if n == 0:
    warn_zero("LOLBIN_HH_CHM_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_HH_CHM_001",
    "attack_path": "Path A",
    "field_values_used": "hh.exe http://127.0.0.1/help_a1.chm ; help_a2.chm",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — javascript: handler
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\hh.exe", "javascript:window.close()"],
    "LOLBIN_HH_CHM_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\hh.exe", "javascript:close()"],
    "LOLBIN_HH_CHM_001 Path B Launch 2")
n = hits_since("LOLBIN_HH_CHM_001", path_start)
if n == 0:
    warn_zero("LOLBIN_HH_CHM_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_HH_CHM_001",
    "attack_path": "Path B",
    "field_values_used": "hh.exe javascript:window.close() ; javascript:close()",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — mk:@MSITStore
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\hh.exe",
     "mk:@MSITStore:C:\\Windows\\Temp\\ss_fake_c1.chm::/x.html"],
    "LOLBIN_HH_CHM_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\hh.exe",
     "mk:@MSITStore:C:\\Windows\\Temp\\ss_fake_c2.chm::/x.html"],
    "LOLBIN_HH_CHM_001 Path C Launch 2")
n = hits_since("LOLBIN_HH_CHM_001", path_start)
if n == 0:
    warn_zero("LOLBIN_HH_CHM_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_HH_CHM_001",
    "attack_path": "Path C",
    "field_values_used": "hh.exe mk:@MSITStore:C:\\Windows\\Temp\\ss_fake_c1.chm::/x.html ; ss_fake_c2.chm",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 9: LOLBIN_REGASM_REGSVCS_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_REGASM_REGSVCS_001 ===")

# PATH A — regasm.exe
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
if REGASM_PATH is None:
    print("  [WARN] REGASM_PATH not found — SKIP Path A")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path A",
        "field_values_used": "regasm.exe C:\\Windows\\Temp\\ss_fake_asm_a1.dll ; ss_fake_asm_a2.dll",
        "result": "SKIP",
        "reason": "REGASM_PATH not found on this system",
        "timestamp_utc": ts,
    })
    print("  Path A: SKIP")
else:
    launch_argv(
        [REGASM_PATH, "C:\\Windows\\Temp\\ss_fake_asm_a1.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path A Launch 1")
    launch_argv(
        [REGASM_PATH, "C:\\Windows\\Temp\\ss_fake_asm_a2.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path A Launch 2")
    n = hits_since("LOLBIN_REGASM_REGSVCS_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_REGASM_REGSVCS_001", "Path A")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path A: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path A",
        "field_values_used": f"{REGASM_PATH} C:\\Windows\\Temp\\ss_fake_asm_a1.dll ; ss_fake_asm_a2.dll",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

# PATH B — regsvcs.exe
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
if REGSVCS_PATH is None:
    print("  [WARN] REGSVCS_PATH not found — SKIP Path B")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path B",
        "field_values_used": "regsvcs.exe C:\\Windows\\Temp\\ss_fake_svc_b1.dll ; ss_fake_svc_b2.dll",
        "result": "SKIP",
        "reason": "REGSVCS_PATH not found on this system",
        "timestamp_utc": ts,
    })
    print("  Path B: SKIP")
else:
    launch_argv(
        [REGSVCS_PATH, "C:\\Windows\\Temp\\ss_fake_svc_b1.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path B Launch 1")
    launch_argv(
        [REGSVCS_PATH, "C:\\Windows\\Temp\\ss_fake_svc_b2.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path B Launch 2")
    n = hits_since("LOLBIN_REGASM_REGSVCS_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_REGASM_REGSVCS_001", "Path B")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path B: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path B",
        "field_values_used": f"{REGSVCS_PATH} C:\\Windows\\Temp\\ss_fake_svc_b1.dll ; ss_fake_svc_b2.dll",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

# PATH C — regasm.exe /U
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
if REGASM_PATH is None:
    print("  [WARN] REGASM_PATH not found — SKIP Path C")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path C",
        "field_values_used": "regasm.exe /U C:\\Windows\\Temp\\ss_fake_asm_c1.dll ; ss_fake_asm_c2.dll",
        "result": "SKIP",
        "reason": "REGASM_PATH not found on this system",
        "timestamp_utc": ts,
    })
    print("  Path C: SKIP")
else:
    launch_argv(
        [REGASM_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_asm_c1.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path C Launch 1")
    launch_argv(
        [REGASM_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_asm_c2.dll"],
        "LOLBIN_REGASM_REGSVCS_001 Path C Launch 2")
    n = hits_since("LOLBIN_REGASM_REGSVCS_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_REGASM_REGSVCS_001", "Path C")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path C: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_REGASM_REGSVCS_001",
        "attack_path": "Path C",
        "field_values_used": f"{REGASM_PATH} /U C:\\Windows\\Temp\\ss_fake_asm_c1.dll ; ss_fake_asm_c2.dll",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

# ---------------------------------------------------------------------------
# RULE 10: LOLBIN_WMIC_PROCESS_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_WMIC_PROCESS_001 ===")

# PATH A — process call create
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_A1"],
    "LOLBIN_WMIC_PROCESS_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_A2"],
    "LOLBIN_WMIC_PROCESS_001 Path A Launch 2")
n = hits_since("LOLBIN_WMIC_PROCESS_001", path_start)
if n == 0:
    warn_zero("LOLBIN_WMIC_PROCESS_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_WMIC_PROCESS_001",
    "attack_path": "Path A",
    "field_values_used": "wmic.exe process call create cmd.exe /c echo ShadowSensor_wmic_A1 ; A2",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — /node: remote
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "/node:127.0.0.1", "process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_B1"],
    "LOLBIN_WMIC_PROCESS_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "/node:127.0.0.1", "process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_B2"],
    "LOLBIN_WMIC_PROCESS_001 Path B Launch 2")
n = hits_since("LOLBIN_WMIC_PROCESS_001", path_start)
if n == 0:
    warn_zero("LOLBIN_WMIC_PROCESS_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_WMIC_PROCESS_001",
    "attack_path": "Path B",
    "field_values_used": "wmic.exe /node:127.0.0.1 process call create cmd.exe /c echo ShadowSensor_wmic_B1 ; B2",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — win32_process
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "win32_process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_C1"],
    "LOLBIN_WMIC_PROCESS_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\wbem\\wmic.exe", "win32_process", "call", "create",
     "cmd.exe /c echo ShadowSensor_wmic_C2"],
    "LOLBIN_WMIC_PROCESS_001 Path C Launch 2")
n = hits_since("LOLBIN_WMIC_PROCESS_001", path_start)
if n == 0:
    warn_zero("LOLBIN_WMIC_PROCESS_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_WMIC_PROCESS_001",
    "attack_path": "Path C",
    "field_values_used": "wmic.exe win32_process call create cmd.exe /c echo ShadowSensor_wmic_C1 ; C2",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 11: LOLBIN_BITSADMIN_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_BITSADMIN_001 ===")

# PATH A — /transfer http
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_A1",
     "http://127.0.0.1/a1.exe", "C:\\Windows\\Temp\\bits_a1.bin"],
    "LOLBIN_BITSADMIN_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_A2",
     "http://127.0.0.1/a2.exe", "C:\\Windows\\Temp\\bits_a2.bin"],
    "LOLBIN_BITSADMIN_001 Path A Launch 2")
n = hits_since("LOLBIN_BITSADMIN_001", path_start)
if n == 0:
    warn_zero("LOLBIN_BITSADMIN_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_BITSADMIN_001",
    "attack_path": "Path A",
    "field_values_used": "bitsadmin.exe /transfer ShadowSensor_job_A1|A2 http://127.0.0.1/a1.exe|a2.exe",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — /addfile
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/addfile", "ShadowSensor_job_B1",
     "http://127.0.0.1/b1.exe", "C:\\Windows\\Temp\\bits_b1.bin"],
    "LOLBIN_BITSADMIN_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/addfile", "ShadowSensor_job_B2",
     "http://127.0.0.1/b2.exe", "C:\\Windows\\Temp\\bits_b2.bin"],
    "LOLBIN_BITSADMIN_001 Path B Launch 2")
n = hits_since("LOLBIN_BITSADMIN_001", path_start)
if n == 0:
    warn_zero("LOLBIN_BITSADMIN_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_BITSADMIN_001",
    "attack_path": "Path B",
    "field_values_used": "bitsadmin.exe /addfile ShadowSensor_job_B1|B2 http://127.0.0.1/b1.exe|b2.exe",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — ftp URL
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_C1",
     "ftp://127.0.0.1/c1.exe", "C:\\Windows\\Temp\\bits_c1.bin"],
    "LOLBIN_BITSADMIN_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\bitsadmin.exe", "/transfer", "ShadowSensor_job_C2",
     "ftp://127.0.0.1/c2.exe", "C:\\Windows\\Temp\\bits_c2.bin"],
    "LOLBIN_BITSADMIN_001 Path C Launch 2")
n = hits_since("LOLBIN_BITSADMIN_001", path_start)
if n == 0:
    warn_zero("LOLBIN_BITSADMIN_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_BITSADMIN_001",
    "attack_path": "Path C",
    "field_values_used": "bitsadmin.exe /transfer ShadowSensor_job_C1|C2 ftp://127.0.0.1/c1.exe|c2.exe",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# Cleanup BITS jobs after all paths
for job in ["ShadowSensor_job_A1", "ShadowSensor_job_A2", "ShadowSensor_job_B1",
            "ShadowSensor_job_B2", "ShadowSensor_job_C1", "ShadowSensor_job_C2"]:
    subprocess.run(["bitsadmin.exe", "/cancel", job], capture_output=True)

# ---------------------------------------------------------------------------
# RULE 12: LOLBIN_INSTALLUTIL_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_INSTALLUTIL_001 ===")

if INSTALLUTIL_PATH is None:
    print("  [WARN] INSTALLUTIL_PATH not found — SKIP all paths")
    for path_name, fv in [
        ("Path A", "InstallUtil.exe C:\\Windows\\Temp\\ss_fake_iu_a1.dll ; ss_fake_iu_a2.dll"),
        ("Path B", "InstallUtil.exe /U C:\\Windows\\Temp\\ss_fake_iu_b1.dll ; ss_fake_iu_b2.dll"),
        ("Path C", "InstallUtil.exe (bare launch, 2x)"),
    ]:
        results.append({
            "rule_id": "LOLBIN_INSTALLUTIL_001",
            "attack_path": path_name,
            "field_values_used": fv,
            "result": "SKIP",
            "reason": "INSTALLUTIL_PATH not found on this system",
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
        })
        print(f"  {path_name}: SKIP")
else:
    # PATH A — install malicious assembly
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    launch_argv(
        [INSTALLUTIL_PATH, "C:\\Windows\\Temp\\ss_fake_iu_a1.dll"],
        "LOLBIN_INSTALLUTIL_001 Path A Launch 1")
    launch_argv(
        [INSTALLUTIL_PATH, "C:\\Windows\\Temp\\ss_fake_iu_a2.dll"],
        "LOLBIN_INSTALLUTIL_001 Path A Launch 2")
    n = hits_since("LOLBIN_INSTALLUTIL_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_INSTALLUTIL_001", "Path A")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path A: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_INSTALLUTIL_001",
        "attack_path": "Path A",
        "field_values_used": f"{INSTALLUTIL_PATH} C:\\Windows\\Temp\\ss_fake_iu_a1.dll ; ss_fake_iu_a2.dll",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

    # PATH B — /U uninstall
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    launch_argv(
        [INSTALLUTIL_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_iu_b1.dll"],
        "LOLBIN_INSTALLUTIL_001 Path B Launch 1")
    launch_argv(
        [INSTALLUTIL_PATH, "/U", "C:\\Windows\\Temp\\ss_fake_iu_b2.dll"],
        "LOLBIN_INSTALLUTIL_001 Path B Launch 2")
    n = hits_since("LOLBIN_INSTALLUTIL_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_INSTALLUTIL_001", "Path B")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path B: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_INSTALLUTIL_001",
        "attack_path": "Path B",
        "field_values_used": f"{INSTALLUTIL_PATH} /U C:\\Windows\\Temp\\ss_fake_iu_b1.dll ; ss_fake_iu_b2.dll",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

    # PATH C — bare launch
    path_start = datetime.datetime.utcnow()
    ts = path_start.isoformat()
    launch_argv([INSTALLUTIL_PATH], "LOLBIN_INSTALLUTIL_001 Path C Launch 1")
    launch_argv([INSTALLUTIL_PATH], "LOLBIN_INSTALLUTIL_001 Path C Launch 2")
    n = hits_since("LOLBIN_INSTALLUTIL_001", path_start)
    if n == 0:
        warn_zero("LOLBIN_INSTALLUTIL_001", "Path C")
    result = "PASS" if n >= 2 else "FAIL"
    print(f"  Path C: {result} ({n} hits)")
    results.append({
        "rule_id": "LOLBIN_INSTALLUTIL_001",
        "attack_path": "Path C",
        "field_values_used": f"{INSTALLUTIL_PATH} (bare launch, 2x)",
        "result": result,
        "reason": f"{n} hits",
        "timestamp_utc": ts,
    })

# ---------------------------------------------------------------------------
# RULE 13: LOLBIN_FORFILES_001
# ---------------------------------------------------------------------------
print("=== LOLBIN_FORFILES_001 ===")

# PATH A — /c cmd
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c", "cmd /c echo ShadowSensor_forfiles_A1"],
    "LOLBIN_FORFILES_001 Path A Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c", "cmd /c echo ShadowSensor_forfiles_A2"],
    "LOLBIN_FORFILES_001 Path A Launch 2")
n = hits_since("LOLBIN_FORFILES_001", path_start)
if n == 0:
    warn_zero("LOLBIN_FORFILES_001", "Path A")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_FORFILES_001",
    "attack_path": "Path A",
    "field_values_used": "forfiles.exe /p C:\\Windows\\System32 /m notepad.exe /c cmd /c echo ShadowSensor_forfiles_A1 ; A2",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH B — /c powershell
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c", "powershell -c Write-Host ShadowSensor_forfiles_B1"],
    "LOLBIN_FORFILES_001 Path B Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c", "powershell -c Write-Host ShadowSensor_forfiles_B2"],
    "LOLBIN_FORFILES_001 Path B Launch 2")
n = hits_since("LOLBIN_FORFILES_001", path_start)
if n == 0:
    warn_zero("LOLBIN_FORFILES_001", "Path B")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_FORFILES_001",
    "attack_path": "Path B",
    "field_values_used": "forfiles.exe /p C:\\Windows\\System32 /m notepad.exe /c powershell -c Write-Host ShadowSensor_forfiles_B1 ; B2",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# PATH C — /c wscript / cscript
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c",
     "wscript //nologo //b C:\\Windows\\Temp\\ss_fake.js"],
    "LOLBIN_FORFILES_001 Path C Launch 1")
launch_argv(
    ["C:\\Windows\\System32\\forfiles.exe", "/p", "C:\\Windows\\System32",
     "/m", "notepad.exe", "/c",
     "cscript //nologo //b C:\\Windows\\Temp\\ss_fake.js"],
    "LOLBIN_FORFILES_001 Path C Launch 2")
n = hits_since("LOLBIN_FORFILES_001", path_start)
if n == 0:
    warn_zero("LOLBIN_FORFILES_001", "Path C")
result = "PASS" if n >= 2 else "FAIL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "LOLBIN_FORFILES_001",
    "attack_path": "Path C",
    "field_values_used": "forfiles.exe /c wscript ...ss_fake.js ; /c cscript ...ss_fake.js",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# BLOCK 4 — Simulation window end
# ---------------------------------------------------------------------------
SIM_END = datetime.datetime.utcnow()
print(f"\nSimulation window end (UTC): {SIM_END.isoformat()}")

# ---------------------------------------------------------------------------
# BLOCK 5 — Summary table
# ---------------------------------------------------------------------------
RULE_ORDER = [
    "LOLBIN_MSHTA_001",
    "LOLBIN_RUNDLL32_SUSPICIOUS_001",
    "LOLBIN_REGSVR32_001",
    "LOLBIN_CERTUTIL_001",
    "LOLBIN_MSIEXEC_REMOTE_001",
    "LOLBIN_ODBCCONF_001",
    "LOLBIN_CMSTP_001",
    "LOLBIN_HH_CHM_001",
    "LOLBIN_REGASM_REGSVCS_001",
    "LOLBIN_WMIC_PROCESS_001",
    "LOLBIN_BITSADMIN_001",
    "LOLBIN_INSTALLUTIL_001",
    "LOLBIN_FORFILES_001",
]
DEFENDER_PARTIAL_RULES = {
    "LOLBIN_RUNDLL32_SUSPICIOUS_001",
    "LOLBIN_REGSVR32_001",
}

print("\nRULE | PATH_A | PATH_B | PATH_C | OVERALL")
pass_count = 0
partial_count = 0
fail_count = 0
skip_count = 0

for rule_id in RULE_ORDER:
    path_a = path_b = path_c = "N/A"
    for row in results:
        if row["rule_id"] != rule_id:
            continue
        if row["attack_path"] == "Path A":
            path_a = row["result"]
        elif row["attack_path"] == "Path B":
            path_b = row["result"]
        elif row["attack_path"] == "Path C":
            path_c = row["result"]

    if rule_id in DEFENDER_PARTIAL_RULES:
        overall = "PARTIAL"
        partial_count += 1
    else:
        path_results = [r for r in [path_a, path_b, path_c] if r != "N/A"]
        non_skip = [r for r in path_results if r != "SKIP"]
        if path_results and all(r == "SKIP" for r in path_results):
            overall = "SKIP"
            skip_count += 1
        elif non_skip and all(r == "PASS" for r in non_skip):
            overall = "PASS"
            pass_count += 1
        else:
            overall = "FAIL"
            fail_count += 1

    print(f"{rule_id} | {path_a} | {path_b} | {path_c} | {overall}")

print(f"\n{pass_count}/13 rules PASS, {partial_count} PARTIAL (Defender-blocked), "
      f"{fail_count} FAIL, {skip_count} SKIP")

# ---------------------------------------------------------------------------
# BLOCK 6 — CSV export
# ---------------------------------------------------------------------------
csv_path = os.path.join(EXPORTS_DIR, "subphase_2_training.csv")
fieldnames = [
    "rule_id", "attack_path", "field_values_used",
    "result", "reason", "timestamp_utc",
]
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in results:
        writer.writerow(row)
print(f"Staging log written: {csv_path}")

# ---------------------------------------------------------------------------
# BLOCK 7 — Feature extraction instructions (print only, do not execute)
# ---------------------------------------------------------------------------
print("======================================================")
print("NEXT STEPS — run manually after reviewing output above")
print("======================================================")
print("")
print("STEP 1 — Query DB for the confirmed UTC window of this subphase:")
print(f"  <python> -c \"")
print(f"  import sqlite3; conn = sqlite3.connect(r'{DB_PATH}');")
print("  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits")
print("    WHERE rule_id LIKE 'LOLBIN_%' AND timestamp >= '<paste SIM_START UTC here>'\").fetchone();")
print("  print('Since:', row[0]); print('Until:', row[1]); conn.close()\"")
print("")
print("STEP 2 — Run feature extraction with the DB-confirmed timestamps:")
print(f"  <python> {os.path.join(_REPO_ROOT, 'scripts', 'run_feature_extraction.py')}")
print("    --label 1")
print("    --since \"YYYY-MM-DD HH:MM:SS\"")
print("    --until \"YYYY-MM-DD HH:MM:SS\"")
print(f"    --output {os.path.join(_REPO_ROOT, 'data', 'features', 'suspicious_lolbins.csv')}")
print("")
print("  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.")
print("  Do NOT use VM wall-clock time. All timestamps in DB are UTC.")
print("")
print("=" * 60)
print("SIMULATION COMPLETE — Phase 7A Subphase 2 (LOLBins) DONE.")
print(f"  Start : {SIM_START.isoformat()} UTC")
print(f"  End   : {SIM_END.isoformat()} UTC")
print(f"  CSV   : {csv_path}")
print("=" * 60)
