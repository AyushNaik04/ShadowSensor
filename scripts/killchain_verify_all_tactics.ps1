# ShadowSensor Kill Chain - Full Verification (All Tactics)
# Run from repo root while pipeline + dashboard are active (Administrator):
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_all_tactics.ps1

$ErrorActionPreference = "Continue"

$coveredTactics = @(
    "Execution",
    "Defense Evasion",
    "Initial Access",
    "Command and Control"
)

function Invoke-OpenProcessLsassTest {
    $repoRoot = (Get-Location).Path
    $pyExe = Join-Path $repoRoot "python_runtime\python.exe"
    $pyScript = Join-Path $env:TEMP "ss_kc_all_openprocess_lsass.py"
    $pyCode = @"
import ctypes
import subprocess

out = subprocess.check_output(
    ['wmic', 'process', 'where', 'name="lsass.exe"', 'get', 'ProcessId'],
    text=True,
)
pid = int([line for line in out.split() if line.strip().isdigit()][0])
access = 0x1F0FFF
handle = ctypes.windll.kernel32.OpenProcess(access, False, pid)
print('OpenProcess handle:', handle)
"@
    Set-Content -Path $pyScript -Value $pyCode -Encoding ASCII
    if (Test-Path $pyExe) {
        Start-Process -FilePath $pyExe -ArgumentList $pyScript -Wait -WindowStyle Hidden
    } else {
        Write-Host '    [WARN] python_runtime\python.exe not found - skipping'
    }
}

function Invoke-NetworkC2Test {
    # Sysmon Event ID 3 logs established outbound TCP connections only.
    # Use example.com (port 80 + 443) instead of blocked Tor IPs; keep process alive briefly.
    $netPs = Join-Path $env:TEMP "ss_kc_net_c2_test.ps1"
    $netCode = @'
$ErrorActionPreference = "SilentlyContinue"
try {
    Invoke-WebRequest -Uri "http://example.com/" -UseBasicParsing -TimeoutSec 15 | Out-Null
} catch {}
Start-Sleep -Seconds 3
try {
    $client = New-Object Net.Sockets.TcpClient
    $client.Connect("93.184.216.34", 443)
    Start-Sleep -Seconds 3
    $client.Close()
} catch {}
Start-Sleep -Seconds 2
'@
    Set-Content -Path $netPs -Value $netCode -Encoding ASCII
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $netPs -Wait
}

function Invoke-CreateRemoteThreadTest {
    $crtPs = Join-Path $env:TEMP "ss_kc_all_crt_test.ps1"
    $crtCode = @'
$cs = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class SsKcAllCrt {
    [DllImport("kernel32")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out IntPtr written);
    [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);
    public static void Run() {
        var np = Process.Start("notepad.exe");
        System.Threading.Thread.Sleep(1500);
        IntPtr h = OpenProcess(0x1F0FFF, false, np.Id);
        IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, 4, 0x3000, 0x40);
        byte[] data = BitConverter.GetBytes(0);
        IntPtr w;
        WriteProcessMemory(h, mem, data, 4, out w);
        CreateRemoteThread(h, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        System.Threading.Thread.Sleep(500);
        try { np.Kill(); } catch { }
    }
}
"@
Add-Type -TypeDefinition $cs -Language CSharp
[SsKcAllCrt]::Run()
'@
    Set-Content -Path $crtPs -Value $crtCode -Encoding ASCII
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $crtPs -WindowStyle Hidden -Wait
}

function Invoke-Technique {
    param(
        [string]$RuleId,
        [string]$Tactic,
        [string]$Description,
        [scriptblock]$Trigger,
        [int]$PostDelaySeconds = 2
    )

    Write-Host "  -> $RuleId ($Tactic): $Description"
    & $Trigger
    Start-Sleep -Seconds $PostDelaySeconds
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Kill Chain Tab - Full Verification"
Write-Host "  All Tactics in Sequence"
Write-Host "========================================"
Write-Host ""
Write-Host "This script simulates suspicious behavior across all ATT&CK"
Write-Host "tactics covered by the current ShadowSensor ruleset."
Write-Host ""
Write-Host "Keep your browser open to:"
Write-Host "  http://localhost:8080/dashboard/killchain"
Write-Host ""
Write-Host "Watch tactic cards light up as each group of techniques fires."
Write-Host "The page auto-refreshes every 5 seconds - no manual reload needed."
Write-Host ""
Write-Host "Total estimated duration: ~90 seconds"
Write-Host ""
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[WARN] Not running as Administrator. LOLBin and network tests may fail.'
    Write-Host '       Right-click PowerShell -> Run as administrator, then re-run this script.'
    Write-Host ""
}
Write-Host "Press Enter to begin or Ctrl+C to cancel."
Read-Host | Out-Null

# ============================================================================
# PHASE 1 - Execution and Defense Evasion
# ============================================================================
Write-Host ""
Write-Host "=== Phase 1: Execution and Defense Evasion ==="
Write-Host "Techniques: PowerShell encoded commands, AMSI bypass indicators,"
Write-Host "LOLBin invocations"
Write-Host "Watch for: EXECUTION and DEFENSE EVASION cards to light up"
Write-Host ""

Invoke-Technique -RuleId "PS_ENCODED_CMD_001" -Tactic "Execution" -Description "Encoded PowerShell command" -Trigger {
    $enc = "JABjAG0AZAAgACcAVABlAHMAdAAnAA=="
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $enc -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "PS_DOWNLOAD_CRADLE_001" -Tactic "Execution" -Description "Download cradle via cmd parent" -Trigger {
    $cradle = 'powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1/noop'')" '
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cradle -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "PS_HIDDEN_WINDOW_001" -Tactic "Execution" -Description "Hidden window PowerShell" -Trigger {
    $hidden = 'powershell.exe -NoProfile -W Hidden -Command "Write-Host hidden-test"'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $hidden -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "PS_AMSI_BYPASS_001" -Tactic "Defense Evasion" -Description "AMSI bypass indicator" -Trigger {
    $amsiCmd = 'powershell.exe -NoProfile -Command "[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')" '
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $amsiCmd -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "LOLBIN_MSHTA_001" -Tactic "Defense Evasion" -Description "mshta.exe launch" -Trigger {
    $mshtaArgs = 'vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""cmd /c echo mshta-test"",0"))'
    Start-Process -FilePath "mshta.exe" -ArgumentList $mshtaArgs -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "LOLBIN_RUNDLL32_SUSPICIOUS_001" -Tactic "Defense Evasion" -Description "rundll32 javascript protocol" -Trigger {
    $rundllLine = 'C:\Windows\System32\rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";close()'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $rundllLine -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "LOLBIN_REGSVR32_001" -Tactic "Defense Evasion" -Description "regsvr32 Squiblydoo" -Trigger {
    $regsvrLine = 'C:\Windows\System32\regsvr32.exe /s /n /u /i:http://127.0.0.1/test.sct scrobj.dll'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $regsvrLine -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "LOLBIN_CERTUTIL_001" -Tactic "Defense Evasion" -Description "certutil -decode" -Trigger {
    $testDir = Join-Path $env:TEMP "shadowsensor_test"
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $b64Path = Join-Path $testDir "test.b64"
    $outPath = Join-Path $testDir "test.out"
    Set-Content -Path $b64Path -Value "dGVzdA==" -Encoding ASCII
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "certutil.exe -decode `"$b64Path`" `"$outPath`"" -Wait
}

Write-Host ""
Write-Host "Phase 1 complete. Waiting 8 seconds for poll cycles to catch up..."
Start-Sleep -Seconds 8
Write-Host "Check the browser now. EXECUTION and DEFENSE EVASION cards"
Write-Host "should be coloured. Press Enter to continue to Phase 2."
Read-Host | Out-Null

# ============================================================================
# PHASE 2 - Initial Access + script host chains (Credential Access: none)
# ============================================================================
Write-Host ""
Write-Host "=== Phase 2: Initial Access and Script Host Chains ==="
Write-Host ""
Write-Host "Credential Access: no rules in the current ruleset - card stays grey (expected)."
Write-Host "Simulating Initial Access (Office macro chains) and Execution (script hosts)."
Write-Host "Watch for: INITIAL ACCESS and additional EXECUTION hits"
Write-Host ""

$fakeWord = Join-Path $env:TEMP "winword.exe"
Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination $fakeWord -Force

Invoke-Technique -RuleId "CHAIN_OFFICE_POWERSHELL_001" -Tactic "Initial Access" -Description "Office -> PowerShell chain" -Trigger {
    Start-Process -FilePath $fakeWord -ArgumentList '/c', 'powershell.exe -NoProfile -Command "Write-Host office-ps-chain"' -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "CHAIN_OFFICE_CMD_001" -Tactic "Initial Access" -Description "Office -> cmd chain" -Trigger {
    Start-Process -FilePath $fakeWord -ArgumentList '/c', 'cmd.exe /c echo office-cmd-chain' -WindowStyle Hidden -Wait
}

Invoke-Technique -RuleId "CHAIN_SCRIPT_HOST_CMD_001" -Tactic "Execution" -Description "wscript -> cmd chain" -Trigger {
    $vbsCmd = Join-Path $env:TEMP "ss_kc_all_chain_cmd.vbs"
    Set-Content -Path $vbsCmd -Value 'CreateObject("WScript.Shell").Run "cmd.exe /c echo wscript-cmd-chain", 0, True' -Encoding ASCII
    Start-Process -FilePath "wscript.exe" -ArgumentList "//B", $vbsCmd -Wait
}

Invoke-Technique -RuleId "CHAIN_SCRIPT_HOST_POWERSHELL_001" -Tactic "Execution" -Description "cscript -> PowerShell chain" -Trigger {
    $vbsPs = Join-Path $env:TEMP "ss_kc_all_chain_ps.vbs"
    Set-Content -Path $vbsPs -Value 'CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -Command Write-Host cscript-ps-chain", 0, True' -Encoding ASCII
    Start-Process -FilePath "cscript.exe" -ArgumentList "//B", $vbsPs -Wait
}

Write-Host ""
Write-Host "Phase 2 complete. Waiting 8 seconds for poll cycles to catch up..."
Start-Sleep -Seconds 8
Write-Host "Check the browser now. INITIAL ACCESS card should be coloured."
Write-Host "Press Enter to continue to Phase 3."
Read-Host | Out-Null

# ============================================================================
# PHASE 3 - Network and API rules
# ============================================================================
Write-Host ""
Write-Host "=== Phase 3: Command and Control + API (Defense Evasion) ==="
Write-Host "Techniques: PowerShell outbound TCP, OpenProcess, CreateRemoteThread"
Write-Host "Watch for: COMMAND AND CONTROL and additional DEFENSE EVASION hits"
Write-Host ""

Write-Host "  (Network test uses example.com - allow ~15s for connection + Sysmon capture)"
Invoke-Technique -RuleId "NET_POWERSHELL_HTTP_001" -Tactic "Command and Control" -Description "PowerShell outbound HTTP/HTTPS to example.com" -Trigger {
    Invoke-NetworkC2Test
} -PostDelaySeconds 6

Invoke-Technique -RuleId "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" -Tactic "Defense Evasion" -Description "OpenProcess -> lsass" -Trigger {
    Invoke-OpenProcessLsassTest
}

Invoke-Technique -RuleId "API_CREATE_REMOTE_THREAD_001" -Tactic "Defense Evasion" -Description "CreateRemoteThread cross-image" -Trigger {
    Invoke-CreateRemoteThreadTest
}

Write-Host ""
Write-Host "Phase 3 complete. Waiting 8 seconds for final poll cycles..."
Start-Sleep -Seconds 8

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host ""
Write-Host "========================================"
Write-Host "  Full Kill Chain Verification Complete"
Write-Host "========================================"
Write-Host ""
Write-Host "In the browser, you should now see:"
foreach ($tactic in $coveredTactics) {
    Write-Host "  - $tactic card coloured with hit count > 0"
}
Write-Host "  - Credential Access card remains grey (no rules yet - expected)"
Write-Host ""
Write-Host "To verify the expansion panel:"
Write-Host "  1. Click any coloured tactic card"
Write-Host "  2. Confirm the rule breakdown table appears with hit counts"
Write-Host "  3. Click View in Alert Feed to jump to filtered alerts"
Write-Host "  4. Click Collapse to close the panel"
Write-Host "  5. Confirm the 5-second poll does NOT close expanded panels"
Write-Host "     (wait 6 seconds with a panel open and check it stays)"
Write-Host ""
Write-Host "To verify the time range selector:"
Write-Host "  - Switch from 24h to 15m - cards should still show (fired recently)"
Write-Host "  - Switch to 7d - same cards, same or higher counts"
Write-Host ""
Write-Host "To verify theme:"
Write-Host "  - Click the theme toggle in the sidebar"
Write-Host "  - Confirm kill chain cards are readable in light mode"
Write-Host ""
Write-Host "Pipeline can now be stopped with Ctrl+C in its terminal."
Write-Host "========================================"
Write-Host ""
