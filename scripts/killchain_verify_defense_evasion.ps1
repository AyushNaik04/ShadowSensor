# ShadowSensor Kill Chain - Defense Evasion Tactic Demo
# Run from repo root while pipeline + dashboard are active (Administrator):
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_defense_evasion.ps1

$ErrorActionPreference = "Continue"

function Invoke-OpenProcessLsassTest {
    $repoRoot = (Get-Location).Path
    $pyExe = Join-Path $repoRoot "python_runtime\python.exe"
    $pyScript = Join-Path $env:TEMP "ss_kc_openprocess_lsass.py"
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
        Write-Host '  [WARN] python_runtime\python.exe not found - skipping OpenProcess simulation'
    }
}

function Invoke-CreateRemoteThreadTest {
    param([string]$ScriptSuffix = "kc")
    $crtPs = Join-Path $env:TEMP "ss_${ScriptSuffix}_crt_test.ps1"
    $crtCode = @'
$cs = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class SsKcCrt {
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
[SsKcCrt]::Run()
'@
    Set-Content -Path $crtPs -Value $crtCode -Encoding ASCII
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $crtPs -WindowStyle Hidden -Wait
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Kill Chain: DEFENSE EVASION Tactic Demo"
Write-Host "========================================"
Write-Host ""
Write-Host "Watch the Kill Chain tab in your browser:"
Write-Host "  http://localhost:8080/dashboard/killchain"
Write-Host ""
Write-Host "The DEFENSE EVASION tactic card should turn coloured within 10 seconds"
Write-Host "after each technique below is simulated."
Write-Host ""
Write-Host "Press Enter to begin, or Ctrl+C to cancel."
Read-Host | Out-Null

function Invoke-RuleSimulation {
    param(
        [string]$RuleId,
        [string]$Description,
        [scriptblock]$Trigger
    )

    Write-Host ""
    Write-Host "--- Simulating: $RuleId ---"
    Write-Host "Technique: $Description"
    Write-Host "Expected: DEFENSE EVASION card hit count increases by 1"
    Write-Host ""

    & $Trigger

    Start-Sleep -Seconds 3

    Write-Host "Done. Check the browser now - poll refreshes every 5 seconds."
    Write-Host ""
}

# PS_AMSI_BYPASS_001
Invoke-RuleSimulation -RuleId "PS_AMSI_BYPASS_001" -Description "PowerShell AMSI bypass indicator in command line (T1562.001)" -Trigger {
    $amsiCmd = 'powershell.exe -NoProfile -Command "[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')" '
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $amsiCmd -WindowStyle Hidden -Wait
}

# LOLBIN_MSHTA_001
Invoke-RuleSimulation -RuleId "LOLBIN_MSHTA_001" -Description "mshta.exe LOLBin execution (T1218.005)" -Trigger {
    $mshtaArgs = 'vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""cmd /c echo mshta-test"",0"))'
    Start-Process -FilePath "mshta.exe" -ArgumentList $mshtaArgs -WindowStyle Hidden -Wait
}

# LOLBIN_RUNDLL32_SUSPICIOUS_001
Invoke-RuleSimulation -RuleId "LOLBIN_RUNDLL32_SUSPICIOUS_001" -Description "rundll32.exe with JavaScript protocol handler (T1218.011)" -Trigger {
    $rundllLine = 'C:\Windows\System32\rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";close()'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $rundllLine -WindowStyle Hidden -Wait
}

# LOLBIN_REGSVR32_001
Invoke-RuleSimulation -RuleId "LOLBIN_REGSVR32_001" -Description "regsvr32 Squiblydoo remote script technique (T1218.010)" -Trigger {
    $regsvrLine = 'C:\Windows\System32\regsvr32.exe /s /n /u /i:http://127.0.0.1/test.sct scrobj.dll'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $regsvrLine -WindowStyle Hidden -Wait
}

# LOLBIN_CERTUTIL_001
Invoke-RuleSimulation -RuleId "LOLBIN_CERTUTIL_001" -Description "certutil.exe Base64 decode (T1140)" -Trigger {
    $testDir = Join-Path $env:TEMP "shadowsensor_test"
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $b64Path = Join-Path $testDir "test.b64"
    $outPath = Join-Path $testDir "test.out"
    Set-Content -Path $b64Path -Value "dGVzdA==" -Encoding ASCII
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "certutil.exe -decode `"$b64Path`" `"$outPath`"" -Wait
}

# API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001
Invoke-RuleSimulation -RuleId "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" -Description "OpenProcess with broad access targeting lsass.exe (T1055)" -Trigger {
    Invoke-OpenProcessLsassTest
}

# API_CREATE_REMOTE_THREAD_001
Invoke-RuleSimulation -RuleId "API_CREATE_REMOTE_THREAD_001" -Description "CreateRemoteThread cross-process injection into notepad (T1055)" -Trigger {
    Invoke-CreateRemoteThreadTest -ScriptSuffix "kc"
}

Write-Host "========================================"
Write-Host "  Defense Evasion tactic simulation complete."
Write-Host ""
Write-Host "In the browser:"
Write-Host "  1. The DEFENSE EVASION card should show coloured border + hit count"
Write-Host "  2. Click the DEFENSE EVASION card to expand the detail panel"
Write-Host "  3. Confirm the rule breakdown table shows the rules above"
Write-Host "  4. Click View in Alert Feed to see the filtered alerts"
Write-Host "  5. Click Collapse to close the detail panel"
Write-Host "========================================"
Write-Host ""
