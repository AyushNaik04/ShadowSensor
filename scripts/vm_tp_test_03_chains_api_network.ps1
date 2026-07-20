# ShadowSensor VM true-positive test - parent chains, network, API rules (7)
# Run from repo root while run_pipeline.py is active (Administrator).
#   cd Z:\
#   powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_03_chains_api_network.ps1
#
# Office chain tests use a cmd.exe copy renamed winword.exe in TEMP (sandbox only).
# API tests simulate technique patterns only - isolated VM use.

$ErrorActionPreference = "Continue"

function Write-TestHeader {
    param([string]$Name, [string]$ExpectedRule)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "TEST: $Name" -ForegroundColor Cyan
    Write-Host "Expected: $ExpectedRule" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
}

function Wait-ForPipeline {
    param([int]$Seconds = 6)
    Write-Host "Waiting $Seconds seconds - watch pipeline for RULE_HIT..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Seconds
}

Write-Host "Part 3/3 - Parent chains, network, API rules (7 tests)" -ForegroundColor Green
Write-Host ""

# --- Parent chain: fake Office parent (winword.exe copy) ---
$fakeWord = Join-Path $env:TEMP "winword.exe"
Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination $fakeWord -Force

Write-TestHeader "Office -> PowerShell chain (simulated)" "CHAIN_OFFICE_POWERSHELL_001 (High)"
Start-Process -FilePath $fakeWord -ArgumentList '/c', 'powershell.exe -NoProfile -Command "Write-Host office-ps-chain"' -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "Office -> cmd chain (simulated)" "CHAIN_OFFICE_CMD_001 (High)"
Start-Process -FilePath $fakeWord -ArgumentList '/c', 'cmd.exe /c echo office-cmd-chain' -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- Script host chains ---
$vbsCmd = Join-Path $env:TEMP "ss_chain_cmd.vbs"
Set-Content -Path $vbsCmd -Value 'CreateObject("WScript.Shell").Run "cmd.exe /c echo wscript-cmd-chain", 0, True' -Encoding ASCII

Write-TestHeader "wscript -> cmd chain" "CHAIN_SCRIPT_HOST_CMD_001 (High)"
Start-Process -FilePath "wscript.exe" -ArgumentList "//B", $vbsCmd -Wait
Wait-ForPipeline

$vbsPs = Join-Path $env:TEMP "ss_chain_ps.vbs"
Set-Content -Path $vbsPs -Value 'CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -Command Write-Host cscript-ps-chain", 0, True' -Encoding ASCII

Write-TestHeader "cscript -> PowerShell chain" "CHAIN_SCRIPT_HOST_POWERSHELL_001 (High)"
Start-Process -FilePath "cscript.exe" -ArgumentList "//B", $vbsPs -Wait
Wait-ForPipeline

# --- Network: outbound PS to non-Microsoft host (connection may fail) ---
Write-TestHeader "PowerShell outbound TCP :443" "NET_POWERSHELL_HTTP_001 (High)"
$netCmd = 'try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("185.220.101.42", 443) } catch { }'
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $netCmd -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- OpenProcess: python opens lsass with broad access ---
Write-TestHeader "OpenProcess -> lsass (python)" "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 (High)"
$repoRoot = (Get-Location).Path
$pyExe = Join-Path $repoRoot "python_runtime\python.exe"
$pyScript = Join-Path $env:TEMP "ss_openprocess_lsass.py"
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
    Write-Host "SKIP: python_runtime\python.exe not found" -ForegroundColor Red
}
Wait-ForPipeline

# --- CreateRemoteThread: minimal cross-process thread into notepad ---
Write-TestHeader "CreateRemoteThread cross-image" "API_CREATE_REMOTE_THREAD_001 (Critical)"
$crtPs = Join-Path $env:TEMP "ss_crt_test.ps1"
$crtCode = @'
$cs = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class SsCrt {
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
[SsCrt]::Run()
'@
Set-Content -Path $crtPs -Value $crtCode -Encoding ASCII
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $crtPs -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-Host ""
Write-Host "Done part 3. Expected hits:" -ForegroundColor Green
Write-Host "  CHAIN_OFFICE_POWERSHELL_001, CHAIN_OFFICE_CMD_001"
Write-Host "  CHAIN_SCRIPT_HOST_CMD_001, CHAIN_SCRIPT_HOST_POWERSHELL_001"
Write-Host "  NET_POWERSHELL_HTTP_001"
Write-Host "  API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001"
Write-Host "  API_CREATE_REMOTE_THREAD_001"
Write-Host ""
Write-Host "All 15 rules: run parts 1, 2, and 3 in order." -ForegroundColor Cyan
