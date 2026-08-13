# ShadowSensor Phase 7A Subphase 6 - CreateRemoteThread (EID-8) telemetry generation (v3)
#
# v3 changes from v2:
#   - E6 fix: LoadLibraryA does not exist in ntdll.dll. Replaced with
#     RtlExitUserThread (a genuine ntdll.dll export) as the CreateRemoteThread
#     start address. No DLL-path parameter needed - VirtualAllocEx and
#     WriteProcessMemory removed entirely. Thread starts and immediately
#     terminates itself via RtlExitUserThread(0) - fully benign, no payload.

$ErrorActionPreference = "Continue"

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class CrtNative {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr attrs, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, out IntPtr threadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
}
"@

$PROCESS_ALL_ACCESS = [uint32]0x001F0FFF

function Invoke-CrtInjection {
    param([int]$TargetPid, [string]$Label)

    $hProcess = [CrtNative]::OpenProcess($PROCESS_ALL_ACCESS, $false, $TargetPid)
    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Host "ERROR ($Label): OpenProcess failed (Win32=$( [Runtime.InteropServices.Marshal]::GetLastWin32Error() ))." -ForegroundColor Red
        return
    }

    $hNtdll = [CrtNative]::GetModuleHandle("ntdll.dll")
    $exitThreadAddr = [CrtNative]::GetProcAddress($hNtdll, "RtlExitUserThread")
    if ($exitThreadAddr -eq [IntPtr]::Zero) {
        Write-Host "ERROR ($Label): GetProcAddress(RtlExitUserThread) failed." -ForegroundColor Red
        [void][CrtNative]::CloseHandle($hProcess)
        return
    }

    $threadId = [IntPtr]::Zero
    $hThread = [CrtNative]::CreateRemoteThread($hProcess, [IntPtr]::Zero, [uint32]0, $exitThreadAddr, [IntPtr]::Zero, [uint32]0, [ref]$threadId)
    if ($hThread -eq [IntPtr]::Zero) {
        Write-Host "ERROR ($Label): CreateRemoteThread failed (Win32=$( [Runtime.InteropServices.Marshal]::GetLastWin32Error() ))." -ForegroundColor Red
        [void][CrtNative]::CloseHandle($hProcess)
        return
    }

    [void][CrtNative]::CloseHandle($hThread)
    [void][CrtNative]::CloseHandle($hProcess)
    Write-Host "$Label complete. Target PID: $TargetPid"
}

Write-Host "=== Part 1: API_CRT_SENSITIVE_TARGET_001 (direct injection -> lsass.exe) ==="
$lsassPid = (Get-Process lsass).Id
Invoke-CrtInjection -TargetPid $lsassPid -Label "Part 1"

Start-Sleep -Seconds 10

Write-Host "=== Part 2: API_CRT_SUSPICIOUS_SOURCE_001 (direct injection -> notepad.exe) ==="
Start-Process notepad
$targetPid = $null
$waited = 0
while (-not $targetPid -and $waited -lt 15) {
    Start-Sleep -Seconds 1
    $waited++
    $proc = Get-Process notepad -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { $targetPid = $proc.Id }
}

if (-not $targetPid) {
    Write-Host "ERROR (Part 2): notepad.exe did not appear within 15 seconds. Skipping." -ForegroundColor Red
} else {
    Write-Host "notepad.exe found after $waited second(s), PID: $targetPid"
    Invoke-CrtInjection -TargetPid $targetPid -Label "Part 2"
    Stop-Process -Name notepad -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 10
Write-Host "Both parts finished. Check pipeline output for API_CRT_SENSITIVE_TARGET_001 and API_CRT_SUSPICIOUS_SOURCE_001."
