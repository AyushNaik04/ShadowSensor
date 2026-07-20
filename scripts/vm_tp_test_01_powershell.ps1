# ShadowSensor VM true-positive test - PowerShell rules (4)
# Run from repo root while run_pipeline.py is active (Administrator).
#   cd Z:\
#   powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_01_powershell.ps1

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
    param([int]$Seconds = 5)
    Write-Host "Waiting $Seconds seconds - watch pipeline for RULE_HIT..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Seconds
}

Write-Host "Part 1/3 - PowerShell rules (4 tests)" -ForegroundColor Green
Write-Host ""

Write-TestHeader "Encoded command" "PS_ENCODED_CMD_001 (High)"
$enc = "JABjAG0AZAAgACcAVABlAHMAdAAnAA=="
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $enc -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "AMSI bypass indicator" "PS_AMSI_BYPASS_001 (High)"
$amsi = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $amsi -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "Download cradle (cmd parent)" "PS_DOWNLOAD_CRADLE_001 (High)"
$cradle = 'powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1/noop'')" '
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cradle -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "Hidden window (cmd parent)" "PS_HIDDEN_WINDOW_001 (Medium)"
$hidden = 'powershell.exe -NoProfile -W Hidden -Command "Write-Host hidden-test"'
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $hidden -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-Host ""
Write-Host "Done part 1. Expected hits:" -ForegroundColor Green
Write-Host "  PS_ENCODED_CMD_001, PS_AMSI_BYPASS_001"
Write-Host "  PS_DOWNLOAD_CRADLE_001, PS_HIDDEN_WINDOW_001"
