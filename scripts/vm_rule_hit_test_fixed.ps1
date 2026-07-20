# ShadowSensor VM rule-hit smoke test
# Run in sandbox VM while run_pipeline.py is active (Administrator).
#
#   cd Z:\
#   powershell -ExecutionPolicy Bypass -File scripts\vm_rule_hit_test.ps1

$ErrorActionPreference = "Continue"

function Write-TestHeader {
    param(
        [string]$Name,
        [string]$ExpectedRule
    )
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "TEST: $Name" -ForegroundColor Cyan
    Write-Host "Expected rule: $ExpectedRule" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
}

function Wait-ForPipeline {
    param([int]$Seconds = 5)
    Write-Host "Waiting $Seconds seconds - check run_pipeline.py for RULE_HIT..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Seconds
}

Write-Host "ShadowSensor rule-hit smoke test" -ForegroundColor Green
Write-Host "Pipeline must be running in another Admin window." -ForegroundColor Green
Write-Host ""

# Test 1: Encoded command
Write-TestHeader "PowerShell encoded command" "PS_ENCODED_CMD_001 (High)"
$enc = "JABjAG0AZAAgACcAVABlAHMAdAAnAA=="
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $enc -WindowStyle Hidden -Wait
Wait-ForPipeline

# Test 2: AMSI bypass indicator (string reference only, does not bypass AMSI)
Write-TestHeader "AMSI bypass indicator in command line" "PS_AMSI_BYPASS_001 (High)"
$amsiCmd = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $amsiCmd -WindowStyle Hidden -Wait
Wait-ForPipeline

# Test 3: Download cradle via cmd parent
Write-TestHeader "Download cradle from cmd.exe parent" "PS_DOWNLOAD_CRADLE_001 (High)"
$cradle = 'powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1/noop'')" '
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cradle -WindowStyle Hidden -Wait
Wait-ForPipeline

# Test 4: Hidden window from cmd parent
Write-TestHeader "Hidden-window PowerShell from cmd.exe" "PS_HIDDEN_WINDOW_001 (Medium)"
$hidden = 'powershell.exe -NoProfile -W Hidden -Command "Write-Host hidden-test"'
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $hidden -WindowStyle Hidden -Wait
Wait-ForPipeline

# Test 5: certutil decode (benign dummy files)
Write-TestHeader "certutil -decode" "LOLBIN_CERTUTIL_001 (Medium)"
$testDir = Join-Path $env:TEMP "shadowsensor_test"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null
$b64Path = Join-Path $testDir "test.b64"
$outPath = Join-Path $testDir "test.out"
Set-Content -Path $b64Path -Value "dGVzdA==" -Encoding ASCII
$certArgs = "/c certutil.exe -decode `"$b64Path`" `"$outPath`""
Start-Process -FilePath "cmd.exe" -ArgumentList $certArgs -Wait
Wait-ForPipeline

Write-Host ""
Write-Host "Done. Expected RULE_HIT rules:" -ForegroundColor Green
Write-Host "  PS_ENCODED_CMD_001      High"
Write-Host "  PS_AMSI_BYPASS_001      High"
Write-Host "  PS_DOWNLOAD_CRADLE_001  High"
Write-Host "  PS_HIDDEN_WINDOW_001    Medium"
Write-Host "  LOLBIN_CERTUTIL_001     Medium"
