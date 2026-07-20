# ShadowSensor VM rule-hit smoke test
# Run ONLY in your isolated Win10 sandbox VM while run_pipeline.py is active.
#
# Usage (second window, while pipeline is running):
#   cd <repo-root>
#   powershell -ExecutionPolicy Bypass -File scripts\vm_rule_hit_test.ps1
#
# Each test spawns a NEW process so Sysmon Event ID 1 (ProcessCreate) fires.
# Watch the run_pipeline.py window for lines starting with RULE_HIT.

$ErrorActionPreference = "Continue"

function Write-TestHeader {
    param([string]$Name, [string]$ExpectedRule)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "TEST: $Name" -ForegroundColor Cyan
    Write-Host "Expected rule: $ExpectedRule" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
}

function Wait-ForPipeline {
    param([int]$Seconds = 5)
    Write-Host "Waiting ${Seconds}s — check run_pipeline.py for RULE_HIT..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Seconds
}

Write-Host "ShadowSensor rule-hit smoke test" -ForegroundColor Green
Write-Host "Make sure scripts\run_pipeline.py is running in another window (Administrator)." -ForegroundColor Green
Write-Host ""

# --- Test 1: Encoded command (always the easiest to verify) ---
Write-TestHeader "PowerShell encoded command" "PS_ENCODED_CMD_001 (High)"
# Base64 of:  Write-Host 'ShadowSensor-test'
$enc = "JABjAG0AZAAgACcAVABlAHMAdAAnAA=="
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $enc -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- Test 2: AMSI bypass indicator (string only — does not bypass AMSI) ---
Write-TestHeader "AMSI bypass indicator in command line" "PS_AMSI_BYPASS_001 (High)"
$amsiCmd = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $amsiCmd -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- Test 3: Download cradle via cmd parent (matches e2e true-positive pattern) ---
Write-TestHeader "Download cradle from cmd.exe parent" "PS_DOWNLOAD_CRADLE_001 (High)"
$cradle = 'powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1/noop'')" '
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cradle -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- Test 4: Hidden window from cmd parent ---
Write-TestHeader "Hidden-window PowerShell from cmd.exe" "PS_HIDDEN_WINDOW_001 (Medium)"
$hidden = 'powershell.exe -NoProfile -W Hidden -Command "Write-Host hidden-test"'
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $hidden -WindowStyle Hidden -Wait
Wait-ForPipeline

# --- Test 5: LOLBin — certutil decode (benign dummy files, no malware) ---
Write-TestHeader "certutil -decode" "LOLBIN_CERTUTIL_001 (Medium)"
$testDir = Join-Path $env:TEMP "shadowsensor_test"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null
$b64Path = Join-Path $testDir "test.b64"
$outPath = Join-Path $testDir "test.out"
# minimal base64 content (the word "test")
Set-Content -Path $b64Path -Value "dGVzdA==" -Encoding ASCII
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "certutil.exe -decode `"$b64Path`" `"$outPath`"" -Wait
Wait-ForPipeline

Write-Host ""
Write-Host "Done. Summary of expected hits in run_pipeline.py / logs\rule_hits.log:" -ForegroundColor Green
Write-Host "  PS_ENCODED_CMD_001      High" -ForegroundColor White
Write-Host "  PS_AMSI_BYPASS_001      High" -ForegroundColor White
Write-Host "  PS_DOWNLOAD_CRADLE_001  High" -ForegroundColor White
Write-Host "  PS_HIDDEN_WINDOW_001    Medium" -ForegroundColor White
Write-Host "  LOLBIN_CERTUTIL_001     Medium" -ForegroundColor White
Write-Host ""
Write-Host "If you saw NONE of these, check:" -ForegroundColor Yellow
Write-Host "  1. Pipeline running as Administrator from repo root" -ForegroundColor Yellow
Write-Host "  2. logs\.shadowsensor_bookmark.xml timestamp updates" -ForegroundColor Yellow
Write-Host "  3. Sysmon Operational log has new Event ID 1 entries" -ForegroundColor Yellow
