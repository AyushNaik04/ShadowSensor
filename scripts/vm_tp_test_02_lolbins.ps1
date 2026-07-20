# ShadowSensor VM true-positive test - LOLBin rules (4)
# Run from repo root while run_pipeline.py is active (Administrator).
#   cd Z:\
#   powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_02_lolbins.ps1

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

Write-Host "Part 2/3 - LOLBin rules (4 tests)" -ForegroundColor Green
Write-Host ""

Write-TestHeader "mshta.exe launch" "LOLBIN_MSHTA_001 (High)"
$mshtaArgs = 'vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""cmd /c echo mshta-test"",0"))'
Start-Process -FilePath "mshta.exe" -ArgumentList $mshtaArgs -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "rundll32 javascript protocol" "LOLBIN_RUNDLL32_SUSPICIOUS_001 (High)"
$rundllArgs = 'javascript:"\..\mshtml,RunHTMLApplication ";close()'
Start-Process -FilePath "rundll32.exe" -ArgumentList $rundllArgs -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "regsvr32 Squiblydoo" "LOLBIN_REGSVR32_001 (High)"
Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s", "/n", "/u", "/i:http://127.0.0.1/test.sct", "scrobj.dll" -WindowStyle Hidden -Wait
Wait-ForPipeline

Write-TestHeader "certutil -decode" "LOLBIN_CERTUTIL_001 (Medium)"
$testDir = Join-Path $env:TEMP "shadowsensor_test"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null
$b64Path = Join-Path $testDir "test.b64"
$outPath = Join-Path $testDir "test.out"
Set-Content -Path $b64Path -Value "dGVzdA==" -Encoding ASCII
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "certutil.exe -decode `"$b64Path`" `"$outPath`"" -Wait
Wait-ForPipeline

Write-Host ""
Write-Host "Done part 2. Expected hits:" -ForegroundColor Green
Write-Host "  LOLBIN_MSHTA_001, LOLBIN_RUNDLL32_SUSPICIOUS_001"
Write-Host "  LOLBIN_REGSVR32_001, LOLBIN_CERTUTIL_001"
