# ShadowSensor Kill Chain - Execution Tactic Demo
# Run from repo root while pipeline + dashboard are active (Administrator):
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_execution.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================"
Write-Host "  Kill Chain: EXECUTION Tactic Demo"
Write-Host "========================================"
Write-Host ""
Write-Host "Watch the Kill Chain tab in your browser:"
Write-Host "  http://localhost:8080/dashboard/killchain"
Write-Host ""
Write-Host "The EXECUTION tactic card should turn coloured within 10 seconds"
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
    Write-Host "Expected: EXECUTION card hit count increases by 1"
    Write-Host ""

    & $Trigger

    Start-Sleep -Seconds 3

    Write-Host "Done. Check the browser now - poll refreshes every 5 seconds."
    Write-Host ""
}

# PS_ENCODED_CMD_001
Invoke-RuleSimulation -RuleId "PS_ENCODED_CMD_001" -Description "PowerShell launched with -EncodedCommand (T1059.001)" -Trigger {
    $enc = "JABjAG0AZAAgACcAVABlAHMAdAAnAA=="
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-EncodedCommand", $enc -WindowStyle Hidden -Wait
}

# PS_DOWNLOAD_CRADLE_001
Invoke-RuleSimulation -RuleId "PS_DOWNLOAD_CRADLE_001" -Description "PowerShell download cradle spawned from cmd.exe (T1059.001)" -Trigger {
    $cradle = 'powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://127.0.0.1/noop'')" '
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cradle -WindowStyle Hidden -Wait
}

# PS_HIDDEN_WINDOW_001
Invoke-RuleSimulation -RuleId "PS_HIDDEN_WINDOW_001" -Description "PowerShell launched with hidden window style (T1059.001)" -Trigger {
    $hidden = 'powershell.exe -NoProfile -W Hidden -Command "Write-Host hidden-test"'
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $hidden -WindowStyle Hidden -Wait
}

# CHAIN_SCRIPT_HOST_CMD_001
Invoke-RuleSimulation -RuleId "CHAIN_SCRIPT_HOST_CMD_001" -Description "Script host (wscript) spawning cmd.exe (T1059.005)" -Trigger {
    $vbsCmd = Join-Path $env:TEMP "ss_kc_chain_cmd.vbs"
    Set-Content -Path $vbsCmd -Value 'CreateObject("WScript.Shell").Run "cmd.exe /c echo wscript-cmd-chain", 0, True' -Encoding ASCII
    Start-Process -FilePath "wscript.exe" -ArgumentList "//B", $vbsCmd -Wait
}

# CHAIN_SCRIPT_HOST_POWERSHELL_001
Invoke-RuleSimulation -RuleId "CHAIN_SCRIPT_HOST_POWERSHELL_001" -Description "Script host (cscript) spawning PowerShell (T1059.005)" -Trigger {
    $vbsPs = Join-Path $env:TEMP "ss_kc_chain_ps.vbs"
    Set-Content -Path $vbsPs -Value 'CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -Command Write-Host cscript-ps-chain", 0, True' -Encoding ASCII
    Start-Process -FilePath "cscript.exe" -ArgumentList "//B", $vbsPs -Wait
}

Write-Host "========================================"
Write-Host "  Execution tactic simulation complete."
Write-Host ""
Write-Host "In the browser:"
Write-Host "  1. The EXECUTION card should show coloured border + hit count"
Write-Host "  2. Click the EXECUTION card to expand the detail panel"
Write-Host "  3. Confirm the rule breakdown table shows the rules above"
Write-Host "  4. Click View in Alert Feed to see the filtered alerts"
Write-Host "  5. Click Collapse to close the detail panel"
Write-Host "========================================"
Write-Host ""
