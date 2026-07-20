# ShadowSensor Kill Chain Tab - Pre-flight Check
# Run from repo root (Administrator):
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_setup.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "ShadowSensor Kill Chain Tab - Pre-flight Check"
Write-Host ""

# --- 1. Pipeline running? ---
$pipelineRunning = $false
try {
    $pipelineRunning = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*run_pipeline.py*' }).Count -gt 0
} catch {
    Write-Host '[WARN] Could not inspect process list:' $_
}

if ($pipelineRunning) {
    Write-Host '[OK] Pipeline is running'
} else {
    Write-Host '[WARN] Pipeline does not appear to be running.'
    Write-Host 'Start it with: python_runtime\python.exe scripts\run_pipeline.py'
    Write-Host 'Run this script again after starting the pipeline.'
    exit 1
}

# --- 2. Dashboard health ---
$dashboardOk = $false
try {
    $health = Invoke-WebRequest -Uri 'http://localhost:8080/api/v1/health' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    if ($health.StatusCode -eq 200 -or ($health.Content -match 'ok')) {
        $dashboardOk = $true
    }
} catch {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'ShadowSensor-Preflight')
        $content = $wc.DownloadString('http://localhost:8080/api/v1/health')
        if ($content -match 'ok') { $dashboardOk = $true }
    } catch {
        Write-Host '[WARN] Dashboard health check failed:' $_
    }
}

if ($dashboardOk) {
    Write-Host '[OK] Dashboard is running at http://localhost:8080'
} else {
    Write-Host '[WARN] Dashboard does not appear to be running.'
    Write-Host 'Start it with: python_runtime\python.exe scripts\run_dashboard.py'
    exit 1
}

# --- 3. Kill Chain page ---
$killchainOk = $false
try {
    $kc = Invoke-WebRequest -Uri 'http://localhost:8080/dashboard/killchain' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    if ($kc.StatusCode -eq 200) { $killchainOk = $true }
} catch {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'ShadowSensor-Preflight')
        $null = $wc.DownloadString('http://localhost:8080/dashboard/killchain')
        $killchainOk = $true
    } catch {
        Write-Host '[FAIL] Kill Chain tab returned an error - check dashboard logs'
        exit 1
    }
}

if ($killchainOk) {
    Write-Host '[OK] Kill Chain tab is reachable'
} else {
    Write-Host '[FAIL] Kill Chain tab returned an error - check dashboard logs'
    exit 1
}

# --- 4. Rules loaded ---
try {
    $rulesResponse = Invoke-WebRequest -Uri 'http://localhost:8080/api/v1/rules' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    $rulesJson = $rulesResponse.Content | ConvertFrom-Json
} catch {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'ShadowSensor-Preflight')
        $rulesJson = ($wc.DownloadString('http://localhost:8080/api/v1/rules')) | ConvertFrom-Json
    } catch {
        Write-Host '[WARN] Could not fetch rules list:' $_
        $rulesJson = $null
    }
}

if ($rulesJson) {
    $ruleList = @($rulesJson)
    $count = $ruleList.Count
    Write-Host "[OK] $count rules loaded"

    $tactics = @($ruleList | ForEach-Object {
            if ($_.PSObject.Properties['mitre_tactic']) { $_.mitre_tactic }
            elseif ($_.PSObject.Properties['tactic']) { $_.tactic }
        } | Where-Object { $_ } | Sort-Object -Unique)

    if ($tactics.Count -gt 0) {
        Write-Host "[INFO] Tactics covered: $($tactics -join ', ')"
    } else {
        Write-Host '[INFO] Tactics covered: (could not parse tactic fields from API response)'
    }
} else {
    Write-Host '[WARN] Rules API unavailable - continuing without rule count'
}

# --- 5. Ready message ---
Write-Host ""
Write-Host "Environment is ready. Open your browser to:"
Write-Host "  http://localhost:8080/dashboard/killchain"
Write-Host "Then run one of the following scripts:"
Write-Host "  scripts\killchain_verify_execution.ps1       (Execution tactic)"
Write-Host "  scripts\killchain_verify_defense_evasion.ps1 (Defense Evasion tactic)"
Write-Host "  scripts\killchain_verify_all_tactics.ps1     (All tactics in sequence)"
Write-Host ""
