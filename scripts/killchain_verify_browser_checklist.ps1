# ShadowSensor Kill Chain - Interactive Browser Checklist
# Run from repo root after killchain_verify_all_tactics.ps1:
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_browser_checklist.ps1

$ErrorActionPreference = "Continue"

$results = @{}

$checklist = @(
    @{ id="CV-1";  text="DevTools Network tab: /dashboard/partials/killchain-overview requests appear every ~5 seconds" },
    @{ id="CV-2";  text="After running killchain_verify_all_tactics.ps1: at least one tactic card is coloured" },
    @{ id="CV-3";  text="The Updated timestamp resets after each poll cycle" },
    @{ id="CV-4";  text="Tactic cards appear in kill chain order (Initial Access first, Impact last)" },
    @{ id="CV-5";  text="Coverage summary shows X of 12 tactics observed with X > 0" },
    @{ id="CV-6";  text="Expanded panel stays visible after 6 seconds (poll does not wipe it)" },
    @{ id="C-1";   text="Click a fired card: inline panel expands below with Active Rules heading" },
    @{ id="C-2";   text="Expanded panel contains table columns: Rule ID, Technique, Hit Count, Last Seen, View Alerts" },
    @{ id="C-3";   text="Rule ID column shows identifier in monospace (e.g. PS_ENCODED_CMD_001)" },
    @{ id="C-4";   text="Hit Count column shows a numbered badge" },
    @{ id="C-5";   text="Last Seen column shows relative time (e.g. 2m ago), not a raw timestamp" },
    @{ id="C-6";   text="View in Alert Feed link navigates to /dashboard/alerts with rule filter applied" },
    @{ id="C-7";   text="Collapse button visible in panel header" },
    @{ id="C-8";   text="Click Collapse: panel disappears" },
    @{ id="C-9";   text="Click same card again: panel re-expands" },
    @{ id="C-10";  text="Expand two different cards simultaneously: both panels visible" },
    @{ id="C-11";  text="Wait 6s with two panels open: both still visible after poll fires" },
    @{ id="C-12";  text="Click a grey (not-fired) card: nothing happens, no error in console" },
    @{ id="C-13";  text="Fired cards have a subtle pulsing border glow animation" },
    @{ id="C-14";  text="Hover fired card: cursor is pointer. Hover grey card: cursor is default" },
    @{ id="C-15";  text="Stage detail panel has visible border and different background from page" },
    @{ id="C-16";  text="Dark theme: all kill chain elements use correct colours, no raw var() text visible" },
    @{ id="C-17";  text="Light mode (toggle): kill chain cards readable, no invisible text" },
    @{ id="C-18";  text="Hard refresh in light mode: theme persists" },
    @{ id="C-19";  text="All 10 dashboard pages load without error (killchain + 9 existing)" },
    @{ id="C-20";  text="Kill Chain nav item: active on /dashboard/killchain, inactive on other pages" }
)

Write-Host ""
Write-Host "========================================"
Write-Host "  Kill Chain Tab - Browser Checklist"
Write-Host "  Type PASS, FAIL, or SKIP for each item"
Write-Host "========================================"
Write-Host ""
Write-Host "Make sure the kill chain tab is open in your browser:"
Write-Host "  http://localhost:8080/dashboard/killchain"
Write-Host ""
Write-Host "Run scripts\killchain_verify_all_tactics.ps1 first if you have not already (to generate rule hits)."
Write-Host ""
Read-Host "Press Enter when ready" | Out-Null

foreach ($item in $checklist) {
    Write-Host ""
    Write-Host "[$($item.id)] $($item.text)"
    $response = Read-Host "Result (PASS/FAIL/SKIP)"
    $results[$item.id] = $response.Trim().ToUpper()
}

Write-Host ""
Write-Host "========================================"
Write-Host "  CHECKLIST SUMMARY"
Write-Host "========================================"

$passed = 0
$failed = 0
$skipped = 0

foreach ($item in $checklist) {
    $r = $results[$item.id]
    $symbol = if ($r -eq "PASS") { "[PASS]" } elseif ($r -eq "FAIL") { "[FAIL]" } else { "[SKIP]" }
    $preview = $item.text.Substring(0, [Math]::Min(60, $item.text.Length))
    Write-Host "$symbol $($item.id): $preview..."
    if ($r -eq "PASS") { $passed++ }
    elseif ($r -eq "FAIL") { $failed++ }
    else { $skipped++ }
}

Write-Host ""
Write-Host "Results: $passed PASS / $failed FAIL / $skipped SKIP"

if ($failed -eq 0 -and $skipped -eq 0) {
    Write-Host ""
    Write-Host "ALL ITEMS PASSED. Kill Chain tab verification complete."
    Write-Host "Gate C is PASS. The holding phase is fully closed."
    Write-Host "Next: Phase 4A - Full Rule Expansion."
} elseif ($failed -gt 0) {
    Write-Host ""
    Write-Host "FAILED ITEMS DETECTED. Review the failures above."
    Write-Host "Report them to the Prompt Agent before proceeding to Phase 4A."
}
