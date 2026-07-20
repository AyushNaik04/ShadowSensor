# ShadowSensor Kill Chain - Credential Access Tactic Demo
# Run from repo root while pipeline + dashboard are active (Administrator):
#   cd "\\vmware-host\Shared Folders\filelessmalware"
#   powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_credential_access.ps1
#
# Current ruleset (15 rules): no rules map to Credential Access.
# API_OPEN_PROCESS targets lsass but is classified as Defense Evasion (T1055).

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================"
Write-Host "  Kill Chain: CREDENTIAL ACCESS Tactic Demo"
Write-Host "========================================"
Write-Host ""
Write-Host "No rules currently mapped to the Credential Access tactic."
Write-Host "The Credential Access card will remain grey - this is expected."
Write-Host "This tactic will be covered when Phase 4A expands the rule set."
Write-Host ""

exit 0
