"""Category B Subphase 1 tests: CHAIN_SCHEDULED_TASK_SCRIPT_001 path-based fix."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import ProcessCreateEvent
from rules.engine import RuleEngine

RULE_ID = "CHAIN_SCHEDULED_TASK_SCRIPT_001"
SIBLING_ID = "CHAIN_SCHEDULED_TASK_SVCHOST_001"

TASKENG = r"C:\Windows\System32\taskeng.exe"
TASKHOSTW = r"C:\Windows\System32\taskhostw.exe"
SCHTASKS = r"C:\Windows\System32\schtasks.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WSCRIPT = r"C:\Windows\System32\wscript.exe"
CSCRIPT = r"C:\Windows\System32\cscript.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"


def _make_process_event(**kwargs) -> ProcessCreateEvent:
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-guid}",
        "process_id": 3344,
        "image": WSCRIPT,
        "command_line": "wscript.exe",
        "current_directory": "C:\\",
        "user": "TEST-HOST\\User",
        "parent_process_id": 2233,
        "parent_image": TASKENG,
        "parent_command_line": "taskeng.exe",
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
# True positives — path-based detection
# ---------------------------------------------------------------------------


def test_tp_taskeng_wscript_users_path(engine: RuleEngine):
    """Emotet-style user-profile staging."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=WSCRIPT,
        command_line=r"wscript.exe C:\Users\username\random.vbs",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskeng_cscript_programdata(engine: RuleEngine):
    """QakBot AppPool.vbs pattern — no network keywords in command line."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=CSCRIPT,
        command_line=r"cscript.exe /E:javascript C:\ProgramData\payload.wpl",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskhostw_powershell_programdata(engine: RuleEngine):
    """taskhostw.exe as valid modern parent for DLL-based tasks."""
    event = _make_process_event(
        parent_image=TASKHOSTW,
        image=PS,
        command_line=r"powershell.exe -File C:\ProgramData\update.ps1",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskhostw_wscript_windows_temp(engine: RuleEngine):
    """Windows\\Temp staging path."""
    event = _make_process_event(
        parent_image=TASKHOSTW,
        image=WSCRIPT,
        command_line=r"wscript.exe C:\Windows\Temp\stage2.vbs",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskeng_mshta_windows_tasks(engine: RuleEngine):
    """Windows\\Tasks path."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=MSHTA,
        command_line=r"mshta.exe C:\Windows\Tasks\payload.hta",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskhostw_wscript_appdata(engine: RuleEngine):
    """AppData\\ substring match."""
    event = _make_process_event(
        parent_image=TASKHOSTW,
        image=WSCRIPT,
        command_line=r"wscript.exe C:\Users\Public\AppData\script.vbs",
    )
    assert _hits(engine, event, RULE_ID)


def test_tp_taskeng_cscript_perflogs(engine: RuleEngine):
    """PerfLogs staging path."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=CSCRIPT,
        command_line=r"cscript.exe C:\PerfLogs\runner.js",
    )
    assert _hits(engine, event, RULE_ID)


# ---------------------------------------------------------------------------
# False positives / exclusions
# ---------------------------------------------------------------------------


def test_fp_schtasks_parent_does_not_fire(engine: RuleEngine):
    """schtasks.exe removed from parent_image — never a valid parent."""
    event = _make_process_event(
        parent_image=SCHTASKS,
        image=PS,
        command_line=r"powershell.exe C:\Users\user\script.ps1",
    )
    assert not _hits(engine, event, RULE_ID)


def test_fp_svchost_parent_does_not_fire(engine: RuleEngine):
    """svchost.exe not in parent_image — covered by sibling rule."""
    event = _make_process_event(
        parent_image=SVCHOST,
        image=WSCRIPT,
        command_line=r"wscript.exe C:\ProgramData\payload.vbs",
    )
    assert not _hits(engine, event, RULE_ID)


def test_fp_system32_path_excluded(engine: RuleEngine):
    """system32 path excluded — legitimate Windows maintenance task."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=PS,
        command_line=r"powershell.exe -File C:\Windows\System32\maintenance.ps1",
    )
    assert not _hits(engine, event, RULE_ID)


def test_fp_calluxxprovider_excluded(engine: RuleEngine):
    """Known-benign Windows path explicitly excluded."""
    event = _make_process_event(
        parent_image=TASKHOSTW,
        image=CSCRIPT,
        command_line=r"cscript.exe C:\Windows\system32\calluxxprovider.vbs",
    )
    assert not _hits(engine, event, RULE_ID)


def test_fp_program_files_vendor_path(engine: RuleEngine):
    """Trusted vendor path — not in suspicious path list."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=PS,
        command_line=r"powershell.exe -File C:\Program Files\Vendor\script.ps1",
    )
    assert not _hits(engine, event, RULE_ID)


def test_fp_no_suspicious_path(engine: RuleEngine):
    """No suspicious path in command line — path-based gate correctly rejects."""
    event = _make_process_event(
        parent_image=TASKENG,
        image=PS,
        command_line="powershell.exe -NonInteractive -WindowStyle Hidden",
    )
    assert not _hits(engine, event, RULE_ID)


# ---------------------------------------------------------------------------
# Sibling rule isolation
# ---------------------------------------------------------------------------


def test_sibling_svchost_rule_unchanged(engine: RuleEngine):
    """CHAIN_SCHEDULED_TASK_SVCHOST_001 still present with original conditions."""
    sibling = next((r for r in engine.rules if r.id == SIBLING_ID), None)
    assert sibling is not None

    parent_image_cond = next(
        c for c in sibling.conditions if c.field == "parent_image"
    )
    parent_cli_cond = next(
        c for c in sibling.conditions if c.field == "parent_command_line"
    )

    assert "svchost.exe" in parent_image_cond.values
    assert "-s Schedule" in parent_cli_cond.values
