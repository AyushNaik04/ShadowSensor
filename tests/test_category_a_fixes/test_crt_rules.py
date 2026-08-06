"""Category A Subphase 2 tests: CreateRemoteThread two-rule split."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import CreateRemoteThreadEvent
from rules.engine import RuleEngine

RULE_SUSPICIOUS_SOURCE = "API_CRT_SUSPICIOUS_SOURCE_001"
RULE_SENSITIVE_TARGET = "API_CRT_SENSITIVE_TARGET_001"


def _make_crt(**kwargs) -> CreateRemoteThreadEvent:
    """Create a CreateRemoteThreadEvent with sensible defaults for CRT rule tests."""
    defaults: dict = {
        "event_id": 8,
        "utc_time": "2026-06-23 10:00:00.000",
        "computer": "TEST-HOST",
        "source_process_id": 3000,
        "source_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "target_process_id": 4000,
        "target_image": r"C:\Windows\System32\notepad.exe",
        "new_thread_id": 5678,
        "start_address": "0x7fff1234abcd",
        "start_module": None,
        "start_function": None,
    }
    defaults.update(kwargs)
    return CreateRemoteThreadEvent(**defaults)


def _hits(engine: RuleEngine, event: CreateRemoteThreadEvent, rule_id: str) -> list:
    """Return matching RuleHit objects for rule_id."""
    return [h for h in engine.evaluate(event) if h.rule_id == rule_id]


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    """Shared RuleEngine instance loaded once per test module."""
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


# ---------------------------------------------------------------------------
# API_CRT_SUSPICIOUS_SOURCE_001 — true positives
# ---------------------------------------------------------------------------


def test_suspicious_source_powershell_to_notepad_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_wscript_to_svchost_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\wscript.exe",
        target_image=r"C:\Windows\System32\svchost.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_mshta_to_explorer_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\mshta.exe",
        target_image=r"C:\Windows\explorer.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_winword_to_notepad_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_msbuild_to_notepad_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_explorer_to_notepad_fires_critical(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\explorer.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


def test_suspicious_source_powershell_unknown_target_fires_critical(engine: RuleEngine):
    """Unresolvable target must not suppress detection."""
    event = _make_crt(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image="<unknown process>",
    )
    hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    assert hits
    assert hits[0].severity == "Critical"


# ---------------------------------------------------------------------------
# API_CRT_SUSPICIOUS_SOURCE_001 — false positives / exclusions
# ---------------------------------------------------------------------------


def test_suspicious_source_pipeline_python_does_not_fire(engine: RuleEngine):
    event = _make_crt(
        source_image=r"Z:\python_runtime\python.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    assert not _hits(engine, event, RULE_SUSPICIOUS_SOURCE)


def test_suspicious_source_svchost_does_not_fire(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\svchost.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
    )
    assert not _hits(engine, event, RULE_SUSPICIOUS_SOURCE)


def test_suspicious_source_wmiprvse_does_not_fire(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\wbem\wmiprvse.exe",
        target_image=r"C:\Windows\System32\winlogon.exe",
    )
    assert not _hits(engine, event, RULE_SUSPICIOUS_SOURCE)


# ---------------------------------------------------------------------------
# API_CRT_SENSITIVE_TARGET_001 — true positives
# ---------------------------------------------------------------------------


def test_sensitive_target_onedrive_to_lsass_fires_high(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    hits = _hits(engine, event, RULE_SENSITIVE_TARGET)
    assert hits
    assert hits[0].severity == "High"


def test_sensitive_target_chrome_to_winlogon_fires_high(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        target_image=r"C:\Windows\System32\winlogon.exe",
    )
    hits = _hits(engine, event, RULE_SENSITIVE_TARGET)
    assert hits
    assert hits[0].severity == "High"


def test_sensitive_target_notepad_to_csrss_fires_high(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\notepad.exe",
        target_image=r"C:\Windows\System32\csrss.exe",
    )
    hits = _hits(engine, event, RULE_SENSITIVE_TARGET)
    assert hits
    assert hits[0].severity == "High"


# ---------------------------------------------------------------------------
# API_CRT_SENSITIVE_TARGET_001 — false positives / exclusions
# ---------------------------------------------------------------------------


def test_sensitive_target_wmiprvse_excluded(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\wbem\wmiprvse.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    assert not _hits(engine, event, RULE_SENSITIVE_TARGET)


def test_sensitive_target_vmtoolsd_excluded(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
        target_image=r"C:\Windows\System32\winlogon.exe",
    )
    assert not _hits(engine, event, RULE_SENSITIVE_TARGET)


def test_sensitive_target_msmpeng_excluded(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    assert not _hits(engine, event, RULE_SENSITIVE_TARGET)


def test_sensitive_target_wininit_excluded(engine: RuleEngine):
    event = _make_crt(
        source_image=r"C:\Windows\System32\wininit.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    assert not _hits(engine, event, RULE_SENSITIVE_TARGET)


def test_sensitive_target_pipeline_python_excluded(engine: RuleEngine):
    event = _make_crt(
        source_image=r"Z:\python_runtime\python.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    assert not _hits(engine, event, RULE_SENSITIVE_TARGET)


# ---------------------------------------------------------------------------
# Dual-signal behavior (expected — not a bug)
# ---------------------------------------------------------------------------


def test_powershell_to_lsass_both_crt_rules_fire(engine: RuleEngine):
    """powershell→lsass: both rules fire — expected dual-signal behavior.

    API_CRT_SUSPICIOUS_SOURCE_001 fires Critical (suspicious source).
    API_CRT_SENSITIVE_TARGET_001 also fires High (sensitive target).
    Both firing is intentional corroboration, not a duplicate-alert bug.
    """
    event = _make_crt(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    source_hits = _hits(engine, event, RULE_SUSPICIOUS_SOURCE)
    target_hits = _hits(engine, event, RULE_SENSITIVE_TARGET)
    assert source_hits
    assert source_hits[0].severity == "Critical"
    assert target_hits
    assert target_hits[0].severity == "High"
