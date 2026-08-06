"""Category A Subphase 3 tests: NET_SCRIPT_ENGINE_OUTBOUND_001."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import NetworkConnectEvent
from rules.engine import RuleEngine

RULE_SCRIPT_OUTBOUND = "NET_SCRIPT_ENGINE_OUTBOUND_001"
RULE_PS_HTTP = "NET_POWERSHELL_HTTP_001"


def _make_network_event(**kwargs) -> NetworkConnectEvent:
    """Create a NetworkConnectEvent with sensible defaults for network rule tests."""
    defaults: dict = {
        "event_id": 3,
        "utc_time": "2026-06-22 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{net-guid}",
        "process_id": 2345,
        "image": r"C:\Windows\System32\wscript.exe",
        "user": "TEST-HOST\\User",
        "protocol": "tcp",
        "initiated": True,
        "source_ip": "192.168.1.100",
        "source_port": 54321,
        "destination_ip": "8.8.8.8",
        "destination_hostname": "example.com",
        "destination_port": 443,
    }
    defaults.update(kwargs)
    return NetworkConnectEvent(**defaults)


def _hits(engine: RuleEngine, event: NetworkConnectEvent, rule_id: str) -> list:
    """Return matching RuleHit objects for rule_id."""
    return [h for h in engine.evaluate(event) if h.rule_id == rule_id]


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    """Shared RuleEngine instance loaded once per test module."""
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


def test_wscript_outbound_fires_high(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\wscript.exe",
        initiated=True,
    )
    hits = _hits(engine, event, RULE_SCRIPT_OUTBOUND)
    assert hits
    assert hits[0].severity == "High"


def test_cscript_outbound_fires_high(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\cscript.exe",
        initiated=True,
    )
    hits = _hits(engine, event, RULE_SCRIPT_OUTBOUND)
    assert hits
    assert hits[0].severity == "High"


def test_mshta_outbound_fires_high(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\mshta.exe",
        initiated=True,
    )
    hits = _hits(engine, event, RULE_SCRIPT_OUTBOUND)
    assert hits
    assert hits[0].severity == "High"


# ---------------------------------------------------------------------------
# False positives / exclusions
# ---------------------------------------------------------------------------


def test_wscript_inbound_does_not_fire(engine: RuleEngine):
    """Inbound connection (initiated=false) is not suspicious for this rule."""
    event = _make_network_event(
        image=r"C:\Windows\System32\wscript.exe",
        initiated=False,
    )
    assert not _hits(engine, event, RULE_SCRIPT_OUTBOUND)


def test_powershell_outbound_does_not_fire_script_engine_rule(engine: RuleEngine):
    """powershell.exe is intentionally excluded — covered by NET_POWERSHELL_HTTP_001."""
    event = _make_network_event(
        image=r"C:\Windows\System32\powershell.exe",
        initiated=True,
    )
    assert not _hits(engine, event, RULE_SCRIPT_OUTBOUND)


def test_svchost_outbound_does_not_fire(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\svchost.exe",
        initiated=True,
    )
    assert not _hits(engine, event, RULE_SCRIPT_OUTBOUND)


# ---------------------------------------------------------------------------
# No overlap with NET_POWERSHELL_HTTP_001
# ---------------------------------------------------------------------------


def test_powershell_fires_ps_http_not_script_engine_outbound(engine: RuleEngine):
    """powershell outbound HTTP fires NET_POWERSHELL_HTTP_001 only — no duplicate."""
    event = _make_network_event(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        initiated=True,
        destination_port=443,
        destination_hostname="evil.com",
    )
    ps_hits = _hits(engine, event, RULE_PS_HTTP)
    script_hits = _hits(engine, event, RULE_SCRIPT_OUTBOUND)
    assert ps_hits
    assert not script_hits
