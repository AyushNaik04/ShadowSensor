"""Phase 4A Subphase 4 — network rule expansion tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import DnsQueryEvent, NetworkConnectEvent
from rules.engine import RuleEngine


def _make_network_event(**kwargs) -> NetworkConnectEvent:
    defaults: dict = {
        "event_id": 3,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{test-net-guid}",
        "process_id": 2345,
        "image": r"C:\Windows\System32\wscript.exe",
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


def _make_dns_event(**kwargs) -> DnsQueryEvent:
    defaults: dict = {
        "event_id": 22,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_id": 3333,
        "image": r"C:\Windows\System32\wscript.exe",
        "query_name": "example.com",
        "query_status": "0",
        "query_results": "93.184.216.34",
    }
    defaults.update(kwargs)
    return DnsQueryEvent(**defaults)


def _hits(engine: RuleEngine, event, rule_id: str) -> bool:
    return any(h.rule_id == rule_id for h in engine.evaluate(event))


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def test_net_scripting_engine_http_fires(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\cscript.exe",
        initiated=True,
        destination_port=80,
    )
    assert _hits(engine, event, "NET_SCRIPTING_ENGINE_HTTP_001")


def test_net_scripting_engine_http_not_firing_on_wrong_port(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\wscript.exe",
        initiated=True,
        destination_port=53,
    )
    assert not _hits(engine, event, "NET_SCRIPTING_ENGINE_HTTP_001")


def test_net_lolbin_process_http_fires(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\mshta.exe",
        initiated=True,
        destination_port=443,
    )
    assert _hits(engine, event, "NET_LOLBIN_PROCESS_HTTP_001")


def test_net_lolbin_process_http_not_firing_on_non_lolbin(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        initiated=True,
        destination_port=443,
    )
    assert not _hits(engine, event, "NET_LOLBIN_PROCESS_HTTP_001")


def test_net_suspicious_port_fires(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\notepad.exe",
        initiated=True,
        destination_port=4444,
    )
    assert _hits(engine, event, "NET_SUSPICIOUS_PORT_001")


def test_net_suspicious_port_not_firing_on_common_port(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\notepad.exe",
        initiated=True,
        destination_port=443,
    )
    assert not _hits(engine, event, "NET_SUSPICIOUS_PORT_001")


def test_net_lolbin_network_fires(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe",
        initiated=True,
        destination_port=8080,
    )
    assert _hits(engine, event, "NET_LOLBIN_NETWORK_001")


def test_net_lolbin_network_not_firing_for_benign_process(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\cmd.exe",
        initiated=True,
        destination_port=8080,
    )
    assert not _hits(engine, event, "NET_LOLBIN_NETWORK_001")


def test_net_smb_lateral_fires(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Users\Public\agent.exe",
        initiated=True,
        destination_port=445,
    )
    assert _hits(engine, event, "NET_SMB_LATERAL_001")


def test_net_smb_lateral_not_firing_for_excluded_process(engine: RuleEngine):
    event = _make_network_event(
        image=r"C:\Windows\System32\svchost.exe",
        initiated=True,
        destination_port=445,
    )
    assert not _hits(engine, event, "NET_SMB_LATERAL_001")


def test_net_dns_long_query_fires(engine: RuleEngine):
    event = _make_dns_event(
        image=r"C:\Windows\System32\wscript.exe",
        query_name="a" * 60 + ".example.com",
    )
    assert _hits(engine, event, "NET_DNS_LONG_QUERY_001")


def test_net_dns_long_query_not_firing_on_short_query(engine: RuleEngine):
    event = _make_dns_event(
        image=r"C:\Windows\System32\wscript.exe",
        query_name="short.example.com",
    )
    assert not _hits(engine, event, "NET_DNS_LONG_QUERY_001")


def test_net_dns_long_query_powershell_true_positive(engine: RuleEngine):
    event = _make_dns_event(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        query_name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
    )
    assert _hits(engine, event, "NET_DNS_LONG_QUERY_001")


def test_net_dns_long_query_searchapp_excluded(engine: RuleEngine):
    event = _make_dns_event(
        image=(
            r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy"
            r"\SearchApp.exe"
        ),
        query_name="b59dd060c31a5268a4dd55e6dc581400.azr.footprintdns.com",
    )
    assert not _hits(engine, event, "NET_DNS_LONG_QUERY_001")


def test_net_dns_long_query_threshold_edges_preserved(engine: RuleEngine):
    query_49_chars = ("a" * 37) + ".example.com"
    query_50_chars = ("a" * 38) + ".example.com"
    query_51_chars = ("a" * 39) + ".example.com"

    powershell_image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    searchapp_image = (
        r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe"
    )

    assert not _hits(
        engine,
        _make_dns_event(image=powershell_image, query_name=query_49_chars),
        "NET_DNS_LONG_QUERY_001",
    )
    assert _hits(
        engine,
        _make_dns_event(image=powershell_image, query_name=query_50_chars),
        "NET_DNS_LONG_QUERY_001",
    )
    assert _hits(
        engine,
        _make_dns_event(image=powershell_image, query_name=query_51_chars),
        "NET_DNS_LONG_QUERY_001",
    )
    assert not _hits(
        engine,
        _make_dns_event(image=searchapp_image, query_name=query_51_chars),
        "NET_DNS_LONG_QUERY_001",
    )


def test_net_dns_script_engine_fires(engine: RuleEngine):
    event = _make_dns_event(
        image=r"C:\Windows\System32\wscript.exe",
        query_name="malicious-control.example",
    )
    assert _hits(engine, event, "NET_DNS_SCRIPT_ENGINE_001")


def test_net_dns_script_engine_not_firing_for_browser(engine: RuleEngine):
    event = _make_dns_event(
        image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        query_name="safe.example.com",
    )
    assert not _hits(engine, event, "NET_DNS_SCRIPT_ENGINE_001")
