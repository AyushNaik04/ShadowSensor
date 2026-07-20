"""Integration tests for Phase 3 FastAPI API endpoints."""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from storage import database as storage_database
from storage.models import AlertRecord, EventRecord, RuleHitRecord


@pytest.fixture()
def api_client(monkeypatch: pytest.MonkeyPatch):
    """Create a TestClient backed by a shared in-memory SQLite database."""
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    test_session_local = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(storage_database, "engine", test_engine)
    monkeypatch.setattr(storage_database, "SessionLocal", test_session_local)
    storage_database.init_db()

    now = datetime.now(UTC)
    recent = now - timedelta(hours=1)
    older = now - timedelta(days=2)

    with test_session_local() as session:
        event_recent = EventRecord(
            event_type_id=1,
            timestamp=recent,
            pid=1111,
            image=r"C:\Windows\System32\cmd.exe",
            raw_json=json.dumps(
                {
                    "event_id": 1,
                    "utc_time": recent.isoformat(),
                    "process_id": 1111,
                    "parent_process_id": 1000,
                    "image": r"C:\Windows\System32\cmd.exe",
                    "parent_image": r"C:\Windows\explorer.exe",
                    "command_line": "cmd.exe /c whoami",
                }
            ),
        )
        event_old = EventRecord(
            event_type_id=3,
            timestamp=older,
            pid=2222,
            image=r"C:\Windows\System32\ping.exe",
            raw_json=json.dumps(
                {
                    "event_id": 3,
                    "utc_time": older.isoformat(),
                    "process_id": 2222,
                    "image": r"C:\Windows\System32\ping.exe",
                }
            ),
        )
        session.add_all([event_recent, event_old])
        session.flush()

        hit_crit = RuleHitRecord(
            event_fk=event_recent.id,
            rule_id="RULE_CRIT",
            rule_name="Critical Rule",
            severity="Critical",
            mitre_technique="T1059.001",
            mitre_tactic="Execution",
            matched_fields=None,
            timestamp=recent,
        )
        hit_high = RuleHitRecord(
            event_fk=event_recent.id,
            rule_id="RULE_HIGH",
            rule_name="High Rule",
            severity="High",
            mitre_technique="T1105",
            mitre_tactic="Command and Control",
            matched_fields=None,
            timestamp=recent,
        )
        hit_high_2 = RuleHitRecord(
            event_fk=event_recent.id,
            rule_id="RULE_HIGH",
            rule_name="High Rule",
            severity="High",
            mitre_technique="T1105",
            mitre_tactic="Command and Control",
            matched_fields=None,
            timestamp=recent,
        )
        session.add_all([hit_crit, hit_high, hit_high_2])
        session.flush()

        session.add_all(
            [
                AlertRecord(
                    rule_hit_fk=hit_crit.id,
                    event_fk=event_recent.id,
                    rule_id="RULE_CRIT",
                    rule_name="Critical Rule",
                    severity="Critical",
                    mitre_technique="T1059.001",
                    mitre_tactic="Execution",
                    process_image=r"C:\Windows\System32\powershell.exe",
                    process_pid=3210,
                    command_line="powershell -enc AAA",
                    parent_image=r"C:\Windows\explorer.exe",
                    status="open",
                    suspected_families=None,
                    timestamp=recent,
                ),
                AlertRecord(
                    rule_hit_fk=hit_high.id,
                    event_fk=event_recent.id,
                    rule_id="RULE_HIGH",
                    rule_name="High Rule",
                    severity="High",
                    mitre_technique="T1105",
                    mitre_tactic="Command and Control",
                    process_image=r"C:\Windows\System32\cmd.exe",
                    process_pid=1111,
                    command_line="cmd /c curl http://example",
                    parent_image=r"C:\Windows\explorer.exe",
                    status="acknowledged",
                    suspected_families=None,
                    timestamp=recent,
                ),
                AlertRecord(
                    rule_hit_fk=hit_high_2.id,
                    event_fk=event_old.id,
                    rule_id="RULE_LOW",
                    rule_name="Low Rule",
                    severity="Low",
                    mitre_technique="T1070",
                    mitre_tactic="Defense Evasion",
                    process_image=r"C:\Windows\System32\notepad.exe",
                    process_pid=5000,
                    command_line="notepad.exe",
                    parent_image=r"C:\Windows\explorer.exe",
                    status="resolved",
                    suspected_families=None,
                    timestamp=older,
                ),
            ]
        )
        session.commit()

    import dashboard.routers.api as api_module
    import dashboard.app as app_module

    importlib.reload(api_module)
    importlib.reload(app_module)

    client = TestClient(app_module.app)
    yield client, test_session_local
    test_engine.dispose()


def test_root_redirects_to_dashboard_home(api_client) -> None:
    client, _ = api_client
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers.get("location") == "/dashboard/home"


def test_health_endpoint_returns_ok(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_stats_has_expected_keys(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/stats?quick=24h").json()
    assert "total_alerts" in payload
    assert "by_severity" in payload


def test_timeline_24h_uses_1h_interval(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/timeline?quick=24h").json()
    assert payload["interval"] == "1h"
    assert payload["buckets"]


def test_timeline_15m_uses_1m_interval(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/timeline?quick=15m").json()
    assert payload["interval"] == "1m"


def test_timeline_30d_uses_1d_interval(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/timeline?quick=30d").json()
    assert payload["interval"] == "1d"


def test_alerts_is_paginated(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/alerts").json()
    assert {"items", "total", "page", "pages"}.issubset(payload.keys())


def test_alerts_filter_by_severity(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/alerts?severity=High").json()
    assert payload["items"]
    assert all(item["severity"] == "High" for item in payload["items"])


def test_alerts_kql_filter_by_critical(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/alerts?q=severity:Critical").json()
    assert payload["items"]
    assert all(item["severity"] == "Critical" for item in payload["items"])


def test_alerts_invalid_kql_returns_400(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/alerts?q=severity:")
    assert response.status_code == 400
    assert "KQL" in response.json()["detail"]


def test_alert_by_id_missing_returns_404(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/alerts/99999")
    assert response.status_code == 404


def test_patch_alert_status_updates_row(api_client) -> None:
    client, session_local = api_client
    with session_local() as session:
        alert = session.query(AlertRecord).filter(AlertRecord.status == "open").first()
        assert alert is not None
        alert_id = alert.id

    response = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "acknowledged"})
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    with session_local() as session:
        updated = session.get(AlertRecord, alert_id)
        assert updated is not None
        assert updated.status == "acknowledged"


def test_events_returns_raw_json_as_dict(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/events").json()
    assert payload["items"]
    assert isinstance(payload["items"][0]["raw_json"], dict)


def test_search_alerts_context_filters_by_kql(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/search?q=severity:High&context=alerts").json()
    assert payload["items"]
    assert all(item["severity"] == "High" for item in payload["items"])


def test_search_missing_q_returns_400(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/search?context=alerts")
    assert response.status_code == 400


def test_ml_status_is_untrained_placeholder(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/ml-status").json()
    assert payload["models_trained"] is False


def test_rules_returns_list(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_process_tree_has_roots_key(api_client) -> None:
    client, _ = api_client
    response = client.get("/api/v1/process-tree?quick=24h")
    assert response.status_code == 200
    assert "roots" in response.json()


def test_top_rules_limit_and_sort(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/top-rules?limit=3").json()
    assert len(payload) <= 3
    counts = [item["count"] for item in payload]
    assert counts == sorted(counts, reverse=True)


def test_severity_distribution_includes_all_keys(api_client) -> None:
    client, _ = api_client
    payload = client.get("/api/v1/severity-distribution").json()
    assert set(payload.keys()) == {"Critical", "High", "Medium", "Low"}
