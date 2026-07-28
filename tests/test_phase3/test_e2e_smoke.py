"""End-to-end smoke tests for Phase 3 dashboard and API integration."""

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
def e2e_client(monkeypatch: pytest.MonkeyPatch):
    """Create a TestClient backed by a shared in-memory SQLite database with E2E seed data."""
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
    older = now - timedelta(hours=48)

    event_type_mix = [1] * 8 + [3] * 4 + [10] * 4 + [22] * 4
    recent_event_ids: list[int] = []
    open_alert_id: int | None = None

    with test_session_local() as session:
        for idx, event_type_id in enumerate(event_type_mix):
            ts = recent if idx < 10 else older
            pid = 1000 + idx
            event = EventRecord(
                event_type_id=event_type_id,
                timestamp=ts,
                pid=pid,
                image=rf"C:\Windows\System32\proc{idx}.exe",
                raw_json=json.dumps(
                    {
                        "event_id": event_type_id,
                        "utc_time": ts.isoformat(),
                        "process_id": pid,
                        "image": rf"C:\Windows\System32\proc{idx}.exe",
                        "command_line": f"proc{idx}.exe /test",
                    }
                ),
            )
            session.add(event)
            session.flush()
            if idx < 10:
                recent_event_ids.append(event.id)

        hit_specs = [
            ("TEST_CRITICAL_001", "Test Critical Rule", "Critical", 0),
            ("TEST_CRITICAL_001", "Test Critical Rule", "Critical", 1),
            ("TEST_HIGH_001", "Test High Rule", "High", 2),
            ("TEST_HIGH_001", "Test High Rule", "High", 3),
            ("TEST_HIGH_001", "Test High Rule", "High", 4),
            ("TEST_MED_001", "Test Medium Rule", "Medium", 5),
            ("TEST_MED_001", "Test Medium Rule", "Medium", 6),
            ("TEST_LOW_001", "Test Low Rule", "Low", 7),
        ]
        status_cycle = ["open", "open", "open", "acknowledged", "acknowledged", "acknowledged", "resolved", "resolved"]

        rule_hits: list[RuleHitRecord] = []
        for (rule_id, rule_name, severity, event_idx), status in zip(hit_specs, status_cycle):
            hit = RuleHitRecord(
                event_fk=recent_event_ids[event_idx],
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                mitre_technique="T1059.001" if severity == "Critical" else "T1105",
                mitre_tactic="Execution",
                matched_fields=None,
                timestamp=recent,
            )
            session.add(hit)
            session.flush()
            rule_hits.append(hit)

            alert = AlertRecord(
                rule_hit_fk=hit.id,
                event_fk=recent_event_ids[event_idx],
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                mitre_technique=hit.mitre_technique,
                mitre_tactic=hit.mitre_tactic,
                process_image=rf"C:\Windows\System32\proc{event_idx}.exe",
                process_pid=1000 + event_idx,
                command_line=f"proc{event_idx}.exe /test",
                parent_image=r"C:\Windows\explorer.exe",
                status=status,
                suspected_families=None,
                timestamp=recent,
            )
            session.add(alert)
            session.flush()
            if status == "open" and open_alert_id is None:
                open_alert_id = alert.id

        session.commit()

    import dashboard.routers.api as api_module
    import dashboard.routers.pages as pages_module
    import dashboard.app as app_module

    importlib.reload(api_module)
    importlib.reload(pages_module)
    importlib.reload(app_module)

    client = TestClient(app_module.app)
    yield client, test_session_local, open_alert_id
    test_engine.dispose()


def test_root_redirects_to_dashboard_home(e2e_client) -> None:
    client, _, _ = e2e_client
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/dashboard/home" in response.headers.get("location", "")


def test_dashboard_home_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    response = client.get("/dashboard/home")
    assert response.status_code == 200
    assert "ShadowSensor" in response.text


def test_dashboard_alerts_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/alerts").status_code == 200


def test_dashboard_events_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/events").status_code == 200


def test_dashboard_process_tree_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/process-tree").status_code == 200


def test_dashboard_search_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/search").status_code == 200


def test_dashboard_ml_insights_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    response = client.get("/dashboard/ml-insights")
    assert response.status_code == 200
    # Phase 6B Subphase 4: placeholder text replaced with real data sections.
    # Empty test DB → no model_scores rows → "Awaiting Data" status badge shown.
    assert "Isolation Forest" in response.text
    assert "Random Forest" in response.text


def test_dashboard_rules_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/rules").status_code == 200


def test_dashboard_settings_returns_200(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/dashboard/settings").status_code == 200


def test_stats_24h_counts(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/stats?quick=24h").json()
    assert payload["total_alerts"] == 8
    assert payload["total_events"] == 10


def test_stats_15m_zero_alerts(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/stats?quick=15m").json()
    assert payload["total_alerts"] == 0


def test_alerts_filter_high_severity(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/alerts?severity=High").json()
    assert payload["items"]
    assert all(item["severity"] == "High" for item in payload["items"])


def test_alerts_filter_open_status(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/alerts?status=open").json()
    assert payload["items"]
    assert all(item["status"] == "open" for item in payload["items"])


def test_alerts_kql_critical_only(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/alerts?q=severity:Critical").json()
    assert payload["items"]
    assert all(item["severity"] == "Critical" for item in payload["items"])


def test_alerts_invalid_kql_returns_400(e2e_client) -> None:
    client, _, _ = e2e_client
    response = client.get("/api/v1/alerts?q=severity:")
    assert response.status_code == 400
    assert "KQL" in response.json()["detail"]


def test_search_alerts_high_severity(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/search?q=severity:High&context=alerts").json()
    assert payload["items"]
    assert all(item["severity"] == "High" for item in payload["items"])


def test_search_missing_q_returns_400(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/api/v1/search?context=alerts").status_code == 400


def test_severity_distribution_24h(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/severity-distribution?quick=24h").json()
    assert set(payload.keys()) == {"Critical", "High", "Medium", "Low"}
    assert sum(payload.values()) == 8


def test_top_rules_limit_and_sort(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/top-rules?limit=3").json()
    assert len(payload) <= 3
    counts = [item["count"] for item in payload]
    assert counts == sorted(counts, reverse=True)


def test_patch_alert_status_updates_db(e2e_client) -> None:
    client, session_local, open_alert_id = e2e_client
    assert open_alert_id is not None
    response = client.patch(
        f"/api/v1/alerts/{open_alert_id}/status",
        json={"status": "resolved"},
    )
    assert response.status_code == 200
    with session_local() as session:
        updated = session.get(AlertRecord, open_alert_id)
        assert updated is not None
        assert updated.status == "resolved"


def test_alert_by_id_missing_returns_404(e2e_client) -> None:
    client, _, _ = e2e_client
    assert client.get("/api/v1/alerts/99999").status_code == 404


def test_ml_status_untrained(e2e_client) -> None:
    client, _, _ = e2e_client
    payload = client.get("/api/v1/ml-status").json()
    assert payload["models_trained"] is False
