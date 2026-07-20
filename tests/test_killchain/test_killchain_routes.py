"""Route tests for kill chain dashboard endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dashboard.app import app


def test_killchain_page_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_killchain_overview_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert response.status_code == 200
    assert "killchain-card" in response.text


def test_killchain_overview_quick_1h() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview?quick=1h")
    assert response.status_code == 200


def test_killchain_overview_quick_24h() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview?quick=24h")
    assert response.status_code == 200


def test_killchain_overview_quick_15m() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview?quick=15m")
    assert response.status_code == 200


def test_killchain_overview_returns_12_tactics() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert response.status_code == 200
    assert response.text.count("killchain-card ") == 12


def test_killchain_stage_ta0002_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert response.status_code == 200
    assert "killchain-detail-panel" in response.text


def test_killchain_stage_ta0005_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0005")
    assert response.status_code == 200
    assert "killchain-detail-panel" in response.text


def test_killchain_stage_invalid_tactic_returns_404() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/INVALID_TACTIC")
    assert response.status_code == 404


def test_killchain_stage_ta0002_with_quick_param() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002?quick=1h")
    assert response.status_code == 200


def test_existing_home_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/home")
    assert response.status_code == 200


def test_existing_alerts_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/alerts")
    assert response.status_code == 200


def test_existing_events_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/events")
    assert response.status_code == 200


def test_existing_rules_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/rules")
    assert response.status_code == 200


def test_existing_settings_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/settings")
    assert response.status_code == 200


def test_existing_search_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/search")
    assert response.status_code == 200


def test_existing_ml_insights_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/ml-insights")
    assert response.status_code == 200


def test_existing_process_tree_still_200() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/process-tree")
    assert response.status_code == 200
