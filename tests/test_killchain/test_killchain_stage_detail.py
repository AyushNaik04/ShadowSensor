"""Route tests for kill chain stage detail partial (Subtask C)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dashboard.app import app


def test_killchain_stage_detail_returns_html() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_killchain_stage_detail_is_fragment() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    body = response.text.lower()
    assert "<html" not in body
    assert "<!doctype" not in body


def test_killchain_stage_detail_contains_panel_class() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert "killchain-detail-panel" in response.text


def test_killchain_stage_detail_contains_header() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert "Active Rules" in response.text


def test_killchain_stage_detail_contains_collapse_button() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert "Collapse" in response.text


def test_killchain_stage_detail_contains_table_or_empty_state() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert "<table" in response.text or "No rules have fired" in response.text


def test_killchain_stage_detail_view_alerts_link_present() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    if "<table" in response.text:
        assert "View in Alert Feed" in response.text
    else:
        assert "No rules have fired" in response.text


def test_killchain_stage_detail_ta0005_returns_html() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0005")
    assert response.status_code == 200


def test_killchain_stage_detail_with_quick_param() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002?quick=1h")
    assert response.status_code == 200


def test_killchain_stage_detail_with_quick_24h() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002?quick=24h")
    assert response.status_code == 200


def test_killchain_stage_detail_invalid_tactic_still_404() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/INVALID_TACTIC")
    assert response.status_code == 404


def test_killchain_stage_detail_contains_tactic_name() -> None:
    with TestClient(app) as client:
        ta0002 = client.get("/dashboard/partials/killchain-stage/TA0002")
        ta0005 = client.get("/dashboard/partials/killchain-stage/TA0005")
    assert "Execution" in ta0002.text
    assert "Defense Evasion" in ta0005.text


def test_killchain_stage_detail_stage_detail_div_id_present() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert "stage-detail-TA0002" in response.text
