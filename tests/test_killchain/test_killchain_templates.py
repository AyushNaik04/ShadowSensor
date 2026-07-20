"""Test Kill Chain Visualisation — Subtask B template rendering."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dashboard.app import app


def _find_div_close(html: str, start_idx: int) -> int:
    depth = 0
    idx = start_idx
    while idx < len(html):
        open_idx = html.find("<div", idx)
        close_idx = html.find("</div>", idx)
        if close_idx == -1:
            return -1
        if open_idx != -1 and open_idx < close_idx:
            depth += 1
            idx = open_idx + 4
            continue
        depth -= 1
        idx = close_idx + 6
        if depth == 0:
            return idx
    return -1


def test_killchain_page_returns_html() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_killchain_page_contains_title() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert "Kill Chain" in response.text or "Kill Chain Coverage" in response.text


def test_killchain_page_contains_htmx_polling_div() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert 'id="killchain-overview"' in response.text


def test_killchain_page_contains_hx_trigger() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert "hx-trigger" in response.text
    assert "every 5s" in response.text


def test_killchain_page_contains_hx_include() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert "hx-include" in response.text


def test_killchain_page_contains_stage_detail_divs() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert 'id="stage-detail-TA0002"' in response.text
    assert 'id="stage-detail-TA0005"' in response.text


def test_killchain_page_stage_detail_outside_polling_div() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    body = response.text
    overview_start = body.find('id="killchain-overview"')
    assert overview_start != -1
    div_open_start = body.rfind("<div", 0, overview_start)
    assert div_open_start != -1
    overview_close = _find_div_close(body, div_open_start)
    assert overview_close != -1
    stage_detail_pos = body.find('id="stage-detail-TA0002"')
    assert stage_detail_pos != -1
    assert stage_detail_pos > overview_close


def test_killchain_page_contains_attribution() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert "MITRE ATT" in response.text
    assert "attack.mitre.org" in response.text


def test_killchain_page_contains_nav_kill_chain() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert "/dashboard/killchain" in response.text


def test_killchain_overview_partial_returns_html_fragment() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_killchain_overview_contains_no_html_tag() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    stripped = response.text.lstrip().lower()
    assert not stripped.startswith("<html")
    assert "<!doctype" not in stripped


def test_killchain_overview_contains_12_tactic_cards() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert response.text.count("killchain-card ") == 12


def test_killchain_overview_contains_ta0001() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert "TA0001" in response.text


def test_killchain_overview_contains_ta0040() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert "TA0040" in response.text


def test_killchain_overview_contains_coverage_summary() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert "of" in response.text
    assert "tactics observed" in response.text


def test_killchain_overview_contains_last_updated() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert "Updated" in response.text


def test_killchain_overview_card_grid_present() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview")
    assert "killchain-card-grid" in response.text


def test_killchain_overview_with_quick_1h() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview?quick=1h")
    assert response.status_code == 200
    assert "killchain-card" in response.text


def test_killchain_overview_with_quick_15m() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-overview?quick=15m")
    assert response.status_code == 200
    assert "killchain-card" in response.text


def test_killchain_stage_detail_returns_html() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/partials/killchain-stage/TA0002")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "killchain-detail-panel" in response.text


def test_killchain_page_no_500_error() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/killchain")
    assert response.status_code < 500


def test_existing_home_page_unaffected() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/home")
    assert response.status_code == 200


def test_existing_alerts_page_unaffected() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/alerts")
    assert response.status_code == 200


def test_existing_base_template_has_9_existing_nav_items() -> None:
    with TestClient(app) as client:
        response = client.get("/dashboard/home")
    body = response.text
    expected_hrefs = [
        "/dashboard/home",
        "/dashboard/alerts",
        "/dashboard/events",
        "/dashboard/process-tree",
        "/dashboard/search",
        "/dashboard/ml-insights",
        "/dashboard/rules",
        "/dashboard/settings",
        "/dashboard/killchain",
    ]
    for href in expected_hrefs:
        assert href in body
