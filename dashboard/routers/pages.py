"""Dashboard page routes and HTMX partial endpoints for ShadowSensor."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dashboard.kql.transformer import ContextType
from dashboard.app import TEMPLATES
from dashboard.routers import api as api_module
from storage.database import DB_PATH, get_session
from storage.models import AlertRecord, EventRecord

router = APIRouter()

_VALID_ALERT_STATUS = frozenset({"open", "acknowledged", "resolved"})


def _register_template_filters(templates: Jinja2Templates) -> None:
    """Register Jinja2 filters used by dashboard templates."""

    def basename(value: Any) -> str:
        if not value:
            return "—"
        return Path(str(value)).name

    def format_ts(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        text = str(value)
        if "T" in text:
            return text.replace("T", " ")[:19]
        return text[:19] if len(text) >= 19 else text

    def truncate(value: Any, length: int = 80) -> str:
        if value is None:
            return "—"
        text = str(value)
        if len(text) <= length:
            return text
        return text[: length - 1] + "…"

    def pretty_json(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return value
        return json.dumps(value, indent=2, default=str)

    def event_key_detail(event: dict[str, Any]) -> str:
        """Extract a human-readable key detail from event raw_json by type."""
        raw = event.get("raw_json") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {}

        event_type = event.get("event_type_id")
        if event_type == 1:
            cmd = raw.get("command_line")
            return truncate(cmd, 80) if cmd else "—"
        if event_type == 3:
            dest_ip = raw.get("destination_ip")
            dest_port = raw.get("destination_port")
            if dest_ip is not None and dest_port is not None:
                return f"{dest_ip}:{dest_port}"
            return "—"
        if event_type == 7:
            loaded = raw.get("image_loaded")
            return basename(loaded) if loaded else "—"
        if event_type == 8:
            src = basename(raw.get("source_image"))
            tgt = basename(raw.get("target_image"))
            if src != "—" or tgt != "—":
                return f"{src} → {tgt}"
            return "—"
        if event_type == 10:
            src = basename(raw.get("source_image"))
            tgt = basename(raw.get("target_image"))
            access = raw.get("granted_access")
            if access:
                return f"{src} → {tgt} [{access}]"
            if src != "—" or tgt != "—":
                return f"{src} → {tgt}"
            return "—"
        if event_type == 22:
            query = raw.get("query_name")
            return query if query else "—"
        return "—"

    env = templates.env
    env.filters["basename"] = basename
    env.filters["format_ts"] = format_ts
    env.filters["truncate"] = truncate
    env.filters["pretty_json"] = pretty_json
    env.filters["event_key_detail"] = event_key_detail


_register_template_filters(TEMPLATES)


def _time_query_params(
    quick: Optional[str],
    from_dt: Optional[str],
    to_dt: Optional[str],
) -> dict[str, Optional[str]]:
    return {"quick": quick or "24h", "from_dt": from_dt, "to_dt": to_dt}


def _pagination_meta(data: dict[str, Any]) -> dict[str, int]:
    return {
        "total": data.get("total", 0),
        "page": data.get("page", 1),
        "pages": data.get("pages", 1),
        "page_size": data.get("page_size", 50),
    }


@router.get("/dashboard/home", response_class=HTMLResponse)
def dashboard_home(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    """Render the Home / Status dashboard page."""
    params = _time_query_params(quick, from_dt, to_dt)
    try:
        initial_stats = api_module.stats(**params)
    except HTTPException:
        initial_stats = None

    return TEMPLATES.TemplateResponse(
        request,
        "home.html",
        {
            "request": request,
            "active_page": "home",
            "initial_stats": initial_stats,
        },
    )


@router.get("/dashboard/alerts", response_class=HTMLResponse)
def dashboard_alerts(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> HTMLResponse:
    """Render the Alert Feed page with initial alert rows."""
    params = _time_query_params(quick, from_dt, to_dt)
    data = api_module.get_alerts(
        **params,
        page=page,
        page_size=50,
        severity=severity,
        status=status,
        q=q,
    )
    return TEMPLATES.TemplateResponse(
        request,
        "alerts.html",
        {
            "request": request,
            "active_page": "alerts",
            "alerts": data["items"],
            "pagination": _pagination_meta(data),
        },
    )


@router.get("/dashboard/alerts/{alert_id}", response_class=HTMLResponse)
def dashboard_alert_detail(request: Request, alert_id: int) -> HTMLResponse:
    """Render alert detail page or styled 404 when alert is missing."""
    raw_json_pretty: Optional[str] = None

    with get_session() as session:
        record = session.get(AlertRecord, alert_id)
        if record is None:
            return TEMPLATES.TemplateResponse(
                request,
                "alert_not_found.html",
                {
                    "request": request,
                    "active_page": "alerts",
                    "alert_id": alert_id,
                },
                status_code=404,
            )

        alert = record.to_dict()
        event_fk = alert.get("event_fk")
        if event_fk is not None:
            event = session.get(EventRecord, event_fk)
            if event is not None:
                try:
                    parsed = json.loads(event.raw_json)
                    raw_json_pretty = json.dumps(parsed, indent=2, default=str)
                except json.JSONDecodeError:
                    raw_json_pretty = event.raw_json

    return TEMPLATES.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "request": request,
            "active_page": "alerts",
            "alert": alert,
            "raw_json_pretty": raw_json_pretty,
        },
    )


@router.get("/dashboard/events", response_class=HTMLResponse)
def dashboard_events(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    event_type_id: Optional[str] = Query(default=None),
    q: Optional[str] = None,
) -> HTMLResponse:
    """Render the Event Explorer page with initial event rows."""
    params = _time_query_params(quick, from_dt, to_dt)
    type_filter = int(event_type_id) if event_type_id else None
    data = api_module.get_events(
        **params,
        page=page,
        page_size=100,
        event_type_id=type_filter,
        q=q,
    )
    return TEMPLATES.TemplateResponse(
        request,
        "events.html",
        {
            "request": request,
            "active_page": "events",
            "events": data["items"],
            "pagination": _pagination_meta(data),
        },
    )


@router.get("/dashboard/process-tree", response_class=HTMLResponse)
def dashboard_process_tree(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    """Render the Process Tree page with initial tree content."""
    params = _time_query_params(quick, from_dt, to_dt)
    tree_data = api_module.process_tree(**params)
    return TEMPLATES.TemplateResponse(
        request,
        "process_tree.html",
        {
            "request": request,
            "active_page": "process_tree",
            "tree_data": tree_data,
            "roots": tree_data.get("roots", []),
        },
    )


@router.get("/dashboard/partials/alerts-rows", response_class=HTMLResponse)
def partial_alerts_rows(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
) -> HTMLResponse:
    """Return HTMX partial rows for the Alert Feed table."""
    params = _time_query_params(quick, from_dt, to_dt)
    data = api_module.get_alerts(
        **params,
        page=page,
        page_size=page_size,
        severity=severity or None,
        status=status or None,
        q=q or None,
    )
    return TEMPLATES.TemplateResponse(
        request,
        "partials/alerts_rows.html",
        {"request": request, "alerts": data["items"]},
    )


@router.get("/dashboard/partials/recent-alerts", response_class=HTMLResponse)
def partial_recent_alerts(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    """Return HTMX partial rows for the Home page recent-alerts table."""
    params = _time_query_params(quick, from_dt, to_dt)
    data = api_module.get_alerts(**params, page=1, page_size=5)
    return TEMPLATES.TemplateResponse(
        request,
        "partials/recent_alerts.html",
        {"request": request, "alerts": data["items"]},
    )


@router.get("/dashboard/partials/events-rows", response_class=HTMLResponse)
def partial_events_rows(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 100,
    event_type_id: Optional[str] = Query(default=None),
    q: Optional[str] = None,
) -> HTMLResponse:
    """Return HTMX partial rows for the Event Explorer table."""
    params = _time_query_params(quick, from_dt, to_dt)
    type_filter = int(event_type_id) if event_type_id else None
    data = api_module.get_events(
        **params,
        page=page,
        page_size=page_size,
        event_type_id=type_filter,
        q=q or None,
    )
    return TEMPLATES.TemplateResponse(
        request,
        "partials/events_rows.html",
        {"request": request, "events": data["items"]},
    )


@router.get("/dashboard/partials/alert-status/{alert_id}", response_class=HTMLResponse)
def partial_alert_status(alert_id: int, status: str) -> HTMLResponse:
    """Update alert status in DB and return the status badge HTML fragment."""
    if status not in _VALID_ALERT_STATUS:
        raise HTTPException(400, detail="Invalid status. Valid values: open, acknowledged, resolved.")

    with get_session() as session:
        record = session.get(AlertRecord, alert_id)
        if record is None:
            raise HTTPException(404, detail=f"Alert {alert_id} not found.")
        record.status = status
        session.add(record)

    badge_html = f'<span class="badge badge-{status}">{status}</span>'
    return HTMLResponse(content=badge_html)


@router.get("/dashboard/partials/process-tree-content", response_class=HTMLResponse)
def partial_process_tree_content(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    """Return HTMX partial process tree HTML."""
    params = _time_query_params(quick, from_dt, to_dt)
    tree_data = api_module.process_tree(**params)
    return TEMPLATES.TemplateResponse(
        request,
        "partials/process_tree_content.html",
        {
            "request": request,
            "roots": tree_data.get("roots", []),
            "tree_data": tree_data,
        },
    )


def _format_db_size(size_bytes: int) -> str:
    """Format byte count as KB or MB for display."""
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


@router.get("/dashboard/search", response_class=HTMLResponse)
def dashboard_search(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    """Render the Search / Query Console page."""
    return TEMPLATES.TemplateResponse(
        request,
        "search.html",
        {
            "request": request,
            "active_page": "search",
        },
    )


@router.get("/dashboard/partials/search-rows", response_class=HTMLResponse)
def partial_search_rows(
    request: Request,
    q: str,
    context: ContextType = "alerts",
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 50,
) -> HTMLResponse:
    """Return HTMX partial rows for the Search / Query Console table."""
    params = _time_query_params(quick, from_dt, to_dt)
    data = api_module.search(
        **params,
        q=q,
        context=context,
        page=page,
        page_size=page_size,
    )
    return TEMPLATES.TemplateResponse(
        request,
        "partials/search_rows.html",
        {
            "request": request,
            "items": data["items"],
            "context": context,
        },
    )


@router.get("/dashboard/ml-insights", response_class=HTMLResponse)
def dashboard_ml_insights(request: Request) -> HTMLResponse:
    """Render the ML Insights page with live Isolation Forest data."""
    import json as _json

    from dashboard.services.ml_insights_service import (
        get_isolation_forest_status,
        get_random_forest_status,
        get_score_trend,
    )

    try:
        isolation_forest = get_isolation_forest_status()
    except Exception:
        isolation_forest = {
            "trained": False,
            "training_date": None,
            "total_scored": 0,
            "score_min": None,
            "score_max": None,
            "score_mean": None,
            "score_median": None,
            "brackets": [],
        }

    try:
        random_forest = get_random_forest_status()
    except Exception:
        random_forest = {
            "trained": False,
            "training_date": None,
            "total_scored": 0,
            "score_min": None,
            "score_max": None,
            "score_mean": None,
            "score_median": None,
            "brackets": [],
        }

    try:
        trend_data = get_score_trend(hours=24)
    except Exception:
        trend_data = []

    return TEMPLATES.TemplateResponse(
        request,
        "ml_insights.html",
        {
            "request": request,
            "active_page": "ml_insights",
            "isolation_forest": isolation_forest,
            "random_forest": random_forest,
            "trend_data_json": _json.dumps(trend_data),
        },
    )


@router.get("/dashboard/rules", response_class=HTMLResponse)
def dashboard_rules(request: Request) -> HTMLResponse:
    """Render the Rules Library page."""
    return TEMPLATES.TemplateResponse(
        request,
        "rules_library.html",
        {
            "request": request,
            "active_page": "rules",
        },
    )


@router.get("/dashboard/settings", response_class=HTMLResponse)
def dashboard_settings(request: Request) -> HTMLResponse:
    """Render the Settings page."""
    return TEMPLATES.TemplateResponse(
        request,
        "settings.html",
        {
            "request": request,
            "active_page": "settings",
        },
    )


@router.get("/dashboard/partials/health", response_class=HTMLResponse)
def partial_health(request: Request) -> HTMLResponse:
    """Return HTML health snapshot fragment for Settings page."""
    db_file = Path(DB_PATH)
    db_size_bytes = os.path.getsize(db_file) if db_file.exists() else 0

    with get_session() as session:
        total_alerts = session.query(AlertRecord).count()
        total_events = session.query(EventRecord).count()

    return TEMPLATES.TemplateResponse(
        request,
        "partials/health.html",
        {
            "request": request,
            "db_path": str(DB_PATH),
            "db_size": _format_db_size(db_size_bytes),
            "total_alerts": total_alerts,
            "total_events": total_events,
        },
    )
