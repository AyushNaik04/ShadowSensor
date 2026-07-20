"""Kill chain dashboard routes for backend verification in Subtask A."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from dashboard.app import TEMPLATES
from dashboard.routers import api as api_module
from dashboard.services.killchain_service import (
    format_relative_time,
    get_kill_chain_status,
    get_rule_tactic_map,
    get_tactic_rule_detail,
    initialise_rule_tactic_map,
)
from storage.database import get_session

router = APIRouter()


@router.on_event("startup")
def _initialise_killchain_rule_map() -> None:
    rules_dir = Path("rules") / "definitions"
    initialise_rule_tactic_map(str(rules_dir))


@router.get("/dashboard/killchain")
async def killchain_page(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    time_from, time_to = api_module.resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        tactic_statuses = get_kill_chain_status(session, time_from, time_to, get_rule_tactic_map())
    return TEMPLATES.TemplateResponse(
        request,
        "killchain.html",
        {
            "request": request,
            "active_page": "killchain",
            "tactic_statuses": tactic_statuses,
            "total_fired": sum(1 for t in tactic_statuses if t.fired),
            "total_tactics": len(tactic_statuses),
            "as_of": datetime.utcnow(),
            "format_relative_time": format_relative_time,
        },
    )


@router.get("/dashboard/partials/killchain-overview")
async def killchain_overview_partial(
    request: Request,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    time_from, time_to = api_module.resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        tactic_statuses = get_kill_chain_status(
            session, time_from, time_to, get_rule_tactic_map()
        )
    return TEMPLATES.TemplateResponse(
        request,
        "partials/killchain_overview.html",
        {
            "request": request,
            "tactic_statuses": tactic_statuses,
            "total_fired": sum(1 for t in tactic_statuses if t.fired),
            "total_tactics": len(tactic_statuses),
            "as_of": datetime.utcnow(),
            "format_relative_time": format_relative_time,
        },
    )


@router.get("/dashboard/partials/killchain-stage/{tactic_id}")
async def killchain_stage_detail_partial(
    request: Request,
    tactic_id: str,
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> HTMLResponse:
    from dashboard.services.killchain_service import _TACTIC_BY_ID

    if tactic_id not in _TACTIC_BY_ID:
        raise HTTPException(status_code=404, detail=f"Unknown tactic_id: {tactic_id}")

    time_from, time_to = api_module.resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        rule_details = get_tactic_rule_detail(
            session, tactic_id, time_from, time_to, get_rule_tactic_map()
        )
    return TEMPLATES.TemplateResponse(
        request,
        "partials/killchain_stage_detail.html",
        {
            "request": request,
            "tactic_id": tactic_id,
            "tactic_name": _TACTIC_BY_ID[tactic_id]["tactic_name"],
            "rule_details": rule_details,
            "format_relative_time": format_relative_time,
        },
    )
