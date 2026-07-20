"""FastAPI endpoints for ShadowSensor dashboard analytics and querying."""

from __future__ import annotations

import json
import logging
import math
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func

from dashboard.kql.parser import KQLParseError, KQLParser
from dashboard.kql.transformer import ContextType, KQLTransformError, KQLTransformer
from rules.engine import RuleEngine
from storage.database import DB_PATH, get_session
from storage.models import AlertRecord, EventRecord, RuleHitRecord

logger = logging.getLogger(__name__)
router = APIRouter()
_start_time = datetime.now(timezone.utc)
_kql_parser = KQLParser()

QUICK_RANGES = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_VALID_ALERT_STATUS = {"open", "acknowledged", "resolved"}


class AlertStatusUpdate(BaseModel):
    """PATCH payload for alert status updates."""

    status: str


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _ensure_utc(value)
    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(candidate)
        return _ensure_utc(parsed)
    raise ValueError(f"Unsupported datetime value: {value!r}")


def resolve_time_range(
    quick: Optional[str],
    from_dt: Optional[str],
    to_dt: Optional[str],
) -> Tuple[datetime, datetime]:
    """Return UTC-aware start/end datetimes from query params."""
    now = datetime.now(timezone.utc)
    if from_dt and to_dt:
        try:
            start = _coerce_datetime(from_dt)
            end = _coerce_datetime(to_dt)
        except ValueError as exc:
            raise HTTPException(400, detail="Invalid datetime format. Use ISO 8601.") from exc
        if start >= end:
            raise HTTPException(400, detail="'from' must be before 'to'.")
        return start, end

    delta = QUICK_RANGES.get(quick or "24h")
    if delta is None:
        raise HTTPException(400, detail=f"Invalid quick range. Valid: {list(QUICK_RANGES)}")
    return now - delta, now


def timeline_interval(start: datetime, end: datetime) -> Tuple[str, timedelta]:
    """Return bucket label and timedelta for alert timeline granularity."""
    span = end - start
    if span <= timedelta(minutes=20):
        return "1m", timedelta(minutes=1)
    if span <= timedelta(hours=2):
        return "5m", timedelta(minutes=5)
    if span <= timedelta(hours=8):
        return "30m", timedelta(minutes=30)
    if span <= timedelta(hours=30):
        return "1h", timedelta(hours=1)
    if span <= timedelta(days=10):
        return "6h", timedelta(hours=6)
    return "1d", timedelta(days=1)


def _iso(dt: datetime) -> str:
    return _ensure_utc(dt).isoformat()


def _time_range_payload(start: datetime, end: datetime) -> dict[str, str]:
    return {"from": _iso(start), "to": _iso(end)}


def _apply_kql_filter(query: Any, q: Optional[str], context: ContextType) -> Any:
    if not q:
        return query

    try:
        tree = _kql_parser.parse(q)
        where_clause = KQLTransformer(context).transform(tree)
    except (KQLParseError, KQLTransformError) as exc:
        raise HTTPException(400, detail=f"KQL parse error: {exc}") from exc

    if where_clause is None:
        return query
    return query.filter(where_clause)


def _event_to_dict(record: EventRecord) -> dict[str, Any]:
    return record.to_dict()


def _rule_hit_to_dict(record: RuleHitRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "event_fk": record.event_fk,
        "rule_id": record.rule_id,
        "rule_name": record.rule_name,
        "severity": record.severity,
        "mitre_technique": record.mitre_technique,
        "mitre_tactic": record.mitre_tactic,
        "matched_fields": json.loads(record.matched_fields) if record.matched_fields else None,
        "timestamp": _iso(_coerce_datetime(record.timestamp)),
        "created_at": _iso(_coerce_datetime(record.created_at)) if record.created_at else None,
    }


def _paginate(query: Any, page: int, page_size: int) -> tuple[list[Any], int, int]:
    total = query.count()
    pages = max(1, math.ceil(total / page_size)) if page_size > 0 else 1
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return items, total, pages


@router.get("/health")
def health() -> dict[str, Any]:
    """Return backend process and database health snapshot."""
    db_file = Path(DB_PATH)
    db_size = os.path.getsize(db_file) if db_file.exists() else 0
    uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
    return {
        "status": "ok",
        "db_path": str(DB_PATH),
        "db_size_bytes": db_size,
        "uptime_seconds": uptime,
        "pipeline_running": False,
    }


@router.get("/stats")
def stats(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> dict[str, Any]:
    """Return top-level dashboard metrics for a selected time range."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        alerts_in_range = session.query(AlertRecord).filter(AlertRecord.timestamp.between(start, end))
        total_alerts = alerts_in_range.count()
        total_events = session.query(EventRecord).filter(EventRecord.timestamp.between(start, end)).count()
        total_rule_hits = session.query(RuleHitRecord).filter(RuleHitRecord.timestamp.between(start, end)).count()
        rules_fired = (
            session.query(func.count(func.distinct(RuleHitRecord.rule_id)))
            .filter(RuleHitRecord.timestamp.between(start, end))
            .scalar()
            or 0
        )
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        for severity, count in (
            alerts_in_range.with_entities(AlertRecord.severity, func.count(AlertRecord.id))
            .group_by(AlertRecord.severity)
            .all()
        ):
            if severity in severity_counts:
                severity_counts[severity] = count

    return {
        "total_alerts": total_alerts,
        "by_severity": severity_counts,
        "total_events": total_events,
        "total_rule_hits": total_rule_hits,
        "rules_fired": rules_fired,
        "time_range": _time_range_payload(start, end),
    }


@router.get("/timeline")
def timeline(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> dict[str, Any]:
    """Return non-sparse alert counts over computed timeline buckets."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    interval_label, delta = timeline_interval(start, end)

    with get_session() as session:
        timestamps = [
            _coerce_datetime(ts)
            for (ts,) in (
                session.query(AlertRecord.timestamp)
                .filter(AlertRecord.timestamp.between(start, end))
                .all()
            )
        ]

    bucket_starts: list[datetime] = []
    cursor = start
    while cursor <= end:
        bucket_starts.append(cursor)
        cursor += delta

    counts: dict[datetime, int] = {bucket: 0 for bucket in bucket_starts}
    for ts in timestamps:
        if ts < start or ts > end:
            continue
        bucket_index = int((ts - start) // delta)
        if bucket_index >= len(bucket_starts):
            bucket_index = len(bucket_starts) - 1
        counts[bucket_starts[bucket_index]] += 1

    return {
        "buckets": [{"bucket": _iso(bucket), "count": counts[bucket]} for bucket in bucket_starts],
        "interval": interval_label,
        "time_range": _time_range_payload(start, end),
    }


@router.get("/severity-distribution")
def severity_distribution(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> dict[str, int]:
    """Return severity breakdown for alerts in selected range."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    with get_session() as session:
        rows = (
            session.query(AlertRecord.severity, func.count(AlertRecord.id))
            .filter(AlertRecord.timestamp.between(start, end))
            .group_by(AlertRecord.severity)
            .all()
        )
    for severity, count in rows:
        if severity in result:
            result[severity] = count
    return result


@router.get("/top-rules")
def top_rules(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return most frequent rule hits with highest-severity snapshot."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        rows = (
            session.query(RuleHitRecord.rule_id, RuleHitRecord.rule_name, RuleHitRecord.severity)
            .filter(RuleHitRecord.timestamp.between(start, end))
            .all()
        )

    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for rule_id, rule_name, severity in rows:
        key = (rule_id, rule_name)
        if key not in aggregates:
            aggregates[key] = {"rule_id": rule_id, "rule_name": rule_name, "count": 0, "top_severity": "Low"}
        aggregates[key]["count"] += 1
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(aggregates[key]["top_severity"], 0):
            aggregates[key]["top_severity"] = severity

    ordered = sorted(aggregates.values(), key=lambda item: item["count"], reverse=True)
    return ordered[: max(0, limit)]


@router.get("/alerts")
def get_alerts(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
) -> dict[str, Any]:
    """Return paginated alerts with optional severity/status/KQL filters."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    with get_session() as session:
        query = session.query(AlertRecord).filter(AlertRecord.timestamp.between(start, end))
        if severity:
            query = query.filter(AlertRecord.severity == severity)
        if status:
            query = query.filter(AlertRecord.status == status)
        query = _apply_kql_filter(query, q, "alerts")
        query = query.order_by(AlertRecord.timestamp.desc())
        items, total, pages = _paginate(query, page, page_size)
        item_payload = [item.to_dict() for item in items]

    return {
        "items": item_payload,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: int) -> dict[str, Any]:
    """Return full alert payload by primary key."""
    with get_session() as session:
        alert = session.get(AlertRecord, alert_id)
    if alert is None:
        raise HTTPException(404, detail=f"Alert {alert_id} not found.")
    return alert.to_dict()


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, payload: AlertStatusUpdate) -> dict[str, Any]:
    """Update alert status to open, acknowledged, or resolved."""
    if payload.status not in _VALID_ALERT_STATUS:
        raise HTTPException(400, detail="Invalid status. Valid values: open, acknowledged, resolved.")

    with get_session() as session:
        alert = session.get(AlertRecord, alert_id)
        if alert is None:
            raise HTTPException(404, detail=f"Alert {alert_id} not found.")
        alert.status = payload.status
        session.add(alert)

    return {"id": alert_id, "status": payload.status}


@router.get("/events")
def get_events(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 100,
    event_type_id: Optional[int] = None,
    q: Optional[str] = None,
) -> dict[str, Any]:
    """Return paginated events with parsed raw_json payloads."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    with get_session() as session:
        query = session.query(EventRecord).filter(EventRecord.timestamp.between(start, end))
        if event_type_id is not None:
            query = query.filter(EventRecord.event_type_id == event_type_id)
        query = _apply_kql_filter(query, q, "events")
        query = query.order_by(EventRecord.timestamp.desc())
        items, total, pages = _paginate(query, page, page_size)
        item_payload = [_event_to_dict(item) for item in items]

    return {
        "items": item_payload,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/rule-hits")
def get_rule_hits(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = 100,
    q: Optional[str] = None,
) -> dict[str, Any]:
    """Return paginated rule hits with optional KQL filtering."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    with get_session() as session:
        query = session.query(RuleHitRecord).filter(RuleHitRecord.timestamp.between(start, end))
        query = _apply_kql_filter(query, q, "rule_hits")
        query = query.order_by(RuleHitRecord.timestamp.desc())
        items, total, pages = _paginate(query, page, page_size)
        item_payload = [_rule_hit_to_dict(item) for item in items]

    return {
        "items": item_payload,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/rules")
def get_rules() -> list[dict[str, Any]]:
    """Return loaded YAML rules enriched with all-time hit counts."""
    rule_engine = RuleEngine(rules_dir=Path("rules"))
    try:
        rule_engine.load()
        rules = rule_engine.rules
    except Exception as exc:
        logger.warning("Failed to load rule definitions for /rules endpoint: %s", exc)
        rules = []

    with get_session() as session:
        hit_rows = (
            session.query(RuleHitRecord.rule_id, func.count(RuleHitRecord.id))
            .group_by(RuleHitRecord.rule_id)
            .all()
        )
    hit_count_by_id = {rule_id: count for rule_id, count in hit_rows}

    payload: list[dict[str, Any]] = []
    for rule in rules:
        payload.append(
            {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "mitre_technique": rule.mitre_technique,
                "mitre_tactic": rule.mitre_tactic,
                "description": rule.description,
                "hit_count": hit_count_by_id.get(rule.id, 0),
            }
        )
    return payload


@router.get("/process-tree")
def process_tree(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
) -> dict[str, Any]:
    """Build parent-child process tree from ProcessCreate event raw_json payloads."""
    start, end = resolve_time_range(quick, from_dt, to_dt)
    with get_session() as session:
        rows = (
            session.query(EventRecord.raw_json, EventRecord.timestamp)
            .filter(EventRecord.event_type_id == 1, EventRecord.timestamp.between(start, end))
            .order_by(EventRecord.timestamp.desc())
            .limit(500)
            .all()
        )

    nodes: dict[int, dict[str, Any]] = {}
    parent_refs: dict[int, Optional[int]] = {}
    for raw_json, row_timestamp in rows:
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            payload = {}
        pid = payload.get("process_id")
        if pid is None:
            continue
        node = {
            "pid": pid,
            "image": payload.get("image"),
            "command_line": payload.get("command_line"),
            "timestamp": _iso(_coerce_datetime(row_timestamp)),
            "children": [],
        }
        nodes[pid] = node
        parent_refs[pid] = payload.get("parent_process_id")

    for pid, parent_pid in parent_refs.items():
        if parent_pid in nodes:
            nodes[parent_pid]["children"].append(nodes[pid])

    roots = [node for pid, node in nodes.items() if parent_refs.get(pid) not in nodes]
    return {"roots": roots, "total_processes": len(nodes)}


@router.get("/search")
def search(
    quick: Optional[str] = "24h",
    from_dt: Optional[str] = Query(default=None, alias="from"),
    to_dt: Optional[str] = Query(default=None, alias="to"),
    q: Optional[str] = None,
    context: ContextType = "alerts",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Run KQL search in alerts/events/rule_hits context."""
    if not q:
        raise HTTPException(400, detail="Missing required query parameter: q")

    if context == "alerts":
        return get_alerts(
            quick=quick,
            from_dt=from_dt,
            to_dt=to_dt,
            page=page,
            page_size=page_size,
            q=q,
        )
    if context == "events":
        return get_events(
            quick=quick,
            from_dt=from_dt,
            to_dt=to_dt,
            page=page,
            page_size=page_size,
            q=q,
        )

    return get_rule_hits(
        quick=quick,
        from_dt=from_dt,
        to_dt=to_dt,
        page=page,
        page_size=page_size,
        q=q,
    )


@router.get("/ml-status")
def ml_status() -> dict[str, Any]:
    """Return fixed Phase 3 ML placeholder status."""
    return {
        "models_trained": False,
        "isolation_forest": None,
        "random_forest": None,
        "message": "No models trained yet. ML scoring available after Phase 6B/7B.",
    }
