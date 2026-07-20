"""Kill chain aggregation helpers for dashboard endpoints."""

from __future__ import annotations

import glob
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

from storage.models import RuleHitRecord

logger = logging.getLogger(__name__)

TACTIC_DISPLAY_ORDER: list[dict] = [
    {"tactic_id": "TA0001", "tactic_name": "Initial Access", "display_order": 1},
    {"tactic_id": "TA0002", "tactic_name": "Execution", "display_order": 2},
    {"tactic_id": "TA0003", "tactic_name": "Persistence", "display_order": 3},
    {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "display_order": 4},
    {"tactic_id": "TA0005", "tactic_name": "Defense Evasion", "display_order": 5},
    {"tactic_id": "TA0006", "tactic_name": "Credential Access", "display_order": 6},
    {"tactic_id": "TA0007", "tactic_name": "Discovery", "display_order": 7},
    {"tactic_id": "TA0008", "tactic_name": "Lateral Movement", "display_order": 8},
    {"tactic_id": "TA0009", "tactic_name": "Collection", "display_order": 9},
    {"tactic_id": "TA0011", "tactic_name": "Command and Control", "display_order": 10},
    {"tactic_id": "TA0010", "tactic_name": "Exfiltration", "display_order": 11},
    {"tactic_id": "TA0040", "tactic_name": "Impact", "display_order": 12},
]

_TACTIC_BY_NAME: dict[str, dict] = {t["tactic_name"].lower(): t for t in TACTIC_DISPLAY_ORDER}
_TACTIC_BY_ID: dict[str, dict] = {t["tactic_id"]: t for t in TACTIC_DISPLAY_ORDER}


@dataclass
class RuleDetail:
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    hit_count: int
    last_seen: Optional[datetime]


@dataclass
class TacticStatus:
    tactic_id: str
    tactic_name: str
    display_order: int
    fired: bool
    hit_count: int
    last_seen: Optional[datetime]
    fired_rules: list = field(default_factory=list)
    total_rules_mapped: int = 0
    all_rule_ids: list = field(default_factory=list)


def _normalise_rules_dir(rules_dir: str) -> Path:
    path = Path(rules_dir)
    if path.is_absolute():
        return path
    return Path.cwd() / path


def load_rule_tactic_map(rules_dir: str) -> dict:
    """
    Read all YAML rule files in rules_dir and return a mapping of
    rule_id → {tactic, tactic_id, technique_id, technique_name, rule_name}.

    Uses the exact field names discovered from pre-flight reads of rules/definitions/.
    Handles missing tactic/technique fields gracefully — treats as empty string.
    Logs a warning for unrecognised tactic values (not in TACTIC_DISPLAY_ORDER).
    """
    resolved_dir = _normalise_rules_dir(rules_dir)
    if not resolved_dir.exists() or not resolved_dir.is_dir():
        logger.warning("Kill chain service: rules directory missing: %s", resolved_dir)
        return {}

    yaml_files = glob.glob(os.path.join(str(resolved_dir), "*.yaml")) + glob.glob(
        os.path.join(str(resolved_dir), "*.yml")
    )
    if not yaml_files:
        logger.warning("Kill chain service: no YAML rules found in %s", resolved_dir)
        return {}

    rule_map: dict[str, dict[str, str]] = {}
    for file_path in sorted(yaml_files):
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("Kill chain service: failed to parse %s: %s", file_path, exc)
            continue

        if isinstance(loaded, dict):
            rules = [loaded]
        elif isinstance(loaded, list):
            rules = [entry for entry in loaded if isinstance(entry, dict)]
        else:
            logger.warning("Kill chain service: unsupported YAML structure in %s", file_path)
            continue

        for rule in rules:
            rule_id = str(rule.get("id", "") or "").strip()
            if not rule_id:
                continue

            rule_name = str(rule.get("name", "") or "").strip()
            tactic_value = str(rule.get("mitre_tactic", "") or "").strip()
            technique_id = str(rule.get("mitre_technique", "") or "").strip()
            technique_name = ""

            tactic_id = ""
            tactic_name = ""
            if not tactic_value:
                logger.debug("Rule %s: missing mitre_tactic field", rule_id)
            else:
                lookup_name = _TACTIC_BY_NAME.get(tactic_value.lower())
                lookup_id = _TACTIC_BY_ID.get(tactic_value)
                if lookup_name:
                    tactic_id = str(lookup_name["tactic_id"])
                    tactic_name = str(lookup_name["tactic_name"])
                elif lookup_id:
                    tactic_id = str(lookup_id["tactic_id"])
                    tactic_name = str(lookup_id["tactic_name"])
                else:
                    logger.warning(
                        "Rule %s: unrecognised tactic '%s' — not in canonical list",
                        rule_id,
                        tactic_value,
                    )
                    tactic_id = "UNKNOWN"
                    tactic_name = tactic_value

            rule_map[rule_id] = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "rule_name": rule_name,
            }
    return rule_map


def format_relative_time(dt: Optional[datetime]) -> str:
    """Returns a human-readable relative time string for a UTC datetime."""
    normalised = _normalise_datetime(dt)
    if normalised is None:
        return "—"
    delta_td = datetime.now(timezone.utc) - normalised
    delta = delta_td.total_seconds()
    if delta_td < timedelta(0):
        return "just now"
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def _normalise_datetime(value: Optional[datetime]) -> Optional[datetime]:
    """Return an aware UTC datetime for mixed naive/aware values."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _empty_statuses(rule_tactic_map: dict) -> list[TacticStatus]:
    statuses: list[TacticStatus] = []
    for tactic in TACTIC_DISPLAY_ORDER:
        tactic_id = tactic["tactic_id"]
        mapped_rule_ids = sorted(
            rule_id for rule_id, meta in rule_tactic_map.items() if meta.get("tactic_id") == tactic_id
        )
        statuses.append(
            TacticStatus(
                tactic_id=tactic_id,
                tactic_name=str(tactic["tactic_name"]),
                display_order=int(tactic["display_order"]),
                fired=False,
                hit_count=0,
                last_seen=None,
                fired_rules=[],
                total_rules_mapped=len(mapped_rule_ids),
                all_rule_ids=mapped_rule_ids,
            )
        )
    return statuses


def get_kill_chain_status(
    session,
    time_from: datetime,
    time_to: datetime,
    rule_tactic_map: dict,
) -> list[TacticStatus]:
    """
    Query rule_hits in [time_from, time_to] and return one TacticStatus per
    entry in TACTIC_DISPLAY_ORDER, in display_order sequence.

    Never raises. On any DB error, logs the exception and returns all tactics
    in not-fired state.
    """
    norm_time_from = _normalise_datetime(time_from)
    norm_time_to = _normalise_datetime(time_to)
    if norm_time_from is None or norm_time_to is None:
        return _empty_statuses(rule_tactic_map)

    try:
        timestamp_col = RuleHitRecord.timestamp
        rule_id_col = RuleHitRecord.rule_id
        rows = (
            session.query(RuleHitRecord)
            .filter(timestamp_col >= time_from, timestamp_col <= time_to)
            .all()
        )
    except Exception:  # noqa: BLE001
        logger.exception("Kill chain status query failed")
        return _empty_statuses(rule_tactic_map)

    hits_by_rule_id: dict[str, dict[str, Optional[datetime] | int]] = {}
    for row in rows:
        row_rule_id = getattr(row, "rule_id", None)
        row_timestamp = getattr(row, "timestamp", None)
        norm_row_timestamp = _normalise_datetime(row_timestamp)
        if not row_rule_id:
            continue
        if (
            norm_row_timestamp is None
            or norm_row_timestamp < norm_time_from
            or norm_row_timestamp > norm_time_to
        ):
            continue
        bucket = hits_by_rule_id.setdefault(str(row_rule_id), {"hit_count": 0, "last_seen": None})
        bucket["hit_count"] = int(bucket["hit_count"]) + 1
        current_last_seen = bucket["last_seen"]
        if current_last_seen is None or norm_row_timestamp > current_last_seen:
            bucket["last_seen"] = norm_row_timestamp

    tactic_hits: dict[str, dict[str, dict[str, Optional[datetime] | int]]] = {}
    for hit_rule_id, agg in hits_by_rule_id.items():
        meta = rule_tactic_map.get(hit_rule_id)
        if meta is None:
            logger.warning("Kill chain status: rule_id %s missing from tactic map; skipping", hit_rule_id)
            continue
        tactic_id = str(meta.get("tactic_id", ""))
        if not tactic_id:
            continue
        tactic_hits.setdefault(tactic_id, {})[hit_rule_id] = agg

    statuses: list[TacticStatus] = []
    for tactic in TACTIC_DISPLAY_ORDER:
        tactic_id = str(tactic["tactic_id"])
        mapped_rule_ids = sorted(
            rule_id for rule_id, meta in rule_tactic_map.items() if meta.get("tactic_id") == tactic_id
        )

        fired_rules: list[RuleDetail] = []
        for mapped_rule_id in mapped_rule_ids:
            hit_meta = tactic_hits.get(tactic_id, {}).get(mapped_rule_id)
            if hit_meta is None or int(hit_meta["hit_count"]) <= 0:
                continue
            rule_meta = rule_tactic_map.get(mapped_rule_id, {})
            fired_rules.append(
                RuleDetail(
                    rule_id=mapped_rule_id,
                    rule_name=str(rule_meta.get("rule_name", "")),
                    technique_id=str(rule_meta.get("technique_id", "")),
                    technique_name=str(rule_meta.get("technique_name", "")),
                    hit_count=int(hit_meta["hit_count"]),
                    last_seen=hit_meta["last_seen"],  # type: ignore[arg-type]
                )
            )

        fired_rules.sort(key=lambda item: item.hit_count, reverse=True)
        hit_count = sum(item.hit_count for item in fired_rules)
        last_seen = max(
            (item.last_seen for item in fired_rules if item.last_seen is not None),
            default=None,
        )
        statuses.append(
            TacticStatus(
                tactic_id=tactic_id,
                tactic_name=str(tactic["tactic_name"]),
                display_order=int(tactic["display_order"]),
                fired=hit_count > 0,
                hit_count=hit_count,
                last_seen=last_seen,
                fired_rules=fired_rules,
                total_rules_mapped=len(mapped_rule_ids),
                all_rule_ids=mapped_rule_ids,
            )
        )
    return statuses


def get_tactic_rule_detail(
    session,
    tactic_id: str,
    time_from: datetime,
    time_to: datetime,
    rule_tactic_map: dict,
) -> list[RuleDetail]:
    """
    Return per-rule breakdown for a single tactic, for rules that fired in the window.
    Returns empty list if tactic_id not in TACTIC_DISPLAY_ORDER or no rules fired.
    Never raises.
    """
    if tactic_id not in _TACTIC_BY_ID:
        return []

    rule_ids = sorted(rule_id for rule_id, meta in rule_tactic_map.items() if meta.get("tactic_id") == tactic_id)
    if not rule_ids:
        return []

    norm_time_from = _normalise_datetime(time_from)
    norm_time_to = _normalise_datetime(time_to)
    if norm_time_from is None or norm_time_to is None:
        return []

    try:
        rows = (
            session.query(RuleHitRecord)
            .filter(
                RuleHitRecord.rule_id.in_(rule_ids),
                RuleHitRecord.timestamp >= time_from,
                RuleHitRecord.timestamp <= time_to,
            )
            .all()
        )
    except Exception:  # noqa: BLE001
        logger.exception("Kill chain stage detail query failed for tactic %s", tactic_id)
        return []

    hits_by_rule_id: dict[str, dict[str, Optional[datetime] | int]] = {}
    for row in rows:
        row_rule_id = getattr(row, "rule_id", None)
        row_timestamp = getattr(row, "timestamp", None)
        norm_row_timestamp = _normalise_datetime(row_timestamp)
        if not row_rule_id:
            continue
        if (
            norm_row_timestamp is None
            or norm_row_timestamp < norm_time_from
            or norm_row_timestamp > norm_time_to
        ):
            continue
        bucket = hits_by_rule_id.setdefault(str(row_rule_id), {"hit_count": 0, "last_seen": None})
        bucket["hit_count"] = int(bucket["hit_count"]) + 1
        current_last_seen = bucket["last_seen"]
        if current_last_seen is None or norm_row_timestamp > current_last_seen:
            bucket["last_seen"] = norm_row_timestamp

    details: list[RuleDetail] = []
    for rule_id, agg in hits_by_rule_id.items():
        if int(agg["hit_count"]) <= 0:
            continue
        rule_meta = rule_tactic_map.get(rule_id, {})
        details.append(
            RuleDetail(
                rule_id=rule_id,
                rule_name=str(rule_meta.get("rule_name", "")),
                technique_id=str(rule_meta.get("technique_id", "")),
                technique_name=str(rule_meta.get("technique_name", "")),
                hit_count=int(agg["hit_count"]),
                last_seen=agg["last_seen"],  # type: ignore[arg-type]
            )
        )

    details.sort(key=lambda item: item.hit_count, reverse=True)
    return details


_rule_tactic_map: dict = {}


def initialise_rule_tactic_map(rules_dir: str) -> None:
    """Call once at application startup to populate the module-level cache."""
    global _rule_tactic_map
    _rule_tactic_map = load_rule_tactic_map(rules_dir)
    logger.info(
        "Kill chain service: loaded %d rules, %d unique tactics covered.",
        len(_rule_tactic_map),
        len(
            set(
                value["tactic_id"]
                for value in _rule_tactic_map.values()
                if value.get("tactic_id") and value["tactic_id"] != "UNKNOWN"
            )
        ),
    )


def get_rule_tactic_map() -> dict:
    """Return the cached rule tactic map. Returns empty dict if not yet initialised."""
    return _rule_tactic_map
