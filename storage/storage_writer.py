"""StorageWriter for persisting normalized events, rule hits, and alerts."""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import UTC, datetime
from typing import Any

from storage.database import get_session
from storage.models import AlertRecord, EventRecord, RuleHitRecord

logger = logging.getLogger(__name__)


class StorageWriter:
    """Persist pipeline artifacts to SQLite.

    Validation problems return None. Unexpected DB/ORM failures are logged and
    re-raised so callers can surface them without silent loss.
    """

    def __init__(self) -> None:
        self._event_type_map: dict[str, int] = {
            "ProcessCreateEvent": 1,
            "NetworkConnectEvent": 3,
            "ImageLoadEvent": 7,
            "CreateRemoteThreadEvent": 8,
            "OpenProcessEvent": 10,
            "DnsQueryEvent": 22,
        }
        self._pid_attr: dict[str, str] = {
            "ProcessCreateEvent": "process_id",
            "NetworkConnectEvent": "process_id",
            "ImageLoadEvent": "process_id",
            "CreateRemoteThreadEvent": "source_process_id",
            "OpenProcessEvent": "source_process_id",
            "DnsQueryEvent": "process_id",
        }
        self._image_attr: dict[str, str] = {
            "ProcessCreateEvent": "image",
            "NetworkConnectEvent": "image",
            "ImageLoadEvent": "image",
            "CreateRemoteThreadEvent": "source_image",
            "OpenProcessEvent": "source_image",
            "DnsQueryEvent": "image",
        }

    @staticmethod
    def _coerce_datetime(value: Any) -> datetime | None:
        """Convert an ISO-like datetime string/object into a datetime."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            candidate = value.replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                return None
        return None

    @staticmethod
    def _utc_now() -> datetime:
        """Return current UTC datetime."""
        return datetime.now(UTC)

    def write_event(self, event: Any) -> int | None:
        """Persist a normalized event dataclass.

        Validation problems (non-dataclass / unknown type) return None.
        Unexpected persistence errors are logged and re-raised for the caller
        to surface without being silently discarded.
        """
        try:
            if not dataclasses.is_dataclass(event):
                logger.warning("write_event received non-dataclass event: %r", type(event))
                return None

            class_name = type(event).__name__
            event_type_id = self._event_type_map.get(class_name) or getattr(event, "event_id", None)
            if event_type_id is None:
                logger.warning("Unable to determine event_type_id for class %s", class_name)
                return None

            timestamp = self._coerce_datetime(getattr(event, "utc_time", None)) or self._utc_now()
            if class_name not in self._event_type_map:
                logger.warning("Unknown event class '%s'; storing nullable pid/image", class_name)

            pid_attr = self._pid_attr.get(class_name, "")
            image_attr = self._image_attr.get(class_name, "")
            pid = getattr(event, pid_attr, None) if pid_attr else None
            image = getattr(event, image_attr, None) if image_attr else None

            payload = json.dumps(dataclasses.asdict(event), default=str)

            with get_session() as session:
                record = EventRecord(
                    event_type_id=int(event_type_id),
                    timestamp=timestamp,
                    pid=pid,
                    image=image,
                    raw_json=payload,
                )
                session.add(record)
                session.flush()
                return record.id
        except Exception as exc:
            logger.error(
                "Failed to write event to SQLite [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            raise

    def write_rule_hit(self, hit: Any, event_id: int | None) -> int | None:
        """Persist a RuleHit object. Persistence errors are logged and re-raised."""
        try:
            ts_value = (
                getattr(hit, "timestamp", None)
                or getattr(hit, "fired_at", None)
                or getattr(getattr(hit, "matched_event", None), "utc_time", None)
            )
            timestamp = self._coerce_datetime(ts_value) or self._utc_now()

            matched_fields = getattr(hit, "matched_fields", None)
            matched_fields_json = None
            if matched_fields is not None:
                matched_fields_json = json.dumps(matched_fields, default=str)

            with get_session() as session:
                record = RuleHitRecord(
                    event_fk=event_id,
                    rule_id=getattr(hit, "rule_id"),
                    rule_name=getattr(hit, "rule_name"),
                    severity=getattr(hit, "severity"),
                    mitre_technique=getattr(hit, "mitre_technique", None),
                    mitre_tactic=getattr(hit, "mitre_tactic", None),
                    matched_fields=matched_fields_json,
                    timestamp=timestamp,
                )
                session.add(record)
                session.flush()
                return record.id
        except Exception as exc:
            logger.error(
                "Failed to write rule hit to SQLite [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            raise

    def write_alert_from_hit(
        self,
        hit: Any,
        rule_hit_id: int | None,
        event_id: int | None,
        raw_event: Any,
    ) -> int | None:
        """Persist one alert for one rule hit. Persistence errors are logged and re-raised."""
        try:
            payload: dict[str, Any] = {}
            if dataclasses.is_dataclass(raw_event):
                payload = json.loads(json.dumps(dataclasses.asdict(raw_event), default=str))
            elif isinstance(raw_event, dict):
                payload = raw_event

            process_image = payload.get("image") or payload.get("source_image")
            process_pid = payload.get("process_id") or payload.get("source_process_id")
            command_line = payload.get("command_line")
            parent_image = payload.get("parent_image")

            ts_value = (
                getattr(hit, "timestamp", None)
                or getattr(hit, "fired_at", None)
                or payload.get("utc_time")
            )
            timestamp = self._coerce_datetime(ts_value) or self._utc_now()

            with get_session() as session:
                record = AlertRecord(
                    rule_hit_fk=rule_hit_id,
                    event_fk=event_id,
                    rule_id=getattr(hit, "rule_id"),
                    rule_name=getattr(hit, "rule_name"),
                    severity=getattr(hit, "severity"),
                    mitre_technique=getattr(hit, "mitre_technique", None),
                    mitre_tactic=getattr(hit, "mitre_tactic", None),
                    process_image=process_image,
                    process_pid=process_pid,
                    command_line=command_line,
                    parent_image=parent_image,
                    status="open",
                    suspected_families=None,
                    timestamp=timestamp,
                )
                session.add(record)
                session.flush()
                return record.id
        except Exception as exc:
            logger.error(
                "Failed to write alert to SQLite [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            raise
