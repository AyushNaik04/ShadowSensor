"""Alert manager stub for Phase 3 one-hit-to-one-alert behavior."""

from __future__ import annotations

import logging
from typing import Any

from storage.storage_writer import StorageWriter

logger = logging.getLogger(__name__)


class AlertManager:
    """Phase 3 stub that maps each rule hit to one alert."""

    def __init__(self, storage_writer: StorageWriter) -> None:
        self._writer = storage_writer

    def process_hit(
        self,
        hit: Any,
        rule_hit_id: int | None,
        event_id: int | None,
        raw_event: Any,
    ) -> None:
        """Create one alert for a rule hit. No deduplication or correlation."""
        try:
            self._writer.write_alert_from_hit(hit, rule_hit_id, event_id, raw_event)
        except Exception as exc:  # pragma: no cover - defensive contract
            logger.warning("AlertManager failed to process hit (non-fatal): %s", exc)
