"""Entry point for starting the ShadowSensor event collection pipeline."""

import logging
import threading
from collections.abc import Callable
from pathlib import Path

from normalizer.models import SysmonEvent
from normalizer.parser import parse_event

from collector.constants import BOOKMARK_FILE, POLL_INTERVAL_SECONDS
from collector.poller import SysmonPoller

logger = logging.getLogger(__name__)


def run_collector(
    callback: Callable[[SysmonEvent], None],
    poll_interval: float = POLL_INTERVAL_SECONDS,
    bookmark_path: Path = BOOKMARK_FILE,
) -> SysmonPoller:
    """Create a SysmonPoller, wire it to the normalizer, and start polling.

    The callback receives a fully typed SysmonEvent dataclass for every
    event received from the Sysmon channel. Events that fail normalization
    are silently dropped (logged at WARNING by the normalizer).

    Args:
        callback: Called with a typed SysmonEvent for each received event.
        poll_interval: Seconds between poll cycles.
        bookmark_path: Path to the bookmark persistence file.

    Returns:
        The running SysmonPoller instance. Call .stop() on it to halt collection.
    """

    def _inner_callback(xml: str, event_id: int) -> None:
        result = parse_event(xml)
        if result is not None:
            callback(result)

    poller = SysmonPoller(
        poll_interval=poll_interval,
        bookmark_path=bookmark_path,
    )

    thread = threading.Thread(
        target=poller.start,
        args=(_inner_callback,),
        daemon=True,
        name="ShadowSensor-Collector",
    )
    thread.start()
    logger.info("Event collection pipeline started (thread: %s)", thread.name)
    return poller
