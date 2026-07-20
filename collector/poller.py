"""Sysmon event log poller using the Windows EVT API."""

import logging
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

if sys.platform != "win32":
    raise ImportError("This module requires Windows. Run on Windows 10/11.")

import win32evtlog
from lxml import etree

from collector.bookmark import load_bookmark, save_bookmark
from collector.constants import (
    BATCH_SIZE,
    BOOKMARK_FILE,
    EVT_XPATH_FILTER,
    POLL_INTERVAL_SECONDS,
    SYSMON_CHANNEL,
)

logger = logging.getLogger(__name__)

# Windows error code returned when there are no more events to retrieve
_ERROR_NO_MORE_ITEMS: int = 259

# XML namespace for all Windows EVT / Sysmon events
_NS: str = "http://schemas.microsoft.com/win/2004/08/events/event"


class SysmonPoller:
    """Polls Microsoft-Windows-Sysmon/Operational and yields raw XML strings
    for the configured target event IDs.

    Args:
        channel: EVT channel name to poll.
        poll_interval: Seconds to sleep between poll cycles.
        bookmark_path: Path to the bookmark persistence file.
        batch_size: Number of events to request per EvtNext call.
    """

    def __init__(
        self,
        channel: str = SYSMON_CHANNEL,
        poll_interval: float = POLL_INTERVAL_SECONDS,
        bookmark_path: Path = BOOKMARK_FILE,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        self._channel = channel
        self._poll_interval = poll_interval
        self._bookmark_path = bookmark_path
        self._batch_size = batch_size
        self._stop_event = threading.Event()
        self._bookmark_xml: str | None = load_bookmark(bookmark_path)
        self._bookmark_handle: Any = win32evtlog.EvtCreateBookmark(self._bookmark_xml)
        self._bookmark_updated: bool = False

    def start(self, callback: Callable[[str, int], None]) -> None:
        """Start the blocking poll loop.

        Calls callback(xml_string, event_id) for every event received.
        Runs until stop() is called from another thread.

        Args:
            callback: Function receiving (xml_string, event_id) for each event.
        """
        try:
            while not self._stop_event.is_set():
                results = self._poll_once()
                for xml, event_id in results:
                    callback(xml, event_id)
                self._stop_event.wait(timeout=self._poll_interval)
        finally:
            self._bookmark_handle.Close()

    def stop(self) -> None:
        """Signal the poll loop to exit after the current cycle completes."""
        self._stop_event.set()

    def _poll_once(self) -> list[tuple[str, int]]:
        """Single poll cycle: query the channel from the current bookmark position,
        process all available events, update the bookmark, return results.

        Returns:
            List of (xml_string, event_id) tuples. Empty list if no new events.
        """
        results: list[tuple[str, int]] = []
        query_handle: Any = None
        try:
            query_handle = self._open_query()
            while True:
                try:
                    events = win32evtlog.EvtNext(query_handle, self._batch_size)
                except Exception as exc:
                    winerror = getattr(exc, "winerror", None)
                    if winerror == _ERROR_NO_MORE_ITEMS:
                        break
                    logger.error("EvtNext failed: %s", exc)
                    break
                if not events:
                    break
                for event_handle in events:
                    try:
                        xml = self._render_event_xml(event_handle)
                        event_id = self._extract_event_id_from_xml(xml)
                        win32evtlog.EvtUpdateBookmark(self._bookmark_handle, event_handle)
                        self._bookmark_updated = True
                        results.append((xml, event_id))
                    except Exception as exc:
                        logger.warning("Failed to process event handle: %s", exc)
                    finally:
                        event_handle.Close()
            if self._bookmark_updated:
                bookmark_xml = win32evtlog.EvtRender(
                    self._bookmark_handle, win32evtlog.EvtRenderBookmark
                )
                save_bookmark(self._bookmark_path, bookmark_xml)
        except RuntimeError:
            raise
        except Exception as exc:
            logger.error("Unexpected error in poll cycle: %s", exc)
        finally:
            if query_handle is not None:
                query_handle.Close()
        return results

    def _open_query(self) -> Any:
        """Open an EVT query handle starting from the current bookmark position.

        If a bookmark exists: opens a forward query and seeks past the last
        bookmarked event so only newer events are returned.
        If no bookmark: opens a forward query and seeks to the end of the log
        so only events arriving after startup are returned.

        Returns:
            EVT query handle. Caller is responsible for calling .Close().

        Raises:
            RuntimeError: If the channel cannot be opened (Sysmon not installed).
        """
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        try:
            query_handle = win32evtlog.EvtQuery(self._channel, flags, EVT_XPATH_FILTER)
        except Exception as exc:
            raise RuntimeError(
                "Sysmon channel not found. Is Sysmon installed and running?"
            ) from exc

        if self._bookmark_updated or self._bookmark_xml is not None:
            try:
                win32evtlog.EvtSeek(
                    query_handle,
                    1,
                    Bookmark=self._bookmark_handle,
                    Flags=win32evtlog.EvtSeekRelativeToBookmark,
                )
            except Exception as exc:
                logger.warning("EvtSeek from bookmark failed, reading from start: %s", exc)
        else:
            try:
                win32evtlog.EvtSeek(
                    query_handle,
                    0,
                    Flags=win32evtlog.EvtSeekRelativeToLast,
                )
            except Exception:
                pass

        return query_handle

    def _render_event_xml(self, event_handle: Any) -> str:
        """Render a single EVT event handle to an XML string.

        Args:
            event_handle: Handle returned by EvtNext.

        Returns:
            XML string representing the full event.
        """
        return win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)

    def _extract_event_id_from_xml(self, xml: str) -> int:
        """Extract the EventID integer from a rendered Sysmon XML string.

        Uses lxml for consistency with the normalizer.

        Args:
            xml: Rendered event XML string.

        Returns:
            Integer event ID.

        Raises:
            ValueError: If EventID cannot be found or parsed from the XML.
        """
        try:
            root = etree.fromstring(xml.encode("utf-8"))
            system = root.find(f"{{{_NS}}}System")
            if system is None:
                raise ValueError("No System element found in event XML")
            event_id_elem = system.find(f"{{{_NS}}}EventID")
            if event_id_elem is None or event_id_elem.text is None:
                raise ValueError("No EventID element found in System block")
            return int(event_id_elem.text)
        except (etree.XMLSyntaxError, UnicodeEncodeError) as exc:
            raise ValueError(f"Malformed XML — cannot extract EventID: {exc}") from exc
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Unexpected error extracting EventID: {exc}") from exc
