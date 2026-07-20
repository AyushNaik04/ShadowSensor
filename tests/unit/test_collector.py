"""Tests for collector.bookmark and collector.poller modules."""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Cross-platform guard: inject a stub win32evtlog into sys.modules so that
# collector.poller can be imported on non-Windows hosts.  On Windows (the
# target platform) the real pywin32 module is used and specific API calls
# are patched per test to avoid touching the live event log.
# ---------------------------------------------------------------------------
if sys.platform != "win32":
    _mock_win32evtlog = MagicMock()
    _mock_win32evtlog.error = OSError
    sys.modules.setdefault("win32evtlog", _mock_win32evtlog)

from collector.bookmark import load_bookmark, save_bookmark
from collector.poller import SysmonPoller

# ---------------------------------------------------------------------------
# bookmark.py tests
# ---------------------------------------------------------------------------


def test_load_bookmark_returns_none_when_file_missing(tmp_path: Path) -> None:
    """load_bookmark returns None when the bookmark file does not exist."""
    result = load_bookmark(tmp_path / "nonexistent_bookmark.xml")
    assert result is None


def test_load_bookmark_returns_xml_when_file_exists(tmp_path: Path) -> None:
    """load_bookmark returns the file content when the bookmark file exists."""
    bookmark_file = tmp_path / "bookmark.xml"
    expected = "<BookmarkList><Bookmark Channel='test' RecordId='42'/></BookmarkList>"
    bookmark_file.write_text(expected, encoding="utf-8")

    result = load_bookmark(bookmark_file)

    assert result == expected


def test_save_bookmark_creates_file(tmp_path: Path) -> None:
    """save_bookmark writes the bookmark XML to the target path."""
    target = tmp_path / "bookmark.xml"
    content = "<BookmarkList><Bookmark Channel='test' RecordId='1'/></BookmarkList>"

    save_bookmark(target, content)

    assert target.exists()
    assert target.read_text(encoding="utf-8") == content


def test_save_bookmark_is_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """save_bookmark removes the .tmp file when the replace operation fails.

    Phase 2B: bookmark.py was changed from Path.rename() to Path.replace() to fix
    WinError 183 on Windows (rename fails when destination already exists; replace
    uses MoveFileExW with REPLACE_EXISTING which works on both platforms).
    This test patches Path.replace to simulate a mid-write failure and verifies
    the cleanup path still removes the orphaned .tmp file.
    """
    target = tmp_path / "bookmark.xml"
    content = "<bookmark/>"

    original_replace = Path.replace
    call_count: list[int] = [0]

    def failing_replace(self: Path, new_path: object) -> object:
        call_count[0] += 1
        if call_count[0] == 1:
            raise OSError("Simulated replace failure for atomic write test")
        return original_replace(self, new_path)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "replace", failing_replace)

    save_bookmark(target, content)

    assert not (tmp_path / "bookmark.tmp").exists(), (
        "Atomic write must not leave a .tmp file behind on replace failure"
    )
    assert not target.exists(), "Target must not be created when replace fails"


# ---------------------------------------------------------------------------
# Helper: build a SysmonPoller with win32evtlog.EvtCreateBookmark patched
# so __init__ does not touch the real event log.
# ---------------------------------------------------------------------------

_MINIMAL_EVENT_XML = """\
<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-22T10:00:00.000000000Z"/>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData/>
</Event>"""


def _make_poller(bookmark_path: Path | None = None) -> SysmonPoller:
    """Create a SysmonPoller instance with EVT init calls patched out."""
    mock_handle = MagicMock()
    mock_handle.Close = MagicMock()
    path = bookmark_path if bookmark_path is not None else Path("nonexistent_bookmark.xml")
    with patch("win32evtlog.EvtCreateBookmark", return_value=mock_handle):
        return SysmonPoller(bookmark_path=path, poll_interval=0.05)


# ---------------------------------------------------------------------------
# poller.py tests (win32evtlog API calls are patched)
# ---------------------------------------------------------------------------


def test_extract_event_id_from_xml() -> None:
    """_extract_event_id_from_xml returns the correct integer EventID."""
    poller = _make_poller()
    result = poller._extract_event_id_from_xml(_MINIMAL_EVENT_XML)
    assert result == 1


def test_extract_event_id_raises_on_malformed_xml() -> None:
    """_extract_event_id_from_xml raises ValueError on garbage input."""
    poller = _make_poller()
    with pytest.raises(ValueError):
        poller._extract_event_id_from_xml("this is definitely not xml {{{{")


def test_poller_stop_exits_loop(tmp_path: Path) -> None:
    """stop() causes the polling thread to exit within the timeout window."""
    poller = _make_poller(bookmark_path=tmp_path / "bookmark.xml")

    received: list[tuple[str, int]] = []

    def dummy_callback(xml: str, event_id: int) -> None:
        received.append((xml, event_id))

    with patch.object(poller, "_poll_once", return_value=[]):
        thread = threading.Thread(
            target=poller.start,
            args=(dummy_callback,),
            daemon=True,
        )
        thread.start()
        time.sleep(0.1)
        poller.stop()
        thread.join(timeout=5.0)

    assert not thread.is_alive(), "Poller thread must exit within 5 seconds of stop()"
