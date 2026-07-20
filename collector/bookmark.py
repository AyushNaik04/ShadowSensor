"""Bookmark persistence for the Sysmon EVT log position."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_bookmark(path: Path) -> str | None:
    """Load a saved EVT bookmark XML string from disk.

    Args:
        path: File path to read the bookmark XML from.

    Returns:
        The bookmark XML string if the file exists, or None if the file is
        absent or any read error occurs.
    """
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8")
        logger.debug("Loaded bookmark from %s", path)
        return content
    except Exception as e:
        logger.error("Failed to load bookmark from %s: %s", path, e)
        return None


def save_bookmark(path: Path, bookmark_xml: str) -> None:
    """Persist an EVT bookmark XML string to disk using an atomic write.

    Writes to a temporary file first, then renames it to the target path.
    A failed save is logged but does not raise — the collector continues
    running, and the next restart may re-process a small number of events.

    Args:
        path: Destination file path for the bookmark XML.
        bookmark_xml: Serialized EVT bookmark XML string.
    """
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(bookmark_xml, encoding="utf-8")
        tmp_path.replace(path)  # replace() is atomic on Windows even when destination exists; rename() is not
        logger.debug("Saved bookmark to %s", path)
    except Exception as e:
        logger.error("Failed to save bookmark to %s: %s", path, e)
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception as cleanup_err:
            logger.error("Failed to clean up temp bookmark file %s: %s", tmp_path, cleanup_err)
