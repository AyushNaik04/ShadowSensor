"""Tests for normalizer.parser and normalizer.models modules."""

from pathlib import Path

import pytest
from normalizer.models import (
    CreateRemoteThreadEvent,
    DnsQueryEvent,
    ImageLoadEvent,
    NetworkConnectEvent,
    OpenProcessEvent,
    ProcessCreateEvent,
)
from normalizer.parser import _coerce_bool, _coerce_int, parse_event

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

SAMPLES_DIR = Path("tests/fixtures/sysmon_samples")


def sample_exists(name: str) -> bool:
    """Return True if the named Sysmon XML sample file exists on disk."""
    return (SAMPLES_DIR / name).exists()


def _missing_note(name: str) -> str:
    return (
        f"Sysmon sample XML files not found — copy from lab host into "
        f"tests/fixtures/sysmon_samples/ before running these tests. Missing: {name}"
    )


# ---------------------------------------------------------------------------
# Happy-path tests using real Sysmon XML samples
# ---------------------------------------------------------------------------

_SAMPLE_1 = "sample_event_1_processcreate.xml"
_SAMPLE_3 = "sample_event_3_networkconnect.xml"
_SAMPLE_7 = "sample_event_7_imageload.xml"
_SAMPLE_10 = "sample_event_10_openprocess.xml"
_SAMPLE_22 = "sample_event_22_dnsquery.xml"


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_1),
    reason=_missing_note(_SAMPLE_1),
)
def test_parse_event_1_returns_process_create_event() -> None:
    """parse_event returns a ProcessCreateEvent for a real Event ID 1 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_1).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, ProcessCreateEvent)
    assert result.event_id == 1
    assert result.image is not None


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_3),
    reason=_missing_note(_SAMPLE_3),
)
def test_parse_event_3_returns_network_connect_event() -> None:
    """parse_event returns a NetworkConnectEvent for a real Event ID 3 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_3).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, NetworkConnectEvent)
    assert result.event_id == 3
    assert result.image is not None


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_7),
    reason=_missing_note(_SAMPLE_7),
)
def test_parse_event_7_returns_image_load_event() -> None:
    """parse_event returns an ImageLoadEvent for a real Event ID 7 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_7).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, ImageLoadEvent)
    assert result.event_id == 7
    assert result.image is not None


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_10),
    reason=_missing_note(_SAMPLE_10),
)
def test_parse_event_10_returns_open_process_event() -> None:
    """parse_event returns an OpenProcessEvent for a real Event ID 10 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_10).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, OpenProcessEvent)
    assert result.event_id == 10
    assert result.source_image is not None


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_22),
    reason=_missing_note(_SAMPLE_22),
)
def test_parse_event_22_returns_dns_query_event() -> None:
    """parse_event returns a DnsQueryEvent for a real Event ID 22 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_22).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, DnsQueryEvent)
    assert result.event_id == 22
    assert result.query_name is not None


# ---------------------------------------------------------------------------
# Event ID 8 — synthetic XML (no real sample exists until Phase 4B)
# ---------------------------------------------------------------------------

_EVENT_8_XML = """\
<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2026-06-22T10:00:00.000000000Z"/>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name="SourceProcessId">1234</Data>
    <Data Name="SourceImage">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="TargetProcessId">5678</Data>
    <Data Name="TargetImage">C:\\Windows\\System32\\notepad.exe</Data>
  </EventData>
</Event>"""


def test_parse_event_8_returns_create_remote_thread_event() -> None:
    """parse_event returns a CreateRemoteThreadEvent for a synthetic Event ID 8 XML."""
    result = parse_event(_EVENT_8_XML)
    assert isinstance(result, CreateRemoteThreadEvent)
    assert result.event_id == 8


# ---------------------------------------------------------------------------
# Error-handling tests
# ---------------------------------------------------------------------------


def test_parse_event_returns_none_on_malformed_xml() -> None:
    """parse_event returns None for input that is not valid XML."""
    result = parse_event("this is not xml {{{{")
    assert result is None


def test_parse_event_returns_none_on_unknown_event_id() -> None:
    """parse_event returns None when EventID is not in TARGET_EVENT_IDS."""
    xml = """\
<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>999</EventID>
    <TimeCreated SystemTime="2026-06-22T10:00:00.000000000Z"/>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData/>
</Event>"""
    result = parse_event(xml)
    assert result is None


# ---------------------------------------------------------------------------
# _coerce_int tests
# ---------------------------------------------------------------------------


def test_coerce_int_handles_valid_string() -> None:
    """_coerce_int returns the integer value for a valid numeric string."""
    assert _coerce_int("1234") == 1234


def test_coerce_int_returns_none_on_none() -> None:
    """_coerce_int returns None when given None."""
    assert _coerce_int(None) is None


def test_coerce_int_returns_none_on_nonnumeric() -> None:
    """_coerce_int returns None for a non-numeric string."""
    assert _coerce_int("abc") is None


# ---------------------------------------------------------------------------
# _coerce_bool tests
# ---------------------------------------------------------------------------


def test_coerce_bool_true_variants() -> None:
    """_coerce_bool returns True for all case variants of 'true'."""
    assert _coerce_bool("true") is True
    assert _coerce_bool("True") is True
    assert _coerce_bool("TRUE") is True


def test_coerce_bool_false_variants() -> None:
    """_coerce_bool returns False for 'false' (case-insensitive)."""
    assert _coerce_bool("false") is False
    assert _coerce_bool("False") is False


def test_coerce_bool_returns_none_on_garbage() -> None:
    """_coerce_bool returns None for unrecognised strings and None input."""
    assert _coerce_bool("yes") is None
    assert _coerce_bool(None) is None


# ---------------------------------------------------------------------------
# Field mapping test using real ProcessCreate sample
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not sample_exists(_SAMPLE_1),
    reason=_missing_note(_SAMPLE_1),
)
def test_process_create_command_line_populated() -> None:
    """ProcessCreateEvent.command_line is populated from the real Event ID 1 sample."""
    xml = (SAMPLES_DIR / _SAMPLE_1).read_text(encoding="utf-8")
    result = parse_event(xml)
    assert isinstance(result, ProcessCreateEvent)
    assert result.command_line is not None
