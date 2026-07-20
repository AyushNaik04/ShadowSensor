"""Sysmon XML parser: converts raw event XML strings into typed SysmonEvent dataclasses."""

import logging
from typing import Any

from collector.constants import TARGET_EVENT_IDS
from lxml import etree

from normalizer.field_maps import FIELD_MAPS
from normalizer.models import (
    CreateRemoteThreadEvent,
    DnsQueryEvent,
    ImageLoadEvent,
    NetworkConnectEvent,
    OpenProcessEvent,
    ProcessCreateEvent,
    SysmonEvent,
)

logger = logging.getLogger(__name__)

# XML namespace for all Windows EVT / Sysmon events
NS: str = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse_event(xml: str) -> SysmonEvent | None:
    """Parse a Sysmon event XML string into a typed dataclass.

    Never raises. Returns None if the XML is malformed, the EventID is not
    in TARGET_EVENT_IDS, or any unrecoverable parse error occurs.

    Args:
        xml: Raw XML string from EvtRender.

    Returns:
        A typed SysmonEvent dataclass, or None.
    """
    try:
        root = etree.fromstring(xml.encode("utf-8"))
    except etree.XMLSyntaxError as exc:
        logger.warning("Skipping malformed event XML: %s", exc)
        return None
    except Exception as exc:
        logger.error("Unexpected error parsing event XML: %s", exc)
        return None

    try:
        system_fields = _extract_system_fields(root)
    except ValueError as exc:
        logger.warning("Skipping event — cannot extract system fields: %s", exc)
        return None

    event_id: int = system_fields["event_id"]
    if event_id not in TARGET_EVENT_IDS:
        return None

    try:
        data_fields = _extract_data_fields(root, event_id)
        return _build_event(event_id, system_fields, data_fields)
    except Exception as exc:
        logger.warning("Skipping event ID %d — build failed: %s", event_id, exc)
        return None


def _extract_system_fields(root: etree._Element) -> dict[str, Any]:
    """Extract EventID, UtcTime, and Computer from the System element.

    Args:
        root: Root element of the parsed event XML.

    Returns:
        Dict with keys: "event_id" (int), "utc_time" (str), "computer" (str).

    Raises:
        ValueError: If EventID cannot be found or parsed.
    """
    system = root.find(f"{{{NS}}}System")
    if system is None:
        raise ValueError("No System element found in event XML")

    event_id_elem = system.find(f"{{{NS}}}EventID")
    if event_id_elem is None or event_id_elem.text is None:
        raise ValueError("EventID element missing or empty")
    try:
        event_id = int(event_id_elem.text)
    except ValueError as exc:
        raise ValueError(f"EventID is not a valid integer: {event_id_elem.text!r}") from exc

    utc_time = _get_utc_time(system)

    computer_elem = system.find(f"{{{NS}}}Computer")
    computer = computer_elem.text if computer_elem is not None and computer_elem.text else ""

    return {"event_id": event_id, "utc_time": utc_time, "computer": computer}


def _extract_data_fields(root: etree._Element, event_id: int) -> dict[str, str | None]:
    """Extract EventData/Data elements for the given event_id using FIELD_MAPS.

    Args:
        root: Root element of the parsed event XML.
        event_id: Sysmon event ID used to look up the correct field map.

    Returns:
        Dict mapping dataclass field names to string values, or None if
        the corresponding Data element is absent or has no text content.
    """
    event_data = root.find(f"{{{NS}}}EventData")
    result: dict[str, str | None] = {}

    field_map = FIELD_MAPS.get(event_id, {})
    for field_name, xml_name in field_map.items():
        if event_data is not None:
            elem = event_data.find(f"{{{NS}}}Data[@Name='{xml_name}']")
            result[field_name] = elem.text if elem is not None else None
        else:
            result[field_name] = None

    return result


def _build_event(event_id: int, system: dict[str, Any], data: dict[str, str | None]) -> SysmonEvent:
    """Dispatch to the correct dataclass constructor based on event_id.

    Handles all type coercions (int fields, bool fields) before passing
    kwargs to the frozen dataclass.

    Args:
        event_id: Sysmon event ID identifying which dataclass to construct.
        system: Dict from _extract_system_fields with "event_id", "utc_time", "computer".
        data: Dict from _extract_data_fields with field-name → raw string mappings.

    Returns:
        A constructed, typed SysmonEvent dataclass instance.

    Raises:
        ValueError: If a required non-Optional integer field cannot be coerced.
        KeyError: If event_id has no registered dataclass (should not occur after filtering).
    """
    base_kwargs: dict[str, Any] = {
        "event_id": system["event_id"],
        "utc_time": system["utc_time"],
        "computer": system["computer"],
    }

    if event_id == 1:
        process_id = _coerce_int(data.get("process_id"))
        if process_id is None:
            raise ValueError("ProcessCreateEvent requires a valid ProcessId")
        return ProcessCreateEvent(
            **base_kwargs,
            process_guid=data.get("process_guid") or "",
            process_id=process_id,
            image=data.get("image") or "",
            command_line=data.get("command_line"),
            current_directory=data.get("current_directory"),
            user=data.get("user"),
            parent_process_id=_coerce_int(data.get("parent_process_id")),
            parent_image=data.get("parent_image"),
            parent_command_line=data.get("parent_command_line"),
            integrity_level=data.get("integrity_level"),
            hashes=data.get("hashes"),
        )

    if event_id == 3:
        process_id = _coerce_int(data.get("process_id"))
        if process_id is None:
            raise ValueError("NetworkConnectEvent requires a valid ProcessId")
        return NetworkConnectEvent(
            **base_kwargs,
            process_guid=data.get("process_guid") or "",
            process_id=process_id,
            image=data.get("image") or "",
            user=data.get("user"),
            protocol=data.get("protocol"),
            initiated=_coerce_bool(data.get("initiated")),
            source_ip=data.get("source_ip"),
            source_port=_coerce_int(data.get("source_port")),
            destination_ip=data.get("destination_ip"),
            destination_hostname=data.get("destination_hostname"),
            destination_port=_coerce_int(data.get("destination_port")),
        )

    if event_id == 7:
        process_id = _coerce_int(data.get("process_id"))
        if process_id is None:
            raise ValueError("ImageLoadEvent requires a valid ProcessId")
        return ImageLoadEvent(
            **base_kwargs,
            process_guid=data.get("process_guid") or "",
            process_id=process_id,
            image=data.get("image") or "",
            image_loaded=data.get("image_loaded"),
            signed=_coerce_bool(data.get("signed")),
            signature=data.get("signature"),
            signature_status=data.get("signature_status"),
            hashes=data.get("hashes"),
        )

    if event_id == 8:
        source_pid = _coerce_int(data.get("source_process_id"))
        target_pid = _coerce_int(data.get("target_process_id"))
        if source_pid is None or target_pid is None:
            raise ValueError(
                "CreateRemoteThreadEvent requires valid SourceProcessId and TargetProcessId"
            )
        return CreateRemoteThreadEvent(
            **base_kwargs,
            source_process_id=source_pid,
            source_image=data.get("source_image") or "",
            target_process_id=target_pid,
            target_image=data.get("target_image") or "",
            new_thread_id=_coerce_int(data.get("new_thread_id")),
            start_address=data.get("start_address"),
            start_module=data.get("start_module"),
            start_function=data.get("start_function"),
        )

    if event_id == 10:
        source_pid = _coerce_int(data.get("source_process_id"))
        target_pid = _coerce_int(data.get("target_process_id"))
        if source_pid is None or target_pid is None:
            raise ValueError("OpenProcessEvent requires valid SourceProcessId and TargetProcessId")
        return OpenProcessEvent(
            **base_kwargs,
            source_process_id=source_pid,
            source_image=data.get("source_image") or "",
            target_process_id=target_pid,
            target_image=data.get("target_image") or "",
            granted_access=data.get("granted_access"),
            call_trace=data.get("call_trace"),
        )

    if event_id == 22:
        process_id = _coerce_int(data.get("process_id"))
        if process_id is None:
            raise ValueError("DnsQueryEvent requires a valid ProcessId")
        return DnsQueryEvent(
            **base_kwargs,
            process_id=process_id,
            image=data.get("image") or "",
            query_name=data.get("query_name") or "",
            query_status=data.get("query_status"),
            query_results=data.get("query_results"),
        )

    raise KeyError(f"No dataclass registered for event_id={event_id}")


def _coerce_int(value: str | None) -> int | None:
    """Safely coerce a string to int.

    Args:
        value: String to coerce, or None.

    Returns:
        Integer value, or None if value is None or not parseable as an integer.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _coerce_bool(value: str | None) -> bool | None:
    """Coerce a "true"/"false" string (case-insensitive) to bool.

    Args:
        value: String to coerce, or None.

    Returns:
        True or False if value is "true" or "false" (case-insensitive),
        otherwise None.
    """
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _get_utc_time(system_element: etree._Element) -> str:
    """Extract TimeCreated/@SystemTime from the System element.

    Args:
        system_element: The System XML element from a Sysmon event.

    Returns:
        The SystemTime attribute string, or an empty string if not found.
    """
    time_created = system_element.find(f"{{{NS}}}TimeCreated")
    if time_created is None:
        logger.warning("TimeCreated element missing from System block")
        return ""
    sys_time = time_created.get("SystemTime")
    if sys_time is None:
        logger.warning("SystemTime attribute missing from TimeCreated element")
        return ""
    return sys_time
