"""Typed dataclasses representing normalized Sysmon events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True)
class BaseEvent:
    """Fields present in the System block of every Sysmon event type.

    Attributes:
        event_id: Sysmon event ID (1, 3, 7, 8, 10, or 22).
        utc_time: Timestamp string from TimeCreated/@SystemTime in the event XML.
        computer: Hostname from System/Computer.
    """

    event_id: int
    utc_time: str
    computer: str


@dataclass(frozen=True)
class ProcessCreateEvent(BaseEvent):
    """Normalized Sysmon Event ID 1 — ProcessCreate.

    Attributes:
        process_guid: Sysmon-assigned GUID for the created process.
        process_id: PID of the created process.
        image: Full path to the process executable.
        command_line: Full command line string used to launch the process.
        current_directory: Working directory at process creation time.
        user: Account name under which the process runs.
        parent_process_id: PID of the parent process.
        parent_image: Full path to the parent process executable.
        parent_command_line: Command line of the parent process.
        integrity_level: Process integrity level (e.g. High, Medium, Low).
        hashes: Raw hash string from Sysmon (e.g. "SHA256=abc123,...").
    """

    process_guid: str
    process_id: int
    image: str
    command_line: str | None
    current_directory: str | None
    user: str | None
    parent_process_id: int | None
    parent_image: str | None
    parent_command_line: str | None
    integrity_level: str | None
    hashes: str | None


@dataclass(frozen=True)
class NetworkConnectEvent(BaseEvent):
    """Normalized Sysmon Event ID 3 — NetworkConnect.

    Attributes:
        process_guid: Sysmon-assigned GUID for the connecting process.
        process_id: PID of the connecting process.
        image: Full path to the connecting process executable.
        user: Account name under which the process runs.
        protocol: Transport protocol ("tcp" or "udp").
        initiated: True if the connection was initiated by this process (outbound).
        source_ip: Source IP address string.
        source_port: Source port number.
        destination_ip: Destination IP address string.
        destination_hostname: Destination hostname if resolved.
        destination_port: Destination port number.
    """

    process_guid: str
    process_id: int
    image: str
    user: str | None
    protocol: str | None
    initiated: bool | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_hostname: str | None
    destination_port: int | None


@dataclass(frozen=True)
class ImageLoadEvent(BaseEvent):
    """Normalized Sysmon Event ID 7 — ImageLoad.

    Attributes:
        process_guid: Sysmon-assigned GUID for the loading process.
        process_id: PID of the loading process.
        image: Full path to the loading process executable.
        image_loaded: Full path to the DLL or image being loaded.
        signed: True if the loaded image has a valid signature.
        signature: Signing authority name.
        signature_status: Signature verification result ("Valid", "Invalid", etc.).
        hashes: Raw hash string from Sysmon for the loaded image.
    """

    process_guid: str
    process_id: int
    image: str
    image_loaded: str | None
    signed: bool | None
    signature: str | None
    signature_status: str | None
    hashes: str | None


@dataclass(frozen=True)
class CreateRemoteThreadEvent(BaseEvent):
    """Normalized Sysmon Event ID 8 — CreateRemoteThread.

    Dataclass defined in Phase 1; validation against a real Sysmon sample
    is deferred to Phase 4B (requires controlled injection simulation).

    Attributes:
        source_process_id: PID of the process that created the remote thread.
        source_image: Full path to the source process executable.
        target_process_id: PID of the process into which the thread was injected.
        target_image: Full path to the target process executable.
        new_thread_id: TID of the newly created remote thread.
        start_address: Start address of the remote thread as a hex string.
        start_module: Module containing the thread start address, if resolved.
        start_function: Function at the start address, if resolved.
    """

    source_process_id: int
    source_image: str
    target_process_id: int
    target_image: str
    new_thread_id: int | None
    start_address: str | None
    start_module: str | None
    start_function: str | None


@dataclass(frozen=True)
class OpenProcessEvent(BaseEvent):
    """Normalized Sysmon Event ID 10 — ProcessAccess.

    Attributes:
        source_process_id: PID of the process that opened the target.
        source_image: Full path to the source process executable.
        target_process_id: PID of the process being accessed.
        target_image: Full path to the target process executable.
        granted_access: Access mask granted as a hex string (e.g. "0x1410").
        call_trace: Stack trace of the OpenProcess call.
    """

    source_process_id: int
    source_image: str
    target_process_id: int
    target_image: str
    granted_access: str | None
    call_trace: str | None


@dataclass(frozen=True)
class DnsQueryEvent(BaseEvent):
    """Normalized Sysmon Event ID 22 — DNSEvent.

    Attributes:
        process_id: PID of the process that issued the DNS query.
        image: Full path to the querying process executable.
        query_name: The DNS name that was queried.
        query_status: DNS response status code ("0" = success).
        query_results: Semicolon-separated DNS result records.
    """

    process_id: int
    image: str
    query_name: str
    query_status: str | None
    query_results: str | None


# Union type used as the return type of parse_event()
SysmonEvent: TypeAlias = (
    ProcessCreateEvent
    | NetworkConnectEvent
    | ImageLoadEvent
    | CreateRemoteThreadEvent
    | OpenProcessEvent
    | DnsQueryEvent
)
