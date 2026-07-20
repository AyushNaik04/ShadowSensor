"""
ShadowSensor Phase 5 — Per-Event Feature Extractor

Takes one event row (dict from SQLite events table / EventRecord.to_dict())
and extracts applicable features. Non-applicable features for the event's EID
are left at defaults. Nested Sysmon fields are read from raw_json per
docs/phase5_schema_reference.md.
"""
from __future__ import annotations

import ipaddress
import json
import math
from collections import Counter
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any

from ml.features.feature_spec import (
    LOLBIN_NAMES,
    SUSPICIOUS_CHAINS,
    SUSPICIOUS_PARENT_IMAGES,
    SUSPICIOUS_PORTS,
    default_feature_vector,
)

# EID-1 schema gap: no "signed" key exists on ProcessCreate. is_signed stays 0.

_ENCODED_MARKERS = ("-encodedcommand", " -enc ", "–enc")
_DOWNLOAD_KEYWORDS = (
    "downloadstring",
    "downloadfile",
    "webclient",
    "invoke-webrequest",
    "wget",
    "curl",
    "bitstransfer",
)

_VM_READ = 0x0010
_VM_WRITE = 0x0020
_ALL_ACCESS = 0x1F0FFF


def shannon_entropy(s: str | None) -> float:
    """Shannon entropy over character distribution (base-2). Empty/None → 0.0."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _windows_filename(path: str | None) -> str | None:
    """Basename of a Windows-style path; None/missing → None."""
    if path is None or path == "":
        return None
    name = PureWindowsPath(path).name
    return name if name else None


def _parse_hour(timestamp: Any) -> int:
    """Extract hour (0–23) from datetime or ISO string; None → -1."""
    if timestamp is None:
        return -1
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            return -1
    if isinstance(timestamp, datetime):
        return timestamp.hour
    return -1


def _parse_raw_json(raw_json: Any) -> dict:
    """Accept a JSON string or an already-parsed dict."""
    if raw_json is None:
        return {}
    if isinstance(raw_json, dict):
        return raw_json
    if isinstance(raw_json, str):
        if not raw_json:
            return {}
        return json.loads(raw_json)
    return {}


def _parse_granted_access(value: Any) -> int | None:
    """Parse granted_access as int or hex string (e.g. '0x0010'). None on failure."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


class EventFeatureExtractor:
    """Extract a 30-key feature vector from a single event row dict."""

    def extract(self, event: dict) -> dict:
        vector = default_feature_vector()
        eid = event.get("event_type_id")
        raw = _parse_raw_json(event.get("raw_json"))

        if eid == 1:
            self._extract_eid1(event, raw, vector)
        elif eid == 3:
            self._extract_eid3(raw, vector)
        elif eid == 7:
            self._extract_eid7(raw, vector)
        elif eid == 8:
            self._extract_eid8(raw, vector)
        elif eid == 10:
            self._extract_eid10(raw, vector)
        elif eid == 22:
            self._extract_eid22(raw, vector)

        return vector

    def _extract_eid1(self, event: dict, raw: dict, vector: dict) -> None:
        cmd = raw.get("command_line") or ""
        parent_cmd = raw.get("parent_command_line") or ""
        cmd_lower = cmd.lower()

        vector["cmd_length"] = len(cmd)
        vector["cmd_entropy"] = shannon_entropy(cmd)
        vector["has_encoded_command"] = (
            1 if any(m in cmd_lower for m in _ENCODED_MARKERS) else 0
        )
        vector["has_download_keyword"] = (
            1 if any(k in cmd_lower for k in _DOWNLOAD_KEYWORDS) else 0
        )
        # Schema gap: EID 1 has no signed field — always leave default 0.
        vector["is_signed"] = 0

        hour = _parse_hour(event.get("timestamp"))
        vector["hour_of_day"] = hour
        vector["is_off_hours"] = 1 if hour == -1 or hour not in range(8, 19) else 0

        image = event.get("image") if event.get("image") is not None else raw.get("image")
        parent_image = raw.get("parent_image")
        image_fn = _windows_filename(image)
        parent_fn = _windows_filename(parent_image)

        vector["is_lolbin"] = (
            1 if image_fn is not None and image_fn.lower() in LOLBIN_NAMES else 0
        )
        vector["is_suspicious_parent"] = (
            1
            if parent_fn is not None and parent_fn.lower() in SUSPICIOUS_PARENT_IMAGES
            else 0
        )
        vector["parent_cmd_length"] = len(parent_cmd)

        if image_fn is not None and parent_fn is not None:
            pair = (parent_fn.lower(), image_fn.lower())
            vector["is_known_suspicious_chain"] = 1 if pair in SUSPICIOUS_CHAINS else 0
            vector["parent_is_same_image"] = (
                1 if parent_fn.lower() == image_fn.lower() else 0
            )
        else:
            vector["is_known_suspicious_chain"] = 0
            vector["parent_is_same_image"] = 0

    def _extract_eid3(self, raw: dict, vector: dict) -> None:
        try:
            dest_port = int(raw.get("destination_port") or 0)
        except (TypeError, ValueError):
            dest_port = 0
        vector["dest_port"] = dest_port
        vector["is_suspicious_port"] = 1 if dest_port in SUSPICIOUS_PORTS else 0

        dest_ip = raw.get("destination_ip")
        is_external = 0
        if dest_ip is not None:
            try:
                ip = ipaddress.ip_address(dest_ip)
                if not ip.is_private and not ip.is_loopback:
                    is_external = 1
            except ValueError:
                is_external = 0
        vector["is_external_ip"] = is_external
        vector["network_event_count"] = 1

    def _extract_eid7(self, raw: dict, vector: dict) -> None:
        vector["image_load_count"] = 1
        signed = raw.get("signed")
        unsigned = 0
        if signed is False:
            unsigned = 1
        elif isinstance(signed, str) and signed.lower() == "false":
            unsigned = 1
        vector["unsigned_image_loaded"] = unsigned

    def _extract_eid8(self, raw: dict, vector: dict) -> None:
        vector["create_remote_thread_count"] = 1

    def _extract_eid10(self, raw: dict, vector: dict) -> None:
        vector["open_process_count"] = 1
        target_fn = _windows_filename(raw.get("target_image"))
        vector["open_process_lsass_target"] = (
            1 if target_fn is not None and target_fn.lower() == "lsass.exe" else 0
        )

        mask = _parse_granted_access(raw.get("granted_access"))
        suspicious = 0
        if mask is not None:
            if (mask & _VM_READ) or (mask & _VM_WRITE) or (mask & _ALL_ACCESS) == _ALL_ACCESS:
                suspicious = 1
        vector["open_process_suspicious_access"] = suspicious

    def _extract_eid22(self, raw: dict, vector: dict) -> None:
        query = raw.get("query_name") or ""
        vector["dns_query_length"] = len(query)
        vector["network_event_count"] = 1
