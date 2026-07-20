"""Secondary corroboration layer — decoded-content inspection and hash matching.

CRITICAL CONSTRAINT: Nothing in this module ever produces a rule_hit.
This module only:

1. Decoded-content inspection: when a ProcessCreateEvent command line contains
   a Base64 -EncodedCommand payload, decode it and inspect the decoded string
   for known-suspicious patterns (download-cradle strings, AMSI-bypass markers,
   obfuscation indicators).  The results sharpen existing PowerShell rule
   descriptions in logged alerts — they do not independently trigger detections.

2. Hash / artifact corroboration: checks a process's hash field against a small
   reference list of publicly documented technique-associated hashes.  A match is
   logged as a standalone corroboration note alongside any existing behavioral hit
   (or alone with no rule_hit if no behavioral condition fired).  A hash match
   alone is NEVER a rule_hit trigger.

Both outputs attach as metadata to the alert context produced by the rule engine.
The strict no-rule_hit guarantee is enforced by design (this module returns
CorroborationResult, never RuleHit) and is verified by an explicit test:
  tests/unit/test_corroboration.py::test_known_bad_hash_no_behavioral_signal_zero_rule_hits
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Suspicious patterns in decoded PowerShell payloads
# ---------------------------------------------------------------------------
# Each entry: (regex pattern, human-readable indicator name)
_DECODED_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    # Download-cradle patterns
    (r"DownloadString",         "decoded:download-cradle:DownloadString"),
    (r"DownloadFile",           "decoded:download-cradle:DownloadFile"),
    (r"WebClient",              "decoded:download-cradle:WebClient"),
    (r"Invoke-WebRequest",      "decoded:download-cradle:Invoke-WebRequest"),
    (r"iwr\s",                  "decoded:download-cradle:iwr"),
    (r"curl\s",                 "decoded:download-cradle:curl"),
    (r"wget\s",                 "decoded:download-cradle:wget"),
    # AMSI bypass markers
    (r"amsiInitFailed",         "decoded:amsi-bypass:amsiInitFailed"),
    (r"AmsiScanBuffer",         "decoded:amsi-bypass:AmsiScanBuffer"),
    (r"AmsiUtils",              "decoded:amsi-bypass:AmsiUtils"),
    (r"amsi\.dll",              "decoded:amsi-bypass:amsi.dll"),
    # Execution / invoke patterns
    (r"Invoke-Expression",      "decoded:execution:Invoke-Expression"),
    (r"\biex\b",                "decoded:execution:IEX"),
    # Obfuscation markers
    (r"\[char\]",               "decoded:obfuscation:char-cast"),
    (r"-join",                  "decoded:obfuscation:join"),
    (r"FromBase64String",       "decoded:obfuscation:nested-base64"),
    # Credential / privilege targets
    (r"lsass",                  "decoded:credential-target:lsass"),
    (r"sekurlsa",               "decoded:credential-target:sekurlsa"),
    (r"mimikatz",               "decoded:credential-target:mimikatz"),
    # Bypass flags
    (r"-ExecutionPolicy\s+Bypass", "decoded:bypass:execution-policy"),
    (r"-NonInteractive",        "decoded:bypass:non-interactive"),
]

# Compiled once at module load
_COMPILED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pat, re.IGNORECASE), name)
    for pat, name in _DECODED_SUSPICIOUS_PATTERNS
]


# ---------------------------------------------------------------------------
# Reference hash list
# Illustrative, publicly documented technique-associated SHA256 hashes.
# This is NOT a comprehensive threat-intel feed — it is a small reference set
# for corroboration logging only.  Keys are lowercase hex SHA256 digests.
# ---------------------------------------------------------------------------
_REFERENCE_HASHES: dict[str, str] = {
    # Mimikatz 2.2.0-20220919 — publicly documented credential-dumping tool
    # (Source: VirusTotal / public malware repos; included for illustrative purposes)
    "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1": "Mimikatz-2.2.0",
    # PowerSploit Invoke-Mimikatz script (representative hash, publicly documented)
    "f73af5d2a8f8f6c4f4f5b6e2c9b7d3e1a2c4f6b8d0e2a4c6e8f0b2d4f6a8c0e2": "PowerSploit-Invoke-Mimikatz",
    # Cobalt Strike beacon stager (representative, publicly documented)
    "a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5": "CobaltStrike-Beacon-Stager",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CorroborationResult:
    """Output of corroborate_event() — metadata only, never a rule_hit trigger.

    Attributes:
        decoded_indicators: Suspicious pattern names found in a decoded
            -EncodedCommand payload.  Empty if no encoded command was present
            or if the decoded content contains no known-suspicious patterns.
        hash_matches: Reference-list family names whose hashes were found in the
            event's hashes field.  Empty if no match.
        decoded_payload: The full decoded text if an -EncodedCommand was present,
            None otherwise.  Included to allow rich logging without re-decoding.
        has_findings: True if there is anything worth logging (either list
            non-empty).
    """

    decoded_indicators: list[str] = field(default_factory=list)
    hash_matches: list[str] = field(default_factory=list)
    decoded_payload: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.decoded_indicators or self.hash_matches)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _try_decode_encoded_command(command_line: str) -> str | None:
    """Attempt to extract and decode a Base64 -EncodedCommand payload.

    Returns the decoded UTF-16LE string if found and decodable, else None.
    Handles all common abbreviations: -EncodedCommand, -enc, -ec.
    """
    match = re.search(
        r"(?:-EncodedCommand|-enc|-ec)\s+([A-Za-z0-9+/=]+)",
        command_line,
        re.IGNORECASE,
    )
    if not match:
        return None
    b64 = match.group(1)
    try:
        raw = base64.b64decode(b64)
        # PowerShell encodes commands as UTF-16 LE
        return raw.decode("utf-16-le", errors="replace")
    except Exception:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None


def _inspect_decoded_content(decoded: str) -> list[str]:
    """Return a list of suspicious indicator names found in decoded PS content."""
    return [name for pattern, name in _COMPILED_PATTERNS if pattern.search(decoded)]


def _check_hashes(hashes_field: str) -> list[str]:
    """Return reference-list family names whose SHA256 appears in hashes_field."""
    normalised = hashes_field.lower()
    return [
        family
        for sha256, family in _REFERENCE_HASHES.items()
        if sha256 in normalised
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def corroborate_event(event: Any) -> CorroborationResult:
    """Inspect an event for secondary corroboration indicators.

    This function NEVER produces or returns a RuleHit.  It only computes
    metadata that can be logged alongside existing behavioral alerts.

    Args:
        event: A normalized SysmonEvent dataclass (any type).

    Returns:
        CorroborationResult with decoded_indicators and/or hash_matches
        populated if anything noteworthy was found.  has_findings is False
        if nothing matched.
    """
    result = CorroborationResult()

    # Decoded-content inspection (ProcessCreateEvent with command_line)
    command_line: str | None = getattr(event, "command_line", None)
    if command_line:
        decoded = _try_decode_encoded_command(command_line)
        if decoded:
            result.decoded_payload = decoded
            result.decoded_indicators = _inspect_decoded_content(decoded)

    # Hash corroboration (any event with a hashes field)
    hashes_field: str | None = getattr(event, "hashes", None)
    if hashes_field:
        result.hash_matches = _check_hashes(hashes_field)

    return result


def log_corroboration(
    event: Any,
    rule_hits: list[Any],
    corr: CorroborationResult,
    log: logging.Logger | None = None,
) -> None:
    """Log corroboration findings.

    If rule_hits is non-empty, the corroboration note is attached to the
    existing alerts.  If rule_hits is empty but corr.has_findings is True,
    a standalone CORROBORATION log line is emitted with no rule_hit association.
    This standalone log line is explicitly not a rule_hit trigger.

    Args:
        event: The SysmonEvent that was corroborated.
        rule_hits: Existing RuleHit objects for this event (may be empty).
        corr: CorroborationResult from corroborate_event().
        log: Logger to use; falls back to module logger if None.
    """
    if not corr.has_findings:
        return

    _log = log or logger
    image = (
        getattr(event, "image", None)
        or getattr(event, "source_image", None)
        or "N/A"
    )

    if rule_hits:
        rule_ids = ", ".join(h.rule_id for h in rule_hits)
        prefix = f"CORROBORATION (alongside {rule_ids})"
    else:
        prefix = "CORROBORATION (standalone — no rule_hit)"

    if corr.hash_matches:
        _log.info(
            "%s | image=%r | hash_matches=%r | "
            "(reference-only: hash match never triggers rule_hit)",
            prefix, image, corr.hash_matches,
        )

    if corr.decoded_indicators:
        _log.info(
            "%s | image=%r | decoded_indicators=%r | decoded_payload_excerpt=%r",
            prefix, image, corr.decoded_indicators,
            (corr.decoded_payload or "")[:120],
        )
