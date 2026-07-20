"""Phase 4A Subphase 5 - API/memory rule expansion tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import ImageLoadEvent, OpenProcessEvent
from rules.engine import RuleEngine


def _make_image_load_event(**kwargs) -> ImageLoadEvent:
    defaults: dict = {
        "event_id": 7,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "process_guid": "{img-guid}",
        "process_id": 1234,
        "image": r"C:\Windows\System32\notepad.exe",
        "image_loaded": r"C:\Windows\System32\kernel32.dll",
        "signed": True,
        "signature": "microsoft windows",
        "signature_status": "valid",
        "hashes": None,
    }
    defaults.update(kwargs)
    return ImageLoadEvent(**defaults)


def _make_open_process_event(**kwargs) -> OpenProcessEvent:
    defaults: dict = {
        "event_id": 10,
        "utc_time": "2026-07-07 10:00:00.000",
        "computer": "TEST-HOST",
        "source_process_id": 2222,
        "source_image": r"C:\Users\Public\loader.exe",
        "target_process_id": 500,
        "target_image": r"C:\Windows\System32\lsass.exe",
        "granted_access": "0x1410",
        "call_trace": None,
    }
    defaults.update(kwargs)
    return OpenProcessEvent(**defaults)


def _hits(engine: RuleEngine, event, rule_id: str) -> bool:
    return any(h.rule_id == rule_id for h in engine.evaluate(event))


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def test_api_dll_load_suspicious_path_fires(engine: RuleEngine):
    event = _make_image_load_event(
        image_loaded=r"C:\Users\test\AppData\Local\Temp\payload.dll",
        signed=False,
    )
    assert _hits(engine, event, "API_DLL_LOAD_SUSPICIOUS_PATH_001")


def test_api_dll_load_suspicious_path_does_not_fire_on_system32_signed(engine: RuleEngine):
    event = _make_image_load_event(
        image_loaded=r"C:\Windows\System32\kernelbase.dll",
        signed=True,
    )
    assert not _hits(engine, event, "API_DLL_LOAD_SUSPICIOUS_PATH_001")


def test_api_lolbin_dll_unsigned_fires(engine: RuleEngine):
    event = _make_image_load_event(
        image=r"C:\Windows\System32\rundll32.exe",
        image_loaded=r"C:\Users\Public\malicious.dll",
        signed=False,
    )
    assert _hits(engine, event, "API_LOLBIN_DLL_UNSIGNED_001")


def test_api_lolbin_dll_unsigned_does_not_fire_when_signed(engine: RuleEngine):
    event = _make_image_load_event(
        image=r"C:\Windows\System32\rundll32.exe",
        image_loaded=r"C:\Windows\System32\shell32.dll",
        signed=True,
    )
    assert not _hits(engine, event, "API_LOLBIN_DLL_UNSIGNED_001")


def test_api_open_process_vm_write_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        granted_access="0x0020",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_excluded_source(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Program Files\Windows Defender\MsMpEng.exe",
        granted_access="0x0020",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_token_manipulation_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\stealer.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x0040",
    )
    assert _hits(engine, event, "API_TOKEN_MANIPULATION_001")


def test_api_token_manipulation_does_not_fire_for_non_restricted_target(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\stealer.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
        granted_access="0x0040",
    )
    assert not _hits(engine, event, "API_TOKEN_MANIPULATION_001")


def test_api_av_process_access_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\killer.exe",
        target_image=r"C:\Program Files\Windows Defender\MsMpEng.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_AV_PROCESS_ACCESS_001")


@pytest.mark.parametrize(
    "excluded_source_image",
    [
        r"C:\Windows\System32\csrss.exe",
        r"C:\Windows\System32\conhost.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\winlogon.exe",
        r"C:\Windows\System32\wininit.exe",
    ],
)
def test_api_av_process_access_does_not_fire_for_issue1_excluded_sources(
    engine: RuleEngine,
    excluded_source_image: str,
):
    event = _make_open_process_event(
        source_image=excluded_source_image,
        target_image=r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_AV_PROCESS_ACCESS_001")
