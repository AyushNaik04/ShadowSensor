"""Category C Subphase 1 tests: API_AV_PROCESS_ACCESS_001 bits_any_set + source merge."""

from __future__ import annotations

from pathlib import Path

import pytest

from normalizer.models import OpenProcessEvent
from rules.engine import RuleEngine

RULE = "API_AV_PROCESS_ACCESS_001"

IMPLANT = r"C:\Users\user\AppData\Local\Temp\implant.exe"
MSMPENG = r"C:\Program Files\Windows Defender\MsMpEng.exe"
MPCMDRUN = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
AVP = r"C:\Program Files\Kaspersky Lab\avp.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
CSRSS = r"C:\Windows\System32\csrss.exe"
CONHOST = r"C:\Windows\System32\conhost.exe"


def _make_open_process(**kwargs) -> OpenProcessEvent:
    defaults: dict = {
        "event_id": 10,
        "utc_time": "2026-06-23 10:00:00.000",
        "computer": "AUDIT-HOST",
        "source_process_id": 1234,
        "source_image": "C:\\Windows\\System32\\powershell.exe",
        "target_process_id": 900,
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1410",
        "call_trace": None,
    }
    defaults.update(kwargs)
    return OpenProcessEvent(**defaults)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def _hits(engine: RuleEngine, event, rule_id: str) -> bool:
    return any(h.rule_id == rule_id for h in engine.evaluate(event))


def test_tp_overgranted_mask_now_caught(engine: RuleEngine):
    """0x1020 contains 0x0020's bit under bits_any_set; must fire (old contains_any miss)."""
    event = _make_open_process(
        source_image=IMPLANT,
        target_image=MSMPENG,
        granted_access="0x1020",
    )
    assert _hits(engine, event, RULE)


def test_tp_minimal_terminate_bit(engine: RuleEngine):
    """Exact PROCESS_TERMINATE (0x0001) against MpCmdRun.exe must fire."""
    event = _make_open_process(
        source_image=IMPLANT,
        target_image=MPCMDRUN,
        granted_access="0x0001",
    )
    assert _hits(engine, event, RULE)


def test_fp_consolidated_svchost_exclusion(engine: RuleEngine):
    """svchost exclusion preserved after source_image block merge."""
    event = _make_open_process(
        source_image=SVCHOST,
        target_image=MSMPENG,
        granted_access="0x0021",
    )
    assert not _hits(engine, event, RULE)


def test_fp_csrss_moved_from_second_block(engine: RuleEngine):
    """csrss exclusion preserved after merge from the old second source_image block."""
    event = _make_open_process(
        source_image=CSRSS,
        target_image=MSMPENG,
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, RULE)


def test_fp_conhost_moved_from_second_block(engine: RuleEngine):
    """conhost exclusion preserved after merge from the old second source_image block."""
    event = _make_open_process(
        source_image=CONHOST,
        target_image=AVP,
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, RULE)


def test_fp_benign_read_only_access(engine: RuleEngine):
    """0x0010 VM_READ only — neither 0x0001 nor 0x0020 bit set; must not fire."""
    event = _make_open_process(
        source_image=IMPLANT,
        target_image=MSMPENG,
        granted_access="0x0010",
    )
    assert not _hits(engine, event, RULE)
