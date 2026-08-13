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
    """C4 Subphase 3: updated from bare 0x0020 (PROCESS_VM_WRITE alone) to
    0x0028 (PROCESS_VM_WRITE | PROCESS_VM_OPERATION) — the realistic
    minimum pairing WriteProcessMemory-based injection actually requires.
    Bare 0x0020 no longer fires this rule as of C4 Subphase 3; see
    test_api_open_process_vm_write_does_not_fire_for_bare_vm_write_alone
    below for the explicit negative-path regression lock on that change."""
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        granted_access="0x0028",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_bare_vm_write_alone(engine: RuleEngine):
    """C4 Subphase 3: bare PROCESS_VM_WRITE (0x0020) with no
    PROCESS_VM_OPERATION bit must NOT fire — WriteProcessMemory-based
    injection requires both bits together; VM_WRITE alone cannot perform
    the write. Regression lock to prevent this floor from silently
    loosening again in a future session."""
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
        granted_access="0x0020",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_excluded_source(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Program Files\Windows Defender\MsMpEng.exe",
        granted_access="0x0020",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_same_basename(engine: RuleEngine):
    """C4 Subphase 1: source and target sharing the same filename
    (self-referential / same-program access) must not fire — this is the
    self-update / multi-process-app pattern (e.g. a staged updater copy
    opening the installed copy of the same binary), not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Program Files (x86)\Microsoft\Temp\EUD4EC.tmp\MicrosoftEdgeUpdate.exe",
        target_image=r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_fires_for_different_basename(engine: RuleEngine):
    """C4 Subphase 1: source and target with DIFFERENT filenames, with a
    non-excluded source, must still fire — confirms the new
    not_same_basename condition only suppresses same-name pairs and does
    not weaken genuine cross-process detection."""
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_runonce(engine: RuleEngine):
    """C4 Subphase 2: RunOnce launching a pending post-boot installer is
    expected Windows behaviour, not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\System32\runonce.exe",
        target_image=r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\150.0.4078.105\Installer\setup.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_sysmon64(engine: RuleEngine):
    """C4 Subphase 2: Sysmon64.exe itself accessing a monitored process is
    the monitoring tool's own instrumentation, not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\Sysmon64.exe",
        target_image=r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_services_exe(engine: RuleEngine):
    """C4 Subphase 2: services.exe (Service Control Manager) starting a
    service host process is routine, constant Windows behaviour."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\System32\services.exe",
        target_image=r"C:\Windows\System32\svchost.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_fires_for_masquerading_svchost(engine: RuleEngine):
    """C4 Subphase 2: masquerade true-positive. A source process named
    svchost.exe but NOT at the real system path must still fire — confirms
    path-anchoring blocks T1036.005 masquerading (mirrors the equivalent
    C3 test on the sibling rule)."""
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\svchost.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_conhost_source(engine: RuleEngine):
    """E1 Subphase 1: conhost.exe acquiring PROCESS_ALL_ACCESS to a
    spawned child is console-host process-management, not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\system32\conhost.exe",
        target_image=r"C:\Windows\system32\cmd.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_cmd_source(engine: RuleEngine):
    """E1 Subphase 1: cmd.exe acquiring PROCESS_ALL_ACCESS to a spawned
    child is shell process-management, not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\system32\cmd.exe",
        target_image=r"Z:\filelessmalware\python_runtime\python.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_fires_for_masquerading_cmd_source(engine: RuleEngine):
    """E1 Subphase 1: masquerade true-positive. A source process named
    cmd.exe but NOT at the real system path must still fire — confirms
    path-anchoring blocks T1036.005 masquerading."""
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\cmd.exe",
        target_image=r"C:\Windows\system32\notepad.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_csc_target(engine: RuleEngine):
    """E1 Subphase 2: powershell.exe acquiring PROCESS_ALL_ACCESS to
    csc.exe during Add-Type compilation is .NET toolchain process-
    management, not injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_does_not_fire_for_cvtres_target(engine: RuleEngine):
    """E1 Subphase 2: csc.exe acquiring PROCESS_ALL_ACCESS to cvtres.exe
    during resource linking is .NET toolchain process-management, not
    injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        target_image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe",
        granted_access="0x1fffff",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_fires_for_masquerading_csc_target(engine: RuleEngine):
    """E1 Subphase 2: masquerade true-positive. A target named csc.exe
    but NOT at the real Framework64 path must still fire — confirms
    path-anchoring blocks T1036.005 masquerading."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image=r"C:\Temp\csc.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_api_open_process_vm_write_fires_for_genuine_target(engine: RuleEngine):
    """E1 Subphase 2: true-positive preservation. powershell.exe opening
    notepad.exe with PROCESS_ALL_ACCESS must still fire — confirms the
    new target_image exclusion does not suppress genuine injection."""
    event = _make_open_process_event(
        source_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_image=r"C:\Windows\System32\notepad.exe",
        granted_access="0x1fffff",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


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


def test_vm_write_e2_call_trace_none_still_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace=None,
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_native_only_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace="ntdll.dll+0x9b6f0|KERNELBASE.dll+0x12345|UNKNOWN",
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_automation_ni_suppressed(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace="ntdll.dll+0x9b6f0|System.Management.Automation.ni.dll+0x1234|Microsoft.PowerShell.Commands.Management.ni.dll+0x5678",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_management_ni_suppressed(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace="ntdll.dll+0x9b6f0|Microsoft.PowerShell.Commands.Management.ni.dll+0x5678|UNKNOWN",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_automation_non_ni_suppressed(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace="ntdll.dll+0x9b6f0|System.Management.Automation.dll+0x1234|UNKNOWN",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_exact_string_suppressed(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace="System.Management.Automation.ni.dll",
    )
    assert not _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")


def test_vm_write_e2_call_trace_none_allow_null_fires(engine: RuleEngine):
    event = _make_open_process_event(
        source_image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1038",
        call_trace=None,
    )
    assert _hits(engine, event, "API_OPEN_PROCESS_VM_WRITE_001")
