# ShadowSensor — Project-Wide Decisions Log

**Purpose:** Permanent, cumulative record of every non-trivial architectural or design decision made across all project phases.
Reverse-chronological order (newest entry first). One entry per decision.
This file persists across all future phases — future sessions must append here rather than creating new logs.
Do not delete or rewrite past entries; corrections go in a new entry referencing the original.

---

## Entry 011 — 2026-08-07 | Issue Catalog Category C — Confirmed False Positives

**Decision:** Fix all three confirmed false positive issues (C1, C2,
C3) in a single combined task executed across three subphases, each
in its own fresh Cursor chat session. All three issues confirmed
closed. 21 new tests added. Test suite: 634 → 655 passing, 0 failed.
Rule count unchanged at 51 (conditions-only category).

---

### C1 — `API_AV_PROCESS_ACCESS_001`

**Issue:** Two classes of false positive confirmed across Phase 4B
and the Phase 7A fix session:
1. `granted_access` used `contains_any` with 5 literal hex strings
   (`0x0001`, `0x0021`, `0x1f0fff`, `0x1fffff`, `0x0020`) — same
   class of bug as Category A's D47/D49: Windows can over-grant
   access bits, producing a value not in the enumerated list, causing
   a miss. Same root cause, same fix class.
2. Two separate `source_image not_ends_with_any` blocks existed in
   the YAML with a duplicate `svchost.exe` entry — fragile and
   redundant structure, error-prone to maintain.

**Fix:**
- `granted_access` operator migrated from `contains_any` to
  `bits_any_set`. Values reduced to `["0x0001", "0x0020"]` — the
  two minimal capability bits. The three removed values (`0x0021`,
  `0x1f0fff`, `0x1fffff`) are redundant supersets under bit-set
  semantics: any value containing those bits necessarily contains
  `0x0001` and/or `0x0020`, so they add no detection coverage while
  narrowing match surface unnecessarily.
- Two `source_image not_ends_with_any` blocks consolidated into one
  block with 12 unique values. Duplicate `svchost.exe` entry removed.

**Verified correct:** The pre-existing `test_api_av_process_access_fires`
test uses `granted_access=0x1fffff`. Under `bits_any_set` with mask
`0x0001`: `0x1fffff & 0x0001 == 0x0001` ✓. With mask `0x0020`:
`0x1fffff & 0x0020 == 0x0020` ✓. Test continues to pass unmodified —
confirmed by independent bitwise verification before any edit was made.

**Test-value authoring error caught mid-implementation:** The
task.md originally specified `0x1010` as a test mask for the
over-grant scenario. Independent bitwise check by Cursor revealed
`0x1010 & 0x0020 == 0` — the mask does not contain the required bit,
so the test would have been testing the wrong thing. Corrected to
`0x1020` (`0x1020 & 0x0020 == 0x0020` ✓) before any edit was made.
Process note: when specifying literal hex/numeric test values in a
task.md, perform independent bitwise verification before finalizing
the document rather than relying on Cursor to catch it post-hoc.

**Residual gap — documented, not fixed:** Modern T1562.001 bypass
techniques (BYOVD kernel-driver kills, direct/indirect syscalls
bypassing user-mode ETW hooks, DLL hijacking inside the AV process
itself) operate below the user-mode `OpenProcess` hook that this rule
observes. These bypass paths are confirmed via threat intelligence:
Reynolds ransomware (2026), Kasseika (2024), RansomHub
EDRKillShifter, HookChain/DEF CON 32 (88% bypass rate across 26 EDR
solutions), ToddyCat vs ESET (2024), LockBit vs MpCmdRun.exe. This
rule's honest scope is commodity/unsophisticated T1562.001 (Ryuk,
RunningRAT, Netwalker, Medusa Group-class) — a defensible and
documented scope, not a weakness. Unfixable at rule-engine level.
Flagged for research paper Section 2.

**Additional confirmed gap (D45, environmental):** PPL (Protected
Process Light) prevents `OpenProcess` against `MsMpEng.exe` even
from a fully elevated Administrator session — confirmed via explicit
control test in Phase 7A Subphase 5 (`Elevated handle obtained:
False`). Genuine-detection capability for this rule cannot be
empirically validated on this VM via the P/Invoke simulation
technique. The same attacker technique class that bypasses the rule
(BYOVD) also bypasses the simulation constraint — coherent, not
contradictory. Flagged for research paper Section 2. Cross-reference
Category D Entry 012, D-e.

**Tests added:** 6, in new file
`tests/test_category_c_fixes/test_c1_av_process_access.py`.
Pre-existing tests in `tests/test_phase4a/test_api_memory_rules.py`
(`test_api_av_process_access_fires` and the 6-way parametrized
`test_api_av_process_access_does_not_fire_for_issue1_excluded_sources`)
confirmed compatible with new `bits_any_set` structure via independent
bitwise verification and left unmodified.

---

### C2 — `NET_DNS_LONG_QUERY_001`

**Issue:** `SearchApp.exe` (Windows taskbar search process) confirmed
generating false positives on 3 independent occurrences across Phase
4B (Subphase 2, Subphase 3, and Subphase 7 formal benign baseline).
Final Subphase 7 occurrence most precisely documented: timestamp
`2026-07-12 23:00:19`, query `b59dd060c31a5268a4dd55e6dc581400.azr
.footprintdns.com` (53 chars, over the 50-char threshold), a
legitimate Microsoft Azure telemetry domain.

**Fix:** No condition, value, operator, or regex change. The live
exclusion list already contained `SearchApp.exe` (applied in the
Phase 4B fix pass). Fix in this session is:
- Comment-only YAML edit annotating each exclusion's evidence basis:
  confirmed-incident (SearchApp.exe, svchost.exe) vs.
  precedent-based (browser processes, msmpeng.exe).
- One new regression-lock test pinning the confirmed 70-char
  `svchost.exe` benign sample (`netseer-ipaddr-assoc...fbcdn.net`,
  Facebook CDN/anti-fraud) as non-firing, to prevent any future
  session from accidentally narrowing this exclusion and
  reintroducing the false positive.

**Why content/entropy tightening was rejected:** The confirmed benign
`SearchApp.exe` sample is a 32-char hex-hash subdomain —
structurally identical to what real DNS-tunneling payloads produce.
Entropy heuristics would still false-positive on it. Frequency/
beaconing detection requires stateful matching the engine does not
have (same architectural limitation as D18, which eliminated
`NET_BEACON_INTERVAL_001`). Correctly deferred to a post-Phase-10
engine revamp if ever warranted.

**Residual gap — documented:** The `svchost.exe` exclusion is
blanket. A genuinely compromised or injected `svchost.exe` issuing
real DNS-tunneling queries would also be excluded. Accepted
tradeoff — compensating coverage exists via
`CHAIN_SCHEDULED_TASK_SVCHOST_001` and the `API_CRT_*` injection
rules. Flagged for research paper Section 2.

**Tests added:** 1, in existing file
`tests/test_phase4a/test_network_rules.py`.

---

### C3 — `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001`

**Issue:** `wmiprvse.exe`, `vmtoolsd.exe`, and `svchost.exe`
confirmed generating false positives by opening handles to
`winlogon.exe`/`lsass.exe` as part of normal OS/VM-integration/WMI
operation. 9 total occurrences across Phase 4B and Phase 7A
Subphases 3, 4, and 5. Resolution threshold (4th occurrence during
deliberate simulation, per decisions_log.md Entry 010) met in Phase
7A Subphase 5.

**Important distinction from D49/Category A:** D49's affected
simulations used access masks that Windows over-granted beyond the
rule's allow-list — a matching-logic bug. C3's false positive
occurrences use `granted_access=0x1410`, which is already inside
the allow-list and matches as designed. C3 is a source-exclusion
scope gap; D49 was a matching-logic bug. Both apply to this same
rule; both are now fixed independently.

**Masquerading risk identified and addressed:** A bare-basename
exclusion (e.g. `svchost.exe` only) would be exploitable via
T1036.005 (Masquerading) — `not_ends_with_any` is a suffix match,
so `C:\Users\Public\svchost.exe` would also match and be silently
excluded. Fix uses full path suffixes instead of bare basenames,
anchoring exclusions to their known system locations. This blocks
masquerading without requiring any engine changes.

**Path investigation performed (two rounds):**
- Round 1: `wmiprvse.exe` → `C:\Windows\system32\wbem\wmiprvse.exe`
  (289 occurrences in logs, both casings). `vmtoolsd.exe` →
  `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` (10
  occurrences, single consistent path). `svchost.exe` →
  `C:\Windows\system32\svchost.exe` (75 occurrences as source for
  this rule).
- Round 2: Confirmed rule engine lowercases both field values and
  YAML condition values before every `ends_with_any`/
  `not_ends_with_any` comparison — centrally, in `rules/engine.py`,
  before any operator runs. Mixed casing in data (`C:\WINDOWS\...`
  vs `C:\Windows\...`) is handled by this normalization. Confirmed
  via code read, not assumed.

**Fix — `source_image not_ends_with_any` condition:**
```yaml
    - field: source_image
      operator: not_ends_with_any
      values:
        - "MsMpEng.exe"
        - "\\Windows\\System32\\csrss.exe"
        - "\\Windows\\System32\\lsass.exe"
        - "\\Windows\\System32\\winlogon.exe"
        - "\\Windows\\System32\\wininit.exe"
        - "\\Windows\\System32\\svchost.exe"
        - "\\Windows\\System32\\wbem\\wmiprvse.exe"
        - "\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
```
`MsMpEng.exe` deliberately left bare-basename: its real install path
contains a Defender-platform-version segment
(`C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\
MsMpEng.exe`) that changes on every Defender update. Anchoring it
would silently break the exclusion after the next update.
`granted_access` (already `bits_any_set` from Category A/D49) and
`target_image` left completely untouched.

**Residual gap — documented:** Path-anchoring blocks masquerading
but does nothing against a genuine, correctly-pathed `svchost.exe`
that has been process-hollowed or injected. Detection of that
scenario is the province of the `API_CRT_*` injection rules, not
this one. Defense-in-depth framing — same as C2. Flagged for
research paper Section 2.

**Tests added:** 14, in existing file
`tests/unit/test_phase_2b_false_positives.py`, class
`TestOpenProcessRule`. Includes: 1 masquerade true-positive (new
capability unlocked by path-anchoring), 9 genuine-path FP
regression tests (including 2 explicit mixed-casing variants to
lock in the case-normalization behavior), 4 confirmed-FP exclusion
tests for the 3 newly authorized source processes. All 9
pre-existing genuine-detection TP tests confirmed passing
unregressed.

---

### Cross-Cutting Process Decisions

**Discovery-step safeguard confirmed working (twice in Category C):**
The mandatory pre-edit discovery step in task.md caught real gaps on
two separate occasions: (1) in C1, found two pre-existing tests the
task.md's discovery step predicted wouldn't exist — both confirmed
compatible after independent bitwise verification, no edit needed;
(2) in the Closing Verification, `git status` showed pre-existing
Category A/B working-tree content that the task.md's clean-repo
assumption didn't account for — Cursor correctly stopped rather than
assuming it was fine. Both instances resolved cleanly. The
"stop and report rather than assume" discipline embedded throughout
task.md is confirmed pulling its weight. Standing rule: preserve
this discipline verbatim in every future task.md, do not relax it.

**Context-management pattern — confirmed standing project convention:**
Each multi-subphase task.md must be executed in a separate fresh
Cursor chat per subphase. Each subphase's starter prompt must
explicitly restate the prior subphase's closing test count and point
to task.md as the ground truth. This pattern was applied across all
three C subphases with zero continuity errors — each subphase's
baseline regression number exactly matched the prior subphase's
after-number, confirming no drift between chat sessions. This is now
a standing project convention, not a one-time recommendation.

**Git state note (carried forward):** As of Category C closure,
nothing in the project had been git committed since the original
initial commit. All of Phase 6A, 6B, Phase 7A Subphases 1–5, and
the entire Category A/B/C fix session existed only in the
uncommitted working tree. This was resolved in the subsequent commit
session (commit 89cf182, 2026-08-06) — see git log for full detail.

---

## Entry 012 — 2026-08-07 | Issue Catalog Category D — Environmental/Telemetry
Limitations

**Decision:** Confirm all 7 Category D items (D-a through D-g) as
genuinely environmental/telemetry limitations with no addressable
code fix at the rule engine, normalizer, or YAML layer. Each item
documented below. No Cursor implementation session required or
authorized for this category. All items flagged for research paper
Section 2 (Telemetry Design). One item (D-a) has an available
config-layer fix path deferred as a separate future task.

---

### D-a / D28 — Sysmon EID-3 port filter captures ports 80 and 443 only

**Confirmed via:** Direct read of
`C:\sysmon\sysmonconfig-export.xml` during Phase 7A Subphase 3.
The NetworkConnect include filter is explicit:
```xml
<NetworkConnect onmatch="include">
    <DestinationPort condition="is">80</DestinationPort>
    <DestinationPort condition="is">443</DestinationPort>
</NetworkConnect>
```

**Impact:** Two rules are structurally unfireable on the current
Sysmon config regardless of rule quality or simulation technique:
- `NET_SUSPICIOUS_PORT_001` — requires ports 4444, 1337, 31337,
  and others in the SUSPICIOUS_PORTS constant set.
- `NET_SMB_LATERAL_001` — requires ports 445 and 139.

**Classification:** Configuration gap, not a rule engine or YAML
defect. The rule conditions themselves are correctly written.

**Fix path:** Expanding the Sysmon config's NetworkConnect include
filter to add the required ports. This is a config-layer change
that belongs in a separate, deliberate task with its own review
before touching the live Sysmon configuration. Not actioned here.
This is a deferred config task, not an accepted permanent
limitation — it should be addressed before Phase 8A/9A when the
tool needs to be production-ready.

**Research paper Section 2:** Wider port coverage increases
telemetry volume with performance implications on the monitoring
host. The current narrow filter was a deliberate starting-point
trade-off, not an oversight. Frame as a known, adjustable
limitation.

---

### D-b / D29 — COM/WinINet HTTP calls produce zero Sysmon telemetry

**Confirmed via:** Phase 7A Subphase 3. A `cscript.exe`-based
`MSXML2.XMLHTTP` call to `https://dns.google:443` completed a
fully verified successful round-trip — HTTP 200 confirmed via
script output, meaning DNS resolution, TCP handshake, TLS, and
the HTTP request/response all genuinely completed. Zero EID-3 and
zero EID-22 events appeared in the pipeline DB or raw Sysmon event
log for any process in that time window.

**Why this is distinct from D-a:** The destination port (443)
passes the D-a port filter. The destination is not loopback
(ruling out D-g). The network activity genuinely occurred. The
gap is at the ETW/COM layer, not at the Sysmon config filter.

**Root cause (working hypothesis):** COM/WinINet's internal network
stack does not trigger the same ETW hook that Sysmon's
NetworkConnect and DnsQuery filters observe. The kernel-level hook
placement does not intercept traffic routed through the COM/WinINet
subsystem's own network path.

**Impact:** `NET_DNS_SCRIPT_ENGINE_001` disposition on this specific
failure mode is INCONCLUSIVE. Note: this is a distinct failure mode
from Phase 4B Issue 6 (where an EID-22 event did fire but had an
unresolved `<unknown process>` identity). D-b is "no event at all";
Issue 6 is "event fires, identity unresolved." Both affect the same
rule but are independent problems.

**Classification:** Environmental — at the ETW/kernel layer. No
rule change, engine change, or Sysmon config change can produce
an event the OS's ETW subsystem never emitted.

**Research paper Section 2:** This is a real-world attacker evasion
surface — a script engine using COM/WinINet for C2 callbacks is
invisible to this telemetry layer. Honest scoping strengthens the
paper's credibility.

---

### D-c / D48 — Managed .NET DLL loads produce no EID-7 ImageLoad
events

**Confirmed via:** Phase 7A Subphase 5. Two independent tests with
two different DLLs, via both `regsvr32` (with and without `/s`
flag) and `[System.Reflection.Assembly]::LoadFile()`. In both
cases the load itself succeeded (regsvr32 confirmed the module
loaded before failing at the DllRegisterServer entry-point lookup,
a post-load step) — yet zero EID-7 events appeared in either the
pipeline DB or the raw Sysmon event log.

**Root cause:** The CLR's internal module-loading path for managed
assemblies does not trigger the same kernel-level ImageLoad ETW
event that a native `LoadLibrary` call produces. This is a .NET
runtime internals gap — the managed assembly loader uses a
different code path that the ETW ImageLoad hook does not intercept.

**Working simulation workaround (Category E, not a code fix):**
Using a genuine native (non-.NET) DLL copied with its full
dependency folder produces a proper EID-7 event.
`python_runtime\DLLs\sqlite3_d.dll` confirmed working. Dependency
folder must be copied alongside the DLL — a first attempt using
only the single DLL file failed with "specified module could not
be found" due to missing dependent DLLs. The underlying gap itself
is not fixed by this workaround.

**Classification:** Environmental — CLR internals, below the ETW
hook layer. No rule, engine, normalizer, or config change can fix
this.

**Research paper Section 2:** Note as a coverage boundary —
managed assembly loads are invisible to this telemetry layer
regardless of signing status.

---

### D-d — mavinject.exe injection mechanism invisible to Sysmon EID-10

**Confirmed via:** Phase 4B and Phase 7A. Atomic Red Team T1055.001
test — `mavinject.exe` and target `notepad.exe` both confirmed
spawned via EID-1 with correct parent-child chain. Zero EID-10
(ProcessAccess) events produced.

**Rule affected:** `API_OPEN_PROCESS_VM_WRITE_001`.

**Critical distinction from D49/Category A:** D49 (the
granted_access over-grant bug on this same rule) was a
matching-logic defect and was fixed in Category A. D-d is an
entirely separate, unrelated problem on the same rule — the
telemetry event itself never fires, so there is nothing for the
matching logic to evaluate. Fixing D49 did not fix D-d. Both
exist independently.

**Root cause:** `mavinject.exe`'s actual memory-write mechanism
does not go through a standard user-mode `OpenProcess` call that
Sysmon's ProcessAccess ETW hook observes, or does so via a path
outside that hook's visibility. No workaround identified.

**Classification:** Environmental — below the Sysmon ETW hook
layer. No rule, engine, normalizer, or config change can produce
a missing telemetry event.

**Research paper Section 2:** This demonstrates that certain
injection tools can operate below Sysmon's observability boundary
even when the process creation itself is visible. Detection of this
specific technique variant requires kernel-level telemetry beyond
user-mode ETW hooks.

---

### D-e / D45 — PPL blocks OpenProcess against MsMpEng.exe at any
privilege level

**Confirmed via:** Phase 7A Subphase 5 explicit control test.
`OpenProcess` against `MsMpEng.exe` with a fully elevated
Administrator session returned `Elevated handle obtained: False`.

**Impact:** `API_AV_PROCESS_ACCESS_001` genuine-detection capability
cannot be empirically validated on this VM via the P/Invoke
`OpenProcess` simulation technique regardless of privilege level.
Only the false-positive suppression side (Category C, C1 fix) can
currently be tested.

**Connection to C1 residual gap:** The same attacker technique
class that bypasses this rule (BYOVD — bring your own vulnerable
driver — to kill the AV process at kernel level) also bypasses the
simulation constraint (PPL prevents user-mode handle acquisition).
These are coherent, not contradictory: the rule's scope covers
commodity-class T1562.001; the techniques that evade it are
sophisticated enough to also evade simulation. Cross-reference
Entry 011, C1 residual gap.

**Classification:** Environmental — Windows kernel PPL protection
mechanism. No rule, engine, normalizer, or config change affects
kernel process protection.

**Research paper Section 2:** Note that genuine-detection
validation is impossible on this VM for this rule via available
simulation techniques, and explain why (PPL). Do not imply the
rule is untested or undesigned — it is correctly designed for its
confirmed commodity-class scope.

---

### D-f / D7 — Defender blocks specific attack signatures
pre-execution across 4 rules

**Confirmed via:** Phase 4B and Phase 7A Subphase 1. Each instance
independently verified via two checks: (1) `Get-MpThreatDetection`
showed a fresh detection entry timestamped within seconds of the
attempt, with `Resources` matching the exact command line; (2)
`Get-WinEvent` against Sysmon's Operational log showed zero
corresponding EID-1 ProcessCreate events.

**Four rules affected:**
- `PS_AMSI_BYPASS_001` — AmsiUtils reflection string
- `PS_CREDENTIAL_ACCESS_001` — Mimikatz-signature command
- `LOLBIN_RUNDLL32_SUSPICIOUS_001` — Atomic Red Team T1055.003
  InjectContext.exe test
- `LOLBIN_REGSVR32_001` — Atomic Red Team T1134.001 payload
  download, AMSI-blocked

**Classification:** Environmental — the pre-execution block happens
before any ETW hook fires. The rules themselves are correctly
written; their detection logic was never exercised because the
payload never reached a state Sysmon can observe. All four rules
classified PARTIAL, not FAIL — this distinction matters for the
research paper's evaluation of detection coverage.

**Research paper Section 2:** This empirically establishes the
boundary between ShadowSensor's behavioral/Sysmon-based detection
layer and the host's pre-existing signature-based AV layer. A
real attacker payload with different obfuscation might not be
caught by Defender and would then reach Sysmon/ShadowSensor as
designed. Frame as a layer-boundary finding, not a rule defect.

---

### D-g / D22 — Sysmon EID-3 does not reliably observe loopback
traffic

**Confirmed via:** Phase 7A Subphase 3. Four consecutive
connection attempts to `127.0.0.1` produced zero EID-3 events.
An identical attempt to `8.8.8.8` fired immediately.

**Root cause:** Either a Sysmon filter behavior (loopback excluded
by design) or an ETW hook placement issue where loopback traffic
bypasses the network stack layer Sysmon monitors. Not fully
isolated.

**Standing simulation convention adopted:** Use `8.8.8.8` or
`8.8.4.4` for all network-layer (EID-3) simulations going forward.
Already applied correctly in Phase 7A Subphase 4 onward.

**Classification:** Environmental — below the rule engine's
observation layer. No rule or code fix is possible.

**Research paper Section 2:** Minor scope note. Loopback-based C2
is rare in real-world campaigns (implies C2 server on the same
machine, unusual outside of tunneling scenarios). Low practical
impact on detection coverage.

---

## Entry 010 — 2026-07-30 | Phase 7A Subphase 4

**Decision:** Classify `CHAIN_BROWSER_SHELL_001` as PARTIAL for this subphase's labeled-data purposes while its overall rule disposition remains PASS (standing on Phase 4B's prior direct validation); treat `CHAIN_SCHEDULED_TASK_SCRIPT_001`'s FAIL as a structural/legacy-coverage issue flagged for Codex, not chased further in-phase; adopt a retry-once convention for silent script-host-spawning failures; log a third occurrence of the Issue-4 pattern and set the resolution threshold at a fourth occurrence during deliberate (not idle) simulation.

This entry consolidates fourteen findings (D30 recurrence, D31–D43) surfaced during Subphase 4 (Parent-Child Chains) simulation and export.

### Live YAML audit result (`parent_child.yaml`)

Full audit per convention 3.1 found **10 live rules** (task.md estimated ~9–10):

| Live rule ID | task.md's documented equivalent | Disposition |
|---|---|---|
| `CHAIN_OFFICE_POWERSHELL_001` | same | Match — SKIPPED (Office not installed) |
| `CHAIN_OFFICE_CMD_001` | same | Match — SKIPPED (Office not installed) |
| `CHAIN_SCRIPT_HOST_CMD_001` | `CHAIN_WSCRIPT_CMD_001` | Renamed + scope-expanded — D31 |
| `CHAIN_SCRIPT_HOST_POWERSHELL_001` | `CHAIN_WSCRIPT_PS_001` | Renamed + scope-expanded — D32; absorbs task.md's separate `CHAIN_CSCRIPT_PS_001` — D33 |
| `CHAIN_BROWSER_SHELL_001` | — (undocumented) | D37 |
| `CHAIN_OFFICE_WSCRIPT_001` | — (undocumented) | D38 — SKIPPED (Office not installed) |
| `CHAIN_REGSVR32_CHILD_001` | — (undocumented in Subphase 4's list) | D39 |
| `CHAIN_SCHEDULED_TASK_SCRIPT_001` | same | Match — D43 |
| `CHAIN_SCHEDULED_TASK_SVCHOST_001` | same | Match |
| `CHAIN_LOLBIN_CHILD_001` | `CHAIN_LOLBIN_SHELL_001` | Rename, confirms D15 — D35; absorbs task.md's separate `CHAIN_MSHTA_CHILD_001` — D34 |
| — | `CHAIN_OFFICE_LOLBIN_001` | No live equivalent exists at all — D36. SKIPPED, no substitute possible. |

- **D31** — `CHAIN_SCRIPT_HOST_CMD_001` (live) = `CHAIN_WSCRIPT_CMD_001` (doc). Renamed + scope expanded: live rule's `parent_image` condition covers both wscript.exe AND cscript.exe, not just wscript as the doc name implies.
- **D32** — `CHAIN_SCRIPT_HOST_POWERSHELL_001` (live) = `CHAIN_WSCRIPT_PS_001` (doc). Same rename + scope-expansion pattern as D31.
- **D33** — task.md's separately-documented `CHAIN_CSCRIPT_PS_001` has no separate live rule — fully absorbed into `CHAIN_SCRIPT_HOST_POWERSHELL_001` (live). Not a gap, just consolidated scope.
- **D34** — task.md's separately-documented `CHAIN_MSHTA_CHILD_001` has no separate live rule — mshta.exe is one of six parent LOLBins already covered by `CHAIN_LOLBIN_CHILD_001` (live). Same consolidation pattern as D33.
- **D35** — Full-file audit confirms D15's incidental Subphase-2 finding: `CHAIN_LOLBIN_SHELL_001` (doc) = `CHAIN_LOLBIN_CHILD_001` (live). Live scope covers 6 parent LOLBins: mshta, rundll32, odbcconf, cmstp, installutil, regasm, regsvcs — broader than the doc name implied.
- **D36** — `CHAIN_OFFICE_LOLBIN_001` documented, absent from live `parent_child.yaml` entirely — no live rule exists, not even a rename. SKIPPED, no substitute possible or needed.
- **D37** — `CHAIN_BROWSER_SHELL_001` exists in live YAML, zero documentation in task.md's Subphase 4 list. Already validated once directly in Phase 4B (custom registered protocol handler technique, confirmed PASS at that time).
- **D38** — `CHAIN_OFFICE_WSCRIPT_001` exists in live YAML, zero documentation in task.md. Requires Office (absent on VM) — SKIPPED.
- **D39** — `CHAIN_REGSVR32_CHILD_001` exists in live YAML, zero documentation in task.md's Subphase 4 rule list (referenced only in passing elsewhere). Simulated successfully this subphase.

Net: 10 live rules. 3 SKIPPED for Office. 7 rules simulated.

### Simulation results

| # | Rule | Result | Notes |
|---|---|---|---|
| 1 | `CHAIN_SCRIPT_HOST_CMD_001` | PASS | Required one retry per D41 |
| 2 | `CHAIN_SCRIPT_HOST_POWERSHELL_001` | PASS | First try, no retry needed |
| 3 | `CHAIN_BROWSER_SHELL_001` | PARTIAL (this subphase) | See D42. Rule's overall disposition remains PASS on Phase 4B's prior direct validation. No fresh label=1 telemetry generated this subphase — deliberate tradeoff, not oversight. |
| 4 | `CHAIN_REGSVR32_CHILD_001` | PASS | Clean, first try. Bonus corroborating hit: `LOLBIN_REGSVR32_001` fired 2s earlier. |
| 5 | `CHAIN_SCHEDULED_TASK_SCRIPT_001` | FAIL | See D43 |
| 6 | `CHAIN_SCHEDULED_TASK_SVCHOST_001` | PASS | Bonus corroborating hit: `PS_INVOKE_EXPRESSION_001` same timestamp |
| 7 | `CHAIN_LOLBIN_CHILD_001` | PASS | Clean, first try. Bonus corroborating hit: `LOLBIN_RUNDLL32_SUSPICIOUS_001` fired 1s earlier. |

**Tally: 5 PASS, 1 PARTIAL (prior-validated), 1 FAIL (structural), 3 SKIPPED (Office).**

### Environmental/tooling findings

- **D30 (third occurrence)** — `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` firing unprompted from `wmiprvse.exe` (and, per fuller log, also `vmtoolsd.exe`) against `winlogon.exe`/`lsass.exe`, recurring at both Subphase 3 pre-flight and Subphase 4 pre-flight, both times with no deliberate simulation running. Consistent with pre-existing Phase 4B Issue 4 (left open/inconclusive). Excluded from Subphase 4's export window per standing policy (3.6). **Decision: set the resolution threshold at a fourth occurrence specifically during DELIBERATE Subphase 5 simulation** — idle/pre-flight recurrences alone do not meet the bar to reopen Issue 4's disposition.
- **D40** — `WScript.Shell` instantiated as a COM object directly inside a PowerShell session (`New-Object -ComObject WScript.Shell`) attributes the resulting child process's `ParentImage` to `powershell.exe`, NOT `wscript.exe`. Confirmed directly via Sysmon. Expected/correct behavior (the actual `CreateProcess` call is issued by PowerShell's own process in this invocation path), but means **this technique cannot substitute for genuine wscript.exe-hosted simulations** — doing so would mislabel telemetry with the wrong parent process, invalidating labeled data for parent-child chain rules specifically.
- **D41 — HIGH VALUE finding.** `wscript.exe → cmd.exe`/`powershell.exe` child-process spawning via a genuine `.vbs`-file-based `WScript.Shell.Run` call showed inconsistent, non-deterministic behavior across repeated identical attempts. First two attempts targeting `cmd.exe` produced no child process at all — confirmed absent from both the pipeline DB and raw Sysmon's own event log — with no corresponding Defender detection logged either (ruling out the D7/D26/D27 clean-block pattern). A `notepad.exe` target using the identical mechanism succeeded immediately on the next attempt. A subsequent retry of the exact same `cmd.exe` payload then succeeded, confirmed via raw Sysmon and the rule engine. Root cause not fully isolated — most likely a race/timing sensitivity in Windows Defender's real-time behavioral monitoring specifically targeting the wscript→shell-interpreter pattern, silently absorbing/delaying the spawn without logging a formal detection, rather than a hard deterministic block. **Decision — practical, reusable rule going forward: on an unexplained silent failure for this specific rule category (script-host spawning a shell interpreter), retry the identical simulation once before concluding FAIL.** The second attempt succeeded cleanly both times this was tested.
- **D42** — `Start-Process msedge.exe "<custom-protocol>:<arg>"` does NOT trigger the corresponding registered protocol handler through Edge — Edge instead treats the argument as a navigation/search string (produces only Edge's own internal self-parented child processes, never the handler's target command). The handler itself is confirmed fully functional via `Start-Process "<protocol>:<arg>"` (letting the OS/PowerShell's own `ShellExecute` resolve the protocol directly) — but in that path, the resulting child process's `ParentImage` is whatever invoked it (`powershell.exe` in testing), NOT the browser. **Practical implication:** generating a genuine `msedge.exe`-parented child process for `CHAIN_BROWSER_SHELL_001` via this technique requires triggering the protocol from inside an actual Edge-rendered page (e.g. clicking an `<a href="protocol:arg">` link on a local HTML file opened in Edge) — not via any command-line invocation. Simulation-technique limitation, not a rule defect; the rule already has a confirmed genuine PASS from Phase 4B using an interactive, in-browser version of this technique.
- **D43 — flag for Codex.** `CHAIN_SCHEDULED_TASK_SCRIPT_001`'s live YAML now explicitly includes `schtasks.exe` in its `parent_image` condition list (added at some point after Phase 4B's original FAIL finding) — but this addition does not make the rule fireable in practice on this Windows build. Confirmed directly: `schtasks.exe` only ever appears in Sysmon telemetry as the tool used to create/invoke a scheduled task; it immediately hands off execution to the real Task Scheduler service host process, consistently `svchost.exe -s Schedule` — never `schtasks.exe` itself as a direct parent of the payload process. Only `CHAIN_SCHEDULED_TASK_SVCHOST_001` (which correctly targets the `svchost.exe -s Schedule` parent) fired; `CHAIN_SCHEDULED_TASK_SCRIPT_001` did not, despite the YAML change. Re-confirms the same root cause originally identified in Phase 4B, just after an intervening YAML edit that didn't actually address it. **Decision: recommend flagging to Codex as a real fix candidate**, separate from routine doc-sync work: either deprecate/remove the rule as effectively redundant and unfireable on modern Windows builds, or explicitly document it as intentionally legacy-only coverage (its legacy `taskeng.exe`/`taskhostw.exe` parent paths may only ever exist on older Windows versions) so its expected FAIL/no-fire status doesn't get mistaken for a bug in future validation passes. Not fixed inline — deferred, not blocking.

### Export

DB-confirmed UTC window 2026-07-30 06:04:56–06:16:42. `suspicious_chains.csv`, 129 process windows, verified uncontaminated (100% label=1), `has_chain_rule_hit` active on exactly 6/6 rows matching the 5 distinct confirmed rule triggers (one rule — `CHAIN_SCRIPT_HOST_POWERSHELL_001` — fired twice from separate process windows, consistent with the precedent already documented in convention 3.8).

**Alternatives considered:**
- Chase `CHAIN_SCHEDULED_TASK_SCRIPT_001` further this subphase (alternate parent-path techniques, older-Windows-style task hosts) — rejected: same root cause as Phase 4B's original finding, low ROI, correctly belongs as a Codex-side rule-design decision (deprecate vs. document-as-legacy) rather than further simulation effort.
- Force `CHAIN_BROWSER_SHELL_001` fresh telemetry via more elaborate automation (e.g. scripted browser UI interaction) — rejected: poor ROI against remaining unverified rules in the subphase; rule's correctness is not in doubt given Phase 4B's prior direct validation, only the automation path is limited.
- Resolve D30/Issue-4 immediately on this third occurrence — rejected: both occurrences so far have been idle/pre-flight, not during deliberate simulation; premature to reopen disposition without a recurrence under deliberate test conditions.

---

## Entry 009 — 2026-07-30 | Phase 7A Subphases 2–3

**Decision:** Document live-ruleset drift in `lolbins.yaml` and `network.yaml` without altering rule code (consistent with Entry 008's precedent); flag Sysmon's EID-3 port-filtering gap (D28) as a dedicated Codex/config task; leave the DNS-script-engine telemetry gap (D29) as INCONCLUSIVE and carry it into the research paper rather than continuing to chase the mechanism; standardize on 8.8.8.8/8.8.4.4 for all network-layer simulations going forward.

This entry consolidates twenty-one findings (D9–D29) surfaced during Subphase 2 (LOLBins) and Subphase 3 (Network) simulation and export. Written up retroactively alongside Entry 010 — both subphases were completed and verified in-session but the permanent decisions log was not updated at the time (see status.md's file-delivery-debt note, now cleared).

### Subphase 2 — LOLBins (`lolbins.yaml`)

- **D9** — `LOLBIN_RUNDLL32_001` (doc) = `LOLBIN_RUNDLL32_SUSPICIOUS_001` (live). Rename only, same mechanism.
- **D10** — `LOLBIN_WMIC_001` (doc) = `LOLBIN_WMIC_PROCESS_001` (live). Rename only.
- **D11** — `LOLBIN_MSIEXEC_001` (doc) = `LOLBIN_MSIEXEC_REMOTE_001` (live). Rename only.
- **D12** — `LOLBIN_REGASM_001` (doc) = `LOLBIN_REGASM_REGSVCS_001` (live). Rename + scope expansion — now also covers regsvcs.exe.
- **D13** — `LOLBIN_FINDSTR_001` documented, absent from live `lolbins.yaml`. SKIPPED.
- **D14** — `LOLBIN_HH_CHM_001` exists in live YAML, zero documentation anywhere. Simulated successfully. Family: Lazarus Group.
- **D15** — `CHAIN_LOLBIN_SHELL_001` (doc) = `CHAIN_LOLBIN_CHILD_001` (live), spotted incidentally during Subphase 2 as a side effect of a LOLBin simulation (bonus corroborating hit, not a deliberate parent_child simulation this subphase). Confirmed via full `parent_child.yaml` audit at Subphase 4 — see Entry 010's D35.

**Decision:** 13/13 live rules PASS (12 documented under corrected names + 1 undocumented, `LOLBIN_HH_CHM_001`). 1 documented rule (`LOLBIN_FINDSTR_001`) SKIPPED — no live equivalent, not fabricated. Export: `suspicious_lolbins.csv`, 63 rows, verified uncontaminated, 14+1 rule-hit-attributable rows matching exactly (13 LOLBin rules + the D15 incidental chain hit).

### Subphase 3 — Network (`network.yaml`)

**Documentation-vs-live-ruleset drift:**
- **D16** — `NET_EXTERNAL_LOLBIN_001` documented, absent from live `network.yaml`. Functionally superseded by `NET_LOLBIN_NETWORK_001` (confirmed working).
- **D17** — `NET_NONSTANDARD_PROTOCOL_001` documented, absent from live `network.yaml`. SKIPPED — no live equivalent identified.
- **D18** — `NET_BEACON_INTERVAL_001` documented, absent from live `network.yaml`. SKIPPED — likely architecturally impossible given the flat AND/OR rule engine (no temporal/stateful "repeated connections within interval" logic exists per the Two-Rule Split architectural principle).
- **D19** — `NET_WSCRIPT_OUTBOUND_001` documented, absent from live `network.yaml`. Functionally superseded by `NET_SCRIPTING_ENGINE_HTTP_001` (confirmed working).
- **D20** — `NET_POWERSHELL_HTTP_001` exists in live YAML, zero documentation anywhere. Simulated successfully.
- **D21** — `NET_LOLBIN_PROCESS_HTTP_001` exists in live YAML, zero documentation anywhere. Simulated successfully (also `NET_LOLBIN_NETWORK_001`, same category, also undocumented).

**Simulation-technique corrections (our own mistakes, not project defects):**
- **D22** — Sysmon's NetworkConnect hook does not reliably observe loopback (127.0.0.1) traffic: 4 consecutive attempts to 127.0.0.1 produced zero EID-3 events, while 8.8.8.8 fired immediately. **Decision: substitute 8.8.8.8 or 8.8.4.4 for any network-layer (EID-3) simulation, going forward from this subphase on.** Note: raw-IP HTTPS via `MSXML2.XMLHTTP` sometimes fails with `msxml3.dll: Access is denied` (TLS certificate/hostname validation issue, unrelated to Sysmon) — 8.8.8.8 specifically has worked reliably.
- **D24** — `MSXML2.XMLHTTP.open()` alone does not initiate a network connection; `.send()` is required. The first wscript-based network simulation template was missing this, producing a false "rule doesn't work" impression until corrected.

**Major structural/architectural findings:**
- **D28 — HIGH PRIORITY.** Confirmed via direct read of `C:\sysmon\sysmonconfig-export.xml`: Sysmon's NetworkConnect (EID-3) config is filtered to include ONLY destination ports 80 and 443:
  ```xml
  <NetworkConnect onmatch="include">
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
  </NetworkConnect>
  ```
  Any rule requiring EID-3 telemetry on a different port is **structurally unfireable**, regardless of rule quality or simulation technique. Killed `NET_SUSPICIOUS_PORT_001` (needs 4444/1337/etc.) and `NET_SMB_LATERAL_001` (needs 445/139) in Subphase 3. This is a telemetry-pipeline gap, not a rule-writing gap. **Decision: flag as a dedicated Codex/config task** (expand the include filter to add needed ports) — not actioned inline, deferred, confirmed not blocking Phase 7A/7B by Ayush.
- **D29 — Confirmed, mechanism not fully resolved.** A `cscript.exe`-based `MSXML2.XMLHTTP` call to `https://dns.google` completed a full, verified successful round-trip (HTTP Status 200 confirmed via script output) — DNS resolution + TCP handshake + TLS + HTTP request/response all genuinely happened — yet **zero Sysmon events of any type (EID-3 or EID-22) were generated**, for any process, in that time window. Distinct from D22 (loopback) and D28 (port filtering): the destination was `dns.google:443`, which passes the port filter, and is not loopback. Root cause not fully isolated (hostname-vs-raw-IP was a candidate variable; raw-IP tests then failed for an unrelated TLS certificate reason before that could be confirmed). **Decision: `NET_DNS_SCRIPT_ENGINE_001` disposition set to INCONCLUSIVE** rather than continuing to chase the mechanism this subphase. Flagged as a genuine, real telemetry visibility gap worth noting in the research paper's Section 2 (Telemetry Design) regardless of whether the exact mechanism is later pinned down. Deferred, not blocking, per Ayush's confirmation (same handling as D28).

**Decision:** 4 PASS, 2 SKIPPED (D28's two structurally-impossible rules), 1 INCONCLUSIVE (D29). Export: `suspicious_network.csv`, DB-confirmed UTC window 2026-07-30 04:53:20–05:06:15, 92 process windows, verified clean — all labels=1, `has_network_rule_hit` active on exactly 3 rows matching the 3 distinct underlying confirmed-simulation processes (powershell.exe → `NET_POWERSHELL_HTTP_001` + `NET_DNS_LONG_QUERY_001`; wscript.exe → `NET_SCRIPTING_ENGINE_HTTP_001` ×2; msiexec.exe → `NET_LOLBIN_PROCESS_HTTP_001` + `NET_LOLBIN_NETWORK_001`).

**Alternatives considered:**
- Hand-tune a temporal/stateful extension to the rule engine to make `NET_BEACON_INTERVAL_001` (D18) fireable — rejected: out of scope for a validation subphase; a rule-engine architecture change belongs with Codex, not spontaneously added mid-simulation.
- Keep chasing D29's root cause (hostname vs. raw-IP, alternate script engines, alternate TLS libraries) until resolved — rejected: diminishing returns against the subphase's remaining rules; INCONCLUSIVE with the finding fully documented is more valuable than an open-ended investigation that risks delaying Subphase 4.
- Expand Sysmon's port-filter config immediately to unblock D28's two rules within this subphase — rejected: a Sysmon config change affects the whole telemetry pipeline and should go through Codex as a deliberate, reviewed change, not be made ad hoc mid-validation-session.

---

## Entry 008 — 2026-07-29 | Phase 7A Subphase 1

**Decision:** Classify Defender pre-execution blocks as PARTIAL (not FAIL); document live-ruleset drift from task.md/master-plan without altering rule code; require DB-sourced UTC timestamps (not console/wall-clock) for all future `--since`/`--until` export bounds.

This entry consolidates eight distinct findings (D1–D8) surfaced during Subphase 1 (PowerShell, 11 rules) simulation and export. All are logged together because they were discovered in the same session and jointly affect how the remaining Phase 7A subphases must be run.

### D1/D2 — Two documented rules absent from live `powershell.yaml`

`PS_NOPROFILE_NONINTERACTIVE_001` and `PS_OBFUSCATION_001` are both listed in `phase7a_task.md`'s Subphase 1 rule set and in the master plan's Phase 4A 11-rule PowerShell breakdown, but do not exist anywhere in the live `rules/definitions/powershell.yaml` (confirmed via full-file `Get-Content` review and `- id:` grep — 11 IDs present, neither of these two among them). No YAML condition block, no partial match, nothing.

**Disposition:** Marked SKIPPED for Subphase 1 — not simulated, not counted as FAIL. These are documentation-vs-implementation gaps, not simulation failures.

**Decision:** Do not fabricate a simulation against a non-existent rule. Flagged for a future decision: either implement these two rules in a Codex pass, or formally strike them from the documentation. Not resolved in this session — deferred to Ayush's call, likely bundled with a broader documentation-sync task after Phase 7A closes.

### D3/D4 — Two rules exist under different IDs than documented; one also has a different mechanism entirely

- `PS_REFLECTION_ASSEMBLY_001` (documented) is actually `PS_REFLECTIVE_ASSEMBLY_001` (live) — same detection intent (`.NET` reflective assembly loading), ID naming drift only. Cosmetic.
- `PS_CONSTRAINED_BYPASS_001` (documented, task.md template used `-Version 2 -Command` as the trigger) is actually `PS_CONSTRAINED_LANG_BYPASS_001` (live), and the live rule's actual condition matches the `__PSLockdownPolicy` environment variable — a completely different detection mechanism than what task.md's simulation template described. Following task.md's original template for this rule would have silently tested `PS_VERSION_DOWNGRADE_001` instead (which does match `-version 2`), producing a false confirmation for the wrong rule.

**Decision:** Simulated using the rule's actual live YAML condition (`$env:__PSLockdownPolicy = "0"`), not task.md's stale template. Confirmed firing correctly (11:52:19 local / 06:22:19 UTC). Flagged for a documentation-sync pass — task.md's template for this rule needs correcting so a future session doesn't repeat the same wrong-rule confirmation.

### D5/D6 — Two rules exist in live YAML with zero documentation trail

`PS_VERSION_DOWNGRADE_001` (PowerShell v2 downgrade attack, T1059.001, matches `-version 2`/`-v 2`/`-ve 2`) and `PS_WMI_EXEC_001` (WMI-based process execution, T1047, matches `Win32_Process`/`Invoke-WmiMethod`/`gwmi`/etc.) both exist as fully-formed, well-documented-in-YAML-comments rules in the live `powershell.yaml`, but appear nowhere in `phase7a_task.md`, the master implementation plan's 11-rule breakdown, or the technical flow document's rule tables.

**Decision:** Both simulated successfully against their real YAML conditions (confirmed firing: `PS_VERSION_DOWNGRADE_001` at 11:46:45 local / 06:16:45 UTC; `PS_WMI_EXEC_001` at 11:52:44 local / 06:22:44 UTC). Both are legitimate, well-designed rules — the gap is purely in documentation coverage, not implementation. Flagged for the documentation-sync pass to add these two rules to the master plan and technical flow doc's rule tables.

### D7 — Windows Defender blocks specific PowerShell rule triggers pre-execution; classified PARTIAL

Two of the 11 PowerShell simulations (`PS_AMSI_BYPASS_001`'s `AmsiUtils` reflection string, and `PS_CREDENTIAL_ACCESS_001`'s `sekurlsa::logonpasswords` Mimikatz signature) were intercepted by Windows Defender's real-time protection before the PowerShell process's creation was logged by Sysmon. Confirmed via two independent checks each time: (1) `Get-MpThreatDetection` showed a fresh detection entry with `Resources` exactly matching our command line, timestamped within seconds of the attempt; (2) `Get-WinEvent` against Sysmon's Operational log showed zero corresponding EID-1 ProcessCreate events.

**Decision:** Both classified **PARTIAL — Defender-blocked pre-execution**, not FAIL. This is consistent with the precedent already established in Phase 4B (Defender/AMSI interference is a distinct outcome category from a genuine rule miss — the rule's detection logic was never exercised because the payload never reached a state where Sysmon could observe it). No process window is generated for these two simulations, and none should be — fabricating one would mislabel non-events as label=1 data.

**Research implication for Phase 10B:** this is useful evidence for Section 2 (Telemetry Design) — it empirically demonstrates the boundary between ShadowSensor's behavioral/Sysmon-based detection layer and the host's pre-existing signature-based AV layer. Both rules are validated as *correctly written* (their conditions are provably reachable via Simulation confirmation in principle — Defender simply intervened first in this specific test environment); a real attacker's payload with different obfuscation might not be caught by Defender and would then reach Sysmon/ShadowSensor as designed.

### D7b (sub-finding) — Unplanned CreateRemoteThread telemetry coinciding with Defender remediation

Three `API_CREATE_REMOTE_THREAD_001` hits (Critical severity, target=`<unknown process>`) fired at 11:34:39–11:34:40 local (06:04:39–06:04:40 UTC), roughly two minutes after the AMSI-bypass Defender block. Not something we simulated — nothing in Simulation #4 targeted CreateRemoteThread. Leading hypothesis: Defender's own remediation/termination action against the quarantined PowerShell process generated genuine CreateRemoteThread activity as part of its cleanup mechanics, and Sysmon logged it as EID 8 with unresolved target identity (consistent with the already-documented Issue 2/6 identity-resolution race condition from Phase 4B).

**Decision:** Flagged and **excluded** from Subphase 1's labeled export window (export `--since`/`--until` bounds were deliberately split around this window — see D8 below). Not counted as genuine injection-technique telemetry; folding it into the labeled dataset would mislabel defensive-tool remediation behavior as attacker behavior. Carried forward explicitly to Subphase 6 (the dedicated CreateRemoteThread/injection subphase) for awareness, and will appear in the Phase 7A final report's Issues Log regardless of final disposition.

**Standing policy going forward (not limited to this instance):** any unexpected rule fire that doesn't correspond to what was just simulated — extra rules firing, wrong rule firing, telemetry with no corresponding deliberate action — gets flagged immediately, excluded from the clean labeled export window by default, and carried into `phase7a_final_report.md`'s Issues Log. This applies to all remaining Phase 7A subphases, not just Subphase 1.

### D8 — Database stores UTC; console output and VM wall-clock are IST (UTC+5:30)

Two consecutive `--since`/`--until` export attempts using local wall-clock-derived timestamp bounds (e.g. `"2026-07-29 11:28:00"`) returned **zero rows**, despite Sysmon and the pipeline both confirmed live and correctly logging events during that window. Root-caused by comparing known-good `RULE_HIT` console timestamps against the same events' stored `rule_hits.timestamp` values in SQLite: every pair showed an exact 5:30:00 offset (e.g. console `11:28:47` ↔ DB `05:58:47.751091`). The database stores UTC; the VM displays IST; the collector's console output also uses IST (matching wall-clock, not DB storage).

**Decision:** All `--since`/`--until` export bounds for the remainder of Phase 7A must be derived by querying the database directly for the actual stored (UTC) timestamps of the first and last simulation in a given subphase window — never from console `RULE_HIT` output or `Get-Date`/wall-clock readings, both of which are IST and will silently produce empty exports if used directly. Re-ran Subphase 1's exports with corrected UTC bounds (`05:58:00`–`06:02:30` and `06:10:00`–`06:23:00`); both succeeded (79 and 73 rows respectively), verified uncontaminated (100% label=1) with exactly 8 rule-hit-attributable rows matching the 8 confirmed rule triggers.

**Note — this is distinct from the Phase 6A VM clock discrepancy.** The Phase 6A issue (see status.md Known Blockers, "Feature-influence note for Phase 7B") was a genuine clock-drift bug, since resolved and reconfirmed synced to real-world time at this session's start (`Get-Date` returned `Wednesday, July 29, 2026 11:20:27 AM`, correctly matching real-world current time). This D8 finding is normal UTC-vs-local-timezone-display behavior — not a bug, not drift — but it was previously undocumented as an operational gotcha for anyone constructing `--since`/`--until` bounds by hand, and needed to be logged so future subphases (and future sessions) don't repeat the two failed zero-row export attempts.

**Alternatives considered:**
- Convert local-to-UTC by hand each time (subtract 5:30) — viable but error-prone; preferred going forward is always querying the DB directly for a subphase's actual first/last event timestamp rather than doing manual arithmetic on wall-clock readings.
- Change the pipeline/collector to log in UTC to the console as well, for consistency — out of scope for Phase 7A (would touch `run_pipeline.py`'s logging code, not a Phase 7A deliverable); noted as a possible future usability improvement, not actioned.

---

## Entry 007 — 2026-07-28 | Phase 6B Subphase 5

**Decision:** Circular import between `dashboard.routers.pages` and `dashboard.app` left unfixed; logged as a known defect.

**Detail:**
`tests/test_phase3/test_e2e_smoke.py` fails with `ImportError` when run in isolation
(`python -m pytest tests/test_phase3/test_e2e_smoke.py`), but passes in the full suite because
a prior test file imports `dashboard.app` first, satisfying the circular dependency as a
side effect of import-order. The root cause is a circular import cycle:

```
dashboard.app → dashboard.routers.pages → (back to dashboard.app for app-state access)
```

This predates Phase 6B and was masked until Subphase 3 added new test files that changed
import ordering. **Decision: do not fix in Phase 6B.** Fixing requires touching
`dashboard/app.py` or `dashboard/routers/pages.py`, both of which are outside Phase 6B's
in-scope file list. The fix belongs in a dedicated dashboard refactor pass — most naturally
in Phase 7A (next session) before any new dashboard routes are added.

The full suite continues to pass (586 passed, 0 failed) because the import-order side effect
is stable across the existing test collection order. Isolation-run failure does not affect CI
or developer workflow as long as tests are run as a suite.

**Logged under Known Blockers / Open Items in `status.md`.**

**Status update (2026-07-29, Phase 7A Subphase 1):** Not yet fixed. No dashboard routes have been touched in Phase 7A as of Subphase 1 (all Phase 7A work so far is VM simulation + feature extraction, no dashboard code). Still deferred — will need to be addressed before any Phase 8A/9A dashboard work begins if not sooner.

**Alternatives considered:**
- Extract shared app state into a third module (no circular dep) — correct fix, but out of
  Phase 6B scope; deferred to Phase 7A.
- Use lazy imports inside the route functions — would work but is non-standard; prefer the
  structural fix instead.

---

## Entry 006 — 2026-07-28 | Phase 6B Subphase 4

**Decision:** ML Insights page uses server-side rendering at page load; no HTMX polling.

**Detail:**
`/dashboard/ml-insights` is server-rendered: the route handler calls
`get_isolation_forest_status()` and `get_score_trend()` at page-load time, passes the
data to the Jinja2 template, and embeds the trend JSON inline for the ApexCharts script.
No HTMX partial endpoint or JS polling was added for this page.

Rationale: ML scores update per-event in real time but dashboard consumers need
aggregated summaries, not live per-event feeds. A page refresh is sufficient for the
use case (checking how the model is performing since the last session). Adding HTMX
polling would require a new partial template and endpoint, adding scope without a
clear user benefit at this phase. The trend chart covers the last 24 hours and is
accurately current at page-load time.

The trend JSON is passed as `trend_data_json` (a `json.dumps()` string) and rendered
via `{{ trend_data_json | safe }}` — the `safe` filter is correct here because the JSON
is server-generated from typed float/int/str values, not user-controlled input.

**Alternatives considered:**
- HTMX partial polling (e.g. every 30s) — rejected: adds scope and a new endpoint
  without a clear real-time UX need for a summary dashboard.
- Separate `/api/v1/ml-insights` JSON endpoint (page fetches via JS on load) — rejected:
  the existing pattern for similar pages (killchain, process-tree) uses server-side
  rendering; consistency preferred over JS-first approach for this page.
- Client-side score computation from raw `/api/v1/ml-status` — rejected: `ml-status`
  returns counts only; full distribution data would bloat the existing endpoint.

---

## Entry 005 — 2026-07-28 | Phase 6B Subphase 3

**Decision:** `handle_persist_and_score_event` supersedes `handle_persist_pipeline_event`
in `on_event`; both functions remain in `run_pipeline.py`.

**Detail:**
Subphase 3 requires the event DB id (`events.id`) for `model_scores.event_fk` linkage.
`handle_persist_pipeline_event` returns `bool` and does not expose the id; changing its
return type was explicitly ruled out in Entry 003 (breaks existing `is True`/`is False`
test assertions). The solution: a new `handle_persist_and_score_event` function is added
that calls `persist_pipeline_event` directly (as Entry 003 specified), getting the event
id, then calls `scorer.score_and_persist()`. `on_event` is updated to call this new
function instead of `handle_persist_pipeline_event`. The old function is retained
unchanged — the tests that assert `is True`/`is False` continue to pass.

The scoring hook (`ml/scoring/scorer.py`) wraps all four steps (event conversion,
feature extraction, model scoring, DB write) in independent try/except blocks, each
with a `logger.error` call — no silent swallowing (Phase 6A lesson). A scoring failure
returns True from `handle_persist_and_score_event` (persistence success is the primary
condition); a persistence failure returns False without attempting scoring.

The model artifact is loaded once at pipeline startup via `EventScorer.__init__()`.
If the artifact is not present, a `logger.warning` is emitted and scoring is disabled
gracefully — the pipeline continues running without ML scoring.

**Alternatives considered:**
- Modify `handle_persist_pipeline_event` to return the event id instead of bool —
  rejected: breaks existing test assertions (Entry 003).
- Query the DB after persistence to get the event id — rejected: extra I/O per event,
  fragile (relies on ROWID / ordering assumptions).
- Separate scoring call after `handle_persist_pipeline_event` with a global
  "last event id" variable — rejected: non-additive, shared mutable state.

---

## Entry 004 — 2026-07-28 | Phase 6B Subphase 2 (corrected validation)

**Decision:** Corrected per-event empirical validation confirms proceed condition met; Subphase 3 authorized.

**Detail:**
The original Subphase 2 empirical validation was invalid: it scored `benign_baseline.csv`'s 621
process-window-aggregated rows in-sample. The corrected validation pulled 722 real individual,
unaggregated Sysmon events from the live database (EID 1: 200, EID 3: 97, EID 7: 200, EID 10: 200,
EID 22: 25) and ran each through `EventFeatureExtractor` alone — no `ProcessWindowAggregator`,
no window accumulation — then scored with the trained model using persisted training-time bounds.

Results: min=0.0106, max=0.6427, mean=0.2032, median=0.0946, std=0.2018, **variance=0.0407**
(vs benign-baseline in-sample variance=0.0268). Score bracket distribution is bimodal and
EID-driven: EID 7/10 cluster in [0.0–0.1) (52.2% of all events); EID 1/3/22 cluster in
[0.3–0.7) (42.9%). No scores above 0.643. No degenerate collapse.

EID 3 uniform score (std=0.0, score=0.3412 for all 97 events) is explained: all 97 EID 3
events in the live database are HTTPS connections (port 443, external IP, non-suspicious port),
producing identical feature vectors. This is correct behavior — the benign traffic is uniformly
HTTPS, not an extractor or model defect.

**Proceed condition:** Variance=0.0407 > 0.0268 (benign-baseline). No clustering near 1.0
(max=0.643). No near-constant collapse. All three task.md stop conditions are not met.
Subphase 3 may proceed.

**Caveats for Subphase 3 / Phase 8A:**
- Score interpretation is EID-sensitive. EID 1 mean=0.44 vs EID 10 mean=0.05 — not directly
  comparable without EID context. Phase 8A correlation engine should account for this.
- EID 3 score will remain near-constant (≈0.34) until network traffic is more varied.
- EID 8 absent from live DB; cannot empirically validate but expected to score low (sparse vector).

**Alternatives considered:** None — the proceed/stop evaluation is deterministic given the
distribution numbers.

---

## Entry 003 — 2026-07-28 | Phase 6B Subphase 2

**Decision:** Per-event scoring in the live pipeline (not per-window); `handle_persist_pipeline_event` return type unchanged.

**Detail:**
1. The live pipeline `on_event` callback fires per individual Sysmon event. No accumulated process-window state exists at that insertion point. Scoring uses `EventFeatureExtractor` on the single current event, followed by `ProcessWindowAggregator` with a single-event window — reusing Phase 5 code exactly, not duplicating it.
2. `handle_persist_pipeline_event` currently returns `bool` (`True`/`False`). Two existing tests assert `is True` / `is False` (strict identity). Changing the return type to `int | None` would break these tests. Therefore the return type is NOT changed. The Subphase 3 scoring hook will call `persist_pipeline_event` directly to obtain the event DB id for `model_scores.event_fk`.

**Reasoning (per-event):** Building a rolling window accumulator in `run_pipeline.py` would require unbounded per-`(image,pid)` in-memory state and a policy for when a window "closes" — significant scope and risk for what must be a purely additive pipeline change. Per-event scoring with a single-event window is a simpler, additive fit. Empirical validation (Subphase 2) confirmed per-event scoring is non-degenerate: variance=0.0268, 61% of rows score < 0.1, only 5% score > 0.5 — reasonable spread.

**Alternatives considered:**
- Rolling in-memory window accumulator per `(image, pid)` — rejected: unbounded memory, window-close policy, non-additive scope.
- Re-query SQLite per event for all recent `(image, pid)` events — rejected: extra I/O per event, time-window definition ambiguous for long-running processes.
- Change `handle_persist_pipeline_event` return type — rejected: breaks existing `is True`/`is False` test assertions.

---

## Entry 002 — 2026-07-28 | Phase 6B Planning (pre-Subphase 1)

**Decision:** Persist continuous anomaly score from Isolation Forest, not binary `predict()` output.

**Detail:** Use `score_samples()` (returns raw anomaly scores where more-negative = more anomalous), then rescale to a 0.0–1.0 float where **higher = more anomalous**, formula: `score = (train_max - raw) / (train_max - train_min)`. When `raw = train_min` (most anomalous raw value) → score = 1.0; when `raw = train_max` (least anomalous) → score = 0.0. Out-of-distribution inputs are clipped to [0.0, 1.0]. (Note: the formula `(raw - raw.min()) / (raw.max() - raw.min())` that appeared in earlier drafts was incorrect — it inverts the direction and was corrected before implementation.)

**Critical addendum (2026-07-28):** The `min` and `max` used in this formula must be computed **once**, from the `score_samples()` output on `benign_baseline.csv` at training time, then **persisted alongside the model artifact** (e.g. as fields in the same joblib file, or a small sidecar JSON). All future scoring — including the live pipeline in Subphase 3 — must load and apply these fixed, persisted training-time bounds. Recomputing min/max from whatever batch is currently being scored is explicitly forbidden: it would produce scores on an inconsistent, batch-dependent scale, making `model_scores` values incomparable across sessions and breaking Phase 8A's fusion logic. A Subphase 2 unit test must confirm that inference-time rescaling uses the persisted training-time bounds and not batch-local ones.

**Reasoning:** `model_scores.score` is defined as a continuous 0.0–1.0 float. The binary `predict()` output (+1 / -1) discards all within-class signal and cannot be stored in this schema. Actual severity/detection thresholding is deferred to Phase 8A's correlation engine, where Isolation Forest and Random Forest scores will be fused. A continuous score on a stable, training-anchored scale is the right interface for that fusion layer.

**Alternatives considered:**
- Binary `predict()` — discards within-class signal, incompatible with `model_scores.score` 0.0–1.0 column constraint, deferred thresholding to Phase 8A makes this premature.
- Min-max rescaling per-prediction batch at scoring time — rejected: produces inconsistent scales across batches; scores from different pipeline runs would not be comparable, breaking Phase 8A fusion.

---

## Entry 001 — 2026-07-28 | Phase 6B Planning (pre-Subphase 1)

**Decision:** Train Isolation Forest with `contamination='auto'`.

**Detail:** Do not hand-tune the `contamination` hyperparameter; use scikit-learn's default `'auto'` setting (which sets the threshold at the score of the most extreme 0.1% of training points).

**Reasoning:** `model_scores.score` is a continuous 0.0–1.0 float by design; actual severity/detection thresholding is explicitly deferred to Phase 8A's correlation engine, where Isolation Forest and Random Forest outputs are fused together. Hand-tuning `contamination` now, against a 621-row benign-only set with no labeled anomalies to validate against, would bake an unvalidated threshold into the model artifact.

**Alternatives considered:**
- Setting `contamination` to a small explicit float (e.g. 0.05) — rejected: no labeled suspicious data exists yet to validate any particular threshold choice; revisit if needed once Phase 7B's labeled suspicious data is available.

---
