# Phase 7A Subphase 5–7 — Simulation Issues Log (Pre-Fix-Session)

**Purpose:** Deep, evidence-grounded record of every discrepancy, false
positive, or unexpected telemetry pattern discovered during Phase 7A
Subphase 5 through Subphase 7 simulation work, prior to the consolidated
fix session that will follow once all simulation is complete.

**Scope:** Covers work starting 2026-08-08 (post-C4 closure), Subphase 5
re-verification onward, through Phase 7A completion. Does NOT cover C4
(closed, see `docs/decisions_log.md` Entry 013) or anything prior.

**Working convention:** No CSV export happens until every subphase
(5, 6, 7) is fully simulated and every discrepancy below is logged. Once
simulation work is complete, this file becomes the input to a single
consolidated fix session (same investigate → discuss → agree →
`task.md` → Cursor-implements discipline as Categories A–D and C4).
After that fix session closes, Subphases 5–7 are re-simulated fresh
against the fixed rule set, and only then exported.

**Entry template:** ID, title, discovered-in, trigger evidence (exact
log lines), root cause analysis, why/where it occurs technically,
provisional category (not committed until fix session), possible fix
directions, residual considerations, cross-references.

---

## E1 — Compiler toolchain cascade falsely triggers `API_OPEN_PROCESS_VM_WRITE_001`

**Discovered in:** Subphase 5 re-simulation session, 2026-08-08, while
setting up Sim1c (`API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` /
`API_OPEN_PROCESS_VM_WRITE_001` / `API_TOKEN_MANIPULATION_001` re-test).

### Trigger evidence (exact log lines)

```
[2026-08-08 21:03:39] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='C:\Windows\system32\cmd.exe' | access=0x1fffff
[2026-08-08 21:03:42] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\cmd.exe' | target='Z:\filelessmalware\python_runtime\python.exe' | access=0x1fffff
[2026-08-08 21:03:42] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='Z:\filelessmalware\python_runtime\python.exe' | access=0x1fffff
[2026-08-08 21:03:42] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\cmd.exe' | target='C:\Windows\system32\print.exe' | access=0x1fffff
[2026-08-08 21:03:43] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='C:\Windows\system32\print.exe' | access=0x1fffff
[2026-08-08 21:03:51] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\cmd.exe' | target='Z:\filelessmalware\python_runtime\python.exe' | access=0x1fffff
[2026-08-08 21:03:51] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='Z:\filelessmalware\python_runtime\python.exe' | access=0x1fffff
[2026-08-08 21:06:06] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | access=0x1fffff
[2026-08-08 21:06:19] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | target='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' | access=0x1fffff
[2026-08-08 21:06:19] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' | access=0x1fffff
[2026-08-08 21:06:20] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' | target='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe' | access=0x1fffff
[2026-08-08 21:06:20] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\system32\conhost.exe' | target='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe' | access=0x1fffff
```

Confirmed via direct observation: these hits appeared **before** the
deliberate Sim1c `OpenProcess` P/Invoke call was actually executed —
they fired during the setup/paste of the PowerShell command block
itself, specifically at the moment the `Add-Type @"..."@` block was
compiled.

### Root cause analysis

Two distinct sub-patterns are interleaved in this evidence:

**Sub-pattern A — terminal/console host chain (`conhost.exe` /
`cmd.exe` / `powershell.exe` → their own children):**
`conhost.exe` is the console host process that backs every `cmd.exe`
or `powershell.exe` window on Windows. When a shell spawns a child
process (running `python.exe`, `print.exe`, etc., or even just
rendering console I/O for a new PowerShell window), both the shell
itself and its `conhost.exe` host acquire broad-access handles to that
freshly-created child as a normal, undocumented-but-common part of
console I/O plumbing and process lifecycle bookkeeping (job-object
association, console attach/detach, exit-code retrieval). This is not
malicious in any sense — it is baseline behavior of the Windows
console subsystem, triggered by the mere act of running any command
in a terminal window.

**Sub-pattern B — `Add-Type` / C# JIT-compilation chain
(`powershell.exe` → `csc.exe` → `cvtres.exe`):**
PowerShell's `Add-Type` cmdlet, when given inline C# source (exactly
what Sim1c/5c/6c's P/Invoke wrapper classes require), does not compile
in-process — it shells out to the real .NET C# compiler
(`csc.exe`), which in turn invokes `cvtres.exe` (the native resource
compiler/linker) to embed compiled resources into the resulting
assembly. `powershell.exe` opens a broad-access handle to `csc.exe`
(its child) to manage its lifecycle and retrieve output/exit status;
`csc.exe` does the same to `cvtres.exe`. This is standard .NET/Visual
Studio build-tooling behavior, present on any Windows machine with the
.NET Framework SDK tools available, and is triggered by any use of
`Add-Type -TypeDefinition` with inline C# — which is exactly the
technique both this project's own Subphase 5 simulation templates
(`phase7a_task.md`) and the D48 native-DLL workaround already rely on.

### Why/where it occurs technically

Both sub-patterns share a common mechanism: **Windows' `CreateProcess`
API returns a process handle with broad rights (commonly
`PROCESS_ALL_ACCESS`, i.e. `0x1fffff`) to the *creating* process at
the moment of child-process creation**, specifically so the parent can
immediately manage the child it just spawned (wait for exit, get exit
code, terminate if needed, duplicate handles for I/O redirection).
This is universal, unavoidable OS behavior for any parent-child
process relationship where the parent retains any interest in the
child's lifecycle — which is the overwhelming majority of process
creation on Windows. `API_OPEN_PROCESS_VM_WRITE_001` currently has no
signal that distinguishes "I just created this child and Windows gave
me a management handle for free" from "I am reaching into an
unrelated, pre-existing process to write malicious code into it" —
the rule only inspects `granted_access` and a static source exclusion
list, neither of which can express this distinction.

### Provisional category (not committed — for fix-session discussion)

Not a Category A–D or C-series match. This looks like a new, more
fundamental design question about `API_OPEN_PROCESS_VM_WRITE_001`
specifically: **should this rule attempt to distinguish "OpenProcess
against a process I just spawned" (structurally benign, near-universal
noise) from "OpenProcess against a process I did not spawn"
(the actual injection signal)?** If the rule engine or telemetry
pipeline can correlate parent-child relationships (Sysmon EID-1
already carries `parent_process_id`/`parent_image`), a
"target is a child I recently created" exclusion could close this
entire noise class at the mechanism level, rather than needing an
ever-growing enumerated source list (which is what C4 already started
down, and which this finding shows is not scalable — C4 excluded 3
specific sources; this session alone surfaced 5 more entirely new
ones: `conhost.exe`, `cmd.exe`, `powershell.exe`, `csc.exe`,
generalized-to-any-shell-doing-anything).

### Possible fix directions (for future discussion, not decided)

1. **Parent-child correlation exclusion:** if the rule engine can
   check "was `target_image`'s process created by `source_image`'s
   process within the last N seconds" (via `parent_process_id`
   matching or a short-lived in-memory cache keyed by PID), suppress
   the rule. Highest-effort, most durable fix — closes the whole
   noise class structurally rather than by enumeration.
2. **Broaden the same-relationship heuristic:** less precise but
   simpler — extend the existing `not_same_basename` self-reference
   concept (C4 Subphase 1) to also check "is `target_image`'s parent
   process the same as `source_image`" using Sysmon's own
   `parent_image` field on the target's original ProcessCreate event,
   if accessible to the rule engine at OpenProcess-evaluation time.
   Needs investigation into whether this data is actually available
   at the point `_evaluate_condition` runs for an EID-10 event.
3. **Enumerate further known-benign source/target console-host and
   build-tool pairs**, same style as C4 Subphase 2 — lowest effort,
   but explicitly acknowledged as non-scalable per this finding (any
   future shell, IDE, or compiler toolchain reintroduces the same
   pattern under a new binary name).
4. **Do nothing, document as expected noise, rely on downstream ML
   layer (Isolation Forest / Random Forest) to deprioritize it** —
   worth discussing given Phase 6B/7B's fusion architecture is
   explicitly designed to combine rule + ML signals; a rule this noisy
   might be more appropriately treated as a weak signal fused with ML
   scoring rather than a standalone Critical-severity alert.

### Residual considerations

- This pattern will recur in **every future simulation session** that
  uses `Add-Type` with inline C# (which is the standard technique this
  project already relies on for P/Invoke-based simulations) — it is
  not a one-time artifact.
- Reusing a single compiled `Add-Type` class across multiple
  simulation steps within one PowerShell session (adopted ad hoc
  during this session, see Sim5c/Sim6c execution) avoids *repeating*
  the `csc.exe`/`cvtres.exe` cascade, but does not eliminate the
  initial occurrence, and does nothing for Sub-pattern A
  (`conhost`/`cmd` chain), which recurs on every new shell command
  regardless.
- Severity note: this rule is configured `Critical`. A structurally
  noisy Critical-severity rule has real operational cost in a
  deployed tool (alert fatigue) beyond just contaminating labeled
  training data — worth flagging for the fix session as a severity
  reconsideration question, not just a conditions question.

### Cross-references

- Structurally related to C4 (same rule, `API_OPEN_PROCESS_VM_WRITE_001`,
  same rule-design-gap category: broad detection surface, thin
  source-side scoping) but distinct sources/mechanism — not a C4
  regression, a new finding.
- Related in spirit to D45 (PPL) and D-d (mavinject) in that it's a
  case where the *rule's* observable signal doesn't map cleanly to
  attacker intent — but unlike those, this is fixable (it's a rule
  design gap, not an environmental/telemetry limitation).

---

## E2 — PowerShell process-management cmdlets incidentally trigger `API_OPEN_PROCESS_VM_WRITE_001`

**Discovered in:** Subphase 5 re-simulation session, 2026-08-08, during
Sim5c (`API_OPEN_PROCESS_VM_WRITE_001` re-test against `notepad.exe`).

### Trigger evidence (exact log lines)

```
[2026-08-08 21:10:23] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | target='C:\Windows\system32\notepad.exe' | access=0x1fffff
[2026-08-08 21:10:28] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | target='C:\Windows\system32\notepad.exe' | access=0x1038   <-- genuine Sim5c hit, confirmed separately
[2026-08-08 21:10:28] RULE_HIT | id=API_OPEN_PROCESS_VM_WRITE_001 | image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | target='C:\Windows\system32\notepad.exe' | access=0x1f3fff
```

The Sim5c script used was:
```powershell
$targetPid = (Get-Process notepad -ErrorAction SilentlyContinue).Id
if (-not $targetPid) { Start-Process notepad; Start-Sleep 2; $targetPid = (Get-Process notepad).Id }
$h = [ProcAccessSim1c]::OpenProcess(0x0038, $false, $targetPid)
if ($h -ne [IntPtr]::Zero) { [ProcAccessSim1c]::CloseHandle($h) }
Write-Host "Sim5c done, handle: $h"
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

Three separate `OpenProcess` calls against `notepad.exe` occurred
across this one script: `Start-Process notepad` (implicitly, via
`Get-Process`'s subsequent PID lookup and Windows' own process-handle
bookkeeping), the deliberate P/Invoke call (`access=0x1038`, the
genuine, correctly-attributed re-test result), and `Stop-Process
-Name notepad` (which requires `PROCESS_TERMINATE`-class broad access
to kill the target, observed here as `access=0x1f3fff`).

### Root cause analysis

PowerShell's built-in process-management cmdlets (`Get-Process`,
`Start-Process`, `Stop-Process`, and others in that family) are thin
wrappers around .NET's `System.Diagnostics.Process` class, which
internally calls `OpenProcess` with broad access rights
(`PROCESS_ALL_ACCESS` or a similarly broad superset) whenever it needs
to interact with a process object — this happens regardless of what
the *script author* actually intended to do with that handle. `Get-
Process notepad`, on the surface a read-only query, still triggers an
`OpenProcess` call under the hood as part of .NET's `Process` object
construction. `Stop-Process` similarly requires broad rights to issue
`TerminateProcess`.

### Why/where it occurs technically

Same underlying OS-level cause as E1 (broad-access handles are simply
how Windows process management works at the API level), but a
distinct **trigger surface**: E1 is about parent-child creation
handles; E2 is about **any interactive process-management action**
performed via .NET/PowerShell tooling, targeting a process the
*current* PowerShell session did not necessarily create at all
(`Get-Process notepad` would trigger this even if `notepad.exe` had
been started by someone else entirely, minutes earlier). This means
E2's noise surface is broader than E1's — a parent-child correlation
fix (Fix Direction 1 under E1) would NOT close this gap, since there
is no creation relationship between `powershell.exe` and a
pre-existing `notepad.exe` instance queried via `Get-Process`.

### Provisional category (not committed)

Related to, but mechanistically distinct from, E1 — needs its own
discussion in the fix session, likely as a sibling finding under the
same broader "`API_OPEN_PROCESS_VM_WRITE_001` has no source-intent
signal" architectural question, but requiring a different specific
fix (E1's parent-child correlation idea does not cover this case).

### Possible fix directions (for future discussion, not decided)

1. **Exclude `powershell.exe`/`pwsh.exe` as a source entirely** —
   simplest, but has an obvious, serious downside: PowerShell is
   simultaneously the single most common vector for genuine
   PowerShell-based injection techniques in real campaigns (see
   `phase7a_task.md`'s own PowerShell simulation templates, Emotet/
   QakBot/TrickBot family references). Blanket-excluding it would
   gut the rule's real detection value. **Committee should treat this
   option with strong skepticism going into the fix session** —
   flagging it here only because it is the "obvious" fix a less
   careful pass might reach for.
2. **Distinguish cmdlet-originated `OpenProcess` calls from direct
   P/Invoke calls** — likely not feasible; Sysmon's EID-10 telemetry
   does not expose "was this OpenProcess call made via a .NET cmdlet
   wrapper vs. raw P/Invoke," only the resulting `granted_access` and
   process identities. Needs confirmation this is truly unavailable
   before ruling it out.
3. **Accept as an unavoidable simulation-environment artifact,
   document clearly, and rely on precise `granted_access` value
   matching to separate genuine simulation hits from noise during
   manual verification** (the approach used ad hoc in this session —
   `0x1038` identified as genuine Sim5c, `0x1fffff`/`0x1f3fff`
   identified as cmdlet noise, by cross-referencing exact requested
   vs. granted values against what the deliberate P/Invoke call
   actually asked for). Lowest engineering cost, but pushes the
   burden onto every future simulation session's manual review rather
   than fixing the rule.
4. **Same as E1's Fix Direction 4** — treat as a case for ML-layer
   fusion rather than standalone rule severity, given how difficult
   this noise class appears to be to close cleanly at the rule-engine
   level.

### Residual considerations

- This will recur in **any future simulation or real deployment**
  where PowerShell-based process management cmdlets are used at all
  — which is extremely common, both in legitimate admin scripting and
  in this project's own simulation methodology.
- Confirms E1's severity concern is not a one-off: two independent
  noise mechanisms, discovered in the same single session, both
  targeting the same Critical-severity rule.

### Cross-references

- Same rule as E1 and C4 (`API_OPEN_PROCESS_VM_WRITE_001`) — three
  independent false-positive mechanisms now documented against this
  one rule across two sessions. Strongly suggests this rule warrants
  the deepest architectural discussion of any single rule in the
  Issue Catalog so far, going into the fix session.

---

## E3 — `phase7a_task.md` Subphase 6 templates cannot reach `API_CRT_SUSPICIOUS_SOURCE_001` as written

**Discovered in:** Subphase 6 pre-flight, before any simulation ran,
2026-08-08/09, while reviewing the live `API_CRT_SUSPICIOUS_SOURCE_001`
/ `API_CRT_SENSITIVE_TARGET_001` conditions against `phase7a_task.md`'s
original Subphase 6 templates.

**Process note:** this entry was identified verbally in-session and
its logging was verbally deferred, then never actually written back
into this file before work continued — caught and corrected only when
the project owner asked "where is E3?" after E4/E5 were added. Logged
here retroactively, matching what was originally found, as a
correction, not a fabrication after the fact. Flagged explicitly so
this doesn't read as if it were caught proactively by the committee's
own process when it wasn't — it was caught by the project owner
checking the tracking file's completeness.

### Trigger evidence

`phase7a_task.md`'s Subphase 6 templates use Atomic Red Team's
`RtlCreateUserThread.exe` as the sole injecting binary for all three
originally-documented rules
(`API_CREATE_REMOTE_THREAD_001`/`API_UNUSUAL_REMOTE_THREAD_TARGET_001`/
`API_MULTIPLE_REMOTE_THREADS_001` — themselves already superseded by
the Category A1 two-rule split, per handover.md Section 19.4). Live
YAML confirms `API_CRT_SUSPICIOUS_SOURCE_001`'s `source_image
ends_with_any` list is a fixed 30-entry allowlist (winword.exe,
excel.exe, powershell.exe, wscript.exe, mshta.exe, and 25 others — see
Category discussion transcript for full list). `RtlCreateUserThread.exe`
does not appear in that list under any of its invocation paths.

### Root cause analysis

`API_CRT_SUSPICIOUS_SOURCE_001` is source-identity-driven by design —
it fires when the *source process itself* is one of a specific set of
processes with no legitimate injection use case, regardless of target.
Atomic Red Team's compiled test harness is a generic, separately-named
injection utility, not a listed suspicious source. Running the
standard Atomic Red Team template produces EID-8 telemetry with
`source_image = RtlCreateUserThread.exe`, which structurally cannot
satisfy this rule's `ends_with_any` condition regardless of target,
access rights, or anything else in the event.

### Why/where it occurs

Documentation/simulation-template drift, same broad pattern already
seen in every other subphase of this project (D1–D44 and counting) —
`phase7a_task.md` was written against an earlier rule set
(pre-Category-A two-rule split) and was never updated to reflect that
`API_CRT_SUSPICIOUS_SOURCE_001` requires the *source* itself to be
listed, which a generic external test tool can never satisfy by
construction.

### Provisional category

Documentation/simulation-template drift — same family as the
Category F backlog (D1–D21, D31–D39, D44), not a rule or engine
defect. No fix needed to the rule; the simulation approach needed to
change instead (and did — see Resolution below).

### Fix directions / Resolution

Not deferred — already resolved in-session, before any simulation
ran, by designing a two-track simulation approach instead of patching
the rule or the original template:
1. `API_CRT_SENSITIVE_TARGET_001` — original Atomic Red Team-style
   approach retained in spirit, retargeted at `lsass.exe` (a rule this
   *can* actually satisfy, since it's target-driven, not
   source-allowlist-driven).
2. `API_CRT_SUSPICIOUS_SOURCE_001` — required a genuinely different
   simulation technique: a direct P/Invoke injection sequence
   performed by `powershell.exe` itself (which *is* on the allowlist),
   rather than shelling out to an external tool. This is what the v2
   script's `Invoke-CrtInjection` function implements.

No YAML or engine change was needed or considered — this was purely a
simulation-methodology fix, decided and implemented before E4/E5 were
even encountered.

### Residual considerations

Reinforces the standing project lesson (repeated at every subphase so
far): **live YAML must be audited before designing simulations, never
assumed from `phase7a_task.md`'s text** — this is now true for
Subphase 6 as much as it was for Subphases 1–4.

### Cross-references

Same documentation-drift family as D1–D44. Directly precedes and
motivates the technique choices that led to E4 (Defender blocking the
Atomic Red Team binary) and E5 (Sysmon's `kernel32.dll` exclusion
affecting the P/Invoke workaround) — E3, E4, and E5 form one causal
chain: template mismatch (E3) → forced a technique change → new
technique choice hit two further environmental obstacles (E4, E5) in
sequence.

---

## E4 — Atomic Red Team `RtlCreateUserThread.exe` blocked pre-execution by Windows Defender

**Discovered in:** Subphase 6, first simulation attempt, 2026-08-08/09.

### Trigger evidence

```
Program 'RtlCreateUserThread.exe' failed to run: Operation did not
complete successfully because the file contains a virus or potentially
unwanted software
```
`Get-MpThreatDetection` for the surrounding window returned no entries
— confirming this was a real-time execution-prevention block (Defender
"Potentially Unwanted Application"-class heuristic, or SmartScreen),
not a logged malware detection.

### Root cause analysis

Atomic Red Team's compiled T1055 test binaries are, by design,
literal implementations of process-injection techniques. Signature/
heuristic AV engines routinely flag such binaries as PUA (Potentially
Unwanted Application) or via generic injection-pattern heuristics,
independent of any wrapping script or invocation context — this is
expected, well-documented industry behavior for this class of test
tooling, not specific to this project or VM.

### Why/where it occurs

Pre-execution block, at the OS/AV layer, before the process is even
created — meaning no Sysmon telemetry (EID-1 or otherwise) was ever
possible for this invocation. Structurally identical in kind to D7
(Defender blocking `PS_AMSI_BYPASS_001`/`PS_CREDENTIAL_ACCESS_001`
trigger commands in Subphase 1), just a compiled-binary block instead
of a command-line-signature block.

### Provisional category

**PARTIAL, consistent with D7 precedent.** Not a rule, engine, or
YAML issue — the technique is validly designed, Defender intervened
first in this specific test environment.

### Fix directions

Not a "fix" in the rule sense. Practical workaround adopted
immediately: replaced the Atomic Red Team binary with a direct P/Invoke
`CreateRemoteThread` sequence (same technique already used
successfully for `API_CRT_SUSPICIOUS_SOURCE_001`'s simulation),
retargeted at `lsass.exe` for `API_CRT_SENSITIVE_TARGET_001`. This
avoided the flagged binary entirely and did not trip Defender.

### Residual considerations

Confirms Atomic Red Team test binaries cannot be relied upon as a
simulation method on this VM going forward without a Defender
exclusion being deliberately configured for the `AtomicRedTeam`
directory — not done in this session, left as a standing constraint
for any future Atomic Red Team-based simulation work.

### Cross-references

Same classification family as D7. Directly resolved by switching to
the technique that also produced E5 (below).

---

## E5 — Sysmon config excludes `CreateRemoteThread` events with `StartModule=kernel32.dll`, making the LoadLibrary-injection technique invisible

**Discovered in:** Subphase 6, second simulation attempt (v2 script,
direct P/Invoke technique used for both parts), 2026-08-10. Both
`API_CRT_SENSITIVE_TARGET_001` and `API_CRT_SUSPICIOUS_SOURCE_001`
produced zero rule hits despite the injection sequence completing
without any reported P/Invoke error.

### Trigger evidence

- Pipeline output across the full simulation window: zero
  `API_CRT_SENSITIVE_TARGET_001` or `API_CRT_SUSPICIOUS_SOURCE_001`
  hits, and — critically — zero EID-8 rule-family activity of any kind.
- Direct DB query, `event_type_id = 8`, window covering the entire
  simulation run: **zero rows returned.**
- Direct raw Sysmon query (`Get-WinEvent ... Where Id -eq 8`, 100 most
  recent events): **zero EID-8 events found**, confirming the gap is
  not a pipeline/collector/normalizer/storage defect — the event was
  never written to the Windows Event Log by Sysmon itself.
- Direct read of `C:\sysmon\sysmonconfig-export.xml`, lines 331–344:

```xml
<RuleGroup name="" groupRelation="or">
    <CreateRemoteThread onmatch="exclude">
        <!--COMMENT: Exclude mostly-safe sources and log anything else.-->
        <SourceImage condition="is">C:\Windows\system32\wbem\WmiPrvSE.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\wininit.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\csrss.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\services.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\winlogon.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\audiodg.exe</SourceImage>
        <StartModule condition="is">C:\Windows\system32\kernel32.dll</StartModule>
        <TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
    </CreateRemoteThread>
</RuleGroup>
```

### Root cause analysis

Line 341's `<StartModule condition="is">C:\Windows\system32\kernel32.dll</StartModule>`
is an unconditional exclusion, independent of `SourceImage` or
`TargetImage` — **any** `CreateRemoteThread` event whose thread start
address resolves inside `kernel32.dll` is dropped by Sysmon before
being written to the event log at all, regardless of who the source
or target process is. Our simulation script's injection technique
(`CreateRemoteThread` starting at `LoadLibraryA`, resolved via
`GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")`) has
its `StartModule` set to exactly `kernel32.dll` — the classic
"reflective/LoadLibrary injection" pattern — so every invocation of
our technique was filtered at the source, before Sysmon, before the
collector, before the rule engine ever had a chance to evaluate
anything.

### Why/where it occurs

This is a deliberate, explicitly-commented design decision in the
SwiftOnSecurity-derived config this project's Sysmon deployment is
built from ("Exclude mostly-safe sources and log anything else"), not
a misconfiguration or accidental gap. `LoadLibrary`-based
`CreateRemoteThread` injection is extremely common in legitimate
software (accessibility tooling, some security products, .NET runtime
hosting, browser internals) — logging every instance system-wide would
produce very high noise volume. The exclusion is a deliberate
noise-reduction tradeoff made by the config's original author, not a
defect.

### Is this a rule defect? — No, confirmed by evidence, not inference

Both `API_CRT_SUSPICIOUS_SOURCE_001` and `API_CRT_SENSITIVE_TARGET_001`
are event-driven off EID-8. With zero EID-8 events reaching the
pipeline (confirmed at both the DB layer and the raw Sysmon layer),
neither rule had any event to evaluate. This rules out a YAML
condition, `rules/engine.py` evaluation, or normalizer defect as the
cause — the gap is entirely upstream, at the Sysmon
capture/exclusion-filter layer, before any ShadowSensor component
runs at all.

### Fix directions

**Two independent fix paths exist, deliberately NOT actioned in this
session — both deferred to after Phase 7A completes, per explicit
project-owner decision:**

1. **Sysmon config change (structural fix):** remove or narrow the
   `<StartModule condition="is">...kernel32.dll</StartModule>`
   exclusion in `sysmonconfig-export.xml`, then reload the Sysmon
   config (`sysmon64 -c <path>` or service restart). This would make
   the LoadLibrary-injection pattern observable system-wide going
   forward, not just for deliberate simulation.
   - **Cost, explicitly weighed before deferring:** this is a
     system-wide, always-on change — once removed, every
     `kernel32`-start `CreateRemoteThread` on the entire VM (including
     ongoing legitimate software activity, not just deliberate
     simulations) starts generating EID-8 telemetry into the pipeline
     permanently, increasing noise and DB load well beyond the scope
     of this one simulation need.
   - **Explicit precedent for deferral:** identical reasoning already
     established for D28 (Sysmon EID-3 port-filter gap) — a Sysmon
     config change affects the whole telemetry pipeline and should be
     a deliberate, reviewed change, not made ad hoc mid-validation.
     **Recommendation: bundle this fix with D28 as a single future
     "Sysmon config revision" task**, since both are the same class of
     decision (loosen a deliberate noise-reduction exclusion to gain
     detection coverage) and reviewing them together, holistically,
     against the full noise-vs-coverage tradeoff is better than two
     separate, uncoordinated config edits.
2. **Simulation-technique workaround (used to unblock Subphase 6
   immediately):** resolve `LoadLibraryA`'s address via a different,
   still non-excluded module already loaded in every process (e.g.
   `ntdll.dll`, not present in the exclusion list) instead of
   `kernel32.dll`. Same harmless LoadLibrary technique, same safety
   profile — the `StartModule` field simply resolves to a different,
   non-excluded DLL, avoiding the specific exclusion without touching
   any config. This is a script-side change only.

### Residual considerations — real, not hypothetical, detection gap

This is not merely a simulation inconvenience — it is a genuine,
confirmed detection blind spot in the deployed tool as currently
configured. **Any real attacker using `LoadLibrary`-based reflective
injection (an extremely common, well-documented technique family) is
currently invisible to this Sysmon deployment**, independent of
whether `API_CRT_SUSPICIOUS_SOURCE_001` or
`API_CRT_SENSITIVE_TARGET_001` would otherwise have caught it — the
event never reaches Sysmon's log at all, regardless of source or
target. This is a materially significant finding for the research
paper's Section 2 (Telemetry Design), likely warranting its own
explicit callout alongside D-a through D-g, not just a footnote to E5.
Until the config-layer fix is applied (post-Phase-7A per the decision
above), Subphase 6 and all future EID-8-dependent simulation work must
avoid `kernel32.dll`-resolved `LoadLibrary` starts and use
`ntdll.dll` (or another non-excluded module) instead.

### Cross-references

Same class of decision as D28 (config-layer detection gap, fix
available but deliberately deferred to a dedicated future task, not
mid-validation). Resolves the technique-selection problem that
produced E4 (Atomic Red Team binary blocked) by using the same direct
P/Invoke method — meaning E4 and E5 together fully explain why the
original Subphase 6 template (Atomic Red Team binary, implicitly
`kernel32`-resolved) could never have worked cleanly on this VM
without modification, independent of any rule-engine issue.

---

## E6 — E5 workaround patch used `LoadLibraryA`, which does not exist in `ntdll.dll`

**Discovered in:** Subphase 6, third simulation attempt, 2026-08-10,
immediately after applying the E5 workaround patch
(`GetModuleHandle("kernel32.dll")` → `GetModuleHandle("ntdll.dll")`).

**Nature of this entry, stated plainly:** unlike E1–E5, this is not an
environmental or telemetry-layer finding — it is a straightforward
authoring mistake in the workaround patch itself. Logged in full per
the project owner's standing instruction to log every issue
encountered, and to keep the audit trail complete and honest, not
because it carries independent research value the way E1–E5 do.

### Trigger evidence

```
=== Part 1: API_CRT_SENSITIVE_TARGET_001 (direct injection -> lsass.exe) ===
ERROR (Part 1): GetProcAddress(LoadLibraryA) failed.
=== Part 2: API_CRT_SUSPICIOUS_SOURCE_001 (direct injection -> notepad.exe) ===
notepad.exe found after 1 second(s), PID: 9440
ERROR (Part 2): GetProcAddress(LoadLibraryA) failed.
```

Pipeline output for this run showed only the already-documented E1/E2
noise pattern (compiler cascade, `OpenProcess` cmdlet noise) — no new
EID-8 telemetry, confirming `CreateRemoteThread` was never reached in
either part; the script errored out one step earlier, at
`GetProcAddress`.

### Root cause analysis

The E5 workaround changed which DLL `GetModuleHandle` resolved
(`kernel32.dll` → `ntdll.dll`) so that the eventual `CreateRemoteThread`
start address would land outside Sysmon's excluded `StartModule`. But
the function being resolved via `GetProcAddress` was left unchanged as
`"LoadLibraryA"` — which is a `kernel32.dll` export, not an
`ntdll.dll` export. `GetProcAddress(hNtdll, "LoadLibraryA")`
correctly returned `IntPtr.Zero`, since no such export exists in that
module, and the script's own error handling correctly caught this and
stopped cleanly rather than proceeding with a null address.

### Why/where it occurs

Direct authoring error: the module and the target function must both
be validated as belonging to the same DLL for `GetProcAddress` to
succeed. The E5 patch changed one half of that pair (the module) but
not the other (the function name), producing a mismatched
module/function combination.

### Fix

Use `RtlExitUserThread` (an `ntdll.dll` export, no arguments required
beyond a single exit-code parameter, which can safely be `0`) as the
`CreateRemoteThread` start address instead of `LoadLibraryA`. This
resolves both problems at once:
- `RtlExitUserThread` genuinely exists in `ntdll.dll`, unlike
  `LoadLibraryA` — fixes the immediate `GetProcAddress` failure.
- It requires no DLL-path parameter, so `VirtualAllocEx` and
  `WriteProcessMemory` (previously used to write the `kernel32.dll`
  path string into target memory) are no longer needed at all —
  simplifies the injection function while remaining fully benign: the
  created remote thread starts and immediately terminates itself via
  `RtlExitUserThread`, executing no attacker logic of any kind.

### Residual considerations

None beyond the immediate fix — this does not represent an ongoing
limitation or gap, just a corrected implementation detail.

### Cross-references

Directly downstream of E5 (the workaround this patch was attempting
to implement). Once corrected, should finally allow both
`API_CRT_SENSITIVE_TARGET_001` and `API_CRT_SUSPICIOUS_SOURCE_001` to
receive genuine EID-8 telemetry.

---

## Open Questions Carried Into the Fix Session

1. Does `rules/engine.py`'s event-evaluation path have access to
   parent-process-relationship data at OpenProcess (EID-10)
   evaluation time, sufficient to implement E1's Fix Direction 1?
   Needs a read-only Cursor investigation before this can be
   discussed meaningfully.
2. Should `API_OPEN_PROCESS_VM_WRITE_001`'s severity be reconsidered
   (from Critical to something lower) given its now-demonstrated high
   noise surface, independent of whatever conditions-level fix is
   chosen?
3. Should `API_OPEN_PROCESS_VM_WRITE_001`'s eventual fix be designed
   as a rule-engine capability addition (e.g. a new
   parent-child-relationship-aware operator) rather than another
   YAML-only conditions patch, given two YAML-only passes (D49, C4)
   have already proven insufficient to close this rule's noise
   surface?
4. **Decision already made, carried here for tracking:** the
   `sysmonconfig-export.xml` `CreateRemoteThread` `kernel32.dll`
   `StartModule` exclusion (E5) will NOT be fixed as part of the
   Phase 7A simulation fix session. It is explicitly deferred to a
   dedicated post-Phase-7A Sysmon config revision task, bundled
   together with D28 (EID-3 port-filter gap) as a single holistic
   noise-vs-coverage review — not two separate uncoordinated config
   edits. This must not be silently dropped; carry forward into
   `status.md` Known Blockers and `handover.md` once this session's
   subphase work closes.

---

*This file is a working document, updated as Subphase 5–7 simulation
proceeds. Not yet a permanent project artifact — will be formally
referenced from `docs/decisions_log.md` once the corresponding fix
session closes, following the same pattern as C4's Entry 013.*
