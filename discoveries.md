## Discoveries Log

### Subphase 0
- **Finding:** the normalizer has no separate PID→Image or PID→ProcessGuid lookup or cache resolver function — the parser maps Sysmon XML fields directly by name via `FIELD_MAPS` in `_extract_data_fields()` and assigns them in `_build_event()`. For EID 22 specifically, the mapping includes `process_id` and `image` but not `process_guid`.
- **Why it is worth noting:** This directly affects the Subphase 4 normalizer diagnosis and must anchor root-cause analysis assumptions before any normalizer fix is proposed.

### Subphase 1
- **Finding:** Full-suite regression initially failed during collection because `lark` was missing in this environment (`ModuleNotFoundError` in KQL parser/import paths); after installing `lark`, regression completed cleanly. Also, deliberate live-fire AV-access validation remains constrained by Defender PPL, so true-positive confirmation for `API_AV_PROCESS_ACCESS_001` is verified via synthetic rule-engine events.
- **Why it is worth noting:** Environment package drift can invalidate regression gates unrelated to rule logic, and PPL constraints will continue to shape validation strategy for AV process-access detections in later subphases.

### Subphase 2
- **Finding:** `NET_DNS_LONG_QUERY_001`'s length condition is implemented as `.{50,}` (50 and above), not strictly greater than 50, so edge-case validation must preserve 50-character matching while applying source exclusions like `SearchApp.exe`.
- **Why it is worth noting:** Future tuning of long-query DNS detections (or cross-rule threshold harmonization) must account for this exact boundary semantics to avoid accidental behavior changes or false regression conclusions.

### Subphase 3
- **Finding:** The current rule DSL only supports flat `AND`/`OR` condition lists (no nested condition groups), so implementing "match `svchost.exe` only when `-s Schedule` is present" safely required an additional `parent_command_line` gating condition that also whitelists scheduler-identifying command-line markers for the legacy `taskeng.exe`/`taskhostw.exe`/`schtasks.exe` parent paths.
- **Why it is worth noting:** Future detections that need parent-image-specific qualifiers (scoped exceptions or service-host narrowing) must account for this flat-logic constraint early, otherwise seemingly simple YAML edits can unintentionally suppress legacy true-positive paths.
- **Finding (correction):** For OR-branched parent logic in this flat DSL, the robust pattern is a **two-rule split** rather than a single merged parent condition block: keep legacy parent-image paths in one rule unchanged, and create a sibling rule for the constrained branch (`svchost.exe` + `-s Schedule`) with identical child-side conditions/metadata.
- **Why it is worth noting:** This avoids cross-branch coupling side effects (for example introducing parent-command-line requirements that unintentionally alter legacy branches) and should be treated as the default design pattern whenever one parent branch needs extra qualifiers that others do not.

### Subphase 4
- **Finding:** Issues 2 (EID 8) and 6 (EID 22) do share a common mechanism: `normalizer/parser.py` extracts event fields exclusively via `FIELD_MAPS` in `_extract_data_fields()` and then assigns those values directly in `_build_event()` with no PID resolver, process-table lookup, or cache layer. For EID 8, `target_image` is mapped from Sysmon `TargetImage` and passed through unchanged; for EID 22, `image` is mapped from Sysmon `Image` and passed through unchanged. `ProcessGuid` for EID 22 is not represented at all because `DNS_QUERY_FIELDS` omits it and `DnsQueryEvent` has no `process_guid` attribute.
- **Why it is worth noting:** This confirms the root cause is schema/path design rather than a lookup race or stale cache. The parser cannot repair `<unknown process>` values and cannot surface DNS `ProcessGuid` even when present in raw XML, which directly explains why EID 22 process identity is unusable and why EID 8 target identity quality is entirely dependent on raw Sysmon field quality.

### Subphase 5
- **Finding:** The enrichment-layer remediation path for Issues 2 and 6 was evaluated and explicitly rejected. While technically feasible, it introduces unacceptable false-positive risk through behavioral drift and PID reuse misattribution, which cannot be made provably false-positive-free under the project's true-positive-only rule engine constraint.
- **Why it is worth noting:** The correct treatment is classification as an environmental telemetry limitation (upstream Sysmon XML identity failure), with documentation ownership in the research paper's Section 2 (Telemetry Design), not a normalizer behavior change.

### Subphase 6
- **Finding:** The final gate closure run holds stable at 49 loaded rules and 412 total tests (baseline 399 + 13 fix-pass additions), and the five issue-specific true-positive paths all pass together in one consolidated session without cross-rule interference. In this host environment, `run_pipeline.py` reaches successful rule loading but cannot maintain a live collector session because the Sysmon operational channel is absent (`EvtQuery` channel-not-found), so baseline/no-FP confirmation is validated through the expanded synthetic negative-path regression corpus.
- **Why it is worth noting:** This cleanly separates rule-engine correctness from environment telemetry prerequisites: gate evidence for rule behavior is now complete and reproducible in tests, while live collection health remains dependent on running inside a Sysmon-enabled VM/session context.
