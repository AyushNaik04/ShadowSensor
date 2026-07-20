# Phase 5 — Confirmed Schema Reference (supersedes task.md's Event/RuleHit
# column assumptions)

## event_type_id mapping (confirmed via storage/storage_writer.py)
event_type_id values ARE the raw Sysmon EIDs directly:
1 = ProcessCreate, 3 = NetworkConnect, 7 = ImageLoad,
8 = CreateRemoteThread, 10 = OpenProcess, 22 = DnsQuery

## EventRecord flat columns (top-level, not in raw_json)
id, event_type_id, timestamp, pid, image, raw_json, ingested_at
-> pid and image ARE available as flat columns for process-window grouping;
   no JSON parsing needed for grouping logic.

## raw_json keys per event type (snake_case, confirmed from live DB / fixtures)

EID 1 (ProcessCreate): command_line, image, parent_image,
  parent_command_line, process_guid, process_id, parent_process_id
  NOTE: no "signed" key exists at EID 1. is_signed (feature #5) must
  default to 0 for all EID-1 rows — this is a genuine schema gap, not a
  naming difference. Do not attempt to derive signed status at EID 1.

EID 3 (NetworkConnect): destination_ip, destination_port, process_id, image

EID 7 (ImageLoad): signed (boolean), process_id, image
  This is the ONLY event type where "signed" is actually present.

EID 8 (CreateRemoteThread): source_process_id, source_image,
  target_process_id, target_image
  NOTE: target_image may literally contain the string "<unknown process>"
  in some rows (known Sysmon-upstream identity-resolution limitation,
  already logged as Issues 2/6 in status.md, environmentally limited).

EID 10 (OpenProcess): source_process_id, source_image, target_process_id,
  target_image, granted_access
  NOTE: task.md's spec referred to this field as "access_mask" — the real
  key is "granted_access". Use granted_access everywhere.

EID 22 (DnsQuery): query_name, process_id, image

## RuleHit join (replaces task.md's timestamp-window matching)
RuleHitRecord.event_fk is a direct foreign key to events.id
(ForeignKey("events.id", ondelete="SET NULL")). No SQLAlchemy relationship()
is defined — join via raw column: rule_hits.event_fk = events.id.
Use this direct join in place of the image+pid+timestamp-range matching
described in task.md Subphase 3/4 — it is strictly more reliable.

## Field-name variance to handle in the extractor
process_id key name differs by event type:
  - EID 1, 3, 7, 22 use: process_id
  - EID 8, 10 use: source_process_id (as the acting/source process) and
    target_process_id (as the target)
The extractor must branch per-EID on this, not assume one constant key name.

## RuleHit prefix-matching and aggregation ground truth (confirmed pre-Subphase-3)
- Prefix checks and unique_rules_fired key off RuleHitRecord.rule_id,
  not rule_name. rule_name is a human-readable label; rule_id carries
  the actual identifier (e.g. "PS_ENCODED_CMD_001", "LOLBIN_MSHTA_001").
- The LOLBin rule ID prefix is "LOLBIN_", not "LOL_" as task.md stated.
  Confirmed against live rule definitions.
- rule_id may be None on some rows; all rule_id-based logic must guard
  against this.
- "First-event" feature merging in the aggregator is EID-scoped (each
  first-event feature is resolved from the first event_vector tuple
  whose event_type_id matches that feature's declared source_eids in
  FEATURE_REGISTRY), not resolved by "first non-default value" as
  task.md originally described — that approach was ambiguous because
  several features' defaults are also legitimate computed values
  (e.g. is_off_hours=0 during business hours).
- event_vectors is passed to the aggregator as a list of
  (event_type_id, vector_dict) tuples, not bare dicts, to support
  EID-scoped resolution.

## Subphase 4 pipeline ground truth (confirmed pre-implementation)
- scripts/run_feature_extraction.py imports DB_PATH from
  storage.database rather than hardcoding a path string, to guarantee
  it can never drift from the SHADOWSENSOR_DB_DIR / local-NTFS
  convention established in Phase 3.
- rule_hits are matched to process windows via event_fk (direct FK
  lookup against an event_id-to-window map), not timestamp-range
  matching as task.md originally specified — event_fk is confirmed to
  exist and be reliable for this purpose.
- events and rule_hits queries both use ORDER BY timestamp ASC; this
  ordering is required for ProcessWindowAggregator's EID-scoped
  first-event resolution to work correctly.
- (image, pid) grouping with no ProcessGuid-based disambiguation is a
  confirmed, accepted, pre-existing limitation inherited from Phase 4B
  (Issues 2/6, environmentally limited; Issue 4, open/inconclusive),
  not a new gap introduced in Phase 5.
