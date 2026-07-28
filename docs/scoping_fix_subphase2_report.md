# Scoping Fix — Sub-Phase 2 Completion Report

**Date/time executed:** 2026-07-27 16:37 +0530  
**Sub-phase goal (restated):** Produce an exact, reviewable implementation plan (read-only) before touching any product code — quote current query/CLI construction, confirm stored timestamp format from a real row, and propose the precise additive `--since`/`--until` design and file-by-file diff.

## What Was Done

1. Re-read `ml/features/pipeline.py` and `scripts/run_feature_extraction.py` in full; quoted the current query and argparse blocks verbatim with line numbers.
2. Queried a real `events.timestamp` row from host `C:\ShadowSensor\data\shadowsensor.db` to confirm the stored format (not assumed).
3. Drafted the exact proposed design: CLI args, validation, pipeline signature, inclusive SQL threading, `ORDER BY` preservation, and file-by-file diffs for Sub-Phase 3.
4. Wrote `docs/vm_clock_drift_finding.md` **now** (documentation-only; no clock fix) so it is not dropped later.
5. **No implementation code was written** in `ml/`, `scripts/`, or `tests/`.

## Evidence

### Step 2.1 — Current `events` query (`ml/features/pipeline.py`)

```34:40:ml/features/pipeline.py
                event_rows = conn.execute(
                    """
                    SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at
                    FROM events
                    ORDER BY timestamp ASC
                    """
                ).fetchall()
```

- **No `WHERE` clause on `timestamp`** (or any other column).
- **`ORDER BY timestamp ASC` is present** and must be preserved.

### Step 2.1 — Current `rule_hits` query (`ml/features/pipeline.py`)

```61:67:ml/features/pipeline.py
                rule_hit_rows = conn.execute(
                    """
                    SELECT id, event_fk, rule_id, timestamp
                    FROM rule_hits
                    ORDER BY timestamp ASC
                    """
                ).fetchall()
```

- **No `WHERE` clause on `timestamp`**.
- **`ORDER BY timestamp ASC` is present** and must be preserved (required for EID-scoped first-event resolution per `docs/phase5_schema_reference.md`).

### Step 2.1 — Current `run()` signature

```21:21:ml/features/pipeline.py
    def run(self, label: int | None = None) -> list[dict]:
```

No `time_from` / `time_to` (or equivalent) parameters today.

### Step 2.2 — Current CLI argument parsing (`scripts/run_feature_extraction.py`)

```20:45:scripts/run_feature_extraction.py
def main() -> int:
    parser = argparse.ArgumentParser(description="Extract process-window features from SQLite.")
    parser.add_argument("--label", type=int, default=None, help="Optional label to append to every row.")
    parser.add_argument(
        "--output",
        type=str,
        default=str(default_output_path()),
        help="Output CSV path.",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=str(DB_PATH),
        help="SQLite database path.",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    output_path = Path(args.output)

    print(f"[INFO] Reading from: {db_path}")
    if str(db_path) != ":memory:" and not db_path.exists():
        print(f"[WARN] Database not found: {db_path} — no events to extract")
        vectors: list[dict] = []
    else:
        vectors = FeatureExtractionPipeline(db_path).run(label=args.label)
```

Flow today: `--label` → `pipeline.run(label=...)`; `--output` → `export_to_csv`; `--db` → `FeatureExtractionPipeline(db_path)`. No time args.

### Step 2.3 — Real stored `events.timestamp` format (queried, not assumed)

```
=== earliest
(1, '2026-07-27 07:44:11.805780')
(2, '2026-07-27 07:58:35.632114')
(3, '2026-07-27 07:58:35.632205')
=== latest
(29687, '2026-07-27 08:04:33.863806')
...
=== typeof
('text', 26, '2026-07-27 07:44:11.805780')
```

**Confirmed format:** SQLite `TEXT`, pattern `YYYY-MM-DD HH:MM:SS.ffffff` (space separator, **microseconds present**, length 26 on sampled rows). Not ISO-8601 `T`-separator in storage.

---

## Proposed Design (for approval — not yet implemented)

### Locked decisions (not re-opened)

1. Inclusive both ends: `timestamp >= since AND timestamp <= until`.
2. No default lookback: omitting both `--since` and `--until` preserves exact current all-time SQL and behavior.
3. Additive only: no `FEATURE_REGISTRY` / aggregator / `run_pipeline.py` / `storage_writer.py` changes.

### CLI arguments

| Arg | Type | Required | Default |
|---|---|---|---|
| `--since` | string | no | omitted → no lower bound |
| `--until` | string | no | omitted → no upper bound |

**Accepted input forms** (parsed then normalized before any DB work):

- `YYYY-MM-DD HH:MM:SS`
- `YYYY-MM-DD HH:MM:SS.ffffff` (1–6 fractional digits allowed on input)
- ISO-8601 with `T`: `YYYY-MM-DDTHH:MM:SS[.ffffff]`

**Normalization before bind** (required because storage uses space + microseconds and SQLite compares TEXT lexicographically):

1. Accept `T` or space; **normalize separator to space** so bind values are lexicographically comparable to stored rows (`T` would sort incorrectly vs space).
2. Parse with `datetime.strptime` / equivalent; on failure → validation error (below).
3. **`--since` without fractional seconds:** bind as `YYYY-MM-DD HH:MM:SS` (lexicographic `>=` still includes `….ffffff` rows in that second).
4. **`--until` without fractional seconds:** bind as `YYYY-MM-DD HH:MM:SS.999999` so every stored event **within that whole second** remains included under inclusive `<=` (otherwise `…03:07:19.123456` would incorrectly sort **after** bare `…03:07:19` and be excluded).
5. If the user supplies fractional seconds on either bound, bind the normalized `YYYY-MM-DD HH:MM:SS.ffffff` form as given (zero-padded/truncated to microseconds as parsed).

This preserves the mandated SQL shape `timestamp >= ?` / `timestamp <= ?` while making second-precision session markers (e.g. log `03:07:19`) actually inclusive against microsecond-stamped rows.

### Validation / malformed input

- Validate in the CLI **after** argparse, **before** `FeatureExtractionPipeline(...).run(...)` and before any “Reading from” work that implies a successful scoped run path for bad bounds.
- Helper (proposed location: `ml/features/pipeline.py` as module-level `parse_time_bound(raw: str, *, bound_name: str) -> str`, also importable by tests) raises `ValueError` with a clear message, e.g.:
  - `Invalid --since value 'not-a-date': expected YYYY-MM-DD HH:MM:SS[.ffffff] or YYYY-MM-DDTHH:MM:SS[.ffffff]`
  - same pattern for `--until`
- CLI behavior: catch `ValueError`, print to **stderr** as `[ERROR] <message>`, return exit code **2** (or **1** — propose **2** to distinguish from generic failure; open to **1** if preferred). **No SQL executed** on malformed input.
- If both provided and normalized `since > until`: also reject before query with  
  `[ERROR] --since (...) is after --until (...)`  
  (same exit code). Optional but recommended; state as part of this design: **yes, include this check**.

### `FeatureExtractionPipeline` signature change

```python
def run(
    self,
    label: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
) -> list[dict]:
```

- `time_from` / `time_to` are **already-normalized** bind strings, or `None`.
- When **both are `None`**: execute today’s exact SQL (no `WHERE`) — zero behavioral change.
- Pipeline does not re-parse CLI strings when called from CLI (CLI passes normalized values). Tests may pass normalized literals directly.
- Optional defense: if a caller passes a clearly empty string, treat as error or as None — propose: empty string → `ValueError` if somehow passed; CLI only passes `None` or normalized non-empty strings.

### SQL threading (inclusive, `ORDER BY` preserved)

Build `WHERE` / params dynamically; **always** keep `ORDER BY timestamp ASC` last.

**Events — neither bound (unchanged):**
```sql
SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at
FROM events
ORDER BY timestamp ASC
```

**Events — only `time_from`:**
```sql
SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at
FROM events
WHERE timestamp >= ?
ORDER BY timestamp ASC
```
params: `(time_from,)`

**Events — only `time_to`:**
```sql
SELECT ... FROM events
WHERE timestamp <= ?
ORDER BY timestamp ASC
```
params: `(time_to,)`

**Events — both:**
```sql
SELECT ... FROM events
WHERE timestamp >= ? AND timestamp <= ?
ORDER BY timestamp ASC
```
params: `(time_from, time_to)`

**Rule hits — identical `WHERE` / param pattern** on:

```sql
SELECT id, event_fk, rule_id, timestamp
FROM rule_hits
[WHERE ...]
ORDER BY timestamp ASC
```

Both queries must use the **same** `time_from` / `time_to` values so `event_fk` joining stays consistent within the scoped event set (hits whose `event_fk` is outside the loaded events continue to be skipped by the existing map lookup — unchanged).

### CLI wiring

```python
# after parse_args, before pipeline.run:
time_from = parse_time_bound(args.since, bound_name="--since") if args.since else None
time_to = parse_time_bound(args.until, bound_name="--until") if args.until else None
# if both: enforce time_from <= time_to after normalization
vectors = FeatureExtractionPipeline(db_path).run(
    label=args.label,
    time_from=time_from,
    time_to=time_to,
)
```

### Files in scope for Sub-Phase 3 implementation

| File | Change |
|---|---|
| `ml/features/pipeline.py` | Add `parse_time_bound`; extend `run(...)`; conditional `WHERE` on both queries |
| `scripts/run_feature_extraction.py` | Add `--since` / `--until`; validate; pass `time_from`/`time_to` |

**Explicitly unchanged in Sub-Phase 3:** `ml/features/exporter.py`, `ml/features/feature_spec.py`, `collector/`, `normalizer/`, `rules/`, `scripts/run_pipeline.py`, `storage/storage_writer.py`.

**Tests:** new coverage is **Sub-Phase 4** (not applied in Sub-Phase 3). Design intent for SP4: extend `tests/test_phase5/test_pipeline.py` (and/or adjacent file) for since-only / until-only / both / neither / inclusive boundaries / malformed CLI — details deferred to SP4 after this design is approved.

### Exact proposed diffs (Sub-Phase 3)

#### `ml/features/pipeline.py`

```diff
--- a/ml/features/pipeline.py
+++ b/ml/features/pipeline.py
@@ -1,8 +1,10 @@
 """Phase 5 process-window feature extraction pipeline."""
 
 from __future__ import annotations
 
 import sqlite3
+from datetime import datetime
 from pathlib import Path
 
 from ml.features.aggregator import ProcessWindowAggregator
 from ml.features.extractor import EventFeatureExtractor
 
 
 WindowKey = tuple[str | None, int | str]
+
+
+_BOUND_FORMATS = (
+    "%Y-%m-%d %H:%M:%S.%f",
+    "%Y-%m-%d %H:%M:%S",
+    "%Y-%m-%dT%H:%M:%S.%f",
+    "%Y-%m-%dT%H:%M:%S",
+)
+
+
+def parse_time_bound(raw: str, *, bound_name: str) -> str:
+    """Parse a CLI/API time bound into a TEXT value comparable to events.timestamp.
+
+    Stored timestamps are 'YYYY-MM-DD HH:MM:SS.ffffff' (space separator, microseconds).
+    Second-precision --until is expanded to .999999 so inclusive <= keeps that whole second.
+    """
+    text = raw.strip()
+    parsed: datetime | None = None
+    matched_with_fraction = False
+    for fmt in _BOUND_FORMATS:
+        try:
+            parsed = datetime.strptime(text, fmt)
+            matched_with_fraction = ".%f" in fmt
+            break
+        except ValueError:
+            continue
+    if parsed is None:
+        raise ValueError(
+            f"Invalid {bound_name} value {raw!r}: expected "
+            "YYYY-MM-DD HH:MM:SS[.ffffff] or YYYY-MM-DDTHH:MM:SS[.ffffff]"
+        )
+
+    if bound_name == "--until" and not matched_with_fraction:
+        # Inclusive end against microsecond-stamped TEXT rows.
+        return parsed.strftime("%Y-%m-%d %H:%M:%S") + ".999999"
+    if matched_with_fraction:
+        return parsed.strftime("%Y-%m-%d %H:%M:%S.%f")
+    return parsed.strftime("%Y-%m-%d %H:%M:%S")
+
+
+def _time_filter_sql(
+    time_from: str | None,
+    time_to: str | None,
+) -> tuple[str, tuple[str, ...]]:
+    """Return (WHERE clause including leading space/newline, bind params)."""
+    clauses: list[str] = []
+    params: list[str] = []
+    if time_from is not None:
+        clauses.append("timestamp >= ?")
+        params.append(time_from)
+    if time_to is not None:
+        clauses.append("timestamp <= ?")
+        params.append(time_to)
+    if not clauses:
+        return "", ()
+    return "\n                    WHERE " + " AND ".join(clauses), tuple(params)
 
 
 class FeatureExtractionPipeline:
     """Read events/rule_hits from SQLite and emit per-window feature vectors."""
 
     def __init__(self, db_path: str | Path):
         self.db_path = Path(db_path) if not isinstance(db_path, Path) else db_path
 
-    def run(self, label: int | None = None) -> list[dict]:
+    def run(
+        self,
+        label: int | None = None,
+        time_from: str | None = None,
+        time_to: str | None = None,
+    ) -> list[dict]:
         db_path_str = str(self.db_path)
         if db_path_str != ":memory:" and not self.db_path.exists():
             return []
@@ -31,13 +88,19 @@ class FeatureExtractionPipeline:
         conn.row_factory = sqlite3.Row
         try:
             try:
-                event_rows = conn.execute(
-                    """
+                events_where, events_params = _time_filter_sql(time_from, time_to)
+                event_rows = conn.execute(
+                    f"""
                     SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at
                     FROM events
+                    {events_where}
                     ORDER BY timestamp ASC
                     """
-                ).fetchall()
+                    ,
+                    events_params,
+                ).fetchall()
             except sqlite3.OperationalError:
                 return []
@@ -58,13 +121,19 @@ class FeatureExtractionPipeline:
 
             window_rule_hits: dict[WindowKey, list[dict]] = {key: [] for key in windows}
             try:
-                rule_hit_rows = conn.execute(
-                    """
+                hits_where, hits_params = _time_filter_sql(time_from, time_to)
+                rule_hit_rows = conn.execute(
+                    f"""
                     SELECT id, event_fk, rule_id, timestamp
                     FROM rule_hits
+                    {hits_where}
                     ORDER BY timestamp ASC
                     """
-                ).fetchall()
+                    ,
+                    hits_params,
+                ).fetchall()
             except sqlite3.OperationalError:
                 rule_hit_rows = []
```

Note on the f-string: when `events_where` is empty, the SQL must remain valid. Implementation detail to apply carefully in SP3 — prefer building the query so an empty filter yields exactly:

```sql
FROM events
ORDER BY timestamp ASC
```

(i.e. no blank `WHERE` line). The helper returning `""` achieves that if the template is:

```python
query = (
    "SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at\n"
    "FROM events"
    f"{events_where}\n"
    "ORDER BY timestamp ASC"
)
```

with `events_where` either `""` or `"\nWHERE timestamp >= ? AND timestamp <= ?"`. **Approve this construction; SP3 will use explicit string assembly rather than a fragile indented f-string if needed to keep the no-filter SQL byte-identical in spirit.**

#### `scripts/run_feature_extraction.py`

```diff
--- a/scripts/run_feature_extraction.py
+++ b/scripts/run_feature_extraction.py
@@ -13,7 +13,7 @@ if str(REPO_ROOT) not in sys.path:
 
 from ml.features.exporter import default_output_path, export_to_csv
 from ml.features.feature_spec import FEATURE_NAMES
-from ml.features.pipeline import FeatureExtractionPipeline
+from ml.features.pipeline import FeatureExtractionPipeline, parse_time_bound
 from storage.database import DB_PATH
 
 
 def main() -> int:
     parser = argparse.ArgumentParser(description="Extract process-window features from SQLite.")
     parser.add_argument("--label", type=int, default=None, help="Optional label to append to every row.")
     parser.add_argument(
         "--output",
         type=str,
         default=str(default_output_path()),
         help="Output CSV path.",
     )
     parser.add_argument(
         "--db",
         type=str,
         default=str(DB_PATH),
         help="SQLite database path.",
     )
+    parser.add_argument(
+        "--since",
+        type=str,
+        default=None,
+        help="Optional inclusive lower bound on event/rule_hit timestamp "
+             "(YYYY-MM-DD HH:MM:SS[.ffffff] or ISO-8601 with T).",
+    )
+    parser.add_argument(
+        "--until",
+        type=str,
+        default=None,
+        help="Optional inclusive upper bound on event/rule_hit timestamp "
+             "(YYYY-MM-DD HH:MM:SS[.ffffff] or ISO-8601 with T).",
+    )
     args = parser.parse_args()
 
+    try:
+        time_from = parse_time_bound(args.since, bound_name="--since") if args.since is not None else None
+        time_to = parse_time_bound(args.until, bound_name="--until") if args.until is not None else None
+        if time_from is not None and time_to is not None and time_from > time_to:
+            raise ValueError(
+                f"--since ({args.since!r} → {time_from!r}) is after "
+                f"--until ({args.until!r} → {time_to!r})"
+            )
+    except ValueError as exc:
+        print(f"[ERROR] {exc}", file=sys.stderr)
+        return 2
+
     db_path = Path(args.db)
     output_path = Path(args.output)
 
     print(f"[INFO] Reading from: {db_path}")
     if str(db_path) != ":memory:" and not db_path.exists():
         print(f"[WARN] Database not found: {db_path} — no events to extract")
         vectors: list[dict] = []
     else:
-        vectors = FeatureExtractionPipeline(db_path).run(label=args.label)
+        vectors = FeatureExtractionPipeline(db_path).run(
+            label=args.label,
+            time_from=time_from,
+            time_to=time_to,
+        )
```

### Out of scope / deferred items confirmed in this design

- **VM clock drift:** documented now in `docs/vm_clock_drift_finding.md` (no fix).
- **Sub-Phase 5:** remains split into host mechanism-proof + VM handoff package for the 71544-row VM DB (session bounds `2026-07-27 01:38:21` / `2026-07-27 03:07:19`).
- **Schema reference doc update:** Sub-Phase 6, not SP3.
- **New automated tests:** Sub-Phase 4.

## Findings / Conclusions

1. Current pipeline reads are unfiltered on both `events` and `rule_hits`, each with `ORDER BY timestamp ASC` only — matches the scoping issue and schema reference.
2. Stored timestamps are TEXT `YYYY-MM-DD HH:MM:SS.ffffff` (space + microseconds). CLI must normalize `T`→space and pad second-precision `--until` to `.999999` for true inclusive-end semantics under lexicographic compare.
3. Proposed change is additive: optional `time_from`/`time_to` on `run()`, optional `--since`/`--until` on CLI, malformed input → stderr `[ERROR]…` + exit 2 before query.
4. No product code has been modified pending approval of this exact plan.

## File-Change Scope (if applicable)

Documentation only in this sub-phase (no product diffs applied):

- `docs/scoping_fix_subphase2_report.md` (this report) — **new**
- `docs/vm_clock_drift_finding.md` — **new** (documentation-only finding; written now so it is not dropped)

## Anomalies / Uncertainties

1. **`--until` microsecond padding** is a necessary consequence of inclusive-end + TEXT lexicographic compare against microsecond storage. It is not a re-litigation of inclusive semantics; it is how to implement them correctly. If you prefer a different mechanism (e.g. always require fractional input), say so before SP3.
2. Exit code **2** for validation errors is proposed, not mandated by the task — confirm or request **1**.
3. f-string SQL assembly must be applied carefully so the no-filter path stays equivalent to today’s queries; SP3 will use explicit query assembly to avoid accidental blank `WHERE`.

## Ready to Proceed?

**Yes** — design is ready for your review. **No implementation until you approve** (including the `--until` `.999999` padding and exit code 2). Awaiting explicit go-ahead before Sub-Phase 3.
