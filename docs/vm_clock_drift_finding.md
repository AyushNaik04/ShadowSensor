# VM Clock Drift Finding (Documentation Only)

**Status:** Documented finding — **out of scope to fix** in the feature-extraction time-scoping task (`phase6a_scoping_fix_task.md`).  
**Date recorded:** 2026-07-27  
**Severity:** Medium for Phase 6B / 7B feature correctness; does not block the `--since`/`--until` scoping fix itself.

---

## Finding

The Phase 6A Lab Win10 VM’s system clock is **internally consistent but offset by approximately 12 hours** relative to the host’s wall-clock / human session narrative used in Phase 6A reports.

Evidence from the same benign collection session:

| Source | Value |
|---|---|
| Human / report narrative (`docs/phase6a_subphase2_report.md`) | approx **14:00–15:38** (host-local framing, IST) |
| Exact `logs/rule_hits.log` markers (VM-written) | **SESSION START `2026-07-27 01:38:21`** → **SESSION END `2026-07-27 03:07:19`** |
| Duration | `1:28:58` (matches the long benign window; report’s “~1h38m” was rounded) |
| Rule-hit cluster inside that session | `2026-07-27 02:10:51`–`02:11:56` (Cloudflare WARP) — same clock as the session markers |

Confirmed decision for scoping work: **`01:38:21` / `03:07:19` remain the correct, internally-consistent boundary values** for filtering events/rule_hits produced on that VM. Do not “correct” them by adding 12 hours when querying the VM database.

---

## Risk to Phase 6B / 7B Features

`FEATURE_REGISTRY` includes time-derived features (see `ml/features/feature_spec.py`):

- **`hour_of_day`** — hour component of the event timestamp (0–23)
- **`is_off_hours`** — whether the event fell outside 08:00–18:00

If the VM clock is wrong by ~12 hours, these features are systematically shifted (e.g. afternoon host-local activity stamped as early-morning VM-local time). That can distort Isolation Forest / later ML baselines even when process/network/API features are otherwise correct.

This does **not** invalidate `--since`/`--until` filters that use the same clock the DB was written with; it **does** mean hour-based features from VM-collected data may not reflect true local time-of-day until the VM clock is corrected for future collections.

---

## Explicit Non-Actions (this task)

- Do **not** change the VM clock as part of the scoping fix.
- Do **not** rewrite historical `events.timestamp` values.
- Do **not** special-case `hour_of_day` / `is_off_hours` in the scoping patch.
- Sub-Phase 5 session bounds stay **`2026-07-27 01:38:21`** / **`2026-07-27 03:07:19`**.

---

## Recommended follow-up (separate task)

1. Correct the Lab Win10 VM OS clock / timezone before the next collection window.
2. Re-evaluate whether existing Phase 6A rows need a documented caveat (or a fresh collection) before Phase 6B training relies on `hour_of_day` / `is_off_hours`.
