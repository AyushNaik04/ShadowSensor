# ShadowSensor — Project-Wide Decisions Log

**Purpose:** Permanent, cumulative record of every non-trivial architectural or design decision made across all project phases.
Reverse-chronological order (newest entry first). One entry per decision.
This file persists across all future phases — future sessions must append here rather than creating new logs.
Do not delete or rewrite past entries; corrections go in a new entry referencing the original.

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
