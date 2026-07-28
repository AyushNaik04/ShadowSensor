# Phase 6B — Subphase 2: Corrected Per-Event Validation Report

**Date:** 2026-07-28
**Author:** Phase 6B agent (Claude Sonnet 4.6)
**Status:** CORRECTED VALIDATION COMPLETE — PROCEED CONDITION MET

---

## What this document covers

The original Subphase 2 empirical validation was **invalid**: it scored
`benign_baseline.csv`'s 621 process-window-aggregated rows against the model
trained on those same rows. That is in-sample validation and does not represent
what the live pipeline in Subphase 3 will actually do.

This document supersedes the original validation finding. The corrected
validation pulls **real individual, unaggregated Sysmon events** from the live
database, runs each through `EventFeatureExtractor` alone (no
`ProcessWindowAggregator` accumulation), scores through the trained model, and
reports the full distribution. All numbers below are real — produced by running
the actual code against the actual live database.

---

## What the original validation did (invalid)

- Loaded `data/features/benign_baseline.csv` (621 rows, each a
  process-window-aggregated summary across a process's observed lifetime)
- Scored those rows against the model trained on those same rows
- Reported that distribution as the "empirical per-event score check"

**Why this was invalid:** `benign_baseline.csv`'s rows are process-window
aggregates. Features like `open_process_count`, `image_load_count`,
`create_remote_thread_count`, and `network_event_count` represent sums across an
entire process's lifetime (means of 41–71 in the benign baseline). The live
pipeline in Subphase 3 will score individual, unaggregated events as they
arrive — those single-event vectors will have most aggregate features near 0 or
exactly 1. This is a fundamentally different input distribution. Scoring
in-sample training data and calling it "per-event validation" was incorrect.

---

## Corrected validation: methodology

**Events source:** `C:\ShadowSensor\data\shadowsensor.db` (live database,
29,687 total events at time of validation)

**Sampling:** Up to 200 events per EID sampled at random
(EID 8 not present in the live database)

| EID | Description | Events sampled |
|-----|-------------|----------------|
| 1 | ProcessCreate | 200 |
| 3 | NetworkConnect | 97 (all events) |
| 7 | ImageLoad | 200 |
| 10 | ProcessAccess | 200 |
| 22 | DnsQuery | 25 (all events) |
| **Total** | | **722** |

**Extractor path:** `EventFeatureExtractor.extract(event)` — exactly one event
per call, no `ProcessWindowAggregator`, no window state accumulation. This
produces the same sparse, mostly-zero vectors the live per-event design in
Subphase 3 will generate in production.

**Scoring:** `score_features(vector, artifact)` using the persisted model at
`ml/models/isolation_forest.joblib` with training-time bounds
(`train_score_min=-0.792823`, `train_score_max=-0.334087`).

---

## Results: full distribution

```
N events scored:  722
Min:              0.010604
Max:              0.642742
Mean:             0.203163
Median:           0.094595
Std:              0.201809
Variance:         0.040727
```

### Score bracket histogram

```
[0.0, 0.1):   377  ( 52.2%)  ##########################
[0.1, 0.2):     6  (  0.8%)
[0.2, 0.3):    25  (  3.5%)  #
[0.3, 0.4):   244  ( 33.8%)  ################
[0.4, 0.5):     1  (  0.1%)
[0.5, 0.6):     3  (  0.4%)
[0.6, 0.7):    66  (  9.1%)  ####
[0.7, 0.8):     0  (  0.0%)
[0.8, 0.9):     0  (  0.0%)
[0.9, 1.0+):    0  (  0.0%)
```

### Per-EID breakdown

| EID | N | Min | Max | Mean | Median | Std |
|-----|---|-----|-----|------|--------|-----|
| 1 (ProcessCreate) | 200 | 0.1418 | 0.6427 | 0.4383 | 0.3759 | 0.1426 |
| 3 (NetworkConnect) | 97 | 0.3412 | 0.3412 | 0.3412 | 0.3412 | 0.0000 |
| 7 (ImageLoad) | 200 | 0.0106 | 0.2591 | 0.0392 | 0.0106 | 0.0793 |
| 10 (ProcessAccess) | 200 | 0.0106 | 0.0946 | 0.0467 | 0.0106 | 0.0416 |
| 22 (DnsQuery) | 25 | 0.3285 | 0.3801 | 0.3499 | 0.3285 | 0.0243 |

---

## EID 3 uniform scores — explained

All 97 EID 3 events in the live database connect to port 443 (HTTPS) to
external IPs. The `EventFeatureExtractor` for EID 3 sets:
- `dest_port = 443`
- `is_external_ip = 1`
- `is_suspicious_port = 0` (port 443 is not in `SUSPICIOUS_PORTS`)
- `network_event_count = 1`

All other features remain at their defaults. This produces an identical feature
vector for all 97 events → identical score (0.3412). This is correct behavior —
the extractor is functioning as designed; the live benign traffic happens to be
uniformly HTTPS. A more varied network dataset would produce variance within
EID 3. This is a database-content observation, not a model or extractor defect.

---

## Comparison with benign-baseline (in-sample) validation

| Metric | Benign baseline (621 rows, in-sample) | Per-event live (722 rows, corrected) |
|--------|---------------------------------------|--------------------------------------|
| Min | 0.0000 | 0.0106 |
| Max | 1.0000 | 0.6427 |
| Mean | 0.1394 | 0.2032 |
| Median | 0.0912 | 0.0946 |
| Std | 0.1636 | 0.2018 |
| Variance | 0.0268 | **0.0407** |

The per-event variance (0.0407) is **higher** than the benign-baseline
in-sample variance (0.0268). The max score is 0.643 — no clustering near 1.0.
The distribution is genuinely bimodal (EID 7/10 cluster near 0; EID 1/3/22
cluster in the 0.3–0.65 range), which is expected because different EIDs
activate different features.

---

## Distribution character: bimodal and EID-driven

The histogram shows two main clusters:

1. **Low cluster (0.0–0.1, 52.2%):** Driven by EID 7 (ImageLoad) and EID 10
   (ProcessAccess). These events set very few non-zero features — `image_load_count=1`
   and `unsigned_image_loaded=0/1` for EID 7; `open_process_count=1` and
   `open_process_suspicious_access=0/1` for EID 10. A sparse vector relative to
   training scores low.

2. **Mid cluster (0.3–0.4, 33.8%) and high tail (0.6–0.7, 9.1%):** Driven by
   EID 1 (ProcessCreate), EID 3 (NetworkConnect), and EID 22 (DnsQuery). These
   events activate more features (command line entropy, LOLbin flags, port
   flags, DNS query length). EID 1's mean of 0.44 and max of 0.64 reflect that
   process creation events produce the most feature-dense vectors.

This bimodal structure is expected and meaningful — the model is reacting to
feature density, which varies systematically by event type. It is not a sign of
degeneracy. A mixed stream of benign events in the live pipeline will produce
scores that spread across this range, giving the Phase 8A correlation engine
real signal to fuse.

---

## Stop/Proceed evaluation

**PROCEED CONDITION MET.** Per task.md's explicit gate:

> "Only if the distribution shows genuine, reasonable variance comparable to
> what was already shown for the benign baseline may you proceed to Subphase 3 —
> and you must state this explicitly and show the numbers before doing so."

- Variance = **0.0407** (exceeds benign-baseline 0.0268 ✅)
- Max score = 0.643 — no clustering near 1.0 ✅
- Near-zero cluster (<0.05): 40.3% — not a degenerate collapse ✅
- Near-one cluster (>0.95): 0.0% ✅
- Distribution is non-constant (range = 0.632) ✅

The three stop conditions from the task (scores cluster near 1.0, near 0.0, or
collapse to near-constant) are all **not met**. The proceed condition is met.

---

## What Subphase 3 must account for

The corrected validation confirms per-event scoring is non-degenerate, but
reveals the bimodal EID-distribution structure. Subphase 3 should note:

1. **Score interpretation is EID-sensitive.** A score of 0.01 from an EID 7
   event and a score of 0.44 from an EID 1 event are not directly comparable
   without knowing the EID. Phase 8A's correlation engine should consider EID
   context when fusing scores.
2. **EID 3 uniform behavior** will persist until the network activity becomes
   more varied. Port 443 HTTPS is entirely benign; a real attacker event (EID 3
   to a suspicious port or non-standard external endpoint) would score
   differently.
3. **EID 8 (CreateRemoteThread) absent from live DB.** Cannot be validated
   here. The extractor sets `create_remote_thread_count=1` and all other
   features at defaults for EID 8 — expect a score similar to EID 7/10 (sparse
   vector, low score).

---

## Files touched

- `docs/phase6b_subphase2_corrected_report.md` — this document (new)
- `docs/decisions_log.md` — Entry 004 added (corrected validation finding)
- `status.md` — updated to reflect corrected Subphase 2 and proceed decision
- `tests/test_phase6b/test_isolation_forest.py` — per-event live DB test added

No source files modified. The model artifact (`ml/models/isolation_forest.joblib`)
is unchanged — only the validation methodology was corrected.

---

## Decisions log entries added this report

**Entry 004** (see `docs/decisions_log.md`): Per-event score distribution
validated against 722 real individual Sysmon events from the live database.
Variance=0.0407, max=0.643, bimodal EID-driven structure confirmed. Proceed
condition met. EID 3 uniform score (all HTTPS→port 443) explained.
