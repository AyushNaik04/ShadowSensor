# SHADOWSENSOR — PHASE 7B FINAL COMMIT
# Authorized by: Ayush
# Executor: Cursor Grok 4.6 High Fast
# Role: Executor only. No judgment calls. No unrequested changes.

---

## CRITICAL STANDING RULES (read before every action)

1. **No `git add .` or `git add -A`** — stage each file by explicit path only (list provided below).
2. **Do not modify any file** — this task is commit-only. If anything looks wrong, stop and report.
3. **Do not amend any existing commit** — create a new commit only.
4. **Do not push** — commit to local branch only. No `git push` under any circumstances.
5. If any pre-commit verification step fails, stop immediately and report the exact failure.
6. Working directory: `E:\filelessmalware` (host machine, not VM).

---

## STEP 0 — Confirm environment

Run:
```
git -C E:\filelessmalware status
```

Expected state — confirm ALL of the following before proceeding:

**Changes not staged for commit (exactly these 9 files, no more, no fewer):**
- modified: committee.md
- modified: dashboard/routers/pages.py
- modified: dashboard/services/ml_insights_service.py
- modified: dashboard/templates/ml_insights.html
- modified: ml/scoring/scorer.py
- modified: progress_log.md
- modified: status.md
- modified: tests/test_phase6b/test_ml_insights.py
- modified: tests/test_phase6b/test_scoring_integration.py

**Untracked files (exactly these 7 items, no more, no fewer):**
- docs/phase7b_metrics.json
- docs/phase7b_report.md
- ml/models/random_forest.joblib
- ml/training/train_random_forest.py
- progress_log_phase7b.md
- prompt_commit_phase7b.md
- tests/test_phase7b/

**Also confirm:**
- `data/` does NOT appear (gitignored)
- `logs/` does NOT appear (gitignored)
- `task.md` does NOT appear (gitignored)
- No staged changes section exists yet
- Branch is `main`

If ANY unexpected file appears or any expected file is absent: stop and report exactly what differs.

---

## STEP 1 — Run full test suite

From `E:\filelessmalware`, run:
```
pytest tests/ -v --tb=short 2>&1
```

**Expected result:** 705 passed, 0 failed, 0 errors.

If any test fails or errors: stop and report the full failure output. Do not proceed to staging.

---

## STEP 2 — Explicit staging (one file at a time, in order)

Stage every file below **one by one** using `git add <path>`. Do not glob. Do not use `.` or `-A`.

### Modified files (9):
```
git -C E:\filelessmalware add committee.md
git -C E:\filelessmalware add dashboard/routers/pages.py
git -C E:\filelessmalware add dashboard/services/ml_insights_service.py
git -C E:\filelessmalware add dashboard/templates/ml_insights.html
git -C E:\filelessmalware add ml/scoring/scorer.py
git -C E:\filelessmalware add progress_log.md
git -C E:\filelessmalware add status.md
git -C E:\filelessmalware add tests/test_phase6b/test_ml_insights.py
git -C E:\filelessmalware add tests/test_phase6b/test_scoring_integration.py
```

### New files — ML training and model (2):
```
git -C E:\filelessmalware add ml/training/train_random_forest.py
git -C E:\filelessmalware add ml/models/random_forest.joblib
```

### New files — docs and metrics (2):
```
git -C E:\filelessmalware add docs/phase7b_metrics.json
git -C E:\filelessmalware add docs/phase7b_report.md
```

### New files — committee documentation (2):
```
git -C E:\filelessmalware add progress_log_phase7b.md
git -C E:\filelessmalware add prompt_commit_phase7b.md
```

### New files — tests (4):
```
git -C E:\filelessmalware add tests/test_phase7b/__init__.py
git -C E:\filelessmalware add tests/test_phase7b/test_rf_insights.py
git -C E:\filelessmalware add tests/test_phase7b/test_rf_scorer.py
git -C E:\filelessmalware add tests/test_phase7b/test_train_random_forest.py
```

---

## STEP 3 — Pre-commit verification

Run:
```
git -C E:\filelessmalware status
```

Confirm:
- Section "Changes to be committed" contains **exactly the 19 files staged above** — no more, no fewer.
- Section "Changes not staged for commit" is **empty**.
- Section "Untracked files" is **empty** (all untracked files have been staged; `data/`, `logs/`, `task.md` remain absent as gitignored).

Also confirm staging count:
```
git -C E:\filelessmalware diff --cached --stat | tail -1
```

Expected: approximately 19 files changed.

If anything is wrong: stop and report before proceeding.

---

## STEP 4 — Commit

Use this exact commit message. Do not modify the wording.

```
git -C E:\filelessmalware commit -m "$(cat <<'EOF'
feat(phase7b): complete Phase 7B — Random Forest training, scorer integration, dashboard wire-up

## Subphase 1 — RF Training Script

ml/training/train_random_forest.py: new training script
- Trains RandomForestClassifier on 621 benign + 1,105 suspicious rows (1,726 total)
- Feature set: 28 features (all 30 minus open_process_suspicious_access and hour_of_day)
- open_process_suspicious_access dropped: anti-discriminative (39.0% benign vs 21.0%
  suspicious activation — VMware WARP-cluster noise on this VM)
- hour_of_day dropped: near-zero discriminative power (benign mean 3.89 vs suspicious
  mean 3.99; separation is a simulation-timing artifact, not a genuine behavioral signal)
- 5-fold stratified CV, class_weight='balanced', n_estimators=100, random_state=42
- CV: precision 0.818±0.008, recall 0.848±0.028, F1 0.833±0.016, ROC-AUC 0.837±0.014
- Top permutation features: parent_cmd_length (0.0197), cmd_entropy (0.0182),
  unique_rules_fired (0.0112) — behavioral/entropy features dominate over rule-hit
  features; RF generalizes beyond rule coverage
- Persists ml/models/random_forest.joblib (keys: model, feature_names, cv_metrics)
- Writes docs/phase7b_metrics.json (per-fold CV values, full permutation importance)

tests/test_phase7b/__init__.py, test_train_random_forest.py: 12 new tests
- RF_FEATURE_NAMES count and exclusions, CSV column integrity, artifact structure,
  cv_metrics keys, ROC-AUC > 0.5 sanity check, metrics JSON validity

## Subphase 2 — RF Scorer Integration

ml/scoring/scorer.py: RF dual-scoring added to EventScorer
- Added: import joblib, import pandas as pd
- Added: RF_MODEL_PATH import from ml.training.train_random_forest
- __init__: loads random_forest.joblib when present; _rf_artifact=None on missing/failure
- score_and_persist() Step 5: writes ModelScoreRecord(model_type='random_forest',
  score=P(suspicious)) between IF DB write and return score
- RF failure is non-fatal — IF score always returned regardless of RF outcome
- Reuses features dict from Step 2; no redundant extractor call
- model_scores.model_type CheckConstraint already includes 'random_forest' — no schema changes

tests/test_phase7b/test_rf_scorer.py: 6 new tests
- _rf_artifact loads/absent, 2-row write (IF+RF), model_type correctness,
  score in [0.0, 1.0], RF failure non-fatal

## Subphase 3 — Dashboard Wire-Up + Phase 7B Report

dashboard/services/ml_insights_service.py: added get_random_forest_status()
- Mirrors get_isolation_forest_status() — queries model_type='random_forest'
- Returns: trained, training_date (artifact mtime), total_scored, score stats, 10 brackets

dashboard/routers/pages.py: dashboard_ml_insights() updated
- Imports and calls get_random_forest_status(); passes live dict to template
- Replaces former hardcoded {"trained": False} stub

dashboard/templates/ml_insights.html: RF placeholder section fully replaced
- Removed: ml-status-future badge, static "Phase 7B" placeholder text
- Added: live RF section with Active/Awaiting Data badge, stats row (when trained),
  score distribution brackets (when trained); no trend chart (intentionally simpler)

docs/phase7b_report.md: full Phase 7B training report
- Sections: overview, training data, 28-feature set with exclusion rationale,
  model config, per-fold CV results, top-10 permutation importance, 15 Phase 7A
  coverage gaps (Office absent; D28/D43/D45/D50-D55 VM Sysmon limits),
  research paper Section 4 notes (supervised vs unsupervised comparison)

tests/test_phase7b/test_rf_insights.py: 5 new tests for get_random_forest_status()
tests/test_phase6b/test_ml_insights.py: placeholder test renamed + 2 new RF tests added

## Test Regression Fix (committee)

tests/test_phase6b/test_scoring_integration.py::test_score_and_persist_writes_model_scores_row
- SP2 correctly writes 2 rows per event (IF + RF); test was written before RF existed
- Changed: assert len(rows)==1 → assert len(rows)>=1 with explicit IF row filter
- SP2 implementation was correct throughout; this was a test-maintenance fix

## Summary

25 new tests total (SP1: 12, SP2: 6, SP3: 7). Full suite: 705 passed, 0 failed.
Dual-model architecture live: IF (anomaly score) + RF (P(suspicious)) both write to
model_scores with model_type discriminator. ML Insights dashboard shows both models.

## Documentation

committee.md: Phase 7A remaining-steps checklist — commits fda482d + 325ff85 marked DONE
progress_log.md: Phase 7B closure summary appended
progress_log_phase7b.md: full SP1/SP2/SP3 committee detail log (new file)
status.md: Phase 7B all subphases COMPLETE; Current Phase updated to 8A

Phase 7B fully closed. Phase 8A (Alert Correlation / Severity Engine) is next.
Closes: Phase 7B — all three subphases implemented, verified, and documented
EOF
)"
```

---

## STEP 5 — Post-commit verification

Run:
```
git -C E:\filelessmalware log -1 --stat
```

Verify:
- Commit message first line is: `feat(phase7b): complete Phase 7B — Random Forest training, scorer integration, dashboard wire-up`
- Stat shows approximately 19 files changed
- No error messages

Then run:
```
git -C E:\filelessmalware status
```

Expected: "nothing to commit, working tree clean" (only gitignored files absent — `data/`, `logs/`, `task.md`).

---

## STEP 6 — Report back

Return the following to the committee:
1. Full output of `git log -1 --stat`
2. The commit hash (first 7 characters)
3. Confirmation that `git status` shows a clean working tree (or exact content if not clean)
4. Any warnings or unexpected output encountered at any step

---

## DO NOT:
- Push to remote (`git push`)
- Modify any file
- Stage `data/` or `logs/` directories
- Stage `task.md` (it is gitignored — if it appears, report immediately)
- Amend prior commits
- Use `git add .` or `git add -A`
- Continue past any step that produces unexpected output — stop and report

---

END OF TASK
