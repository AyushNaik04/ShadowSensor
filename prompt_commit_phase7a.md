# SHADOWSENSOR — PHASE 7A FINAL COMMIT
# Authorized by: Ayush
# Executor: Cursor Grok 4.5
# Role: Executor only. No judgment calls. No unrequested changes.

---

## CRITICAL STANDING RULES (read before every action)

1. **No `git add .` or `git add -A`** — stage each file by explicit path only (list provided below).
2. **Do not modify any file** — this task is commit-only. If anything looks wrong, stop and report.
3. **Do not amend any existing commit** — create a new commit only.
4. **Do not push** — commit to local branch only.
5. If any pre-commit verification step fails, stop immediately and report the exact failure.
6. The working directory is the **HOST** machine at `E:\filelessmalware` (mapped as `Z:\filelessmalware` on the VM). Run git commands here, not on the VM.

---

## STEP 0 — Confirm environment

Run:
```
git -C E:\filelessmalware status --short
```

Expected: exactly the files listed in §STAGE LIST below — no more, no fewer.
Confirm the mystery file `=` is **absent** (it was deleted before this task).
Confirm `data/features/` and `logs/` do NOT appear (they are gitignored).

If you see any unexpected files, stop and report.

---

## STEP 1 — Run unit tests

From `E:\filelessmalware`, run:
```
python_runtime\python.exe -m pytest tests/test_phase4a/test_api_memory_rules.py tests/test_phase7a_fixes/ -v --tb=short 2>&1
```

If pytest is not available in `python_runtime`, try:
```
python_runtime\python.exe -m pytest tests/ -v --tb=short -k "api_memory or e2_engine" 2>&1
```

**Expected result:** All tests pass (0 failures, 0 errors). If any test fails, stop and report the full output.

---

## STEP 2 — Explicit staging

Stage every file below **one by one** using `git add <path>`. Do not glob. Do not use `.` or `-A`.

### Modified files (6):
```
git -C E:\filelessmalware add VM_RUN_GUIDE.md
git -C E:\filelessmalware add docs/decisions_log.md
git -C E:\filelessmalware add rules/definitions/api_memory.yaml
git -C E:\filelessmalware add rules/engine.py
git -C E:\filelessmalware add status.md
git -C E:\filelessmalware add tests/test_phase4a/test_api_memory_rules.py
```

### New files — governance & documentation (8):
```
git -C E:\filelessmalware add committee.md
git -C E:\filelessmalware add phase7a_subphase5-7_issues_log.md
git -C E:\filelessmalware add progress_log.md
git -C E:\filelessmalware add rule_insights.md
git -C E:\filelessmalware add prompt.md
git -C E:\filelessmalware add prompt_subphase2.md
git -C E:\filelessmalware add prompt_subphase3.md
git -C E:\filelessmalware add prompt_subphase4.md
git -C E:\filelessmalware add prompt_subphase5.md
git -C E:\filelessmalware add docs/phase7a_final_report.md
git -C E:\filelessmalware add prompt_commit_phase7a.md
```

### New files — simulation scripts (9):
```
git -C E:\filelessmalware add scripts/simulate_subphase_1.py
git -C E:\filelessmalware add scripts/simulate_subphase_2.py
git -C E:\filelessmalware add scripts/simulate_subphase_3.py
git -C E:\filelessmalware add scripts/simulate_subphase_4.py
git -C E:\filelessmalware add scripts/simulate_subphase_5.py
git -C E:\filelessmalware add scripts/vm_subphase6_crt_simulations.ps1
git -C E:\filelessmalware add scripts/diag_download_cradle.py
git -C E:\filelessmalware add scripts/diag_fp_parent.py
git -C E:\filelessmalware add scripts/diag_sp1_status.py
git -C E:\filelessmalware add scripts/e2_check_call_trace.py
git -C E:\filelessmalware add scripts/e2_check_call_trace2.py
git -C E:\filelessmalware add scripts/e2_check_call_trace3.py
git -C E:\filelessmalware add scripts/e2_check_call_trace4.py
```

### New files — staging CSVs (5):
```
git -C E:\filelessmalware add exports/subphase_1_training.csv
git -C E:\filelessmalware add exports/subphase_2_training.csv
git -C E:\filelessmalware add exports/subphase_3_training.csv
git -C E:\filelessmalware add exports/subphase_4_training.csv
git -C E:\filelessmalware add exports/subphase_5_training.csv
```

### New files — tests (2):
```
git -C E:\filelessmalware add tests/test_phase7a_fixes/__init__.py
git -C E:\filelessmalware add tests/test_phase7a_fixes/test_e2_engine_guard.py
```

---

## STEP 3 — Pre-commit verification

Run:
```
git -C E:\filelessmalware status
```

Confirm:
- Section "Changes to be committed" contains exactly the files staged above.
- Section "Changes not staged for commit" is **empty**.
- Section "Untracked files" is **empty** (or contains only files that are intentionally not being committed — none expected at this point).

If anything is wrong, stop and report before proceeding.

Also confirm staging count:
```
git -C E:\filelessmalware diff --cached --stat | tail -1
```

Expected: approximately 43 files changed (6 modified + 37 new).

---

## STEP 4 — Commit

Use this exact commit message. Do not modify the wording.

```
git -C E:\filelessmalware commit -m "$(cat <<'EOF'
feat(phase7a): complete Phase 7A — rule fixes E1/E2/C4, simulation scripts SP1-5, labeled telemetry

## Rule Engine Fixes

E1 — api_memory.yaml: changed match_all: true → false on 8 single-condition EID-10 rules
     (single-condition MATCH_ALL is semantically incorrect; rule behavior unchanged)

E2 — engine.py: added None-guard before int() on GrantedAccess field in EID-10 path
     (prevents KeyError/TypeError when GrantedAccess absent in raw Sysmon event)

C4 — api_memory.yaml: API_OPEN_PROCESS_VM_WRITE_001 FP suppression block extended
     with compiler-toolchain exclusions (cl.exe, link.exe, devenv.exe, msbuild.exe,
     vctip.exe) and conhost.exe (console host launched by compiler in terminal)

## Simulation Scripts (Phase 7A — all five subphases)

scripts/simulate_subphase_1.py  powershell.yaml     → suspicious_ps.csv      312 rows
scripts/simulate_subphase_2.py  lolbins.yaml        → suspicious_lolbins.csv  196 rows
scripts/simulate_subphase_3.py  network.yaml        → suspicious_network.csv  194 rows
scripts/simulate_subphase_4.py  parent_child.yaml   → suspicious_chains.csv   186 rows
scripts/simulate_subphase_5.py  api_memory.yaml     → suspicious_api.csv      217 rows

All scripts follow the mandated pattern: launch_argv(), hits_since() with 180s poll +
30s secondary wait, warn_zero() (no sys.exit), try/except, hardcoded DB_PATH.

Staging CSVs (31 features, label=1) exported to exports/subphase_N_training.csv.

Diagnostic scripts (diag_*.py) and E2 investigation scripts (e2_check_call_trace*.py)
included as project artifacts. CRT reference script vm_subphase6_crt_simulations.ps1
included (superseded by SP5 which covers all 8 api_memory.yaml rules).

## Tests

tests/test_phase4a/test_api_memory_rules.py: C4 regression tests, E1 semantics
  tests, E2 None-guard tests added (246 insertions).
tests/test_phase7a_fixes/test_e2_engine_guard.py: dedicated E2 engine-level guard
  tests for None/missing/zero GrantedAccess variants.

## Subphase 7 — Consolidation, Decontamination Check & Handoff

All 5 subphase CSVs combined into data/features/suspicious.csv:
  suspicious_ps.csv (312) + suspicious_lolbins.csv (196) + suspicious_network.csv (194)
  + suspicious_chains.csv (186) + suspicious_api.csv (217) = 1,105 rows, 31 cols, all label=1

Contamination check PASSED. Rule-hit feature activation confirmed for all 5 categories.

Isolation Forest score comparison (suspicious vs benign baseline):
  Suspicious: mean=0.2152, median=0.1294, 14.7% anomalous (>0.5)
  Benign:     mean=0.1394, median=0.0912,  5.0% anomalous (>0.5)
  Delta mean: +0.0758 — consistent positive separation; RF needed for full classification

docs/phase7a_final_report.md written — includes per-rule confirmation table (51 rules),
family enrichment log, IF score distribution, coverage gaps table (15 rules with no
label=1 due to Office absence and D28/D45/D52-D55 VM Sysmon limitations), explicit
Phase 7B readiness statement.

Phase 7A is now fully closed. Phase 7B (Random Forest training) is next.

## Documentation

docs/decisions_log.md: Entry 014 replaced with committee-vetted final version
  (compiler-toolchain + console-host FP root cause and fix); Entry 015 added
  (SP5 EID-7/EID-8 Sysmon visibility limitations — D54/D55).

committee.md: §12 corrected — injection.yaml does not exist, SP6 superseded by SP5
  (api_memory.yaml covers all 8 rules including EID-8 CRT rules); §15 stale flag
  cleared (Entry 014 already vetted); §16 Phase 7A remaining steps updated.

VM_RUN_GUIDE.md: fixed corrupt CMD quick-reference block; removed duplicate
  "Known Environment: SQLite Journal Mode" section; appended Phase 7A section
  with simulation procedure, feature extraction PS workaround (temp-file approach),
  and D44/D45/D47/D48/D52-D55 operational findings table.

status.md, progress_log.md: complete Phase 7A execution record including per-path
  simulation results, CSV integrity check, and SP6 supersession rationale.

rule_insights.md: source-of-truth document for all simulation scripts — maps every
  rule ID to its category, EID, conditions, and multi-path attack vectors.

prompt.md + prompt_subphase2-5.md: Grok task files used to generate each simulation
  script; committed as reproducibility artifacts.

phase7a_subphase5-7_issues_log.md: structured issue catalog for deferred fix session
  (D52-D55 EID-7/EID-8/EID-10 visibility gaps; PPL process access constraints).

## Environmental findings (D44–D55) — newly documented

D44: VM pipeline lag 10-15 min; stale hit bleed; FP hard-stops converted to [WARN]
D45: hh.exe EID-1 not logged by Sysmon on this VM (LOLBIN_HH_CHM_001 unfireable)
D47/D48: Sysmon EID-3 filter captures ports 80/443 only (NET_SUSPICIOUS_PORT_001 and
         NET_SMB_LATERAL_001 structurally unfireable on this VM)
D52: PPL-protected processes deny OpenProcess; EID-10 not logged for denied handles
D53: Fake AV process in user-writable Temp dir not in Sysmon ProcessAccess filter
D54/D55: python.exe and LOLBin (rundll32/regsvr32) ImageLoad events not generated
         by this VM's Sysmon ImageLoad filter configuration

Phase 7A fully closed: 1105 rows suspicious.csv + phase7a_final_report.md complete.
Closes: Phase 7A / all outstanding Category A-E rule issues since cda95c3
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
- Commit message starts with `feat(phase7a): complete Phase 7A`
- Stat shows approximately 41 files changed
- No error messages

Then run:
```
git -C E:\filelessmalware status
```

Expected: "nothing to commit, working tree clean" (or only intentionally untracked files).

---

## STEP 6 — Report back

Return the following to the committee:
1. Full output of `git log -1 --stat`
2. The commit hash (first 7 characters)
3. Confirmation that `git status` shows a clean working tree
4. Any warnings or unexpected output encountered during the process

---

## DO NOT:
- Push to remote (`git push`)
- Modify any file
- Stage `data/` or `logs/` directories
- Amend prior commits
- Use `git add .` or `git add -A`
- Continue if any step fails — stop and report

---

END OF TASK
