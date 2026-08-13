# ShadowSensor Phase 7B — Random Forest Training Report

## 1. Overview
Phase 7B trains the Random Forest classifier using Phase 7A's
labeled telemetry and Phase 6A's benign baseline, integrates RF scoring into the live
pipeline, and surfaces RF metrics on the ML Insights dashboard.

## 2. Training Data
- Negative class: data/features/benign_baseline.csv — 621 rows, label=0
- Positive class: data/features/suspicious.csv — 1,105 rows, label=1
- Combined total: 1,726 rows
- Class distribution: 64% suspicious / 36% benign

## 3. Feature Set (28 features)
Used features:
- cmd_length
- cmd_entropy
- has_encoded_command
- has_download_keyword
- is_signed
- is_off_hours
- is_lolbin
- is_suspicious_parent
- parent_cmd_length
- is_known_suspicious_chain
- parent_is_same_image
- dns_query_length
- dest_port
- is_suspicious_port
- is_external_ip
- network_event_count
- image_load_count
- unsigned_image_loaded
- create_remote_thread_count
- open_process_count
- open_process_lsass_target
- rule_hit_count
- unique_rules_fired
- has_powershell_rule_hit
- has_lolbin_rule_hit
- has_network_rule_hit
- has_api_rule_hit
- has_chain_rule_hit

Excluded features and rationale:
- open_process_suspicious_access: excluded — anti-discriminative (39.0% benign activation
  vs 21.0% suspicious activation due to VMware tooling WARP-cluster behavior on this VM)
- hour_of_day: excluded — near-zero discriminative power (benign mean 3.89 vs suspicious
  mean 3.99; separation is simulation-timing artifact, not a genuine behavioral signal)

## 4. Model Configuration
- Algorithm: sklearn.ensemble.RandomForestClassifier
- n_estimators: 100
- class_weight: 'balanced'
- random_state: 42
- All other parameters: sklearn defaults

## 5. Cross-Validation Results
5-fold stratified CV from docs/phase7b_metrics.json:

- Precision: mean 0.8183 ± 0.0082
  - per-fold: 0.8243, 0.8246, 0.8027, 0.8225, 0.8174
- Recall: mean 0.8480 ± 0.0278
  - per-fold: 0.8281, 0.8507, 0.8100, 0.8597, 0.8914
- F1: mean 0.8327 ± 0.0157
  - per-fold: 0.8262, 0.8374, 0.8063, 0.8407, 0.8528
- ROC-AUC: mean 0.8368 ± 0.0143
  - per-fold: 0.8349, 0.8523, 0.8228, 0.8201, 0.8541

Exact values from metrics JSON:
- precision mean=0.8183029038391352 std=0.00821759085427924
- recall mean=0.8479638009049774 std=0.027834491401320747
- f1 mean=0.8326859412742212 std=0.01568444927776552
- roc_auc mean=0.8368266238505327 std=0.014275448504789697

## 6. Feature Importance (Permutation, Top 10)
From docs/phase7b_metrics.json (mean permutation delta, descending):

1. parent_cmd_length — 0.019694717287269382
2. cmd_entropy — 0.018248949439890527
3. unique_rules_fired — 0.011178054960664296
4. rule_hit_count — 0.011056399973821573
5. unsigned_image_loaded — 0.0037613407409498923
6. has_api_rule_hit — 0.0015847943605653558
7. has_powershell_rule_hit — 0.0012635031140891596
8. parent_is_same_image — 0.0012201465207925643
9. has_lolbin_rule_hit — 0.0005522921234406786
10. has_download_keyword — 0.0005137141469377049

## 7. Phase 7A Coverage Gaps
The following rules have zero label=1 coverage in suspicious.csv due to VM environmental
limits documented in docs/phase7a_final_report.md. The RF model cannot detect these
technique patterns at inference time:

- PS_NOPROFILE_NONINTERACTIVE_001 — Rule does not exist in live YAML (D1)
- PS_OBFUSCATION_001 — Rule does not exist in live YAML (D1)
- LOLBIN_FINDSTR_001 — Rule does not exist in live YAML (D13)
- LOLBIN_HH_CHM_001 — Sysmon/Defender prevents EID-1 for hh.exe (D45)
- NET_SUSPICIOUS_PORT_001 — EID-3 filter captures ports 80/443 only (D28)
- NET_SMB_LATERAL_001 — EID-3 filter captures ports 80/443 only (D28)
- NET_DNS_SCRIPT_ENGINE_001 — cscript HTTPS → 0 Sysmon events (D29)
- CHAIN_OFFICE_POWERSHELL_001 — Office not installed on sandbox VM
- CHAIN_OFFICE_CMD_001 — Office not installed on sandbox VM
- CHAIN_OFFICE_WSCRIPT_001 — Office not installed on sandbox VM
- CHAIN_SCHEDULED_TASK_SCRIPT_001 — schtasks.exe never true parent (D43)
- CHAIN_REGSVR32_CHILD_001 — Defender terminates child before EID-1 (D50)
- API_AV_PROCESS_ACCESS_001 — Sysmon ProcessAccess filter excludes arbitrary Temp processes (D53)
- API_DLL_LOAD_SUSPICIOUS_PATH_001 — Sysmon ImageLoad filter excludes python.exe (D54)
- API_LOLBIN_DLL_UNSIGNED_001 — Sysmon ImageLoad filter excludes rundll32/regsvr32 DLL loads (D55)

## 8. Research Paper — Section 4 Notes
- Supervised vs. Unsupervised Comparison: RF precision/recall/F1/ROC-AUC directly comparable
  to IF's anomalous-rate metric (14.7% suspicious, 5.0% benign from Phase 7A IF comparison)
- RF provides a classification boundary; IF provides a continuous anomaly score
- Both models write to model_scores with model_type discriminator — dual-model architecture
- Coverage gap: 15 rules with no suspicious training data reduce RF's coverage ceiling
  for those specific technique categories

## 9. Model Artifact
- Path: ml/models/random_forest.joblib
- Artifact keys: model, feature_names, cv_metrics
- Metrics JSON: docs/phase7b_metrics.json
