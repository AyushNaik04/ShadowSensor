# Phase 6A - Sub-Phase 4 Completion Report

**Date/time executed:** 2026-07-27
**Sub-phase goal (restated):** Run the Phase 5 feature extraction CLI against the real, now-populated database for the first time, producing the labeled benign baseline CSV.

## What Was Completed
- Ran: python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --output data\features\benign_baseline.csv
- Extracted 795 process windows from 71544 events
- Exported to data\features\benign_baseline.csv
- Verified CSV structure: 31 header columns, 795 data rows, first column cmd_length, last column label

## What's Working
Feature extraction ran successfully end-to-end against real, non-trivial live data for the first time (previous Phase 5 closure verification only tested against an empty DB). Process window count (795) is sensible given 71544 events over a ~1h38m session with many distinct processes. CSV structure fully matches expected format: 30 features + label = 31 columns, 795 data rows, correct first/last column names.

## What's Not Working / Unexpected
Minor documentation-vs-behavior discrepancy, not a defect: the console output printed "Features per row: 31" rather than the task spec's expected "Features per row: 30". Verified via direct CSV inspection that this is because the console message counts all columns including the label column when --label is passed (30 features + 1 label = 31). The task doc's expected pattern of 30 was written for the unlabeled case. No actual structural issue - CSV itself is correct in every respect. Flagging for accuracy only, no action needed.

## Issues Log
None.

## Ready to Proceed?
Yes - Sub-Phase 4 complete. benign_baseline.csv is structurally valid and ready for Sub-Phase 5 activation analysis. Awaiting Ayush's go-ahead.
