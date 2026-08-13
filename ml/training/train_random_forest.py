"""
ShadowSensor Phase 7B — Random Forest Training

Trains a RandomForestClassifier on labeled benign + suspicious feature CSVs
and persists the model together with CV metrics as a single joblib artifact at
ml/models/random_forest.joblib.

Feature set is the 28-element RF_FEATURE_NAMES list. Two columns are
deliberately excluded from training:
  open_process_suspicious_access — anti-discriminative
  hour_of_day — near-zero discriminative power
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BENIGN_CSV_PATH  = _REPO_ROOT / "data" / "features" / "benign_baseline.csv"
SUSPICIOUS_CSV_PATH = _REPO_ROOT / "data" / "features" / "suspicious.csv"
MODEL_PATH   = _REPO_ROOT / "ml" / "models" / "random_forest.joblib"
METRICS_PATH = _REPO_ROOT / "docs" / "phase7b_metrics.json"

RF_FEATURE_NAMES: list[str] = [
    "cmd_length",
    "cmd_entropy",
    "has_encoded_command",
    "has_download_keyword",
    "is_signed",
    "is_off_hours",
    "is_lolbin",
    "is_suspicious_parent",
    "parent_cmd_length",
    "is_known_suspicious_chain",
    "parent_is_same_image",
    "dns_query_length",
    "dest_port",
    "is_suspicious_port",
    "is_external_ip",
    "network_event_count",
    "image_load_count",
    "unsigned_image_loaded",
    "create_remote_thread_count",
    "open_process_count",
    "open_process_lsass_target",
    "rule_hit_count",
    "unique_rules_fired",
    "has_powershell_rule_hit",
    "has_lolbin_rule_hit",
    "has_network_rule_hit",
    "has_api_rule_hit",
    "has_chain_rule_hit",
]


def feature_permutation_importance(
    clf: RandomForestClassifier,
    X: pd.DataFrame,
    n_repeats: int = 10,
    random_state: int = 42,
) -> dict[str, float]:
    """Estimate per-feature importance via permutation on predict_proba[:, 1].

    For each feature: shuffle its values, re-score all rows, measure mean change
    in mean P(suspicious) vs. the unpermuted baseline.

    A large positive delta when a feature is permuted means the feature was
    contributing to correct suspicious classification = high importance.

    Returns a dict mapping feature_name -> mean_delta, sorted descending
    (most important first by magnitude of positive delta).
    """
    rng = np.random.RandomState(random_state)
    base_mean = float(clf.predict_proba(X)[:, 1].mean())

    importances: dict[str, float] = {}
    X_arr = X.values.copy()
    for i, col in enumerate(X.columns):
        deltas = []
        for _ in range(n_repeats):
            X_perm = X_arr.copy()
            X_perm[:, i] = rng.permutation(X_perm[:, i])
            perm_df = pd.DataFrame(X_perm, columns=X.columns)
            perm_mean = float(clf.predict_proba(perm_df)[:, 1].mean())
            deltas.append(perm_mean - base_mean)
        importances[col] = float(np.mean(deltas))

    return dict(sorted(importances.items(), key=lambda kv: kv[1], reverse=True))


def train_and_persist(
    benign_csv_path: Path = BENIGN_CSV_PATH,
    suspicious_csv_path: Path = SUSPICIOUS_CSV_PATH,
    model_path: Path = MODEL_PATH,
    metrics_path: Path = METRICS_PATH,
    random_state: int = 42,
    n_repeats_importance: int = 10,
) -> dict:
    """Train Random Forest, persist artifact and metrics JSON, return metadata."""
    # Step 1 — Load both CSVs.
    df_benign = pd.read_csv(benign_csv_path)
    df_suspicious = pd.read_csv(suspicious_csv_path)

    # Step 2 — Validate all RF_FEATURE_NAMES columns are present in both DataFrames.
    missing_benign = [c for c in RF_FEATURE_NAMES if c not in df_benign.columns]
    missing_suspicious = [c for c in RF_FEATURE_NAMES if c not in df_suspicious.columns]
    missing = sorted(set(missing_benign + missing_suspicious))
    if missing:
        raise ValueError(f"CSV missing expected RF feature columns: {missing}")

    # Step 3 — Combine and split into X, y.
    df = pd.concat([df_benign, df_suspicious], ignore_index=True)
    X = df[RF_FEATURE_NAMES].copy()
    y = df["label"].copy()

    n_benign = int((y == 0).sum())
    n_suspicious = int((y == 1).sum())
    n_total = int(len(y))

    # Step 4 — 5-fold stratified cross-validation.
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    clf_cv = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", random_state=random_state
    )
    cv_results = cross_validate(
        clf_cv, X, y, cv=cv,
        scoring=["precision", "recall", "f1", "roc_auc"],
        return_train_score=False,
    )

    # Step 5 — Train final model on full dataset.
    final_clf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", random_state=random_state
    )
    final_clf.fit(X, y)

    # Step 6 — Permutation feature importance (n_repeats_importance repeats).
    importance_dict = feature_permutation_importance(
        final_clf, X, n_repeats=n_repeats_importance, random_state=random_state
    )

    # Step 7 — Persist artifact.
    artifact = {
        "model": final_clf,
        "feature_names": RF_FEATURE_NAMES,
        "cv_metrics": {
            "precision_mean": float(cv_results["test_precision"].mean()),
            "precision_std":  float(cv_results["test_precision"].std()),
            "recall_mean":    float(cv_results["test_recall"].mean()),
            "recall_std":     float(cv_results["test_recall"].std()),
            "f1_mean":        float(cv_results["test_f1"].mean()),
            "f1_std":         float(cv_results["test_f1"].std()),
            "roc_auc_mean":   float(cv_results["test_roc_auc"].mean()),
            "roc_auc_std":    float(cv_results["test_roc_auc"].std()),
        },
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)

    # Step 8 — Save docs/phase7b_metrics.json.
    metrics_data = {
        "phase": "7B",
        "n_benign":    n_benign,
        "n_suspicious": n_suspicious,
        "n_total":     n_total,
        "feature_set": RF_FEATURE_NAMES,
        "dropped_features": ["open_process_suspicious_access", "hour_of_day"],
        "cv_folds": 5,
        "cv_results": {
            "precision": {
                "mean": float(cv_results["test_precision"].mean()),
                "std":  float(cv_results["test_precision"].std()),
                "per_fold": [float(v) for v in cv_results["test_precision"]],
            },
            "recall": {
                "mean": float(cv_results["test_recall"].mean()),
                "std":  float(cv_results["test_recall"].std()),
                "per_fold": [float(v) for v in cv_results["test_recall"]],
            },
            "f1": {
                "mean": float(cv_results["test_f1"].mean()),
                "std":  float(cv_results["test_f1"].std()),
                "per_fold": [float(v) for v in cv_results["test_f1"]],
            },
            "roc_auc": {
                "mean": float(cv_results["test_roc_auc"].mean()),
                "std":  float(cv_results["test_roc_auc"].std()),
                "per_fold": [float(v) for v in cv_results["test_roc_auc"]],
            },
        },
        "feature_importance": importance_dict,
        "model_path": str(model_path),
    }
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_path, "w") as fh:
        json.dump(metrics_data, fh, indent=2)

    # Step 9 — Print to console.
    cv_metrics = artifact["cv_metrics"]
    logger.info("[train] n_benign=%d  n_suspicious=%d  n_total=%d", n_benign, n_suspicious, n_total)
    logger.info(
        "[train] Precision  %.4f ± %.4f",
        cv_metrics["precision_mean"], cv_metrics["precision_std"],
    )
    logger.info(
        "[train] Recall     %.4f ± %.4f",
        cv_metrics["recall_mean"], cv_metrics["recall_std"],
    )
    logger.info(
        "[train] F1         %.4f ± %.4f",
        cv_metrics["f1_mean"], cv_metrics["f1_std"],
    )
    logger.info(
        "[train] ROC-AUC    %.4f ± %.4f",
        cv_metrics["roc_auc_mean"], cv_metrics["roc_auc_std"],
    )
    logger.info("[train] Top 5 features by permutation importance:")
    for feat, delta in list(importance_dict.items())[:5]:
        logger.info("  %-40s  mean_delta=% .6f", feat, delta)
    logger.info("[train] Model saved:   %s", model_path)
    logger.info("[train] Metrics saved: %s", metrics_path)

    # Step 10 — Return metadata dict.
    return {
        "model_path": str(model_path),
        "n_train": n_total,
        "n_features": len(RF_FEATURE_NAMES),
        "cv_metrics": cv_metrics,
        "permutation_importance": importance_dict,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    train_and_persist()
