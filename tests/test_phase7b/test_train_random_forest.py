from ml.training.train_random_forest import RF_FEATURE_NAMES

def test_rf_feature_names_count():
    assert len(RF_FEATURE_NAMES) == 28

def test_rf_feature_names_excludes_open_process_suspicious_access():
    assert "open_process_suspicious_access" not in RF_FEATURE_NAMES

def test_rf_feature_names_excludes_hour_of_day():
    assert "hour_of_day" not in RF_FEATURE_NAMES

def test_rf_feature_names_excludes_label():
    assert "label" not in RF_FEATURE_NAMES

def test_benign_csv_exists_and_has_rf_features():
    import pandas as pd
    from ml.training.train_random_forest import BENIGN_CSV_PATH
    assert BENIGN_CSV_PATH.exists()
    df = pd.read_csv(BENIGN_CSV_PATH)
    for col in RF_FEATURE_NAMES:
        assert col in df.columns, f"Missing column in benign CSV: {col}"

def test_suspicious_csv_exists_and_has_rf_features():
    import pandas as pd
    from ml.training.train_random_forest import SUSPICIOUS_CSV_PATH
    assert SUSPICIOUS_CSV_PATH.exists()
    df = pd.read_csv(SUSPICIOUS_CSV_PATH)
    for col in RF_FEATURE_NAMES:
        assert col in df.columns, f"Missing column in suspicious CSV: {col}"

def test_train_and_persist_creates_model_artifact(tmp_path):
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "random_forest.joblib"
    metrics_out = tmp_path / "phase7b_metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    assert model_out.exists()

def test_artifact_has_required_keys(tmp_path):
    import joblib
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "rf.joblib"
    metrics_out = tmp_path / "metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    artifact = joblib.load(model_out)
    assert "model" in artifact
    assert "feature_names" in artifact
    assert "cv_metrics" in artifact

def test_artifact_feature_names_matches_rf_feature_names(tmp_path):
    import joblib
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "rf.joblib"
    metrics_out = tmp_path / "metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    artifact = joblib.load(model_out)
    assert artifact["feature_names"] == RF_FEATURE_NAMES

def test_cv_metrics_has_required_keys(tmp_path):
    import joblib
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "rf.joblib"
    metrics_out = tmp_path / "metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    cv = joblib.load(model_out)["cv_metrics"]
    for key in [
        "precision_mean", "precision_std",
        "recall_mean",    "recall_std",
        "f1_mean",        "f1_std",
        "roc_auc_mean",   "roc_auc_std",
    ]:
        assert key in cv, f"Missing cv_metrics key: {key}"

def test_roc_auc_better_than_random(tmp_path):
    import joblib
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "rf.joblib"
    metrics_out = tmp_path / "metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    roc = joblib.load(model_out)["cv_metrics"]["roc_auc_mean"]
    assert roc > 0.5, f"ROC-AUC {roc} is not better than random (0.5)"

def test_metrics_json_created_and_valid(tmp_path):
    import json
    from ml.training.train_random_forest import train_and_persist
    model_out   = tmp_path / "rf.joblib"
    metrics_out = tmp_path / "metrics.json"
    train_and_persist(model_path=model_out, metrics_path=metrics_out)
    assert metrics_out.exists()
    with open(metrics_out) as fh:
        data = json.load(fh)
    assert data["phase"] == "7B"
    assert data["n_total"] == data["n_benign"] + data["n_suspicious"]
    assert set(data["feature_set"]) == set(RF_FEATURE_NAMES)
