"""
backend/ml_inference.py
========================
Loads the trained model bundle (best_model + IsolationForest + scaler) and
exposes score() and feature_importance() used by the live agent-metrics
endpoint and the public demo endpoint.

Feature order MUST match ml/train_model.py's FEATURE_COLS exactly.
"""
import joblib
import numpy as np
from . import config

FEATURE_COLS = [
    "entropy_mean",
    "entropy_slope",
    "entropy_max",
    "entropy_std",
    "write_rate_mb_s",
    "write_events_per_s",
    "read_events_per_s",
    "lba_variance",
]

# Human-readable labels for the frontend, since raw column names read poorly
# in a chart legend.
FEATURE_LABELS = {
    "entropy_mean": "Avg. data randomness",
    "entropy_slope": "Randomness trend",
    "entropy_max": "Peak data randomness",
    "entropy_std": "Randomness volatility",
    "write_rate_mb_s": "Write throughput (MB/s)",
    "write_events_per_s": "Write events/sec",
    "read_events_per_s": "Read events/sec",
    "lba_variance": "Disk access spread",
}

_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(config.MODEL_PATH)
    return _bundle


def score(features: dict) -> dict:
    """
    features: dict with keys matching FEATURE_COLS (missing keys default to 0).
    Returns: {risk_score: float 0-1, severity: str, model_prob: float, anomaly_score: float}
    """
    bundle = _load()
    model = bundle["rf"]        # key name kept for compatibility with train_model.py output
    iso = bundle["iso"]
    scaler = bundle["scaler"]

    x = np.array([[features.get(c, 0.0) for c in FEATURE_COLS]], dtype=float)
    x_scaled = scaler.transform(x)

    model_prob = float(model.predict_proba(x_scaled)[0, 1])
    iso_raw = float(iso.score_samples(x_scaled)[0])
    iso_norm = float(np.clip(iso_raw + 0.5, 0, 1))

    risk_score = 0.70 * model_prob + 0.30 * (1.0 - iso_norm)
    risk_score = float(np.clip(risk_score, 0, 1))

    if risk_score >= 0.85:
        severity = "critical"
    elif risk_score >= 0.65:
        severity = "high"
    elif risk_score >= 0.40:
        severity = "medium"
    else:
        severity = "low"

    return {
        "risk_score": round(risk_score, 4),
        "severity": severity,
        "model_prob": round(model_prob, 4),
        "anomaly_score": round(1.0 - iso_norm, 4),
    }


def feature_importance() -> list[dict]:
    """
    Returns the REAL trained model's feature importances (not fabricated),
    sorted descending, with human-readable labels for the UI.
    """
    bundle = _load()
    model = bundle["rf"]
    if not hasattr(model, "feature_importances_"):
        return []

    importances = model.feature_importances_
    rows = [
        {
            "feature": col,
            "label": FEATURE_LABELS.get(col, col),
            "importance": round(float(imp), 4),
        }
        for col, imp in zip(FEATURE_COLS, importances)
    ]
    rows.sort(key=lambda r: r["importance"], reverse=True)
    return rows
