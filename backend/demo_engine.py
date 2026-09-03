"""
backend/demo_engine.py
=======================
Serves the public zero-install demo timeline.

IMPORTANT: this does NOT fabricate feature values. backend/data/demo_timeline.json
was built by scoring every real row in the trained dataset (data/dataset.csv)
through the actual model, then selecting 20 real rows spanning the risk-score
range (0.27 -> 0.995) in ascending order. This guarantees the demo timeline
is consistent with what the model actually learned, instead of a hand-guessed
"benign = low entropy, ransomware = high entropy" curve that turned out to be
wrong (real benign/ransomware entropy distributions overlap heavily; the
model separates them on a multivariate combination of features, not any
single one).

To regenerate after retraining the model: rerun the row-selection script
against the new data/dataset.csv + ml/model.pkl and overwrite
backend/data/demo_timeline.json.
"""
import json
import os

_TIMELINE_PATH = os.path.join(os.path.dirname(__file__), "data", "demo_timeline.json")
_timeline = None


def _load_timeline() -> list[dict]:
    global _timeline
    if _timeline is None:
        with open(_TIMELINE_PATH) as f:
            _timeline = json.load(f)
    return _timeline


def generate_demo_step(step: int) -> dict:
    timeline = _load_timeline()
    step = max(0, min(step, len(timeline) - 1))
    return dict(timeline[step])


def timeline_length() -> int:
    return len(_load_timeline())
