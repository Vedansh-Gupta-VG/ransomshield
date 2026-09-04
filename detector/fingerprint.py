"""
detector/fingerprint.py
========================
Execution Fingerprint - aggregates all behavioral signals into one scored object.

The "execution fingerprint" is the core concept of this project:
  A multi-dimensional behavioral vector that distinguishes malicious encryption
  (ransomware) from legitimate encryption (7-Zip, VeraCrypt, backup agents).

Feature vector (matches ml/dataset.csv columns):
  ┌─────────────────────────────┬──────────────────────────────────────────┐
  │ Feature                     │ Description                              │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ entropy_mean                │ Mean normalized entropy (10-sample window)│
  │ entropy_slope               │ Linear slope of entropy rise             │
  │ entropy_max                 │ Peak entropy in window                   │
  │ io_read_rate_mb             │ Disk read rate (MB/s)                    │
  │ io_write_rate_mb            │ Disk write rate (MB/s)                   │
  │ rw_ratio                    │ write / (read + write)                   │
  │ cpu_percent                 │ CPU usage %                              │
  │ file_mod_count_3s           │ File modifications in last 3 seconds     │
  │ files_with_entropy_gt7      │ Files with entropy > 7.0 bits            │
  └─────────────────────────────┴──────────────────────────────────────────┘

Threat score formula (ensemble):
  score = 0.70 × P(ransomware | RF) + 0.30 × (1 − ISO_norm)

Reference: Hirano et al., RanSAP (2022); RanSMAP (2024)
"""

import time
import numpy as np
from dataclasses import dataclass, field
from typing import Optional

from detector.entropy import (
    calculate_entropy_normalized,
    count_high_entropy_files,
    entropy_slope,
)


# ── Severity thresholds ───────────────────────────────────────────────────────

SEVERITY_THRESHOLDS = {
    "CRITICAL": 0.80,
    "HIGH":     0.55,
    "MEDIUM":   0.30,
    "LOW":      0.00,
}


def score_to_severity(score: float) -> str:
    for label, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return label
    return "LOW"


# ── Core dataclass ────────────────────────────────────────────────────────────

@dataclass
class ExecutionFingerprint:
    """
    Full behavioral fingerprint for one process at one point in time.
    This is the unit of analysis passed to the ML model.
    """

    # Identity
    process_name: str
    pid: int
    timestamp: float = field(default_factory=time.time)

    # Entropy features
    entropy_window: list[float] = field(default_factory=list)   # 10 normalized values
    entropy_mean: float = 0.0
    entropy_slope: float = 0.0
    entropy_max: float = 0.0

    # I/O features
    io_read_rate_mb: float = 0.0
    io_write_rate_mb: float = 0.0
    rw_ratio: float = 0.0

    # CPU features
    cpu_percent: float = 0.0

    # File activity features
    file_mod_count_3s: int = 0
    files_with_entropy_gt7: int = 0

    # Scoring (populated by score())
    threat_score: float = 0.0
    severity: str = "LOW"
    model_used: str = "not_scored"

    def as_feature_vector(self) -> np.ndarray:
        """Return feature vector matching dataset column order."""
        return np.array([[
            self.entropy_mean,
            self.entropy_slope,
            self.entropy_max,
            self.io_read_rate_mb,
            self.io_write_rate_mb,
            self.rw_ratio,
            self.cpu_percent,
            float(self.file_mod_count_3s),
            float(self.files_with_entropy_gt7),
        ]])

    def to_log_row(self) -> dict:
        """Flat dict for CSV logging."""
        return {
            "timestamp": self.timestamp,
            "process_name": self.process_name,
            "pid": self.pid,
            "entropy_mean": round(self.entropy_mean, 4),
            "entropy_slope": round(self.entropy_slope, 6),
            "entropy_max": round(self.entropy_max, 4),
            "io_read_rate_mb": round(self.io_read_rate_mb, 4),
            "io_write_rate_mb": round(self.io_write_rate_mb, 4),
            "rw_ratio": round(self.rw_ratio, 4),
            "cpu_percent": round(self.cpu_percent, 2),
            "file_mod_count_3s": self.file_mod_count_3s,
            "files_with_entropy_gt7": self.files_with_entropy_gt7,
            "threat_score": round(self.threat_score, 4),
            "severity": self.severity,
        }


# ── Builder ───────────────────────────────────────────────────────────────────

def build_fingerprint(
    process_name: str,
    pid: int,
    entropy_window: list[float],
    io_read_rate_mb: float,
    io_write_rate_mb: float,
    cpu_percent: float,
    file_mod_count_3s: int,
    monitored_files: Optional[list[str]] = None,
) -> ExecutionFingerprint:
    """
    Construct an ExecutionFingerprint from raw sensor readings.

    Args:
        monitored_files: If provided, count_high_entropy_files() is called.
                         Otherwise files_with_entropy_gt7 defaults to 0.
    """
    ew = entropy_window or [0.0]

    e_mean  = float(np.mean(ew))
    e_slope = entropy_slope(ew)
    e_max   = float(np.max(ew))

    total_io = io_read_rate_mb + io_write_rate_mb
    rw = io_write_rate_mb / (total_io + 1e-9)

    high_ent_count = 0
    if monitored_files:
        high_ent_count = count_high_entropy_files(monitored_files, threshold_bits=7.0)

    return ExecutionFingerprint(
        process_name=process_name,
        pid=pid,
        entropy_window=ew,
        entropy_mean=round(e_mean, 4),
        entropy_slope=round(e_slope, 6),
        entropy_max=round(e_max, 4),
        io_read_rate_mb=round(io_read_rate_mb, 4),
        io_write_rate_mb=round(io_write_rate_mb, 4),
        rw_ratio=round(rw, 4),
        cpu_percent=round(cpu_percent, 2),
        file_mod_count_3s=file_mod_count_3s,
        files_with_entropy_gt7=high_ent_count,
    )


def score_fingerprint(fp: ExecutionFingerprint, model_bundle: Optional[dict] = None) -> ExecutionFingerprint:
    """
    Score an ExecutionFingerprint using the ML model bundle or rule-based fallback.
    Mutates and returns the same fingerprint object (sets threat_score, severity).
    """
    X = fp.as_feature_vector()

    if model_bundle is not None:
        rf     = model_bundle["rf"]
        iso    = model_bundle["iso"]
        scaler = model_bundle.get("scaler")

        X_scaled = scaler.transform(X) if scaler else X
        rf_prob  = float(rf.predict_proba(X_scaled)[0][1])
        iso_raw  = float(iso.score_samples(X_scaled)[0])
        iso_norm = max(0.0, min(1.0, iso_raw + 0.5))

        fp.threat_score = round(0.70 * rf_prob + 0.30 * (1.0 - iso_norm), 4)
        fp.model_used   = "RandomForest+IsolationForest"
    else:
        # Rule-based fallback
        score = 0.0
        if fp.entropy_mean  > 0.90: score += 0.35
        if fp.entropy_slope > 0.05: score += 0.20
        if fp.rw_ratio      > 0.75: score += 0.20
        if fp.file_mod_count_3s > 3: score += 0.15
        if fp.io_write_rate_mb  > 20: score += 0.10
        fp.threat_score = round(min(score, 1.0), 4)
        fp.model_used   = "rule-based"

    fp.severity = score_to_severity(fp.threat_score)
    return fp
