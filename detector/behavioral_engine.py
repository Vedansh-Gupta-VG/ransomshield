"""
detector/behavioral_engine.py
==============================
Unified behavioral detection engine - the analytical core of RansomShield.

Implements the full risk scoring formula:
  risk_score = w1*entropy + w2*io_rate + w3*cpu_usage
             + w4*file_change_rate + w5*network_score

Architecture:
  BaselineModel   → learns normal process behavior over N seconds
  SlidingWindow   → maintains a rolling buffer of the last T seconds of signals
  SignalCorrelator → detects joint signal conditions (entropy high AND io high)
  BehavioralEngine → orchestrates all components, outputs structured Alert

Output:
  Alert dataclass with timestamp, risk_score, severity, contributing features
  Also emits to SIEM via siem_forwarder.emit_json_alert()
"""

import time
import math
import json
import logging
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Optional
import datetime

log = logging.getLogger("ransomshield.engine")

# ── Scoring weights (sum = 1.0) ────────────────────────────────────────────────
WEIGHTS = {
    "entropy":           0.30,
    "io_rate":           0.25,
    "cpu_usage":         0.20,
    "file_change_rate":  0.15,
    "network_score":     0.10,
}

SEVERITY_THRESHOLDS = {
    "CRITICAL": 0.80,
    "HIGH":     0.55,
    "MEDIUM":   0.30,
    "LOW":      0.00,
}

# ── Alert dataclass ────────────────────────────────────────────────────────────

@dataclass
class Alert:
    timestamp:    str
    risk_score:   float
    severity:     str
    process_name: str
    pid:          int

    # Contributing signal scores (normalized 0–1 each)
    entropy_score:       float = 0.0
    io_score:            float = 0.0
    cpu_score:           float = 0.0
    file_change_score:   float = 0.0
    network_score:       float = 0.0

    # Raw values for forensics
    entropy_mean:        float = 0.0
    entropy_slope:       float = 0.0
    io_write_mb:         float = 0.0
    cpu_percent:         float = 0.0
    file_mods_3s:        int   = 0
    extension_changes:   int   = 0
    rename_events:       int   = 0

    # Correlation flags
    joint_entropy_io:    bool  = False
    joint_entropy_cpu:   bool  = False
    rapid_rename:        bool  = False
    extension_change:    bool  = False

    # Model info
    model_used:          str   = "behavioral_engine"
    correlated_incident: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def score_to_severity(score: float) -> str:
    for label, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return label
    return "LOW"


# ── Sliding window ─────────────────────────────────────────────────────────────

class SlidingWindow:
    """
    Maintains a time-bounded rolling buffer of signal readings.
    Readings older than window_sec are automatically evicted.
    Provides statistical aggregates: mean, max, slope, variance.
    """

    def __init__(self, window_sec: float = 30.0, max_samples: int = 200):
        self.window_sec  = window_sec
        self.max_samples = max_samples
        # deque of (timestamp, value)
        self._data: deque = deque(maxlen=max_samples)
        self._lock = threading.Lock()

    def push(self, value: float, ts: Optional[float] = None):
        t = ts or time.time()
        with self._lock:
            self._data.append((t, value))
            self._evict()

    def _evict(self):
        cutoff = time.time() - self.window_sec
        while self._data and self._data[0][0] < cutoff:
            self._data.popleft()

    def values(self) -> list[float]:
        self._evict()
        with self._lock:
            return [v for _, v in self._data]

    def mean(self) -> float:
        v = self.values()
        return sum(v) / len(v) if v else 0.0

    def maximum(self) -> float:
        v = self.values()
        return max(v) if v else 0.0

    def variance(self) -> float:
        v = self.values()
        if len(v) < 2:
            return 0.0
        m = sum(v) / len(v)
        return sum((x - m) ** 2 for x in v) / len(v)

    def slope(self) -> float:
        """Linear regression slope - positive = rising signal."""
        v = self.values()
        n = len(v)
        if n < 2:
            return 0.0
        xs = list(range(n))
        x_mean = (n - 1) / 2.0
        y_mean = sum(v) / n
        num = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(xs, v))
        den = sum((xi - x_mean) ** 2 for xi in xs)
        return num / den if den else 0.0

    def rate_per_sec(self) -> float:
        """Events per second in the current window."""
        with self._lock:
            self._evict()
            if not self._data:
                return 0.0
            span = self._data[-1][0] - self._data[0][0]
            return len(self._data) / max(span, 1.0)

    def __len__(self) -> int:
        return len(self._data)


# ── Baseline model ─────────────────────────────────────────────────────────────

class BaselineModel:
    """
    Learns the normal behavioral baseline of the system over an observation period.
    After learning, it returns a deviation score (0–1) for each new reading.

    Technique: maintains exponential moving average + std for each signal.
    Deviation = |value - mean| / (std + epsilon), clipped to [0, 1].
    """

    def __init__(self, alpha: float = 0.05):
        # alpha: EMA smoothing factor - lower = slower adaptation to new values
        self._alpha  = alpha
        self._means: dict[str, float] = {}
        self._vars:  dict[str, float] = {}
        self._n:     dict[str, int]   = {}

    def update(self, signal_name: str, value: float):
        """Online update of EMA mean and variance for a named signal."""
        if signal_name not in self._means:
            self._means[signal_name] = value
            self._vars[signal_name]  = 0.0
            self._n[signal_name]     = 1
            return

        old_mean = self._means[signal_name]
        new_mean = (1 - self._alpha) * old_mean + self._alpha * value
        new_var  = (1 - self._alpha) * (self._vars[signal_name] + self._alpha * (value - old_mean) ** 2)

        self._means[signal_name] = new_mean
        self._vars[signal_name]  = new_var
        self._n[signal_name]    += 1

    def deviation_score(self, signal_name: str, value: float) -> float:
        """
        Returns normalized deviation [0, 1].
        0 = within normal range, 1 = extreme outlier.
        """
        if signal_name not in self._means or self._n[signal_name] < 5:
            # Not enough data - treat as baseline
            return 0.0

        mean = self._means[signal_name]
        std  = math.sqrt(self._vars[signal_name] + 1e-9)
        z    = abs(value - mean) / std

        # Sigmoid squash: z=2 → 0.73, z=3 → 0.95, z=4 → 0.99
        return 1.0 / (1.0 + math.exp(-0.8 * (z - 2.5)))

    def is_trained(self, min_samples: int = 10) -> bool:
        return all(n >= min_samples for n in self._n.values())


# ── Signal correlator ──────────────────────────────────────────────────────────

class SignalCorrelator:
    """
    Detects joint signal conditions that are individually explainable
    but together strongly indicate ransomware.

    Key correlations (from RanSAP behavioral analysis):
      entropy_high AND io_high   → encryption sweep in progress
      entropy_high AND cpu_high  → active encryption computation
      rapid_renames              → Ryuk/LockBit extension renaming phase
      extension_changes          → file-type camouflage
    """

    ENTROPY_HIGH_THRESHOLD   = 0.88   # normalized
    IO_HIGH_THRESHOLD_MB     = 20.0   # MB/s write
    CPU_HIGH_THRESHOLD       = 40.0   # %
    RENAME_RATE_THRESHOLD    = 2.0    # renames/sec in window
    CORRELATION_BOOST        = 0.15   # score added when correlation confirmed

    def correlate(self,
                  entropy_mean:   float,
                  io_write_mb:    float,
                  cpu_percent:    float,
                  rename_rate:    float,
                  ext_change_count: int) -> tuple[float, dict]:
        """
        Returns (score_boost, flags_dict).
        score_boost is added to the base risk_score when correlations hold.
        """
        boost = 0.0
        flags: dict[str, bool] = {
            "joint_entropy_io":  False,
            "joint_entropy_cpu": False,
            "rapid_rename":      False,
            "extension_change":  False,
        }

        entropy_high = entropy_mean >= self.ENTROPY_HIGH_THRESHOLD
        io_high      = io_write_mb  >= self.IO_HIGH_THRESHOLD_MB
        cpu_high     = cpu_percent  >= self.CPU_HIGH_THRESHOLD

        if entropy_high and io_high:
            flags["joint_entropy_io"] = True
            boost += self.CORRELATION_BOOST

        if entropy_high and cpu_high:
            flags["joint_entropy_cpu"] = True
            boost += self.CORRELATION_BOOST * 0.5

        if rename_rate >= self.RENAME_RATE_THRESHOLD:
            flags["rapid_rename"] = True
            boost += self.CORRELATION_BOOST

        if ext_change_count > 0:
            flags["extension_change"] = True
            boost += self.CORRELATION_BOOST * 0.7

        return min(boost, 0.40), flags   # cap correlation boost at 0.40


# ── Incident correlator ────────────────────────────────────────────────────────

class IncidentCorrelator:
    """
    Groups related alerts into incidents.
    If multiple HIGH/CRITICAL alerts fire within incident_window_sec
    they are linked under a single incident ID.
    """

    def __init__(self, window_sec: float = 60.0):
        self._window    = window_sec
        self._incidents: dict[str, list] = {}   # incident_id → [alert timestamps]
        self._last_id:   Optional[str]   = None
        self._last_ts:   float = 0.0

    def correlate(self, alert: Alert) -> str:
        """Returns incident ID that this alert belongs to."""
        now = time.time()

        if (self._last_id and alert.severity in ("HIGH", "CRITICAL")
                and (now - self._last_ts) < self._window):
            self._incidents[self._last_id].append(alert.timestamp)
            return self._last_id

        # New incident
        incident_id = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')}-{alert.severity[:3]}"
        self._incidents[incident_id] = [alert.timestamp]
        self._last_id = incident_id
        self._last_ts = now
        return incident_id


# ── Main engine ────────────────────────────────────────────────────────────────

class BehavioralEngine:
    """
    Orchestrates all detection components.

    Usage:
      engine = BehavioralEngine()
      engine.ingest(signal_dict)   # called by monitor.py every event
      alert = engine.last_alert    # read current alert
    """

    def __init__(self, window_sec: float = 30.0):
        # Sliding windows for each signal
        self.entropy_window    = SlidingWindow(window_sec)
        self.io_write_window   = SlidingWindow(window_sec)
        self.cpu_window        = SlidingWindow(window_sec)
        self.file_mod_window   = SlidingWindow(window_sec)
        self.rename_window     = SlidingWindow(window_sec)

        self.baseline    = BaselineModel(alpha=0.05)
        self.correlator  = SignalCorrelator()
        self.incidents   = IncidentCorrelator(window_sec=60.0)

        self.last_alert: Optional[Alert] = None
        self._lock = threading.Lock()

    def ingest(self,
               process_name:    str,
               pid:             int,
               entropy_norm:    float,
               io_write_mb:     float,
               io_read_mb:      float,
               cpu_percent:     float,
               file_mod_count:  int,
               rename_count:    int   = 0,
               ext_change_count: int  = 0,
               network_score:   float = 0.0) -> Alert:
        """
        Ingest one behavioral reading and return a scored Alert.
        Thread-safe - can be called from watchdog event threads.
        """
        now = time.time()

        # Push to sliding windows
        self.entropy_window.push(entropy_norm, now)
        self.io_write_window.push(io_write_mb, now)
        self.cpu_window.push(cpu_percent, now)
        self.file_mod_window.push(float(file_mod_count), now)
        self.rename_window.push(float(rename_count), now)

        # Update baseline (adapts to what's normal for this host)
        self.baseline.update("entropy", entropy_norm)
        self.baseline.update("io_write", io_write_mb)
        self.baseline.update("cpu", cpu_percent)
        self.baseline.update("file_mods", float(file_mod_count))

        # ── Compute individual signal scores ──────────────────────────────────
        # Each score is the max of: absolute normalized value + baseline deviation
        # This means both "high absolute value" AND "unusual spike" trigger detection.

        entropy_mean  = self.entropy_window.mean()
        entropy_slope = self.entropy_window.slope()
        entropy_abs   = min(entropy_mean / 1.0, 1.0)                    # 0–1
        entropy_dev   = self.baseline.deviation_score("entropy", entropy_norm)
        entropy_score = min(max(entropy_abs * 0.6 + entropy_dev * 0.4 + max(entropy_slope * 5, 0), 0), 1)

        io_abs        = min(self.io_write_window.mean() / 100.0, 1.0)   # 100 MB/s = max
        io_dev        = self.baseline.deviation_score("io_write", io_write_mb)
        io_score      = min(io_abs * 0.5 + io_dev * 0.5, 1.0)

        cpu_abs       = min(self.cpu_window.mean() / 100.0, 1.0)
        cpu_dev       = self.baseline.deviation_score("cpu", cpu_percent)
        cpu_score     = min(cpu_abs * 0.5 + cpu_dev * 0.5, 1.0)

        fc_abs        = min(self.file_mod_window.rate_per_sec() / 10.0, 1.0)   # 10 mods/s = max
        fc_dev        = self.baseline.deviation_score("file_mods", float(file_mod_count))
        file_change_score = min(fc_abs * 0.6 + fc_dev * 0.4, 1.0)

        net_score = min(network_score, 1.0)

        # ── Weighted risk score ────────────────────────────────────────────────
        base_risk = (
            WEIGHTS["entropy"]          * entropy_score +
            WEIGHTS["io_rate"]          * io_score +
            WEIGHTS["cpu_usage"]        * cpu_score +
            WEIGHTS["file_change_rate"] * file_change_score +
            WEIGHTS["network_score"]    * net_score
        )

        # ── Signal correlation boost ──────────────────────────────────────────
        rename_rate = self.rename_window.rate_per_sec()
        boost, corr_flags = self.correlator.correlate(
            entropy_mean, io_write_mb, cpu_percent, rename_rate, ext_change_count
        )

        risk_score = round(min(base_risk + boost, 1.0), 4)
        severity   = score_to_severity(risk_score)

        alert = Alert(
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            risk_score=risk_score,
            severity=severity,
            process_name=process_name,
            pid=pid,
            # Component scores
            entropy_score=round(entropy_score, 4),
            io_score=round(io_score, 4),
            cpu_score=round(cpu_score, 4),
            file_change_score=round(file_change_score, 4),
            network_score=round(net_score, 4),
            # Raw values
            entropy_mean=round(entropy_mean, 4),
            entropy_slope=round(entropy_slope, 6),
            io_write_mb=round(io_write_mb, 3),
            cpu_percent=round(cpu_percent, 2),
            file_mods_3s=file_mod_count,
            extension_changes=ext_change_count,
            rename_events=rename_count,
            # Correlation
            **corr_flags,
        )

        # Incident grouping
        if severity in ("HIGH", "CRITICAL"):
            alert.correlated_incident = self.incidents.correlate(alert)

        with self._lock:
            self.last_alert = alert

        if severity in ("HIGH", "CRITICAL"):
            log.warning("ALERT [%s] score=%.3f entropy=%.3f io=%.1fMB/s cpu=%.1f%% corr=%s",
                        severity, risk_score, entropy_mean, io_write_mb, cpu_percent,
                        alert.correlated_incident)

        return alert
