"""
detector/cpu_tracker.py
========================
CPU usage tracker per process.

Ransomware exhibits a characteristic CPU spike during the encryption phase:
  - AES-256 encryption is CPU-intensive
  - Spike typically starts 1–3s after rapid file modification begins
  - Spike is sustained (not brief like a compile step)

Features extracted:
  cpu_percent          – instantaneous CPU % of the process
  cpu_sustained_spike  – True if CPU > threshold for > spike_duration_sec

"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

log = logging.getLogger("ransomshield.cpu_tracker")

# Thresholds derived from RanSAP dataset analysis
CPU_SPIKE_THRESHOLD   = 40.0   # % - ransomware typically runs 40–95% during encryption
CPU_SPIKE_DURATION    = 2.0    # seconds - must be sustained to count
SAMPLE_INTERVAL       = 0.5    # seconds between samples


@dataclass
class CPUSnapshot:
    pid: Optional[int]
    process_name: str
    cpu_percent: float
    cpu_spike_detected: bool
    sustained_spike_sec: float       # how long the spike has lasted
    timestamp: float = field(default_factory=time.time)


class CPUTracker:
    """
    Tracks CPU usage for a specific PID.
    Detects sustained spikes characteristic of encryption workloads.
    """

    def __init__(self, pid: int, spike_threshold: float = CPU_SPIKE_THRESHOLD):
        self.pid = pid
        self.spike_threshold = spike_threshold
        self._process = None
        self._spike_start: Optional[float] = None

        if PSUTIL_AVAILABLE:
            try:
                self._process = psutil.Process(pid)
                # First call always returns 0.0 (psutil needs a reference point)
                self._process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                log.warning("Cannot track CPU for PID %d: %s", pid, e)

    def snapshot(self, interval: float = SAMPLE_INTERVAL) -> CPUSnapshot:
        name = "unknown"
        cpu = 0.0

        if self._process and PSUTIL_AVAILABLE:
            try:
                name = self._process.name()
                cpu  = self._process.cpu_percent(interval=interval)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        now = time.time()
        if cpu >= self.spike_threshold:
            if self._spike_start is None:
                self._spike_start = now
            sustained = now - self._spike_start
        else:
            self._spike_start = None
            sustained = 0.0

        spike_detected = sustained >= CPU_SPIKE_DURATION

        return CPUSnapshot(
            pid=self.pid,
            process_name=name,
            cpu_percent=round(cpu, 2),
            cpu_spike_detected=spike_detected,
            sustained_spike_sec=round(sustained, 2),
        )


def get_system_cpu_percent() -> float:
    """System-wide CPU % (1-second sample)."""
    if not PSUTIL_AVAILABLE:
        return 0.0
    return psutil.cpu_percent(interval=1.0)


def find_high_cpu_processes(threshold: float = CPU_SPIKE_THRESHOLD) -> list[dict]:
    """
    Return all processes currently exceeding the CPU threshold.
    Used during live monitoring to identify suspicious processes.
    """
    if not PSUTIL_AVAILABLE:
        return []

    results = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            cpu = proc.cpu_percent(interval=0.1)
            if cpu >= threshold:
                results.append({
                    "pid": proc.pid,
                    "name": proc.name(),
                    "cpu_percent": cpu,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return sorted(results, key=lambda x: x["cpu_percent"], reverse=True)
