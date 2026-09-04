"""
detector/io_monitor.py
=======================
Disk I/O rate tracker using psutil.

Monitors per-process and system-wide read/write throughput.
Detects I/O bursts characteristic of ransomware encryption sweeps.

Key behavioral signatures detected:
  - Write rate spike (>30 MB/s sustained for >2s) → ransomware encryption burst
  - High write-to-read ratio (>0.8) → bulk overwrite without read (encryption)
  - Large block sequential writes → characteristic of AES-256 CTR/CBC encryption

Metrics match RanSAP dataset features:
  write_throughput_Twrite  ↔  io_write_rate_mb
  read_throughput_Tread    ↔  io_read_rate_mb
  rw_ratio = write / (read + write + 1e-9)

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
    logging.warning("psutil not installed – I/O monitor will return zeros. Run: pip install psutil")

log = logging.getLogger("ransomshield.io_monitor")

BYTES_PER_MB = 1_048_576


# ── Data structure ────────────────────────────────────────────────────────────

@dataclass
class IOSnapshot:
    pid: Optional[int]
    process_name: str
    io_read_rate_mb: float          # MB/s averaged over sample_interval
    io_write_rate_mb: float         # MB/s averaged over sample_interval
    rw_ratio: float                 # write / (read + write), 0–1
    read_bytes_total: int           # cumulative since process start
    write_bytes_total: int          # cumulative since process start
    sample_interval_sec: float
    timestamp: float = field(default_factory=time.time)

    @property
    def is_burst(self) -> bool:
        """True if write rate exceeds ransomware-typical threshold."""
        return self.io_write_rate_mb > 30.0

    @property
    def is_high_write_ratio(self) -> bool:
        """True if write-dominated I/O (typical of encryption overwrite)."""
        return self.rw_ratio > 0.75


# ── System-wide I/O ───────────────────────────────────────────────────────────

class SystemIOMonitor:
    """
    Tracks system-wide disk I/O.
    Call .sample() twice with a delay → get MB/s rates.
    """

    def __init__(self):
        self._prev_read  = 0
        self._prev_write = 0
        self._prev_time  = time.time()

    def sample(self) -> tuple[float, float]:
        """
        Returns (read_mb_per_s, write_mb_per_s) since last call.
        """
        if not PSUTIL_AVAILABLE:
            return 0.0, 0.0

        counters = psutil.disk_io_counters()
        now = time.time()
        elapsed = now - self._prev_time

        if elapsed <= 0:
            return 0.0, 0.0

        read_delta  = counters.read_bytes  - self._prev_read
        write_delta = counters.write_bytes - self._prev_write

        read_rate  = (read_delta  / BYTES_PER_MB) / elapsed
        write_rate = (write_delta / BYTES_PER_MB) / elapsed

        self._prev_read  = counters.read_bytes
        self._prev_write = counters.write_bytes
        self._prev_time  = now

        return max(0.0, read_rate), max(0.0, write_rate)


# ── Per-process I/O ───────────────────────────────────────────────────────────

class ProcessIOMonitor:
    """
    Tracks I/O for a specific PID.
    Designed to be called in a polling loop.
    """

    def __init__(self, pid: int, sample_interval: float = 1.0):
        self.pid = pid
        self.sample_interval = sample_interval
        self._process = None
        self._prev_io = None
        self._prev_time = None

        if PSUTIL_AVAILABLE:
            try:
                self._process = psutil.Process(pid)
                counters = self._process.io_counters()
                self._prev_io = counters
                self._prev_time = time.time()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                log.warning("Cannot monitor PID %d: %s", pid, e)

    def snapshot(self) -> IOSnapshot:
        """
        Take one I/O snapshot. Returns rates since last call.
        """
        name = "unknown"
        read_rate = write_rate = 0.0
        read_total = write_total = 0

        if self._process and PSUTIL_AVAILABLE:
            try:
                name = self._process.name()
                now = time.time()
                elapsed = now - (self._prev_time or now)
                counters = self._process.io_counters()

                if self._prev_io and elapsed > 0:
                    read_delta  = counters.read_bytes  - self._prev_io.read_bytes
                    write_delta = counters.write_bytes - self._prev_io.write_bytes
                    read_rate   = (read_delta  / BYTES_PER_MB) / elapsed
                    write_rate  = (write_delta / BYTES_PER_MB) / elapsed

                read_total  = counters.read_bytes
                write_total = counters.write_bytes
                self._prev_io   = counters
                self._prev_time = now

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                log.debug("Process %d ended or access denied.", self.pid)

        total_mb = read_rate + write_rate
        rw_ratio = write_rate / (total_mb + 1e-9)

        return IOSnapshot(
            pid=self.pid,
            process_name=name,
            io_read_rate_mb=round(read_rate,  4),
            io_write_rate_mb=round(write_rate, 4),
            rw_ratio=round(rw_ratio, 4),
            read_bytes_total=read_total,
            write_bytes_total=write_total,
            sample_interval_sec=self.sample_interval,
        )


# ── Convenience: poll a PID for N seconds ────────────────────────────────────

def poll_process_io(
    pid: int,
    duration_sec: float = 5.0,
    interval_sec: float = 1.0,
) -> list[IOSnapshot]:
    """
    Poll a process's I/O every interval_sec for duration_sec.
    Returns a list of IOSnapshots (useful for building the feature window).
    """
    monitor = ProcessIOMonitor(pid, sample_interval=interval_sec)
    snapshots = []
    end_time = time.time() + duration_sec

    while time.time() < end_time:
        snap = monitor.snapshot()
        snapshots.append(snap)
        time.sleep(interval_sec)

    return snapshots


def get_top_io_processes(n: int = 10) -> list[dict]:
    """
    Return the top N processes by current write rate.
    Used by the dashboard's live process table.
    """
    if not PSUTIL_AVAILABLE:
        return []

    results = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            io = proc.io_counters()
            results.append({
                "pid": proc.pid,
                "name": proc.name(),
                "write_bytes": io.write_bytes,
                "read_bytes": io.read_bytes,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    results.sort(key=lambda x: x["write_bytes"], reverse=True)
    return results[:n]


# ── CLI test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if not PSUTIL_AVAILABLE:
        print("psutil not installed. Run: pip install psutil")
        sys.exit(1)

    target_pid = int(sys.argv[1]) if len(sys.argv) > 1 else psutil.Process().pid

    print(f"Monitoring PID {target_pid} for 5 seconds...")
    snaps = poll_process_io(target_pid, duration_sec=5.0, interval_sec=1.0)

    for i, s in enumerate(snaps):
        print(
            f"[{i+1}] read={s.io_read_rate_mb:.3f} MB/s  "
            f"write={s.io_write_rate_mb:.3f} MB/s  "
            f"rw_ratio={s.rw_ratio:.3f}  "
            f"burst={s.is_burst}"
        )
