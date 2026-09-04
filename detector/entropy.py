"""
detector/entropy.py
====================
Shannon entropy calculation engine - upgraded from v1.

Changes over original entropy.py:
  - calculate_entropy_evolution()  : 10-point sliding window over time
  - calculate_entropy_normalized() : returns 0–1 (divide by log2(256) = 8)
  - batch_entropy()                : process a list of files efficiently
  - EntropySnapshot dataclass      : structured result with metadata

Used by:  fingerprint.py, backend/app.py, monitor.py
Dataset:  RanSAP stores normalized entropy (0–1). We match that convention.

"""

import math
import time
import os
from dataclasses import dataclass, field
from typing import Optional

# Maximum possible entropy for a byte stream = log2(256) = 8.0 bits
MAX_ENTROPY_BITS = 8.0


# ── Data structure ────────────────────────────────────────────────────────────

@dataclass
class EntropySnapshot:
    file_path: str
    entropy_bits: float            # Raw Shannon entropy (0–8 bits)
    entropy_normalized: float      # Divided by 8.0 → 0–1 (matches RanSAP convention)
    file_size_bytes: int
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None

    @property
    def is_high_entropy(self) -> bool:
        """True if entropy > 7.0 bits (strong indicator of encryption)."""
        return self.entropy_bits > 7.0

    @property
    def is_ransomware_range(self) -> bool:
        """True if entropy is in the 7.5–8.0 bit range typical of AES-256 ciphertext."""
        return self.entropy_bits >= 7.5


# ── Core calculation ──────────────────────────────────────────────────────────

def calculate_entropy(file_path: str) -> float:
    """
    Shannon entropy of a file in bits (0–8).
    Reads the full file as raw bytes.
    Returns 0.0 on error.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        n = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            p = count / n
            entropy -= p * math.log2(p)

        return entropy

    except Exception as e:
        return 0.0


def calculate_entropy_normalized(file_path: str) -> float:
    """
    Returns entropy as a fraction of maximum (0.0–1.0).
    Matches the convention used in the RanSAP dataset.
    """
    return calculate_entropy(file_path) / MAX_ENTROPY_BITS


def calculate_entropy_snapshot(file_path: str) -> EntropySnapshot:
    """
    Full structured result with metadata.
    """
    try:
        size = os.path.getsize(file_path)
        bits = calculate_entropy(file_path)
        return EntropySnapshot(
            file_path=file_path,
            entropy_bits=round(bits, 6),
            entropy_normalized=round(bits / MAX_ENTROPY_BITS, 6),
            file_size_bytes=size,
        )
    except Exception as e:
        return EntropySnapshot(
            file_path=file_path,
            entropy_bits=0.0,
            entropy_normalized=0.0,
            file_size_bytes=0,
            error=str(e),
        )


# ── Sliding window evolution ──────────────────────────────────────────────────

def calculate_entropy_evolution(
    file_path: str,
    windows: int = 10,
    interval_sec: float = 0.5,
) -> list[float]:
    """
    Captures entropy of a file at N points over time (normalized 0–1).

    In live monitoring, the file changes between reads (ransomware is writing).
    This gives us the SLOPE of entropy - a key feature distinguishing ransomware
    (sharp rising slope) from legitimate encryption (gradual or stable).

    Args:
        file_path   : Path to monitored file
        windows     : Number of samples (default 10 → 5-second window at 0.5s intervals)
        interval_sec: Seconds between samples

    Returns:
        List of normalized entropy values (length = windows).
        Values from before the file existed are filled with 0.0.

    Note:
        In post-hoc analysis (e.g., on RanSAP dataset rows), call this on
        pre-aggregated entropy columns rather than live files.
    """
    evolution = []
    for _ in range(windows):
        if os.path.exists(file_path):
            evolution.append(calculate_entropy_normalized(file_path))
        else:
            evolution.append(0.0)
        time.sleep(interval_sec)
    return evolution


def entropy_slope(evolution: list[float]) -> float:
    """
    Linear regression slope over an entropy evolution window.
    Positive slope = entropy rising (encryption in progress).
    Near-zero slope = stable (benign or already-encrypted).

    Args:
        evolution: List of normalized entropy values (0–1)

    Returns:
        Slope coefficient (units: entropy/sample)
    """
    if len(evolution) < 2:
        return 0.0

    n = len(evolution)
    x_mean = (n - 1) / 2.0
    y_mean = sum(evolution) / n

    numerator   = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(evolution))
    denominator = sum((i - x_mean) ** 2 for i in range(n))

    return numerator / denominator if denominator != 0 else 0.0


# ── Batch processing ──────────────────────────────────────────────────────────

def batch_entropy(file_paths: list[str]) -> list[EntropySnapshot]:
    """
    Compute entropy for a list of files.
    Used by monitor.py to scan the honeypot directory efficiently.
    """
    return [calculate_entropy_snapshot(p) for p in file_paths]


def count_high_entropy_files(file_paths: list[str], threshold_bits: float = 7.0) -> int:
    """
    Count how many files in a list exceed the entropy threshold.
    Key feature: ransomware encrypts many files rapidly → this count spikes.
    """
    return sum(
        1 for p in file_paths
        if os.path.exists(p) and calculate_entropy(p) > threshold_bits
    )


# ── Quick CLI test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else __file__

    snap = calculate_entropy_snapshot(target)
    print(f"File          : {snap.file_path}")
    print(f"Entropy (bits): {snap.entropy_bits:.4f} / 8.0")
    print(f"Normalized    : {snap.entropy_normalized:.4f}")
    print(f"Size          : {snap.file_size_bytes:,} bytes")
    print(f"High entropy? : {snap.is_high_entropy}")
    print(f"Ransomware range? : {snap.is_ransomware_range}")
