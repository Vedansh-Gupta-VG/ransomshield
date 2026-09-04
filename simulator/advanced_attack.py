"""
simulator/advanced_attack.py  (v3 - production EDR-grade)
===========================================================
Staged ransomware behavior simulator for detection testing.

IMPORTANT: This is a SAFE SIMULATION. It writes only to the honeypot/
directory and does not execute any real malware or cryptographic operations.
Purpose: generate realistic behavioral signals to validate detection engine.

Attack phases:
  1. Recon      - filesystem walk, file-type fingerprinting
  2. Simulation - file modification with entropy increase + extension rename
  3. Cleanup    - drop ransom note, write manifest

Behavioral realism:
  - Partial-bytes modification (LockBit 3.0 style - first N bytes only)
  - Extension renaming (.locked suffix, like Ryuk)
  - Burst I/O with configurable chunk size
  - CPU-intensive work simulation (triggers cpu_tracker alerts)
  - Random evasion delays between operations
  - Detailed JSON audit log of every action
"""

import os
import sys
import time
import random
import json
import argparse
import datetime
import threading
import logging

log = logging.getLogger("ransomshield.simulator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIM] %(message)s")

DEFAULT_CFG = {
    "honeypot_dir":        "honeypot",
    "delay_ms":            200,
    "partial_bytes":       4096,       # only modify first N bytes (low-impact simulation)
    "burst_size":          5,          # files per burst
    "burst_pause_sec":     0.8,        # pause between bursts
    "cpu_work_sec":        2.0,        # seconds of CPU-intensive work to trigger cpu_tracker
    "extension":           ".locked",  # appended suffix for renamed files
    "log_file":            "data/sample_logs/attack_sim.json",
    "evasion_jitter":      True,
    "modification_mode":   "partial",  # partial | full_random | xor_pattern
}

AUDIT_LOG: list[dict] = []


def _audit(event_type: str, details: dict):
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "event_type": event_type,
        **details,
    }
    AUDIT_LOG.append(entry)
    log.info("[%s] %s", event_type, json.dumps({k: v for k, v in details.items() if k != "header_hex"}))


def _save_audit(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(AUDIT_LOG, f, indent=2)


def _delay(cfg: dict):
    base = cfg["delay_ms"] / 1000.0
    if cfg.get("evasion_jitter"):
        base = max(0.01, base + random.uniform(-0.5, 0.5) * base)
    time.sleep(base)


def _cpu_work(duration_sec: float):
    """
    CPU-intensive busy loop - generates a sustained CPU spike that triggers
    cpu_tracker.CPUTracker spike detection. Uses integer arithmetic only.
    """
    end = time.time() + duration_sec
    x = 1
    while time.time() < end:
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF


# ── Phase 1: Reconnaissance ───────────────────────────────────────────────────

def phase1_recon(cfg: dict) -> list[str]:
    """Walk honeypot tree, fingerprint every file. Returns prioritised target list."""
    _audit("PHASE_START", {"phase": 1, "name": "Reconnaissance"})

    priority_exts = {".docx", ".xlsx", ".pdf", ".txt", ".csv", ".py"}
    priority, secondary = [], []

    for root, _, files in os.walk(cfg["honeypot_dir"]):
        for fname in files:
            path = os.path.join(root, fname)
            ext  = os.path.splitext(fname)[1].lower()
            if ext == cfg["extension"] or fname.startswith("."):
                continue
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    header = f.read(8)
                _audit("FILE_RECON", {
                    "path": path, "size": size, "ext": ext,
                    "magic": header.hex(), "priority": ext in priority_exts,
                })
                (priority if ext in priority_exts else secondary).append(path)
            except Exception as e:
                _audit("RECON_ERROR", {"path": path, "error": str(e)})
            _delay(cfg)

    all_targets = priority + secondary
    _audit("PHASE_END", {"phase": 1, "total": len(all_targets), "priority": len(priority)})
    log.info("Recon: %d priority + %d secondary", len(priority), len(secondary))
    return all_targets


# ── Phase 2: File modification simulation ─────────────────────────────────────

def _modify_file(path: str, cfg: dict) -> dict:
    """
    Simulate file modification to produce high-entropy behavioral signals.

    Modes:
      partial      → overwrite first partial_bytes with high-entropy data (LockBit style)
      full_random  → replace entire file with random bytes (WannaCry style)
      xor_pattern  → XOR content with repeating pattern (observable entropy ~6.5)

    Then rename file with .locked extension (Ryuk behavior).
    Returns result dict for audit.
    """
    mode    = cfg.get("modification_mode", "partial")
    partial = cfg["partial_bytes"]

    try:
        with open(path, "rb") as f:
            original = f.read()
        orig_size = len(original)

        if mode == "full_random":
            modified = os.urandom(orig_size)
        elif mode == "xor_pattern":
            # XOR with repeating 32-byte pattern - detectable but less extreme than random
            key = bytes([i * 7 % 256 for i in range(32)])
            modified = bytes(b ^ key[i % 32] for i, b in enumerate(original))
        else:  # partial - most realistic
            head = os.urandom(min(partial, orig_size))
            modified = head + original[len(head):]

        with open(path, "wb") as f:
            f.write(modified)

        new_path = path + cfg["extension"]
        os.rename(path, new_path)

        return {
            "original_path": path,
            "new_path": new_path,
            "original_size": orig_size,
            "mode": mode,
            "success": True,
        }

    except Exception as e:
        return {"original_path": path, "error": str(e), "success": False}


def phase2_simulate(targets: list[str], cfg: dict):
    """Process targets in bursts with CPU work thread running concurrently."""
    _audit("PHASE_START", {"phase": 2, "name": "FileModification", "target_count": len(targets)})

    # CPU work thread to trigger cpu_tracker during file modification phase
    total_time = len(targets) * cfg["delay_ms"] / 1000.0 + cfg["cpu_work_sec"]
    cpu_thread = threading.Thread(target=_cpu_work, args=(total_time,), daemon=True)
    cpu_thread.start()

    success_count = 0
    for i, path in enumerate(targets):
        result = _modify_file(path, cfg)
        _audit("FILE_MODIFIED", result)
        success_count += int(result.get("success", False))
        _delay(cfg)

        # Burst pause - simulates C2 check-in between batches
        if (i + 1) % cfg["burst_size"] == 0:
            _audit("BURST_PAUSE", {"files_done": i + 1, "pause_sec": cfg["burst_pause_sec"]})
            time.sleep(cfg["burst_pause_sec"])

    _audit("PHASE_END", {"phase": 2, "success": success_count, "failed": len(targets) - success_count})
    log.info("Modification: %d/%d files processed", success_count, len(targets))


# ── Phase 3: Cleanup ──────────────────────────────────────────────────────────

RANSOM_NOTE = """\
=== [SIMULATION ONLY - NOT REAL RANSOMWARE] ===

Your files have been renamed with extension: {extension}
This is a controlled ransomware detection test by RansomShield.

In a real incident, contact your incident response team immediately.
Do NOT pay ransoms. Restore from clean backups.

Simulation ID : RANSOMSHIELD-{sim_id}
Timestamp     : {timestamp}
Files affected: {file_count}
"""


def phase3_cleanup(targets: list[str], cfg: dict):
    """Drop ransom notes per directory and write encrypted file manifest."""
    _audit("PHASE_START", {"phase": 3, "name": "Cleanup"})

    dirs = set(os.path.dirname(t) for t in targets)
    sim_id = random.randint(100000, 999999)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for d in dirs:
        note_path = os.path.join(d, "README_DECRYPT.txt")
        count = sum(1 for t in targets if os.path.dirname(t) == d)
        with open(note_path, "w") as f:
            f.write(RANSOM_NOTE.format(
                extension=cfg["extension"],
                sim_id=sim_id,
                timestamp=ts,
                file_count=count,
            ))
        _audit("NOTE_DROPPED", {"path": note_path, "file_count": count})

    manifest = {
        "sim_id": sim_id,
        "timestamp": ts,
        "mode": cfg["modification_mode"],
        "extension": cfg["extension"],
        "files": [t + cfg["extension"] for t in targets],
    }
    manifest_path = os.path.join(cfg["honeypot_dir"], ".sim_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    _audit("PHASE_END", {"phase": 3, "dirs_noted": len(dirs), "manifest": manifest_path})
    log.info("Cleanup complete. Notes in %d dirs.", len(dirs))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RansomShield Simulator - SAFE simulation only")
    parser.add_argument("--phase",    type=int, default=0,
                        help="0=all, 1=recon, 2=modify, 3=cleanup")
    parser.add_argument("--delay",    type=int, default=200)
    parser.add_argument("--mode",     default="partial",
                        choices=["partial", "full_random", "xor_pattern"])
    parser.add_argument("--honeypot", default="honeypot")
    parser.add_argument("--no-jitter", action="store_true")
    args = parser.parse_args()

    cfg = {
        **DEFAULT_CFG,
        "honeypot_dir":      args.honeypot,
        "delay_ms":          args.delay,
        "modification_mode": args.mode,
        "evasion_jitter":    not args.no_jitter,
    }

    print("=" * 62)
    print("  RansomShield Simulator - SAFE SIMULATION ONLY")
    print("=" * 62)
    print(f"  Honeypot : {os.path.abspath(cfg['honeypot_dir'])}")
    print(f"  Mode     : {cfg['modification_mode']}")
    print(f"  Delay    : {cfg['delay_ms']}ms")
    print()

    os.makedirs(cfg["honeypot_dir"], exist_ok=True)
    for i in range(1, 4):
        p = os.path.join(cfg["honeypot_dir"], f"file{i}.txt")
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write(f"Decoy file {i}.\n" * 80)

    try:
        targets: list[str] = []
        if args.phase in (0, 1):
            targets = phase1_recon(cfg)
        else:
            targets = [
                os.path.join(r, fn)
                for r, _, fns in os.walk(cfg["honeypot_dir"])
                for fn in fns
                if not fn.endswith(cfg["extension"]) and not fn.startswith(".")
            ]

        if args.phase in (0, 2) and targets:
            phase2_simulate(targets, cfg)

        if args.phase in (0, 3):
            phase3_cleanup(targets, cfg)

    finally:
        _save_audit(cfg["log_file"])
        print(f"\nOK Done. Audit: {cfg['log_file']}")
        print("  Check the monitor terminal and dashboard for triggered alerts.")


if __name__ == "__main__":
    main()
