"""
detector/monitor.py  
==========================
Live monitoring engine - upgraded to use BehavioralEngine multi-signal scoring.

New in v3 vs v2:
  - Recursive honeypot watching (nested directory support)
  - on_moved() for rename and extension-change detection
  - on_created() for ransom note detection
  - BehavioralEngine replaces single-score fingerprint
  - JSON-structured alert log (SIEM-ready) alongside legacy CSV
  - Network score integration hook (from tools/network_monitor.py)
"""

import os
import time
import json
import csv
import logging
import datetime
import threading
import argparse
from collections import deque

import joblib
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileMovedEvent

from detector.entropy import calculate_entropy_snapshot, count_high_entropy_files
from detector.io_monitor import SystemIOMonitor
from detector.cpu_tracker import get_system_cpu_percent
from detector.fingerprint import build_fingerprint, score_fingerprint
from detector.behavioral_engine import BehavioralEngine, Alert
from tools.siem_forwarder import emit_json_alert

# ── Config ────────────────────────────────────────────────────────────────────
HONEYPOT_FOLDER   = "honeypot"
LOG_CSV           = "data/sample_logs/monitor.log"
ALERTS_LOG        = "alerts.log"
JSON_ALERTS_LOG   = "data/sample_logs/alerts.json"
MODEL_PATH        = "ml/model.pkl"
API_BASE          = os.environ.get("RANSOMSHIELD_API_BASE", "http://localhost:8000")
ENTROPY_THRESHOLD = 6.5
WINDOW_SEC        = 30.0
ENTROPY_WIN_SIZE  = 30

os.makedirs("data/sample_logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("data/sample_logs/monitor_v3.log"),
    ],
)
log = logging.getLogger("ransomshield.monitor")

CSV_HEADER = [
    "timestamp", "process_name", "pid", "file",
    "entropy_bits", "entropy_norm", "entropy_slope",
    "io_read_mb", "io_write_mb", "rw_ratio",
    "cpu_percent", "file_mod_count_3s", "files_high_entropy",
    "risk_score", "severity", "alert",
    "rename_events", "ext_changes", "joint_entropy_io",
]

# Ransom note filenames dropped by major ransomware families
RANSOM_NOTE_NAMES = {
    "readme_decrypt.txt", "how_to_decrypt.txt", "!!!readme!!!.txt",
    "decrypt_instructions.txt", "restore_files.txt", "ransom.txt",
    "_readme.txt", "how_to_back_files.html",
}


def load_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            log.warning("Model load failed: %s - rule-based fallback", e)
    log.warning("No model.pkl - rule-based scoring. Run: python ml/train_model.py")
    return None


def init_csv():
    if not os.path.exists(LOG_CSV):
        with open(LOG_CSV, "w", newline="") as f:
            csv.writer(f).writerow(CSV_HEADER)


def log_to_csv(row: dict):
    with open(LOG_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        w.writerow({k: row.get(k, "") for k in CSV_HEADER})


def log_alert_legacy(file_path: str, entropy: float, alert_type: str):
    """Legacy format - keeps dashboard backward compatibility."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERTS_LOG, "a") as f:
        f.write(f"{ts},{file_path},{entropy:.2f},{alert_type}\n")


def log_alert_json(alert: Alert):
    with open(JSON_ALERTS_LOG, "a") as f:
        f.write(json.dumps(alert.to_dict()) + "\n")


# ── Watchdog handler ──────────────────────────────────────────────────────────

class HoneypotHandler(FileSystemEventHandler):

    def __init__(self, model_bundle, io_mon: SystemIOMonitor, engine: BehavioralEngine):
        self.model_bundle  = model_bundle
        self.io_mon        = io_mon
        self.engine        = engine
        self.entropy_win   = deque(maxlen=ENTROPY_WIN_SIZE)
        self.mod_times     = deque()
        self.rename_times  = deque()
        self.ext_changes   = 0
        self._lock         = threading.Lock()

    def _all_files(self) -> list[str]:
        out = []
        for root, _, files in os.walk(HONEYPOT_FOLDER):
            for f in files:
                out.append(os.path.join(root, f))
        return out

    def _record_mod(self, now: float):
        self.mod_times.append(now)
        while self.mod_times and now - self.mod_times[0] > 3.0:
            self.mod_times.popleft()

    def _record_rename(self, now: float):
        self.rename_times.append(now)
        while self.rename_times and now - self.rename_times[0] > 10.0:
            self.rename_times.popleft()

    def on_moved(self, event):
        """
        Rename detection - one of the strongest ransomware behavioral IOCs.
        LockBit appends .lockbit, Ryuk appends .RYK, STOP appends .STOP etc.
        Any extension change from a document type triggers immediate analysis.
        """
        if event.is_directory:
            return
        src_ext = os.path.splitext(event.src_path)[1].lower()
        dst_ext = os.path.splitext(event.dest_path)[1].lower()
        now = time.time()
        with self._lock:
            self._record_rename(now)
            if src_ext != dst_ext:
                self.ext_changes += 1
        log.warning("RENAME: %s -> %s  [ext: %s -> %s]",
                    os.path.basename(event.src_path),
                    os.path.basename(event.dest_path),
                    src_ext, dst_ext)
        self._process_event(event.dest_path, forced_ext_change=(src_ext != dst_ext))

    def on_created(self, event):
        if event.is_directory:
            return
        fname = os.path.basename(event.src_path).lower()
        if fname in RANSOM_NOTE_NAMES:
            log.critical(" RANSOM NOTE CREATED: %s - late-stage ransomware IOC", event.src_path)
        self._process_event(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path)

    def _process_event(self, file_path: str, forced_ext_change: bool = False):
        time.sleep(0.1)

        snap = calculate_entropy_snapshot(file_path)
        norm = snap.entropy_normalized

        with self._lock:
            self.entropy_win.append(norm)
            ew = list(self.entropy_win)
            now = time.time()
            self._record_mod(now)
            mod_count  = len(self.mod_times)
            rename_cnt = len(self.rename_times)
            ext_cnt    = self.ext_changes

        read_mb, write_mb = self.io_mon.sample()
        cpu = get_system_cpu_percent()
        all_files = self._all_files()
        high_ent  = count_high_entropy_files(all_files, threshold_bits=7.0)

        # ── BehavioralEngine scoring ──────────────────────────────────────────
        alert = self.engine.ingest(
            process_name="honeypot_monitor",
            pid=os.getpid(),
            entropy_norm=norm,
            io_write_mb=write_mb,
            io_read_mb=read_mb,
            cpu_percent=cpu,
            file_mod_count=mod_count,
            rename_count=rename_cnt,
            ext_change_count=ext_cnt + int(forced_ext_change),
        )

        # ── ML fingerprint scoring ────────────────────────────────────────────
        fp = build_fingerprint(
            process_name="honeypot_monitor",
            pid=os.getpid(),
            entropy_window=ew,
            io_read_rate_mb=read_mb,
            io_write_rate_mb=write_mb,
            cpu_percent=cpu,
            file_mod_count_3s=mod_count,
            monitored_files=all_files,
        )
        fp = score_fingerprint(fp, self.model_bundle)

        # Take maximum of the two scoring approaches for conservatism
        final_score    = max(alert.risk_score, fp.threat_score)
        final_severity = alert.severity if alert.risk_score >= fp.threat_score else fp.severity

        alert_type = "NO_ALERT"
        if final_severity in ("HIGH", "CRITICAL") or forced_ext_change:
            alert_type = "RANSOMWARE_ALERT"
        elif snap.entropy_bits > ENTROPY_THRESHOLD:
            alert_type = "HIGH_ENTROPY"

        # ── Console output ────────────────────────────────────────────────────
        bar = "─" * 65
        print(f"\n{bar}")
        print(f"  File      : {file_path}")
        print(f"  Entropy   : {snap.entropy_bits:.4f} bits  norm={norm:.4f}  slope={alert.entropy_slope:+.5f}")
        print(f"  I/O       : read={read_mb:.2f}  write={write_mb:.2f} MB/s")
        print(f"  CPU       : {cpu:.1f}%")
        print(f"  Mods/3s   : {mod_count}  Renames: {rename_cnt}  ExtChg: {ext_cnt}")
        print(f"  High-ent  : {high_ent} files")
        print(f"   Engine : {alert.risk_score:.3f}  ML: {fp.threat_score:.3f}  -> [{final_severity}]")
        if alert.joint_entropy_io:
            print("   CORRELATION: High entropy + High I/O")
        if alert.joint_entropy_cpu:
            print("   CORRELATION: High entropy + CPU spike")
        if forced_ext_change:
            print("   EXTENSION CHANGE DETECTED")
        if alert_type == "RANSOMWARE_ALERT":
            print("   RANSOMWARE ALERT TRIGGERED")

        # ── Logging ───────────────────────────────────────────────────────────
        row = {
            "timestamp":          datetime.datetime.now().isoformat(),
            "process_name":       "honeypot_monitor",
            "pid":                os.getpid(),
            "file":               file_path,
            "entropy_bits":       round(snap.entropy_bits, 4),
            "entropy_norm":       round(norm, 4),
            "entropy_slope":      round(alert.entropy_slope, 6),
            "io_read_mb":         round(read_mb, 4),
            "io_write_mb":        round(write_mb, 4),
            "rw_ratio":           round(fp.rw_ratio, 4),
            "cpu_percent":        round(cpu, 2),
            "file_mod_count_3s":  mod_count,
            "files_high_entropy": high_ent,
            "risk_score":         round(final_score, 4),
            "severity":           final_severity,
            "alert":              alert_type,
            "rename_events":      rename_cnt,
            "ext_changes":        ext_cnt,
            "joint_entropy_io":   alert.joint_entropy_io,
        }
        log_to_csv(row)
        log_alert_legacy(file_path, snap.entropy_bits, alert_type)

        if alert_type == "RANSOMWARE_ALERT":
            log_alert_json(alert)
            try:
                emit_json_alert(alert.to_dict())
            except Exception:
                pass

        def _push():
            try:
                requests.post(f"{API_BASE}/analyze", json={
                    "process_name": "honeypot_monitor",
                    "pid": os.getpid(),
                    "entropy_window": ew,
                    "io_read_rate_mb": read_mb,
                    "io_write_rate_mb": write_mb,
                    "cpu_percent": cpu,
                    "file_mod_count_3s": mod_count,
                    "files_with_entropy_gt7": high_ent,
                    "rw_ratio": fp.rw_ratio,
                }, timeout=2)
            except Exception:
                pass
        threading.Thread(target=_push, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder",   default=HONEYPOT_FOLDER)
    parser.add_argument("--no-model", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.folder, exist_ok=True)
    init_csv()

    model_bundle = None if args.no_model else load_model()
    io_mon = SystemIOMonitor()
    io_mon.sample()

    engine  = BehavioralEngine(window_sec=WINDOW_SEC)
    handler = HoneypotHandler(model_bundle, io_mon, engine)
    observer = Observer()
    observer.schedule(handler, args.folder, recursive=True)
    observer.start()

    print("\n" + "═" * 65)
    print("  RansomShield Monitor v3 - Active")
    print(f"  Watching : {os.path.abspath(args.folder)}  (recursive)")
    print(f"  Engine   : BehavioralEngine (sliding {WINDOW_SEC}s window)")
    print(f"  Model    : {'ML (RF+ISO)' if model_bundle else 'rule-based fallback'}")
    print(f"  CSV log  : {LOG_CSV}")
    print(f"  JSON log : {JSON_ALERTS_LOG}")
    print("  Ctrl+C to stop")
    print("═" * 65 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log.info("Monitor stopped.")
    observer.join()


if __name__ == "__main__":
    main()
