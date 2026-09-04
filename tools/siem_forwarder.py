"""
tools/siem_forwarder.py  
==============================
Structured SIEM-ready logging and alert forwarding.

Two output formats:
  1. JSON logs  -> data/sample_logs/siem_alerts.json  (primary, machine-readable)
  2. CEF syslog -> data/sample_logs/siem_alerts.cef   (Splunk/QRadar compatible)

JSON schema per alert:
  {
    "timestamp":   "2024-04-05T10:23:45Z",
    "event_type":  "RANSOMWARE_ALERT | HIGH_ENTROPY | EXTENSION_CHANGE | ...",
    "severity":    "LOW | MEDIUM | HIGH | CRITICAL",
    "risk_score":  0.0–1.0,
    "details": {
      "process_name", "pid", "entropy_mean", "io_write_mb",
      "cpu_percent", "correlation_flags", "incident_id", ...
    }
  }

Incident correlation:
  Multiple HIGH/CRITICAL alerts within 60 seconds are grouped under one incident ID.
  Incidents appear in siem_incidents.json for SOC analysis.
"""

import os
import json
import socket
import logging
import datetime
import threading
from typing import Optional

log = logging.getLogger("ransomshield.siem")

# ── Output files ──────────────────────────────────────────────────────────────
os.makedirs("data/sample_logs", exist_ok=True)

JSON_LOG    = "data/sample_logs/siem_alerts.json"
CEF_LOG     = "data/sample_logs/siem_alerts.cef"
INCIDENT_LOG= "data/sample_logs/siem_incidents.json"

CEF_VENDOR  = "RansomShield"
CEF_PRODUCT = "DynamicExecutionFingerprinting"
CEF_VERSION = "3.0"

SEVERITY_TO_CEF = {"LOW": 2, "MEDIUM": 5, "HIGH": 7, "CRITICAL": 9}

# ── Incident correlator ────────────────────────────────────────────────────────
_incident_lock   = threading.Lock()
_incidents: dict = {}          # incident_id -> {start, end, alerts: [...], severity}
_last_incident:  Optional[str] = None
_last_alert_ts:  float         = 0.0
INCIDENT_WINDOW  = 60.0        # seconds


def _get_or_create_incident(severity: str, alert_ts: str) -> str:
    """Group consecutive HIGH/CRITICAL alerts into one incident."""
    global _last_incident, _last_alert_ts
    import time

    now = time.time()
    with _incident_lock:
        if (severity in ("HIGH", "CRITICAL")
                and _last_incident
                and (now - _last_alert_ts) < INCIDENT_WINDOW):
            _last_alert_ts = now
            return _last_incident

        # New incident
        inc_id = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')}-{severity[:3]}"
        _incidents[inc_id] = {
            "incident_id": inc_id,
            "start_time":  alert_ts,
            "end_time":    alert_ts,
            "severity":    severity,
            "alert_count": 0,
            "alerts":      [],
        }
        _last_incident = inc_id
        _last_alert_ts = now
        return inc_id


def _update_incident(inc_id: str, alert_dict: dict):
    with _incident_lock:
        if inc_id not in _incidents:
            return
        _incidents[inc_id]["alert_count"] += 1
        _incidents[inc_id]["end_time"]    = alert_dict.get("timestamp", "")
        _incidents[inc_id]["alerts"].append({
            "risk_score": alert_dict.get("risk_score"),
            "severity":   alert_dict.get("severity"),
            "timestamp":  alert_dict.get("timestamp"),
        })
        # Escalate severity
        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        old = _incidents[inc_id]["severity"]
        new = alert_dict.get("severity", old)
        if sev_order.index(new) > sev_order.index(old):
            _incidents[inc_id]["severity"] = new

    _save_incidents()


def _save_incidents():
    with open(INCIDENT_LOG, "w") as f:
        json.dump(list(_incidents.values()), f, indent=2)


# ── JSON alert emitter ────────────────────────────────────────────────────────

def emit_json_alert(alert_data: dict) -> dict:
    """
    Emit a structured JSON alert.

    Args:
        alert_data: Any dict - typically Alert.to_dict() from behavioral_engine.py

    Returns:
        The enriched alert dict that was written.
    """
    severity   = alert_data.get("severity", "LOW")
    risk_score = alert_data.get("risk_score", alert_data.get("threat_score", 0.0))
    ts         = alert_data.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")

    structured = {
        "timestamp":  ts,
        "event_type": _classify_event(alert_data),
        "severity":   severity,
        "risk_score": risk_score,
        "host":       socket.gethostname(),
        "details": {
            "process_name":     alert_data.get("process_name", ""),
            "pid":              alert_data.get("pid", 0),
            "entropy_mean":     alert_data.get("entropy_mean", 0.0),
            "entropy_slope":    alert_data.get("entropy_slope", 0.0),
            "io_write_mb":      alert_data.get("io_write_mb", alert_data.get("io_write_rate_mb", 0.0)),
            "cpu_percent":      alert_data.get("cpu_percent", 0.0),
            "file_mods_3s":     alert_data.get("file_mods_3s", 0),
            "rename_events":    alert_data.get("rename_events", 0),
            "extension_changes":alert_data.get("extension_changes", 0),
            "correlation_flags":{
                "joint_entropy_io":  alert_data.get("joint_entropy_io",  False),
                "joint_entropy_cpu": alert_data.get("joint_entropy_cpu", False),
                "rapid_rename":      alert_data.get("rapid_rename",      False),
                "extension_change":  alert_data.get("extension_change",  False),
            },
            "model_used": alert_data.get("model_used", ""),
        }
    }

    # Incident correlation
    if severity in ("HIGH", "CRITICAL"):
        inc_id = _get_or_create_incident(severity, ts)
        structured["incident_id"] = inc_id
        _update_incident(inc_id, structured)

    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(structured) + "\n")

    log.info("JSON alert -> %s  severity=%s  score=%.3f", JSON_LOG, severity, risk_score)
    return structured


def _classify_event(data: dict) -> str:
    """Classify alert into a meaningful event type string."""
    if data.get("extension_changes", 0) > 0:
        return "EXTENSION_CHANGE"
    if data.get("rename_events", 0) > 2:
        return "RAPID_RENAME"
    if data.get("joint_entropy_io"):
        return "ENTROPY_IO_CORRELATION"
    if data.get("severity") == "CRITICAL":
        return "RANSOMWARE_ALERT"
    if data.get("severity") == "HIGH":
        return "RANSOMWARE_SUSPECTED"
    if data.get("entropy_mean", 0) > 0.875:
        return "HIGH_ENTROPY"
    return "BEHAVIORAL_ANOMALY"


# ── CEF alert emitter ─────────────────────────────────────────────────────────

def emit_cef_alert(alert_data: dict) -> str:
    """
    Emit alert in Common Event Format (CEF).
    Compatible with Splunk, IBM QRadar, ArcSight.
    """
    severity    = alert_data.get("severity", "LOW")
    risk_score  = alert_data.get("risk_score", alert_data.get("threat_score", 0.0))
    cef_sev     = SEVERITY_TO_CEF.get(severity, 5)
    hostname    = socket.gethostname()
    ts          = datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")
    sig_id      = "200" if severity in ("CRITICAL", "HIGH") else "100"
    name        = "RansomwareActivityDetected" if sig_id == "200" else "SuspiciousBehavior"

    ext = (
        f"src={hostname} "
        f"dproc={alert_data.get('process_name', 'unknown')} "
        f"dpid={alert_data.get('pid', 0)} "
        f"cs1={risk_score:.4f} cs1Label=RiskScore "
        f"cs2={severity} cs2Label=Severity "
        f"cs3={alert_data.get('entropy_mean', 0.0):.4f} cs3Label=EntropyMean "
        f"cs4={alert_data.get('io_write_mb', 0.0):.3f} cs4Label=WriteRateMBs "
        f"cs5={int(alert_data.get('extension_changes', 0))} cs5Label=ExtensionChanges "
        f"msg={_classify_event(alert_data)}"
    )

    cef = (f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}|{sig_id}|{name}|{cef_sev}|{ext}")
    line = f"{ts} {hostname} {cef}"

    with open(CEF_LOG, "a") as f:
        f.write(line + "\n")

    return cef


# ── Read helpers ──────────────────────────────────────────────────────────────

def read_json_alerts(limit: int = 100) -> list[dict]:
    """Read the last N JSON alerts from the log file."""
    if not os.path.exists(JSON_LOG):
        return []
    alerts = []
    with open(JSON_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts[-limit:]


def read_incidents() -> list[dict]:
    """Read all correlated incidents."""
    if not os.path.exists(INCIDENT_LOG):
        return []
    with open(INCIDENT_LOG) as f:
        return json.load(f)


# ── CLI test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test = {
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
        "severity":         "CRITICAL",
        "risk_score":       0.94,
        "process_name":     "test_process.exe",
        "pid":              9999,
        "entropy_mean":     0.997,
        "io_write_mb":      48.3,
        "cpu_percent":      82.1,
        "file_mods_3s":     12,
        "rename_events":    5,
        "extension_changes":3,
        "joint_entropy_io": True,
        "joint_entropy_cpu":True,
    }
    out = emit_json_alert(test)
    cef = emit_cef_alert(test)
    print("JSON alert:")
    print(json.dumps(out, indent=2))
    print("\nCEF alert:")
    print(cef)
    print(f"\nWritten to: {JSON_LOG}\n           {CEF_LOG}")
