"""
backend/main.py
================
RansomShield unified API.

Two layers in one server:
  1. Public demo  -- stateless, rate-limited, no install required.
     Serves the pre-scored timeline to the Next.js frontend.

  2. Detection API -- real-time behavioral analysis consumed by the
     installed agent (detector/monitor.py) and the Streamlit dashboard.

Endpoints:
  GET  /health          liveness check (extended with model/alert info)
  POST /demo/start      full pre-scored demo timeline for the frontend
  POST /analyze         score a live process snapshot from the agent
  GET  /alerts          paginated alert history
  GET  /metrics         latest system metrics from the monitor log
  POST /simulate        trigger the attack simulator via subprocess
  GET  /logs            forensics event log viewer

Run locally:
  uvicorn backend.main:app --reload --port 8000
"""

import os
import sys
import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from . import config
from . import ml_inference
from . import demo_engine
from .demo_engine import generate_demo_step

# Local modules needed by the detection endpoints
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools.siem_forwarder import emit_cef_alert

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("ransomshield")

# ---------------------------------------------------------------------------
# Detection-layer state (in-memory; replace with DB for multi-instance deploy)
# ---------------------------------------------------------------------------

# The ML bundle loaded at startup (used by both demo and detection layers)
_detection_bundle: dict | None = None

# In-memory alert store for the detection API
ALERT_STORE: list[dict] = []

# ---------------------------------------------------------------------------
# Feature columns expected by the detection model
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "entropy_mean", "entropy_slope", "entropy_max", "entropy_std",
    "write_rate_mb_s", "write_events_per_s", "read_events_per_s", "lba_variance",
]

# ---------------------------------------------------------------------------
# Lifespan: load demo model + detection model bundle at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Fail fast if the demo model or timeline can't be loaded."""
    global _detection_bundle

    # Demo layer -- mandatory, raises on failure
    try:
        ml_inference._load()
        log.info("Demo model loaded from %s", config.MODEL_PATH)
    except Exception as e:
        log.error("FATAL: Could not load demo model: %s", e)
        raise
    try:
        demo_engine._load_timeline()
        log.info("Demo timeline loaded (%d steps)", demo_engine.timeline_length())
    except Exception as e:
        log.error("FATAL: Could not load demo timeline: %s", e)
        raise

    # Detection layer -- optional, falls back to rule-based scoring if missing
    detection_model_path = os.path.join(
        os.path.dirname(__file__), "..", "ml", "model.pkl"
    )
    try:
        _detection_bundle = joblib.load(detection_model_path)
        log.info("Detection model bundle loaded from %s", detection_model_path)
    except FileNotFoundError:
        log.warning(
            "model.pkl not found at %s -- detection endpoints will use "
            "rule-based fallback until ml/train_model.py is run.",
            detection_model_path,
        )
        _detection_bundle = None

    yield


# ---------------------------------------------------------------------------
# App + middleware
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="RansomShield API",
    description="Unified demo and real-time behavioral ransomware detection",
    version="4.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Pydantic schemas (detection layer)
# ---------------------------------------------------------------------------

class ProcessSnapshot(BaseModel):
    """
    Single behavioral snapshot of a monitored process.
    Sent by detector/monitor.py every N seconds.
    """
    process_name: str
    pid: int
    entropy_window: list[float]       # rolling normalized entropy values (0-1)
    io_read_rate_mb: float            # MB/s over last 5s
    io_write_rate_mb: float           # MB/s over last 5s
    cpu_percent: float
    file_mod_count_3s: int            # files modified in last 3s
    files_with_entropy_gt7: int       # files whose entropy > 7.0 bits
    rw_ratio: float                   # write / (read + write), 0-1


class SimulateRequest(BaseModel):
    phase: int = 1        # 1=recon, 2=encrypt, 3=ransom_note
    delay_ms: int = 200


# ---------------------------------------------------------------------------
# Helper: compute threat score from ML bundle or rule-based fallback
# ---------------------------------------------------------------------------

def _compute_threat_score(snapshot: ProcessSnapshot) -> dict:
    ew = snapshot.entropy_window or [0.0]
    entropy_mean  = float(np.mean(ew))
    entropy_slope = float(np.polyfit(range(len(ew)), ew, 1)[0]) if len(ew) > 1 else 0.0
    entropy_max   = float(np.max(ew))
    entropy_std   = float(np.std(ew))

    # Map agent fields to the 8 features ransomshield's model was trained on.
    # write_events_per_s: file mods measured over 3s window -> divide by 3
    # read_events_per_s:  no direct agent equivalent -> use read MB/s as proxy
    # lba_variance:       hypervisor-level metric, unavailable from agent -> 0.0
    write_events_per_s = snapshot.file_mod_count_3s / 3.0
    read_events_per_s  = snapshot.io_read_rate_mb
    lba_variance       = 0.0

    feature_vec = np.array([[
        entropy_mean,
        entropy_slope,
        entropy_max,
        entropy_std,
        snapshot.io_write_rate_mb,   # write_rate_mb_s
        write_events_per_s,
        read_events_per_s,
        lba_variance,
    ]])

    if _detection_bundle is not None:
        rf     = _detection_bundle["rf"]
        iso    = _detection_bundle["iso"]
        scaler = _detection_bundle.get("scaler")
        X      = scaler.transform(feature_vec) if scaler else feature_vec

        rf_prob   = float(rf.predict_proba(X)[0][1])
        iso_score = float(iso.score_samples(X)[0])
        iso_norm  = max(0.0, min(1.0, iso_score + 0.5))
        threat_score = 0.70 * rf_prob + 0.30 * (1.0 - iso_norm)

        contributing = {
            col: round(float(imp), 4)
            for col, imp in zip(FEATURE_COLS, rf.feature_importances_)
        }
        model_used = "RandomForest + IsolationForest ensemble"
    else:
        score = 0.0
        if entropy_mean > 0.9:              score += 0.35
        if entropy_slope > 0.05:            score += 0.20
        if snapshot.rw_ratio > 0.75:        score += 0.20
        if snapshot.file_mod_count_3s > 3:  score += 0.15
        if snapshot.io_write_rate_mb > 20:  score += 0.10
        threat_score = min(score, 1.0)
        contributing = {}
        model_used = "rule-based fallback (run ml/train_model.py for ML scoring)"

    if threat_score >= 0.80:   severity = "CRITICAL"
    elif threat_score >= 0.55: severity = "HIGH"
    elif threat_score >= 0.30: severity = "MEDIUM"
    else:                      severity = "LOW"

    return {
        "threat_score": round(threat_score, 4),
        "severity": severity,
        "contributing_features": contributing,
        "model_used": model_used,
        "computed_features": {
            "entropy_mean":  round(entropy_mean, 4),
            "entropy_slope": round(entropy_slope, 6),
            "entropy_max":   round(entropy_max, 4),
        },
    }


# ===========================================================================
# ENDPOINTS
# ===========================================================================

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "demo_model_loaded": ml_inference._bundle is not None,
        "detection_model_loaded": _detection_bundle is not None,
        "active_alerts": len([a for a in ALERT_STORE if a.get("status") == "ACTIVE"]),
        "time": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Demo layer
# ---------------------------------------------------------------------------

@app.post("/demo/start")
@limiter.limit(config.DEMO_RATE_LIMIT)
def demo_start(request: Request):
    """
    Returns the full pre-scored demo timeline in one response.
    The Next.js frontend animates it locally -- no session state needed.
    """
    timeline = []
    for step in range(demo_engine.timeline_length()):
        features = generate_demo_step(step)
        scored   = ml_inference.score(features)
        timeline.append({"step": step, "features": features, **scored})

    return {
        "session_id": str(uuid.uuid4()),
        "timeline": timeline,
        "feature_importance": ml_inference.feature_importance(),
    }


# ---------------------------------------------------------------------------
# Detection layer
# ---------------------------------------------------------------------------

@app.post("/analyze", summary="Score a live process snapshot from the agent")
def analyze(snapshot: ProcessSnapshot):
    """
    Accepts a behavioral snapshot from detector/monitor.py.
    Scores it, logs HIGH/CRITICAL alerts, and forwards to SIEM.
    """
    result = _compute_threat_score(snapshot)
    result["process_name"] = snapshot.process_name
    result["pid"]          = snapshot.pid
    result["timestamp"]    = datetime.now(timezone.utc).isoformat() + "Z"
    result["snapshot"]     = snapshot.dict()

    if result["severity"] in ("HIGH", "CRITICAL"):
        alert = {
            "id":               len(ALERT_STORE) + 1,
            "timestamp":        result["timestamp"],
            "process_name":     snapshot.process_name,
            "pid":              snapshot.pid,
            "threat_score":     result["threat_score"],
            "severity":         result["severity"],
            "entropy_mean":     result["computed_features"]["entropy_mean"],
            "io_write_rate_mb": snapshot.io_write_rate_mb,
            "status":           "ACTIVE",
        }
        ALERT_STORE.append(alert)
        log.warning(
            "ALERT [%s] process=%s pid=%d score=%.2f",
            result["severity"], snapshot.process_name, snapshot.pid, result["threat_score"],
        )
        try:
            emit_cef_alert(alert)
        except Exception as e:
            log.error("SIEM forwarding failed: %s", e)

    return JSONResponse(content=result)


@app.get("/alerts", summary="Paginated alert history")
def get_alerts(
    page:      int           = Query(1,    ge=1),
    page_size: int           = Query(20,   ge=1, le=100),
    severity:  Optional[str] = Query(None, description="Filter: LOW/MEDIUM/HIGH/CRITICAL"),
):
    filtered = ALERT_STORE
    if severity:
        filtered = [a for a in filtered if a["severity"] == severity.upper()]
    filtered = list(reversed(filtered))
    total    = len(filtered)
    start    = (page - 1) * page_size
    return {
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "alerts":    filtered[start: start + page_size],
    }


@app.get("/metrics", summary="Latest system metrics from the monitor log")
def get_metrics():
    try:
        log_path = "data/sample_logs/monitor.log"
        if os.path.exists(log_path):
            df = pd.read_csv(
                log_path,
                names=["timestamp", "process", "entropy", "io_write", "io_read", "cpu", "alert"],
                on_bad_lines="skip",
            )
            recent = df.tail(50)
            return {
                "entropy_histogram": recent["entropy"].dropna().tolist(),
                "io_write_series":   recent["io_write"].dropna().tolist(),
                "io_read_series":    recent["io_read"].dropna().tolist(),
                "cpu_series":        recent["cpu"].dropna().tolist(),
                "last_updated":      datetime.now(timezone.utc).isoformat() + "Z",
                "active_alerts":     len([a for a in ALERT_STORE if a["status"] == "ACTIVE"]),
            }
    except Exception as e:
        log.error("Metrics read error: %s", e)

    return {
        "entropy_histogram": [],
        "io_write_series":   [],
        "io_read_series":    [],
        "cpu_series":        [],
        "last_updated":      datetime.now(timezone.utc).isoformat() + "Z",
        "active_alerts":     0,
        "note":              "No log data yet - start detector/monitor.py first",
    }


@app.post("/simulate", summary="Trigger the attack simulator")
def simulate(req: SimulateRequest):
    """
    Triggers simulator/advanced_attack.py (3-phase staged simulation).
    Phase 1=recon, 2=encrypt, 3=ransom note drop.
    """
    if req.phase not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="phase must be 1, 2, or 3")

    result = subprocess.run(
        ["python", "simulator/advanced_attack.py",
         "--phase", str(req.phase),
         "--delay", str(req.delay_ms)],
        capture_output=True, text=True, timeout=30,
    )
    return {
        "phase":       req.phase,
        "stdout":      result.stdout[-2000:],
        "returncode":  result.returncode,
        "timestamp":   datetime.now(timezone.utc).isoformat() + "Z",
    }


@app.get("/logs", summary="Forensics event log viewer")
def get_logs(
    limit:      int  = Query(100,   ge=1, le=1000),
    alert_only: bool = Query(False, description="Return only RANSOMWARE_ALERT rows"),
):
    log_path = "alerts.log"
    if not os.path.exists(log_path):
        return {"entries": [], "total": 0}
    try:
        df = pd.read_csv(
            log_path,
            names=["timestamp", "file", "entropy", "alert"],
            on_bad_lines="skip",
        )
        if alert_only:
            df = df[df["alert"] == "RANSOMWARE_ALERT"]
        df = df.tail(limit).iloc[::-1]
        return {"entries": df.to_dict(orient="records"), "total": len(df)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
