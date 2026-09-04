"""
backend/main.py
================
RansomShield demo API - a live, stateless demonstration of the trained
ransomware-detection model. No accounts, no database, no auth: every visitor
gets the same real model scoring real training-data rows.

Run locally:
  uvicorn backend.main:app --reload --port 8000

Endpoints:
  GET  /health        liveness check
  POST /demo/start     returns the full pre-scored demo timeline + real
                        feature importance from the trained model
"""
import uuid
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from . import config
from . import ml_inference
from . import demo_engine
from .demo_engine import generate_demo_step

log = logging.getLogger("ransomshield")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Fail fast if the model or demo data can't be loaded."""
    try:
        ml_inference._load()
        log.info("Model loaded successfully from %s", config.MODEL_PATH)
    except Exception as e:
        log.error("FATAL: Could not load model from %s: %s", config.MODEL_PATH, e)
        raise
    try:
        demo_engine._load_timeline()
        log.info("Demo timeline loaded (%d steps)", demo_engine.timeline_length())
    except Exception as e:
        log.error("FATAL: Could not load demo timeline: %s", e)
        raise
    yield

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="RansomShield Demo API", version="3.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/demo/start")
@limiter.limit(config.DEMO_RATE_LIMIT)
def demo_start(request: Request):
    """
    Returns the ENTIRE scored demo timeline in one response (the frontend
    animates it locally), plus the real trained model's feature importance.
    No database, no session tracking -- this is a stateless demo endpoint.
    """
    timeline = []
    for step in range(demo_engine.timeline_length()):
        features = generate_demo_step(step)
        scored = ml_inference.score(features)
        timeline.append({"step": step, "features": features, **scored})

    return {
        "session_id": str(uuid.uuid4()),
        "timeline": timeline,
        "feature_importance": ml_inference.feature_importance(),
    }
