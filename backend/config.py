"""
backend/config.py
==================
This is a stateless demo API -- no database, no auth, no per-user secrets.
Only real configuration needed is CORS origins and the model path.
"""
import os
from dotenv import load_dotenv

load_dotenv()

MODEL_PATH = os.environ.get(
    "MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "ml", "model.pkl")
)

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

DEMO_RATE_LIMIT = "20/minute"  # generous -- one call per page load, no per-step calls
