import pytest
from fastapi.testclient import TestClient
from backend.main import app
import backend.demo_engine as demo_engine

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "time" in response.json()

def test_demo_start():
    # Make sure we don't hit the rate limit during tests
    response = client.post("/demo/start")
    assert response.status_code == 200
    data = response.json()
    
    assert "session_id" in data
    assert "timeline" in data
    assert "feature_importance" in data
    
    # Check that timeline has the expected length
    expected_len = demo_engine.timeline_length()
    assert len(data["timeline"]) == expected_len
    
    # Verify that the first step has expected properties
    if expected_len > 0:
        first_step = data["timeline"][0]
        assert "step" in first_step
        assert "features" in first_step
        assert "risk_score" in first_step
        assert "severity" in first_step
        assert "model_prob" in first_step
        assert "anomaly_score" in first_step
        
        # Verify feature importance format
        fi = data["feature_importance"]
        assert isinstance(fi, list)
        if len(fi) > 0:
            assert "feature" in fi[0]
            assert "label" in fi[0]
            assert "importance" in fi[0]
