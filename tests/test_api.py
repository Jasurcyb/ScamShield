import os
import sys
import pytest
import io
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from app.main import app

client = TestClient(app)

# ── Fixtures for mock files ───────────────────────────────────────────────────

@pytest.fixture
def dummy_png():
    """Returns a valid 1x1 transparent PNG file binary representation."""
    return b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82'


@pytest.fixture
def dummy_txt():
    return b"Hello world! This is a simple test file."


# ── Test Endpoints ────────────────────────────────────────────────────────────

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Swagger" in response.json()["message"]


def test_analyze_text():
    response = client.post("/analyze/text", data={"text": "Urgent! Account block at kap1talbank.uz!"})
    assert response.status_code == 200
    data = response.json()
    assert "risk_level" in data
    assert "text_findings" in data
    assert "summary" in data
    # Levenshtein typo-squatting must trigger here
    assert any("typo-squatting" in f.lower() or "similar" in f.lower() for f in data["text_findings"])


def test_analyze_text_empty():
    response = client.post("/analyze/text", data={"text": ""})
    assert response.status_code == 400


def test_analyze_vision(dummy_png):
    # Mocking environment variables to prevent actual API calling failure during test
    os.environ["ANTHROPIC_API_KEY"] = ""
    os.environ["GEMINI_API_KEY"] = ""
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434" # Dummy Ollama local fallback
    
    file_payload = {"file": ("test.png", dummy_png, "image/png")}
    response = client.post("/analyze/vision", files=file_payload)
    
    # Since Ollama might not be running locally in test environment, it may result in error_result dict
    # But the endpoint should still return HTTP 200 containing the structured error/success dict as VisionResponse.
    assert response.status_code == 200
    data = response.json()
    assert "risk_level" in data
    assert "visual_findings" in data
    assert "summary" in data


def test_analyze_vision_unsupported_format(dummy_txt):
    file_payload = {"file": ("test.txt", dummy_txt, "text/plain")}
    response = client.post("/analyze/vision", files=file_payload)
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]


def test_analyze_stego(dummy_png):
    file_payload = {"file": ("test.png", dummy_png, "image/png")}
    response = client.post("/analyze/stego", files=file_payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_level" in data
    assert "lsb_findings" in data
    assert "ctf_flags" in data
    assert "threat_words" in data
    assert "macro_analysis" in data
    assert "summary" in data


def test_analyze_full_text_only():
    response = client.post("/analyze/full", data={"text": "Simple message without threats."})
    assert response.status_code == 200
    data = response.json()
    assert "overall_risk" in data
    assert "fraud_probability" in data
    assert "agent_reports" in data
    assert "final_summary" in data
    assert "router_metadata" in data
    
    # Short text -> Should route to local
    assert data["router_metadata"]["selected_provider"] == "local"
    assert data["router_metadata"]["cost_estimate"] == 0.0


def test_analyze_full_with_file_and_text(dummy_png):
    file_payload = {"file": ("test.png", dummy_png, "image/png")}
    response = client.post("/analyze/full", files=file_payload, data={"text": "Check this out."})
    assert response.status_code == 200
    data = response.json()
    assert "overall_risk" in data
    assert "agent_reports" in data
    assert "router_metadata" in data


def test_analyze_full_empty():
    response = client.post("/analyze/full")
    assert response.status_code == 400
    assert "Must provide at least one input" in response.json()["detail"]
