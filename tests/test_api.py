import os
from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.main import app, router_controller


client = TestClient(app)


@pytest.fixture
def dummy_png():
    """A valid one-pixel transparent PNG."""
    buffer = BytesIO()
    Image.new("RGBA", (1, 1), (0, 0, 0, 0)).save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture
def text_llm_stub(monkeypatch):
    monkeypatch.setattr(
        "tools.text_url_tool.call_text_llm",
        lambda prompt, provider=None: (
            '{"risk_level":"high","text_findings":["Подозрительный домен"],'
            '"summary":"Вероятная фишинговая попытка."}'
        ),
    )


def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Swagger" in response.json()["message"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_analyze_text(text_llm_stub):
    response = client.post("/analyze/text", data={"text": "Urgent! Account block at kap1talbank.uz!"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "high"
    assert data["text_findings"]


def test_analyze_text_empty():
    response = client.post("/analyze/text", data={"text": ""})
    assert response.status_code == 400


def test_analyze_text_too_long():
    response = client.post("/analyze/text", data={"text": "a" * 10_001})
    assert response.status_code == 413


def test_analyze_vision(dummy_png, monkeypatch):
    async def vision_stub(_path):
        return {"risk_level": "low", "visual_findings": [], "summary": "Изображение выглядит безопасным."}

    monkeypatch.setattr("app.main.vision_fraud_tool", vision_stub)
    response = client.post("/analyze/vision", files={"file": ("test.png", dummy_png, "image/png")})
    assert response.status_code == 200
    assert response.json()["risk_level"] == "low"


def test_analyze_vision_rejects_unsupported_format():
    response = client.post("/analyze/vision", files={"file": ("test.txt", b"text", "text/plain")})
    assert response.status_code == 415


def test_analyze_vision_rejects_extension_spoofing():
    response = client.post("/analyze/vision", files={"file": ("test.png", b"not an image", "image/png")})
    assert response.status_code == 415


def test_analyze_stego(dummy_png, monkeypatch):
    async def stego_stub(_path):
        return {
            "risk_level": "low",
            "lsb_findings": {},
            "ctf_flags": [],
            "threat_words": [],
            "macro_analysis": {},
            "summary": "Файл выглядит безопасным.",
        }

    monkeypatch.setattr("app.main.stego_security_tool", stego_stub)
    response = client.post("/analyze/stego", files={"file": ("test.png", dummy_png, "image/png")})
    assert response.status_code == 200
    assert response.json()["risk_level"] == "low"


def test_analyze_full_text_only(monkeypatch):
    async def router_stub(*, file_path=None, text=None):
        assert file_path is None
        assert text == "Simple message without threats."
        return {
            "overall_risk": "low",
            "fraud_probability": 15,
            "agent_reports": {},
            "final_summary": "Безопасно.",
            "router_metadata": {"selected_provider": "local", "tokens_used": None, "cost_estimate": 0.0},
        }

    monkeypatch.setattr(router_controller, "route_decision", router_stub)
    response = client.post("/analyze/full", data={"text": "Simple message without threats."})
    assert response.status_code == 200
    assert response.json()["router_metadata"]["selected_provider"] == "local"


def test_analyze_full_with_file_and_text(dummy_png, monkeypatch):
    async def router_stub(*, file_path=None, text=None):
        assert file_path and os.path.exists(file_path)
        assert text == "Check this out."
        return {
            "overall_risk": "low",
            "fraud_probability": 15,
            "agent_reports": {},
            "final_summary": "Безопасно.",
            "router_metadata": {"selected_provider": "local", "tokens_used": None, "cost_estimate": 0.0},
        }

    monkeypatch.setattr(router_controller, "route_decision", router_stub)
    response = client.post(
        "/analyze/full",
        files={"file": ("test.png", dummy_png, "image/png")},
        data={"text": "Check this out."},
    )
    assert response.status_code == 200


def test_analyze_full_empty():
    response = client.post("/analyze/full")
    assert response.status_code == 400
