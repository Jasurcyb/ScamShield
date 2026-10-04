import asyncio
from types import SimpleNamespace

import pytest

from bot import service
from bot.state import get_chat_state
from tools.stego_tool import _build_summary


class StubBot:
    """Bot double that satisfies the download step without touching Telegram.

    The download itself is a no-op: mkstemp already created the empty temp file,
    and the signature check plus analysis tools are stubbed in each test.
    """

    async def get_file(self, file_id):
        stub_file = SimpleNamespace()
        setattr(stub_file, "file_" + "path", "stub")
        return stub_file

    async def download_file(self, remote_path, destination):
        return None


@pytest.fixture
def no_signature_check(monkeypatch):
    monkeypatch.setattr(service, "validate_uploaded_file", lambda path, ext: None)


def test_text_input_rejected_in_stego_mode():
    with pytest.raises(ValueError, match="wrong_mode"):
        asyncio.run(service.analyze_text_content("hello", language="ru", mode="stego"))


def test_text_input_rejected_in_vision_mode():
    with pytest.raises(ValueError, match="wrong_mode"):
        asyncio.run(service.analyze_text_content("hello", language="ru", mode="vision"))


def test_vision_mode_rejects_non_image():
    with pytest.raises(ValueError, match="wrong_mode"):
        asyncio.run(
            service.analyze_telegram_file(StubBot(), file_id="x", filename="doc.pdf", language="ru", mode="vision")
        )


def test_stego_mode_runs_only_stego_tool(monkeypatch, no_signature_check):
    calls = []

    async def stego_stub(path, language="en"):
        calls.append(("stego", language))
        return {"risk_level": "high", "summary": "Suspicious."}

    async def vision_stub(path, provider=None, language="en"):
        calls.append(("vision",))
        return {"risk_level": "low", "summary": "Fine."}

    monkeypatch.setattr(service, "stego_security_tool", stego_stub)
    monkeypatch.setattr(service, "vision_fraud_tool", vision_stub)

    result = asyncio.run(
        service.analyze_telegram_file(StubBot(), file_id="x", filename="photo.jpg", language="ru", mode="stego")
    )

    assert calls == [("stego", "ru")]
    assert result["overall_risk"] == "high"
    assert result["final_summary"] == "Suspicious."
    assert set(result["agent_reports"]) == {"stego"}


def test_vision_mode_runs_only_vision_tool(monkeypatch, no_signature_check):
    calls = []

    async def stego_stub(path, language="en"):
        calls.append(("stego",))
        return {"risk_level": "low", "summary": "Fine."}

    async def vision_stub(path, provider=None, language="en"):
        calls.append(("vision", language))
        return {"risk_level": "medium", "summary": "Edited."}

    monkeypatch.setattr(service, "stego_security_tool", stego_stub)
    monkeypatch.setattr(service, "vision_fraud_tool", vision_stub)

    result = asyncio.run(
        service.analyze_telegram_file(StubBot(), file_id="x", filename="photo.jpg", language="uz", mode="vision")
    )

    assert calls == [("vision", "uz")]
    assert result["overall_risk"] == "medium"
    assert set(result["agent_reports"]) == {"vision"}


def test_full_mode_routes_with_language(monkeypatch, no_signature_check):
    captured = {}

    async def route_stub(*, file_path=None, text=None, language="en"):
        captured["language"] = language
        captured["caption"] = text
        return {
            "overall_risk": "low",
            "fraud_probability": 15,
            "agent_reports": {},
            "final_summary": "OK.",
            "router_metadata": {"selected_provider": "local", "tokens_used": None, "cost_estimate": 0.0},
        }

    monkeypatch.setattr(service.router_controller, "route_decision", route_stub)

    result = asyncio.run(
        service.analyze_telegram_file(
            StubBot(), file_id="x", filename="photo.jpg", caption="check this", language="ru", mode="full"
        )
    )

    assert captured["language"] == "ru"
    assert captured["caption"] == "check this"
    assert result["final_summary"] == "OK."


def test_text_tool_prompt_uses_selected_language(monkeypatch):
    import tools.text_url_tool as text_tool

    captured = {}

    def llm_stub(prompt, provider=None):
        captured["prompt"] = prompt
        return '{"risk_level": "low", "text_findings": [], "summary": "ok"}'

    monkeypatch.setattr(text_tool, "call_text_llm", llm_stub)

    result = asyncio.run(text_tool.text_url_fraud_tool("hello friend", provider="local", language="ru"))

    assert "Russian" in captured["prompt"]
    assert result["risk_level"] == "low"


def test_text_tool_prompt_stays_english_by_default(monkeypatch):
    import tools.text_url_tool as text_tool

    captured = {}

    def llm_stub(prompt, provider=None):
        captured["prompt"] = prompt
        return '{"risk_level": "low", "text_findings": [], "summary": "ok"}'

    monkeypatch.setattr(text_tool, "call_text_llm", llm_stub)

    asyncio.run(text_tool.text_url_fraud_tool("hello friend", provider="local"))

    assert "Russian" not in captured["prompt"]
    assert "Uzbek" not in captured["prompt"]


def test_stego_summary_is_localized():
    lsb = {
        "lsb_anomaly": {"status": "warning"},
        "histogram": {"status": "ok"},
        "trailing_data": {"status": "ok"},
    }

    assert "LSB-стеганография" in _build_summary("medium", lsb, [], [], {}, "ru")
    assert "LSB steganography" in _build_summary("medium", lsb, [], [], {}, "en")
    assert "steganografiya" in _build_summary("medium", lsb, [], [], {}, "uz")


def test_chat_state_persists_per_chat():
    state = get_chat_state(424242)
    state.language = "uz"
    state.mode = "stego"
    state.accepted_terms = True

    again = get_chat_state(424242)
    assert (again.language, again.mode, again.accepted_terms) == ("uz", "stego", True)
