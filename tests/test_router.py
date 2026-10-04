import asyncio

import pytest

from app.router import HybridRouter


def test_router_uses_selected_provider_for_agent_calls(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-key")
    selected_providers = []

    async def text_stub(_text, provider=None, language=None):
        selected_providers.append(provider)
        return {"risk_level": "high", "text_findings": ["Фишинг"], "summary": "Опасный текст."}

    async def summary_stub(_reports, _provider, language="en"):
        return "Опасный текст."

    monkeypatch.setattr("app.router.text_url_fraud_tool", text_stub)
    router = HybridRouter()
    monkeypatch.setattr(router, "_generate_final_summary", summary_stub)

    result = asyncio.run(router.route_decision(text="Urgent: verify your bank card at http://example.com"))

    assert selected_providers == ["fireworks"]
    assert result["router_metadata"]["selected_provider"] == "fireworks"
    assert result["router_metadata"]["tokens_used"] is None


def test_router_always_uses_cloud_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-key")
    router = HybridRouter()

    assert router._determine_llm_provider() == "fireworks"


def test_router_requires_a_cloud_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    router = HybridRouter()

    with pytest.raises(RuntimeError, match="No LLM provider configured"):
        router._determine_llm_provider()
