import pytest

import tools.llm_provider as llm_provider
from tools.llm_provider import best_remote_text_provider, call_text_llm


def test_provider_priority_is_anthropic_then_gemini_then_fireworks(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)

    assert best_remote_text_provider() is None

    monkeypatch.setenv("FIREWORKS_API_KEY", "test-key")
    assert best_remote_text_provider() == "fireworks"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert best_remote_text_provider() == "gemini"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert best_remote_text_provider() == "anthropic"


def test_call_without_any_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="No LLM provider configured"):
        call_text_llm("hello")


def test_call_with_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        call_text_llm("hello", provider="local")


def test_explicit_provider_is_used(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-key")

    def fireworks_ok(prompt):
        return "ok"

    monkeypatch.setattr(llm_provider, "call_fireworks_text", fireworks_ok)

    assert call_text_llm("hello", provider="fireworks") == "ok"
