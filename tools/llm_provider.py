"""
tools/llm_provider.py — Shared LLM client for ScamShield agents.

Provides a single entry-point to call a text LLM (Anthropic Claude or Google
Gemini) with automatic provider selection based on available API keys.

Both vision_tool.py and text_url_tool.py import from here to avoid duplicating
provider-negotiation logic.
"""

from __future__ import annotations

import json
import os
import re

# ── Ensure .env is loaded ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv

    _SCAMSHIELD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(_SCAMSHIELD_ROOT, ".env"))
except ImportError:
    pass


# ── JSON response parser ──────────────────────────────────────────────────────

def parse_llm_json(raw_text: str, fallback_findings_key: str = "findings") -> dict:
    """
    Parse an LLM response that should contain a JSON object.
    Handles markdown code fences and partial JSON gracefully.
    """
    text = raw_text.strip()

    # Strip markdown code fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return {
                    "risk_level": "unknown",
                    fallback_findings_key: ["LLM response could not be parsed as JSON."],
                    "summary": f"Analysis completed but the response was malformed. Raw excerpt: {text[:200]}",
                }
        else:
            return {
                "risk_level": "unknown",
                fallback_findings_key: ["LLM response contained no JSON object."],
                "summary": f"Analysis completed but no structured output was returned. Raw: {text[:200]}",
            }

    # Normalise risk_level
    valid = {"low", "medium", "high", "critical", "unknown"}
    if parsed.get("risk_level") not in valid:
        parsed["risk_level"] = "unknown"

    parsed.setdefault("summary", "No summary provided by the model.")
    return parsed


def error_result(error_type: str, detail: str, findings_key: str = "findings") -> dict:
    """Standardised error response."""
    return {
        "risk_level": "unknown",
        findings_key: [f"{error_type}: {detail}"],
        "summary": (
            f"Analysis could not be completed due to an {error_type.lower()}. "
            f"Details: {detail}. Please retry or check your configuration."
        ),
    }


# ── Text-only LLM call ────────────────────────────────────────────────────────

def call_text_llm(prompt: str) -> str:
    """
    Send a text prompt to the best available LLM provider and return the
    raw text response.  Preference order: Anthropic → Gemini.

    Raises RuntimeError on configuration / provider errors so callers can
    translate into their own error dicts.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if not anthropic_key and not gemini_key:
        raise RuntimeError(
            "Neither ANTHROPIC_API_KEY nor GEMINI_API_KEY is set. "
            "Add one to your .env file or environment."
        )

    if anthropic_key:
        return _call_anthropic_text(anthropic_key, prompt)
    else:
        return _call_gemini_text(gemini_key, prompt)


# ── Anthropic backend ─────────────────────────────────────────────────────────

def _call_anthropic_text(api_key: str, prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model="claude-sonnet-4-6-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


# ── Gemini backend ─────────────────────────────────────────────────────────────

def _call_gemini_text(api_key: str, prompt: str) -> str:
    import requests

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        "models/gemini-2.5-flash:generateContent"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Gemini API returned status {resp.status_code}: {resp.text}")

    res_json = resp.json()
    try:
        return res_json["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        raise RuntimeError(f"Unexpected Gemini response structure: {json.dumps(res_json)[:300]}")
