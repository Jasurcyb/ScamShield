"""
tools/llm_provider.py — Shared LLM client for ScamShield agents.

Provides a single entry-point to call a text LLM (Anthropic Claude, Google
Gemini, or Fireworks AI) with automatic provider selection based on available API keys.
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


def is_valid_key(key: str | None) -> bool:
    """Helper to detect if a key exists and is not a placeholder value."""
    if not key:
        return False
    key_strip = key.strip()
    if not key_strip or "your_" in key_strip or "placeholder" in key_strip:
        return False
    return True


# ── Text-only LLM call ────────────────────────────────────────────────────────

def call_text_llm(prompt: str) -> str:
    """
    Send a text prompt to the best available LLM provider and return the
    raw text response. Preference order: Anthropic → Gemini → Fireworks → Ollama.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")
    fireworks_key = os.environ.get("FIREWORKS_API_KEY")

    if is_valid_key(anthropic_key):
        return _call_anthropic_text(anthropic_key, prompt)
    elif is_valid_key(gemini_key):
        return _call_gemini_text(gemini_key, prompt)
    elif is_valid_key(fireworks_key):
        return call_fireworks_text(prompt)
    else:
        return _call_ollama_text(prompt)


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


# ── Fireworks AI backend ────────────────────────────────────────────────────────

def call_fireworks_text(prompt: str) -> str:
    """
    Calls Fireworks AI text completion API.
    Attempts Google Gemma 4 31B IT first, and falls back to DeepSeek V4 Flash if not deployed/accessible.
    """
    import requests

    api_key = os.environ.get("FIREWORKS_API_KEY")
    if not api_key:
        raise RuntimeError("FIREWORKS_API_KEY is not set.")

    url = "https://api.fireworks.ai/inference/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Try Gemma 4 first
    gemma_payload = {
        "model": "accounts/fireworks/models/gemma-4-31b-it",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 1024
    }
    try:
        resp = requests.post(url, json=gemma_payload, headers=headers, timeout=60)
        if resp.status_code == 200:
            res_json = resp.json()
            return res_json["choices"][0]["message"]["content"]
    except Exception:
        pass
        
    # Fallback to DeepSeek V4 Flash
    fallback_payload = {
        "model": "accounts/fireworks/models/deepseek-v4-flash",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 1024
    }
    resp = requests.post(url, json=fallback_payload, headers=headers, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Fireworks AI API returned status {resp.status_code}: {resp.text}")

    res_json = resp.json()
    try:
        return res_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"Unexpected Fireworks response structure: {json.dumps(res_json)[:300]}")


def call_fireworks_vision(image_base64: str, media_type: str, prompt: str) -> str:
    """
    Calls Fireworks AI Vision API.
    Attempts Google Gemma 4 31B IT first, and falls back to Kimi K2.6 if not deployed/accessible.
    """
    import requests

    api_key = os.environ.get("FIREWORKS_API_KEY")
    if not api_key:
        raise RuntimeError("FIREWORKS_API_KEY is not set.")

    url = "https://api.fireworks.ai/inference/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Try Gemma 4 first
    gemma_payload = {
        "model": "accounts/fireworks/models/gemma-4-31b-it",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{media_type};base64,{image_base64}"
                        }
                    }
                ]
            }
        ],
        "temperature": 0.1,
        "max_tokens": 1024
    }
    try:
        resp = requests.post(url, json=gemma_payload, headers=headers, timeout=60)
        if resp.status_code == 200:
            res_json = resp.json()
            return res_json["choices"][0]["message"]["content"]
    except Exception:
        pass
        
    # Fallback to Minimax M3 (a cheaper multimodal model than Kimi)
    fallback_payload = {
        "model": "accounts/fireworks/models/minimax-m3",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{media_type};base64,{image_base64}"
                        }
                    }
                ]
            }
        ],
        "temperature": 0.1,
        "max_tokens": 1024
    }
    resp = requests.post(url, json=fallback_payload, headers=headers, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Fireworks AI Vision API returned status {resp.status_code}: {resp.text}")

    res_json = resp.json()
    try:
        return res_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"Unexpected Fireworks Vision response structure: {json.dumps(res_json)[:300]}")


# ── Ollama backend ─────────────────────────────────────────────────────────────

def _call_ollama_text(prompt: str) -> str:
    import requests

    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    if base_url.endswith("/v1"):
        base_url = base_url[:-3]
    elif base_url.endswith("/v1/"):
        base_url = base_url[:-4]

    url = f"{base_url}/api/chat"
    model = os.environ.get("OLLAMA_MODEL", "minimax-m3:cloud")

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=120)
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama API returned status {resp.status_code}: {resp.text}")

    res_json = resp.json()
    try:
        return res_json["message"]["content"]
    except (KeyError, TypeError):
        raise RuntimeError(f"Unexpected Ollama response structure: {json.dumps(res_json)[:300]}")
