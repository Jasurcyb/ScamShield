"""
tools/vision_tool.py — ScamShield Vision Fraud Detector (Agent 1)

Analyses images (screenshots of bank transfers, documents, QR codes, etc.)
for visual signs of fraud using a vision LLM (Anthropic Claude, Gemini, or Fireworks AI).
"""

from __future__ import annotations

import base64
import asyncio
import json
import mimetypes
import os
import sys
import re

# ── Ensure .env is loaded (if python-dotenv is available) ──────────────────────
try:
    from dotenv import load_dotenv
    _SCAMSHIELD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(_SCAMSHIELD_ROOT, ".env"))
except ImportError:
    pass

# Ensure parent directory is on sys.path for importing siblings/parents
_PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from tools.llm_provider import call_fireworks_vision, parse_llm_json, is_valid_key, summary_language_instruction

# ── Vision analysis prompt ─────────────────────────────────────────────────────

_VISION_SYSTEM_PROMPT = """\
You are a professional forensic fraud analyst. You receive an image and must \
determine whether it shows signs of visual manipulation, forgery, or fraud.

Analyse the image for ALL of the following indicators:
• Font inconsistencies — different typefaces, sizes, weights, or rendering \
  within text that should be uniform (e.g. transaction amounts, dates, names).
• Editing artefacts — visible cut/paste boundaries, mismatched lighting or \
  shadows, JPEG re-compression ghosts, cloned regions, smudge/blur tool marks.
• Fake banking details — implausible account numbers, suspicious bank logos, \
  mismatched currency symbols, round-number amounts typical of scams.
• QR code anomalies — QR codes overlaid on images, low resolution QR that \
  may redirect to phishing, multiple conflicting QR codes.
• Date/amount mismatches — timestamps that conflict with each other, amounts \
  that don't add up, inconsistent formatting within the same document.
• Layout anomalies — misaligned columns, uneven spacing, elements that \
  appear pasted over an original background.
• Metadata clues visible in the image — e.g. a Photoshop toolbar, editing \
  UI elements accidentally left in the screenshot.

Respond ONLY with valid JSON (no markdown fences, no extra text) matching \
this exact schema:

{
  "risk_level": "low" | "medium" | "high" | "critical",
  "visual_findings": ["finding 1", "finding 2", ...],
  "summary": "A concise 2-4 sentence professional English verdict."
}

Rules for risk_level:
- "low"      — No fraud indicators detected. Image appears authentic.
- "medium"   — Minor anomalies that could be innocent but warrant review.
- "high"     — Multiple clear fraud indicators. Likely manipulated.
- "critical" — Obvious forgery / phishing attempt with strong evidence.

If the image is not a document/screenshot (e.g. a landscape photo), return \
risk_level "low" with an appropriate summary.
"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _encode_image(file_path: str) -> tuple[str, str]:
    """
    Read and base64-encode an image file.
    Returns (base64_data, media_type).
    """
    mime, _ = mimetypes.guess_type(file_path)
    if mime is None:
        ext = os.path.splitext(file_path)[1].lower()
        mime_map = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".bmp": "image/bmp",
        }
        mime = mime_map.get(ext, "image/png")

    with open(file_path, "rb") as f:
        data = base64.standard_b64encode(f.read()).decode("ascii")
    return data, mime


def _parse_llm_response(raw_text: str) -> dict:
    """Helper delegated to parse_llm_json from llm_provider."""
    return parse_llm_json(raw_text, fallback_findings_key="visual_findings")


def _error_result(error_type: str, detail: str) -> dict:
    """Return a standardised error response."""
    return {
        "risk_level": "unknown",
        "visual_findings": [f"{error_type}: {detail}"],
        "summary": (
            f"Vision analysis could not be completed due to an {error_type.lower()}. "
            f"Details: {detail}. Please retry or inspect the image manually."
        ),
    }


# ── Standalone Async Function (LangChain @tool removed) ─────────────────────────

async def vision_fraud_tool(file_path: str, provider: str | None = None, language: str = "en") -> dict:
    """
    Vision-based fraud detector. The verdict summary is written in `language`.
    """
    # ── Validate file ─────────────────────────────────────────────────────────
    if not os.path.isfile(file_path):
        return _error_result("File Error", f"File not found at '{file_path}'")

    # ── Check API keys ────────────────────────────────────────────────────────
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")
    fireworks_key = os.environ.get("FIREWORKS_API_KEY")

    if provider is None:
        if is_valid_key(anthropic_key):
            provider = "anthropic"
        elif is_valid_key(gemini_key):
            provider = "gemini"
        elif is_valid_key(fireworks_key):
            provider = "fireworks"
        else:
            return _error_result(
                "Configuration Error",
                "No vision provider configured. Set ANTHROPIC_API_KEY, GEMINI_API_KEY or FIREWORKS_API_KEY.",
            )

    # ── Build the language-aware prompt ───────────────────────────────────────
    language_note = summary_language_instruction(language)
    prompt = f"{_VISION_SYSTEM_PROMPT}\n\n{language_note}" if language_note else _VISION_SYSTEM_PROMPT

    # ── Encode image ──────────────────────────────────────────────────────────
    try:
        image_data, media_type = _encode_image(file_path)
    except Exception as exc:
        return _error_result("Encoding Error", str(exc))

    # ── Route to providers ────────────────────────────────────────────────────
    if provider == "anthropic":
        if not is_valid_key(anthropic_key):
            return _error_result("Configuration Error", "Anthropic provider was selected without a valid API key.")
        # ── Call Anthropic Vision API ─────────────────────────────────────────────
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=anthropic_key)

            message = await asyncio.to_thread(
                client.messages.create,
                model="claude-sonnet-4-6-20250514",
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": media_type,
                                    "data": image_data,
                                },
                            },
                            {
                                "type": "text",
                                "text": prompt,
                            },
                        ],
                    }
                ],
            )

            raw_text = message.content[0].text
            return _parse_llm_response(raw_text)

        except anthropic.RateLimitError as exc:
            return _error_result("Rate Limit Error", f"Anthropic API rate limit hit: {exc}")
        except anthropic.APITimeoutError as exc:
            return _error_result("Timeout Error", f"Anthropic API request timed out: {exc}")
        except anthropic.AuthenticationError as exc:
            return _error_result("Auth Error", f"Invalid ANTHROPIC_API_KEY: {exc}")
        except anthropic.APIConnectionError as exc:
            return _error_result("Connection Error", f"Could not connect to Anthropic API: {exc}")
        except anthropic.APIStatusError as exc:
            return _error_result("API Error", f"Anthropic returned status {exc.status_code}: {exc.message}")
        except ImportError:
            return _error_result(
                "Dependency Error",
                "The 'anthropic' package is not installed. Run: pip install anthropic",
            )
        except Exception as exc:
            return _error_result("Unexpected Error", str(exc))

    elif provider == "gemini":
        if not is_valid_key(gemini_key):
            return _error_result("Configuration Error", "Gemini provider was selected without a valid API key.")
        # ── Call Gemini Vision API via requests ───────────────────────────────────
        try:
            import requests

            url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
            
            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            },
                            {
                                "inlineData": {
                                    "mimeType": media_type,
                                    "data": image_data
                                }
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "responseMimeType": "application/json"
                }
            }
            
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": gemini_key
            }
            
            response = await asyncio.to_thread(requests.post, url, json=payload, headers=headers, timeout=60)
            
            if response.status_code != 200:
                return _error_result(
                    "API Error",
                    f"Gemini API returned status {response.status_code}: {response.text}"
                )
                
            res_json = response.json()
            try:
                raw_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
                return _parse_llm_response(raw_text)
            except (KeyError, IndexError) as e:
                return _error_result(
                    "API Error",
                    f"Failed to parse Gemini API response structure. Response: {json.dumps(res_json)}"
                )
        except requests.exceptions.Timeout as exc:
            return _error_result("Timeout Error", f"Gemini API request timed out: {exc}")
        except requests.exceptions.RequestException as exc:
            return _error_result("Connection Error", f"Could not connect to Gemini API: {exc}")
        except Exception as exc:
            return _error_result("Unexpected Error", str(exc))

    elif provider == "fireworks":
        if not is_valid_key(fireworks_key):
            return _error_result("Configuration Error", "Fireworks provider was selected without a valid API key.")
        # ── Call Fireworks AI Vision API ──────────────────────────────────────────
        try:
            raw_text = await asyncio.to_thread(call_fireworks_vision, image_data, media_type, prompt)
            return _parse_llm_response(raw_text)
        except Exception as exc:
            return _error_result("Fireworks Vision Error", str(exc))

    else:
        return _error_result("Configuration Error", f"Unknown vision provider: {provider}")
