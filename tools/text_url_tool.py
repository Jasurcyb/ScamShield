"""
tools/text_url_tool.py — ScamShield Text/URL Fraud Detector (Agent 3)

Analyses text messages and URLs for phishing, social engineering,
and suspicious domains.
"""

from __future__ import annotations

import asyncio
import re
import os
import sys
from urllib.parse import urlparse
import Levenshtein

# Ensure parent directory is on sys.path
_PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from tools.llm_provider import call_text_llm, parse_llm_json, error_result, summary_language_instruction

# Top banks in Uzbekistan for typo-squatting checks
TOP_UZ_BANKS = [
    "kapitalbank.uz",
    "hamkorbank.uz",
    "ipakyulibank.uz",
    "nbu.uz",
    "sqb.uz",
    "agrobank.uz",
    "ipotekabank.uz",
    "xb.uz",
    "aloqabank.uz",
    "ofb.uz",
    "infinbank.com",
    "tengebank.uz",
    "asakabank.uz",
    "trustbank.uz",
    "turonbank.uz"
]

_TEXT_SYSTEM_PROMPT = """\
You are a professional forensic fraud analyst. You receive a text message \
which may contain a URL, and you must determine whether it shows signs of \
phishing, social engineering, or fraud.

Analyse the text for ALL of the following indicators:
• Phishing/Social Engineering — urgency (e.g. "your account will be blocked"), \
  threats, promises of money or prizes, requests for sensitive information.
• Suspicious domains — typosquatting of known brands, unusual TLDs, IP addresses \
  instead of domains, URL shorteners used to hide the destination.
• Inconsistencies — mismatches between the claimed sender and the tone/content \
  of the message.

Respond ONLY with valid JSON (no markdown fences, no extra text) matching \
this exact schema:

{
  "risk_level": "low" | "medium" | "high" | "critical",
  "text_findings": ["finding 1", "finding 2", ...],
  "summary": "A concise 2-4 sentence professional English verdict."
}

Rules for risk_level:
- "low"      — No fraud indicators detected. Text appears benign.
- "medium"   — Minor anomalies that could be innocent but warrant caution.
- "high"     — Multiple clear fraud indicators. Likely a scam.
- "critical" — Obvious phishing attempt / malicious link with strong evidence.
"""

def _extract_urls(text: str) -> list[str]:
    """Extract explicit URLs and bare domains commonly sent in chat messages."""
    url_pattern = re.compile(
        r'(?<![\w@])(?:(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:/[^\s<>]*)?)',
        re.IGNORECASE,
    )
    return [match.rstrip(".,!?;:)") for match in url_pattern.findall(text)]

def _check_url_heuristics(url: str) -> list[str]:
    """Perform basic pattern checks on a URL."""
    findings = []
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = (parsed.hostname or "").lower()
        if not domain:
            return findings

        # Check Punycode (IDN homograph attacks)
        if any(label.startswith('xn--') for label in domain.split('.')):
            findings.append(f"Punycode domain detected ({domain}), often used for homograph attacks.")

        # Check Levenshtein distance to top banks
        for bank_domain in TOP_UZ_BANKS:
            if domain == bank_domain:
                continue # Exact match is fine
            
            # Simple heuristic: if distance is small (1 or 2), it's suspicious
            # Only compare if lengths are similar to avoid false positives on short names
            if abs(len(domain) - len(bank_domain)) <= 2:
                dist = Levenshtein.distance(domain, bank_domain)
                if 0 < dist <= 2:
                     findings.append(f"Typo-squatting suspected: '{domain}' is visually similar to '{bank_domain}'.")

    except Exception:
        pass # Ignore parsing errors for heuristics
    return findings


# ── Standalone Async Function (LangChain @tool removed) ─────────────────────────

async def text_url_fraud_tool(text: str, provider: str | None = None, language: str = "en") -> dict:
    """
    Text and URL fraud detector. The verdict summary is written in `language`.
    URLs are also fetched server-side (with SSRF guards) when URL_CHECK_ENABLED
    is on, so shorteners and redirects are expanded before typosquat checks.
    """
    if not text or not text.strip():
         return {
             "risk_level": "low",
             "text_findings": [],
             "summary": "No text provided for analysis."
         }

    heuristic_findings = []
    urls = _extract_urls(text)
    for url in urls:
        heuristic_findings.extend(_check_url_heuristics(url))

    # Server-side link inspection (safe fetch, manual redirects). Runs in
    # parallel with the LLM call; adds findings from the FINAL domain.
    from tools.url_checker import check_urls_in_text
    url_reports_task = asyncio.create_task(check_urls_in_text(text))

    prompt_sections = [
        _TEXT_SYSTEM_PROMPT,
        summary_language_instruction(language),
        f"Text to analyze:\n{text}",
    ]
    prompt = "\n\n".join(section for section in prompt_sections if section)

    try:
        llm_task = asyncio.to_thread(call_text_llm, prompt, provider)
        raw_response, url_reports = await asyncio.gather(llm_task, url_reports_task)

        for report in url_reports:
            heuristic_findings.extend(report.get("findings", []))

        result = parse_llm_json(raw_response, fallback_findings_key="text_findings")

        # Merge heuristic findings if they aren't already covered
        if heuristic_findings:
            current_findings = result.get("text_findings", [])
            current_findings.extend(heuristic_findings)
            result["text_findings"] = list(set(current_findings)) # Deduplicate

            # Elevate risk if heuristics found something
            if result.get("risk_level") in ["low", "medium"]:
                result["risk_level"] = "high"

        return result

    except Exception as exc:
        # The URL report may still be useful when the LLM path failed.
        try:
            url_reports = await url_reports_task
        except Exception:
            url_reports = []
        if url_reports or heuristic_findings:
            for report in url_reports:
                heuristic_findings.extend(report.get("findings", []))
            return {
                "risk_level": "high" if heuristic_findings else "unknown",
                "text_findings": list(set(heuristic_findings)),
                "summary": (
                    "The language model could not be reached, but automated link "
                    "and domain checks produced findings. Treat flagged links with caution."
                ),
            }
        return error_result("LLM Error", str(exc), findings_key="text_findings")
