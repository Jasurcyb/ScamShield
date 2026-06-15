"""
tools/text_url_tool.py — ScamShield Text/URL Fraud Detector (Agent 3)

Analyses text messages and URLs for phishing, social engineering,
and suspicious domains.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse
import Levenshtein

from langchain_core.tools import tool
from tools.llm_provider import call_text_llm, parse_llm_json, error_result

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
    """Extract URLs from text using a regex."""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)

def _check_url_heuristics(url: str) -> list[str]:
    """Perform basic pattern checks on a URL."""
    findings = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return findings

        # Strip port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        # Check Punycode (IDN homograph attacks)
        if domain.startswith('xn--'):
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

@tool
async def text_url_fraud_tool(text: str) -> dict:
    """
    Text and URL fraud detector.

    Analyses text messages and URLs for phishing, social engineering,
    and suspicious domains using an LLM.

    Checks include: urgency, threats, typo-squatting of Uzbek banks,
    punycode domains, and URL anomalies.

    Args:
        text: The text message or URL to analyse.

    Returns:
        A structured dict with keys:
            risk_level       — "low" | "medium" | "high" | "critical" | "unknown"
            text_findings    — list of individual fraud indicators
            summary          — professional English verdict for judges
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

    prompt = f"{_TEXT_SYSTEM_PROMPT}\n\nText to analyze:\n{text}"

    try:
        # Run synchronous LLM call in a thread
        raw_response = await asyncio.to_thread(call_text_llm, prompt)
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
        return error_result("LLM Error", str(exc), findings_key="text_findings")
