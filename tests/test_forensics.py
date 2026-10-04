import asyncio
from pathlib import Path
from uuid import uuid4

from tools.stego_tool import stego_security_tool


def _temporary_document(name: str, content: str) -> Path:
    directory = Path(".test_artifacts")
    directory.mkdir(exist_ok=True)
    document = directory / f"{uuid4()}-{name}.txt"
    document.write_text(content, encoding="utf-8")
    return document


def test_plain_password_reference_is_not_a_critical_threat():
    document = _temporary_document("policy", "The password policy requires at least 12 characters.")
    try:
        result = asyncio.run(stego_security_tool(str(document)))
        assert result["risk_level"] == "low"
        assert result["threat_words"] == []
    finally:
        document.unlink(missing_ok=True)


def test_malware_marker_requires_review_but_is_not_automatically_critical():
    document = _temporary_document("report", "Incident report: malware was found on a workstation.")
    try:
        result = asyncio.run(stego_security_tool(str(document)))
        assert result["risk_level"] in {"medium", "high"}
        assert result["threat_words"] == ["malware"]
    finally:
        document.unlink(missing_ok=True)
