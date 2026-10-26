"""Safe bridge between Telegram updates and ScamShield analysis."""

from __future__ import annotations

import html
import os
import tempfile
from pathlib import Path
from typing import Any

from aiogram import Bot

from app.router import HybridRouter
from app.security import (
    FORENSIC_EXTENSIONS,
    IMAGE_FORMATS,
    MAX_TEXT_CHARS,
    MAX_UPLOAD_BYTES,
    get_analysis_semaphore,
    validate_uploaded_file,
)
from app import db, scoring
from bot.localization import DEFAULT_LANGUAGE, text
from tools.stego_tool import stego_security_tool
from tools.vision_tool import vision_fraud_tool


router_controller = HybridRouter()

_FILE_MODES = {"full", "stego", "vision"}
_TEXT_MODES = {"full", "text"}


def _analysis_slot():
    """Acquire the shared analysis-capacity slot; fail fast when the server is saturated."""
    semaphore = get_analysis_semaphore()
    if semaphore.locked():
        raise ValueError("server_busy")
    return semaphore


def _risk_key(result: dict[str, Any]) -> str:
    risk = result.get("overall_risk", result.get("risk_level", "unknown"))
    return risk if risk in {"low", "medium", "high", "critical"} else "unknown"


def format_result(result: dict[str, Any], language: str) -> str:
    """Build a short, escaped HTML report suitable for Telegram."""
    risk = _risk_key(result)
    summary = result.get("final_summary") or result.get("summary") or text(language, "failed")
    recommendation = text(language, f"recommend_{risk}")
    report = text(
        language,
        "result",
        risk=text(language, risk),
        summary=html.escape(str(summary)),
        recommendation=html.escape(recommendation),
    )
    return f"{report}\n\n<i>{html.escape(text(language, 'disclaimer'))}</i>"


def _persist_scan(chat_id: int, mode: str, input_type: str, result: dict[str, Any]) -> None:
    """Best-effort verdict storage; sets scan_id for the feedback buttons."""
    if not db.db_enabled():
        return
    scan_id = db.save_scan(
        chat_id,
        mode=mode,
        input_type=input_type,
        overall_risk=_risk_key(result),
        fraud_probability=int(result.get("fraud_probability", 0) or 0),
        summary=str(result.get("final_summary") or result.get("summary") or "")[:1000],
    )
    result["scan_id"] = scan_id


def _wrap_single_tool_result(agent_name: str, report: dict[str, Any]) -> dict[str, Any]:
    """Present a single-tool (mode-restricted) result in the router's response shape."""
    return {
        "overall_risk": _risk_key(report),
        "fraud_probability": scoring.fraud_probability(
            report.get("risk_level", "unknown"), scoring.count_findings({"agent": report})
        ),
        "agent_reports": {agent_name: report},
        "final_summary": report.get("summary", ""),
        "router_metadata": {
            "selected_provider": "local",
            "tokens_used": None,
            "cost_estimate": 0.0,
        },
    }


async def analyze_text_content(
    content: str,
    *,
    chat_id: int = 0,
    language: str = DEFAULT_LANGUAGE,
    mode: str = "full",
) -> dict[str, Any]:
    if mode not in _TEXT_MODES:
        raise ValueError("wrong_mode")
    if len(content) > MAX_TEXT_CHARS:
        raise ValueError("text_too_long")
    async with _analysis_slot():
        result = await router_controller.route_decision(text=content, language=language)
    _persist_scan(chat_id, mode, "text", result)
    return result


async def analyze_telegram_file(
    bot: Bot,
    *,
    file_id: str,
    filename: str,
    caption: str | None = None,
    chat_id: int = 0,
    language: str = DEFAULT_LANGUAGE,
    mode: str = "full",
) -> dict[str, Any]:
    """Download a Telegram file, validate it, analyse it in the selected mode, then erase it."""
    extension = Path(filename).suffix.lower()
    if extension not in FORENSIC_EXTENSIONS:
        raise ValueError("unsupported_format")
    if mode not in _FILE_MODES:
        raise ValueError("wrong_mode")
    if mode == "vision" and extension not in IMAGE_FORMATS:
        raise ValueError("wrong_mode")

    descriptor, path = tempfile.mkstemp(suffix=extension)
    os.close(descriptor)
    try:
        telegram_file = await bot.get_file(file_id)
        await bot.download_file(telegram_file.file_path, destination=path)
        if os.path.getsize(path) > MAX_UPLOAD_BYTES:
            raise ValueError("file_too_large")
        validate_uploaded_file(path, extension)

        async with _analysis_slot():
            if mode == "stego":
                report = await stego_security_tool(path, language=language)
                result = _wrap_single_tool_result("stego", report)
            elif mode == "vision":
                report = await vision_fraud_tool(path, language=language)
                result = _wrap_single_tool_result("vision", report)
            else:
                result = await router_controller.route_decision(file_path=path, text=caption, language=language)
        _persist_scan(chat_id, mode, "file", result)
        return result
    finally:
        if os.path.exists(path):
            os.unlink(path)
