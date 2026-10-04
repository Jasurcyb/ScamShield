"""
tools/stego_tool.py — ScamShield Stego/Forensics Agent Tool

Wraps the production-grade forensics engine from analyzer.py as a standalone function.
All synchronous scanner functions are offloaded to thread pools via asyncio.to_thread()
to keep the async event loop responsive.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

# Ensure the ScamShield project root (parent of 'tools/') is on sys.path so that
# `analyzer` and `database` (the stub) can be imported directly.
_SCAMSHIELD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCAMSHIELD_ROOT not in sys.path:
    sys.path.insert(0, _SCAMSHIELD_ROOT)

import analyzer

# ── Internal helpers ───────────────────────────────────────────────────────────

def _classify_risk(danger_score: int, is_critical: bool) -> str:
    """Convert a numeric danger score to a human-readable risk tier."""
    if is_critical:
        return "critical"
    if danger_score >= 15:
        return "high"
    if danger_score >= 5:
        return "medium"
    return "low"


_SUMMARY_PACKS: dict[str, dict[str, object]] = {
    "en": {
        "headlines": {
            "critical": "CRITICAL THREAT DETECTED.",
            "high":     "High-risk indicators found.",
            "medium":   "Suspicious activity detected.",
            "low":      "File appears clean.",
        },
        "lsb": "Hidden data detected via LSB steganography analysis (statistically non-random pixel noise in blue channel).",
        "hist": "Histogram comb-effect detected — a classic sign of LSB embedding that distorts channel value distribution.",
        "trailing": "Appended data found beyond the file's EOF marker ({sz} bytes) — possible polyglot or stego container.",
        "ctf": "{count} CTF-style flag(s) extracted from file content (e.g. 'flag{{...}}' patterns). This strongly suggests the file was crafted for a capture-the-flag challenge.",
        "threats": "Threat keywords matched in file data: {words}.",
        "macro_autoexec": "VBA macro with AutoExec trigger found — code will execute automatically when the document is opened.",
        "macro_plain": "VBA macros detected in the Office document. Manual review recommended before opening.",
        "pdf": "Active JavaScript or embedded files found inside the PDF — potential for drive-by execution.",
        "archive": "Archive contains executable files or double-extension tricks ({details}).",
    },
    "ru": {
        "headlines": {
            "critical": "ОБНАРУЖЕНА КРИТИЧЕСКАЯ УГРОЗА.",
            "high":     "Найдены индикаторы высокого риска.",
            "medium":   "Обнаружена подозрительная активность.",
            "low":      "Файл выглядит чистым.",
        },
        "lsb": "Обнаружены скрытые данные (LSB-стеганография: неестественно равномерный шум в синем канале).",
        "hist": "Обнаружен «гребёночный» эффект гистограммы — классический признак LSB-внедрения.",
        "trailing": "Найдены данные после маркера конца файла ({sz} байт) — возможен полиглот- или стегано-контейнер.",
        "ctf": "Извлечены CTF-флаги ({count} шт., шаблон 'flag{{...}}'). Похоже, файл подготовлен для CTF-соревнования.",
        "threats": "Совпадения с ключевыми словами угроз: {words}.",
        "macro_autoexec": "Найден VBA-макрос с автозапуском — код выполнится при открытии документа.",
        "macro_plain": "В документе есть VBA-макросы. Перед открытием рекомендуется ручная проверка.",
        "pdf": "В PDF найдены активный JavaScript или вложения — возможна скрытая загрузка файлов.",
        "archive": "В архиве исполняемые файлы или приём с двойным расширением ({details}).",
    },
    "uz": {
        "headlines": {
            "critical": "JUDA XAVFLI TAHDIT ANIQLANDI.",
            "high":     "Yuqori xavf belgilari topildi.",
            "medium":   "Shubhali faollik aniqlandi.",
            "low":      "Fayl toza ko‘rinadi.",
        },
        "lsb": "Yashirin ma‘lumotlar aniqlandi (LSB-steganografiya: ko‘k kanalda tabiiy bo‘lmagan bir tekis shovqin).",
        "hist": "Gistogramma «tarak» effekti aniqlandi — LSB qo‘yishning klassik belgisi.",
        "trailing": "Fayl oxiri belgisidan keyin ma‘lumot topildi ({sz} bayt) — polyglot yoki stego-konteyner bo‘lishi mumkin.",
        "ctf": "Fayl tarkibidan CTF-bayroqlar ajratib olindi ({count} ta, 'flag{{...}}' namunasi). Fayl CTF uchun tayyorlangan ko‘rinadi.",
        "threats": "Tahdid kalit so‘zlari bilan mosliklar: {words}.",
        "macro_autoexec": "AutoExec triggerli VBA makrosi topildi — hujjat ochilganda kod avtomatik ishga tushadi.",
        "macro_plain": "Hujjatda VBA makrolari mavjud. Ochishdan oldin qo‘lda tekshirish tavsiya etiladi.",
        "pdf": "PDF ichida faol JavaScript yoki biriktirilgan fayllar topildi — yashirin yuklab olish xavfi bor.",
        "archive": "Arxivda bajariladigan fayllar yoki ikki kengaytma taktikasi mavjud ({details}).",
    },
}


def _build_summary(
    risk_level: str,
    lsb_findings: dict,
    ctf_flags: list,
    threat_words: list,
    macro_analysis: dict,
    language: str = "en",
) -> str:
    """
    Produce a concise summary suitable for end users, in the requested language.
    Avoids raw technical dumps — translates findings into plain language.
    """
    pack = _SUMMARY_PACKS.get(language) or _SUMMARY_PACKS["en"]
    parts: list[str] = []

    # Risk headline
    parts.append(pack["headlines"][risk_level])

    # LSB / steganography
    lsb_status = lsb_findings.get("lsb_anomaly", {}).get("status", "ok")
    hist_status = lsb_findings.get("histogram", {}).get("status", "ok")
    trailing_status = lsb_findings.get("trailing_data", {}).get("status", "ok")

    if lsb_status != "ok":
        parts.append(pack["lsb"])
    if hist_status != "ok":
        parts.append(pack["hist"])
    if trailing_status not in ("ok", "error"):
        trailing_sz = lsb_findings.get("trailing_data", {}).get("trailing_size", 0)
        parts.append(pack["trailing"].format(sz=trailing_sz))

    # CTF flags
    if ctf_flags:
        parts.append(pack["ctf"].format(count=len(ctf_flags)))

    # Threat keywords
    if threat_words:
        matched = ", ".join(threat_words[:5]) + ("..." if len(threat_words) > 5 else "")
        parts.append(pack["threats"].format(words=matched))

    # Macro / script analysis
    macro_status = macro_analysis.get("word_macro", {}).get("status", "ok")
    pdf_status   = macro_analysis.get("pdf_script", {}).get("status", "ok")
    archive_status = macro_analysis.get("archive", {}).get("status", "ok")

    if macro_status != "ok":
        details = macro_analysis["word_macro"].get("details", "")
        if "AutoExec" in details or "автозапуск" in details.lower():
            parts.append(pack["macro_autoexec"])
        else:
            parts.append(pack["macro_plain"])

    if pdf_status != "ok":
        parts.append(pack["pdf"])

    if archive_status not in ("ok", "error"):
        arch_details = macro_analysis["archive"].get("details", "")
        if "danger" in macro_analysis["archive"].get("status", ""):
            parts.append(pack["archive"].format(details=arch_details[:120]))

    return " ".join(parts)


async def _run_all_analyses(file_path: str) -> dict[str, Any]:
    """
    Run all applicable scanner functions from analyzer.py concurrently.
    """
    ext = file_path.lower()
    is_image   = ext.endswith((".png", ".bmp", ".jpg", ".jpeg"))
    is_audio   = ext.endswith((".mp3", ".ogg", ".wav"))
    is_word    = ext.endswith((".doc", ".docx"))
    is_pdf     = ext.endswith(".pdf")
    is_archive = ext.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"))

    # ── Always-run checks ─────────────────────────────────────────────────────
    tasks: dict[str, asyncio.Task] = {
        "entropy":    asyncio.create_task(
            asyncio.to_thread(analyzer.calculate_entropy, file_path)
        ),
        "trailing":   asyncio.create_task(
            asyncio.to_thread(analyzer.check_trailing_data, file_path)
        ),
        "artifacts":  asyncio.create_task(
            asyncio.to_thread(analyzer.scan_artifacts, file_path)
        ),
    }

    # ── Image-specific checks ─────────────────────────────────────────────────
    if is_image:
        tasks["lsb_anomaly"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_lsb_anomaly, file_path)
        )
        tasks["histogram"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_histogram_anomaly, file_path)
        )
        tasks["metadata"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_metadata, file_path)
        )

    # ── Audio-specific checks ─────────────────────────────────────────────────
    if is_audio:
        tasks["spectrum"]       = asyncio.create_task(
            asyncio.to_thread(analyzer.check_audio_spectrum, file_path)
        )
        tasks["audio_metadata"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_audio_metadata, file_path)
        )

    # ── Document checks ───────────────────────────────────────────────────────
    if is_word:
        tasks["word_macro"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_word_macros, file_path)
        )
    if is_pdf:
        tasks["pdf_script"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_pdf_scripts, file_path)
        )

    # ── Archive checks ────────────────────────────────────────────────────────
    if is_archive:
        tasks["archive"] = asyncio.create_task(
            asyncio.to_thread(analyzer.check_archive_contents, file_path)
        )

    # Wait for all tasks concurrently
    results: dict[str, Any] = {}
    for key, task in tasks.items():
        try:
            results[key] = await task
        except Exception as exc:
            results[key] = {"status": "error", "details": str(exc)}

    return results


# ── Standalone Async Function (LangChain @tool removed) ─────────────────────────

async def stego_security_tool(file_path: str, language: str = "en") -> dict:
    """
    Forensic steganography & threat scanner. The summary is written in `language`.
    """
    if not os.path.isfile(file_path):
        return {
            "risk_level":     "low",
            "lsb_findings":   {},
            "ctf_flags":      [],
            "threat_words":   [],
            "macro_analysis": {},
            "summary":        f"Error: File not found at path '{file_path}'.",
        }

    raw = await _run_all_analyses(file_path)

    # ── Extract artifact scan results ─────────────────────────────────────────
    artifacts     = raw.get("artifacts", {})
    ctf_flags     = artifacts.get("ctf_flags", [])
    threat_words  = artifacts.get("threat_words", [])

    # ── Group LSB / stego findings ────────────────────────────────────────────
    lsb_findings = {
        "lsb_anomaly":  raw.get("lsb_anomaly",  {"status": "ok", "details": "N/A"}),
        "histogram":    raw.get("histogram",     {"status": "ok", "details": "N/A"}),
        "trailing_data":raw.get("trailing",      {"status": "ok", "details": "N/A"}),
        "entropy":      raw.get("entropy",       {"status": "ok", "details": "N/A"}),
        "metadata":     raw.get("metadata",      {"status": "ok", "details": "N/A"}),
        "spectrum":     raw.get("spectrum",      {"status": "ok", "details": "N/A"}),
        "audio_metadata":raw.get("audio_metadata",{"status": "ok", "details": "N/A"}),
    }

    # ── Group macro / document / archive findings ─────────────────────────────
    macro_analysis = {
        "word_macro": raw.get("word_macro", {"status": "ok", "details": "N/A"}),
        "pdf_script": raw.get("pdf_script", {"status": "ok", "details": "N/A"}),
        "archive":    raw.get("archive",    {"status": "ok", "details": "N/A"}),
    }

    # ── Compute risk score using verdict function ─────────────────────────────
    lsb_res      = raw.get("lsb_anomaly", {"status": "ok"})
    macro_res    = (
        raw.get("word_macro")
        or raw.get("pdf_script")
        or {"status": "ok"}
    )
    trailing_res = raw.get("trailing", {"status": "ok"})
    entropy_res  = raw.get("entropy",  {"status": "ok"})
    spectrum_res = raw.get("spectrum")
    hist_res     = raw.get("histogram")
    archive_res  = raw.get("archive")

    verdict_status, _verdict_text, danger_score = analyzer.calculate_final_verdict(
        lsb_res, macro_res, trailing_res, entropy_res,
        spectrum_res, hist_res, archive_res, artifacts or None
    )

    is_critical = verdict_status == "ОПАСНО" or bool(ctf_flags) or bool(threat_words)
    # CTF-like strings and suspicious words warrant review, but they are not
    # proof of an active threat on their own. Reserve the critical verdict for
    # a confirmed malicious archive or an auto-executing macro.
    if ctf_flags or threat_words:
        archive_is_dangerous = macro_analysis["archive"].get("status") == "danger"
        macro_details = macro_analysis["word_macro"].get("details", "")
        is_critical = archive_is_dangerous or "AutoExec" in macro_details

    risk_level  = _classify_risk(danger_score, is_critical)

    summary = _build_summary(
        risk_level, lsb_findings, ctf_flags, threat_words, macro_analysis, language
    )

    return {
        "risk_level":     risk_level,
        "lsb_findings":   lsb_findings,
        "ctf_flags":      ctf_flags,
        "threat_words":   threat_words,
        "macro_analysis": macro_analysis,
        "summary":        summary,
    }
