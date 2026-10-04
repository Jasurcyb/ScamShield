import asyncio

import pytest

from bot.localization import text
from bot.service import analyze_text_content, format_result


def test_result_formatting_escapes_model_output():
    report = format_result(
        {"overall_risk": "high", "final_summary": "<script>unsafe</script>"},
        "ru",
    )

    assert "&lt;script&gt;unsafe&lt;/script&gt;" in report
    assert "Высокий риск" in report


def test_localization_falls_back_to_russian():
    assert text("unknown-language", "low") == "Безопасно"


def test_privacy_notice_includes_contact_and_sensitive_data_warning():
    notice = text("ru", "privacy", support_contact="@scamshield_support")

    assert "@scamshield_support" in notice
    assert "пароли" in notice
    assert "AI-провайдером" in notice


def test_bot_rejects_oversized_text_before_model_call():
    with pytest.raises(ValueError, match="text_too_long"):
        asyncio.run(analyze_text_content("a" * 10_001))
