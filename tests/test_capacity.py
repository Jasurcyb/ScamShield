import asyncio

import pytest

from app import security
from bot import service
from bot.state import check_rate
from analyzer import calculate_entropy


def test_per_chat_throttle_blocks_after_limit():
    chat_id = 987654
    assert all(check_rate(chat_id, 3) for _ in range(3))
    assert check_rate(chat_id, 3) is False


def test_throttle_windows_are_per_chat():
    assert check_rate(987655, 1)
    assert check_rate(987656, 1)


def test_analysis_semaphore_rejects_when_saturated(monkeypatch):
    # The semaphore size is read from the module global at creation time,
    # so patch the global (not the env) and drop the lazily created instance.
    monkeypatch.setattr(security, "MAX_CONCURRENT_ANALYSES", 1)
    security._analysis_semaphore = None

    async def route_stub(*, file_path=None, text=None, language="en"):
        return {}

    monkeypatch.setattr(service.router_controller, "route_decision", route_stub)

    async def scenario():
        semaphore = security.get_analysis_semaphore()
        async with semaphore:
            with pytest.raises(ValueError, match="server_busy"):
                await service.analyze_text_content("hello", language="ru", mode="full")

    try:
        asyncio.run(scenario())
    finally:
        security._analysis_semaphore = None


def test_entropy_matches_shannon_for_known_data(tmp_path):
    target = tmp_path / "known.bin"
    target.write_bytes(b"\x00\x01\x02\x03" * 512)

    result = calculate_entropy(str(target))

    assert result["entropy"] == 2.0
    assert result["status"] == "ok"
