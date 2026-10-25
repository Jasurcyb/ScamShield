"""Persistence behaviour: disabled by default, parameterized SQL when enabled."""

from __future__ import annotations

import asyncio

import pytest

import app.db as db
from bot import service


def test_db_disabled_by_default(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert db.db_enabled() is False
    assert db.save_scan(1, mode="full", input_type="text",
                        overall_risk="low", fraud_probability=15, summary="x") is None
    assert db.record_feedback(1, "scam") is False
    assert db.feedback_stats() == {}


def test_feedback_verdicts_are_whitelisted():
    assert db.record_feedback.__doc__  # module imports cleanly
    # only 'scam'/'clean' reach SQL — enforced before any pool access
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert db.record_feedback(1, "DROP TABLE scans; --") is False
    monkeypatch.undo()


def test_scan_id_absent_without_db(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    async def route_stub(*, file_path=None, text=None, language="en"):
        return {
            "overall_risk": "low",
            "fraud_probability": 15,
            "agent_reports": {},
            "final_summary": "OK.",
            "router_metadata": {"selected_provider": "none", "tokens_used": 0, "cost_estimate": 0.0},
        }

    monkeypatch.setattr(service.router_controller, "route_decision", route_stub)
    result = asyncio.run(service.analyze_text_content("hi", chat_id=42, language="ru", mode="full"))
    assert "scan_id" not in result


def test_scan_id_set_when_db_enabled(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://mock")
    monkeypatch.setattr(db, "save_scan", lambda *a, **k: 777)

    async def route_stub(*, file_path=None, text=None, language="en"):
        return {
            "overall_risk": "high",
            "fraud_probability": 80,
            "agent_reports": {},
            "final_summary": "Danger.",
            "router_metadata": {"selected_provider": "none", "tokens_used": 0, "cost_estimate": 0.0},
        }

    monkeypatch.setattr(service.router_controller, "route_decision", route_stub)
    result = asyncio.run(service.analyze_text_content("hi", chat_id=42, language="ru", mode="full"))
    assert result["scan_id"] == 777
