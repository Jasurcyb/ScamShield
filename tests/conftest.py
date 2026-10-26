"""Shared test fixtures.

Unit tests must be offline and deterministic: server-side link checks are
disabled globally unless a test explicitly re-enables them with mocks.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _offline_url_checks(monkeypatch):
    monkeypatch.setenv("URL_CHECK_ENABLED", "false")
    import tools.url_checker as uc

    monkeypatch.setattr(uc, "REPUTATION_ENABLED", False)
