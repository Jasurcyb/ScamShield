"""Optional PostgreSQL persistence for scan verdicts and user feedback.

Enabled by setting DATABASE_URL (e.g. postgres://user:pass@host:5432/scamshield).
Without it every function is a no-op and the bot keeps working — free deploys
do not need a database.

Privacy: message and file CONTENT is never stored — only the verdict metadata
and the user's optional scam/not-scam feedback.

All data queries use parameterized placeholders; the only non-parameterized
statements are the idempotent CREATE TABLE/INDEX literals below.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

_pool: Any = None          # psycopg_pool.ConnectionPool when enabled
_init_lock = threading.Lock()
_init_done = False


def db_enabled() -> bool:
    return bool(os.getenv("DATABASE_URL"))


def _get_pool() -> Any:
    global _pool, _init_done
    if not db_enabled():
        return None
    with _init_lock:
        if not _init_done:
            from psycopg_pool import ConnectionPool

            _pool = ConnectionPool(
                conninfo=os.environ["DATABASE_URL"],
                min_size=1,
                max_size=5,
                open=True,
            )
            with _pool.connection() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS scans ("
                    " id BIGSERIAL PRIMARY KEY,"
                    " chat_id BIGINT NOT NULL,"
                    " created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
                    " mode TEXT NOT NULL,"
                    " input_type TEXT NOT NULL,"
                    " overall_risk TEXT NOT NULL,"
                    " fraud_probability INT NOT NULL DEFAULT 0,"
                    " summary TEXT NOT NULL DEFAULT '',"
                    " feedback TEXT CHECK (feedback IN ('scam', 'clean')) DEFAULT NULL)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scans_chat ON scans (chat_id, created_at DESC)"
                )
            _init_done = True
    return _pool


def save_scan(
    chat_id: int,
    *,
    mode: str,
    input_type: str,
    overall_risk: str,
    fraud_probability: int,
    summary: str,
) -> Optional[int]:
    """Store a verdict; returns the scan id (for feedback buttons) or None."""
    pool = _get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO scans (chat_id, mode, input_type, overall_risk, fraud_probability, summary)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (chat_id, mode, input_type, overall_risk, fraud_probability, summary[:1000]),
            ).fetchone()
            return row[0]
    except Exception:
        logger.exception("save_scan failed")
        return None


def record_feedback(scan_id: int, feedback: str) -> bool:
    """Attach 'scam' or 'clean' feedback to a stored scan."""
    if feedback not in {"scam", "clean"}:
        return False
    pool = _get_pool()
    if pool is None:
        return False
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "UPDATE scans SET feedback = %s WHERE id = %s RETURNING id",
                (feedback, scan_id),
            ).fetchone()
            return row is not None
    except Exception:
        logger.exception("record_feedback failed")
        return False


def feedback_stats() -> dict[str, int]:
    """Aggregate feedback counts (for future quality reporting)."""
    pool = _get_pool()
    if pool is None:
        return {}
    try:
        with pool.connection() as conn:
            rows = conn.execute(
                "SELECT feedback, COUNT(*) FROM scans WHERE feedback IS NOT NULL GROUP BY feedback"
            ).fetchall()
            return {str(label): int(count) for label, count in rows}
    except Exception:
        logger.exception("feedback_stats failed")
        return {}
