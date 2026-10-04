"""In-memory per-chat state for the Telegram MVP.

Resets when the bot process restarts. Acceptable for the pilot because only
language, analysis mode, terms acceptance and a rate window are stored.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

from bot.localization import DEFAULT_LANGUAGE


@dataclass
class ChatState:
    language: str = DEFAULT_LANGUAGE
    mode: str = "full"
    accepted_terms: bool = False


_states: dict[int, ChatState] = {}
_analysis_attempts: dict[int, deque[float]] = defaultdict(deque)


def get_chat_state(chat_id: int) -> ChatState:
    state = _states.get(chat_id)
    if state is None:
        state = ChatState()
        _states[chat_id] = state
    return state


def check_rate(chat_id: int, limit: int, window_seconds: float = 60.0) -> bool:
    """Sliding-window per-chat throttle.

    Returns True and records the attempt when the chat is under the limit;
    returns False (without recording) when the chat is sending too fast.
    """
    now = time.monotonic()
    attempts = _analysis_attempts[chat_id]
    while attempts and attempts[0] <= now - window_seconds:
        attempts.popleft()
    if len(attempts) >= limit:
        return False
    attempts.append(now)
    return True
