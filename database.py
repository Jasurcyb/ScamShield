"""
database.py — Lightweight stub for ScamShield (standalone mode).

Replaces the original SQLite-backed database.py from the Stego-Shield Telegram bot.
This version has NO database dependencies and returns a hardcoded threat word list,
allowing analyzer.py to run fully standalone without any Telegram or DB setup.
"""

# Curated threat-word list used by the forensic scanner.
# Covers CTF flags, credential markers, crypto key headers, and malware keywords.
DEFAULT_THREAT_WORDS = [
    "flag{",        # Generic CTF flag prefix
    "CTF{",         # Alternate CTF bracket notation
    "password",     # Plaintext credential keyword
    "secret_key",   # Secret/API key marker
    "admin_token",  # Administrative token indicator
    "private_key",  # RSA / PEM private key label
    "BEGIN RSA",    # PEM private key header
    "malware",      # Malware artifact keyword
    "backdoor",     # Backdoor / RAT indicator
    "exploit",      # Exploit payload marker
    # Supplemental Russian-language threat keywords (mirroring original bot defaults)
    "взрыв",        # explosion
    "теракт",       # terrorist act
    "оружие",       # weapon
    "тротил",       # TNT / trinitrotoluene
    "заминирован",  # mined / booby-trapped
]


def get_trigger_words() -> list[bytes]:
    """
    Returns threat/trigger words as a list of UTF-8 encoded bytes.
    Mirrors the original database.get_trigger_words() interface exactly
    so that analyzer.py can call this function without modification.
    """
    return [w.encode("utf-8") for w in DEFAULT_THREAT_WORDS]


# ── Stub no-ops for any other database calls that might be referenced ──────────

def init_db() -> None:
    """No-op stub. No database to initialise in standalone mode."""
    pass


def save_scan(*args, **kwargs) -> None:
    """No-op stub. Scan results are not persisted in standalone mode."""
    pass


def get_scan(file_hash: str):
    """Always returns None — no cache in standalone mode."""
    return None


def get_cached_scan(file_hash: str):
    """Always returns None — no cache in standalone mode."""
    return None


def update_ai_text(*args, **kwargs) -> None:
    """No-op stub."""
    pass


def clear_scans() -> None:
    """No-op stub."""
    pass


def get_stats() -> tuple[int, int, int]:
    """Returns zeroed stats — no database in standalone mode."""
    return 0, 0, 0


def add_trigger_word(word: str) -> None:
    """No-op stub. Words are not persisted in standalone mode."""
    pass
