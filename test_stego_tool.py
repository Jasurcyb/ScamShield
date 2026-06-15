"""
test_stego_tool.py — ScamShield integration tests for the Stego/Forensics Agent tool.

Two test cases:
  1. Clean file  → expected risk_level: "low"
  2. Seeded file → expected risk_level: "high" or "critical"

Run:
    python test_stego_tool.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

import numpy as np
from PIL import Image

# ── Ensure ScamShield root is resolvable ───────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.stego_tool import stego_security_tool  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# Helpers to create test files
# ──────────────────────────────────────────────────────────────────────────────

def _make_clean_png(path: str) -> None:
    """Create a 64×64 solid-colour PNG with no hidden data."""
    img = Image.new("RGB", (64, 64), color=(120, 180, 90))
    img.save(path, format="PNG")


def _make_lsb_seeded_png(path: str, payload: str) -> None:
    """
    Create a 256×256 PNG image with:
      • A perfectly uniform LSB distribution (~50% ones) in the blue channel
        to trigger the LSB-anomaly detector.
      • The payload string embedded at the start of the raw bytes so that
        the flag/keyword scanner can find it.
    The image also contains 'flag{hidden_data_found}' in its pixel byte stream
    to trigger CTF-flag extraction in scan_artifacts().
    """
    rng = np.random.default_rng(seed=42)

    # Build pixel array
    pixels = rng.integers(0, 256, (256, 256, 3), dtype=np.uint8)

    # Force LSB of blue channel to be exactly 50% ones (steganography fingerprint)
    blue_lsbs = rng.integers(0, 2, (256, 256), dtype=np.uint8)
    pixels[:, :, 2] = (pixels[:, :, 2] & 0xFE) | blue_lsbs
    ones_ratio = blue_lsbs.mean()
    # Clamp to the suspicious range 0.499–0.501
    target = 0.5000
    ones_count = int(target * 256 * 256)
    flat_lsbs = np.zeros(256 * 256, dtype=np.uint8)
    flat_lsbs[:ones_count] = 1
    rng.shuffle(flat_lsbs)
    pixels[:, :, 2] = (pixels[:, :, 2] & 0xFE) | flat_lsbs.reshape(256, 256)

    img = Image.fromarray(pixels, "RGB")
    img.save(path, format="PNG")

    # Append the payload as trailing bytes after the PNG IEND chunk
    # (this triggers check_trailing_data AND scan_artifacts text scan)
    with open(path, "ab") as f:
        f.write(f"\n{payload}\n".encode("utf-8"))


# ──────────────────────────────────────────────────────────────────────────────
# Test runner
# ──────────────────────────────────────────────────────────────────────────────

def _print_result(label: str, result: dict, expected_risk: str) -> bool:
    """Pretty-print the tool output and return True if the risk matches expectation."""
    sep = "─" * 60
    risk = result.get("risk_level", "unknown")
    passed = risk in (expected_risk, "critical") if expected_risk == "high" else risk == expected_risk

    print(f"\n{sep}")
    print(f"TEST: {label}")
    print(f"  Expected risk level : {expected_risk}")
    print(f"  Actual risk level   : {risk}  {'✅ PASS' if passed else '❌ FAIL'}")
    print(f"  CTF flags found     : {result.get('ctf_flags', [])}")
    print(f"  Threat words        : {result.get('threat_words', [])}")
    print(f"\n  Summary:\n    {result.get('summary', '')}")
    print(f"\n  LSB findings:")
    for k, v in result.get("lsb_findings", {}).items():
        status = v.get("status", "?") if isinstance(v, dict) else "?"
        detail = v.get("details", "") if isinstance(v, dict) else str(v)
        if status != "ok" or "N/A" not in detail:
            print(f"    [{status.upper():7s}] {k}: {detail[:100]}")
    print(f"\n  Macro analysis:")
    for k, v in result.get("macro_analysis", {}).items():
        status = v.get("status", "?") if isinstance(v, dict) else "?"
        detail = v.get("details", "") if isinstance(v, dict) else str(v)
        print(f"    [{status.upper():7s}] {k}: {detail[:100]}")
    print(sep)
    return passed


async def run_tests() -> None:
    passed = 0
    total  = 2

    with tempfile.TemporaryDirectory() as tmpdir:

        # ── Test 1: Clean file ────────────────────────────────────────────────
        clean_path = os.path.join(tmpdir, "clean_image.png")
        _make_clean_png(clean_path)

        print("\n🔬 Running Test 1 — Clean file (expect: low risk)...")
        result1 = await stego_security_tool.ainvoke({"file_path": clean_path})
        if _print_result("Clean 64×64 PNG", result1, expected_risk="low"):
            passed += 1

        # ── Test 2: LSB-seeded file with CTF flag ─────────────────────────────
        seeded_path = os.path.join(tmpdir, "seeded_stego.png")
        _make_lsb_seeded_png(
            seeded_path,
            payload="flag{hidden_payload_lsb_detected} password secret_key backdoor"
        )

        print("\n🔬 Running Test 2 — LSB-seeded PNG with CTF flag (expect: high/critical)...")
        result2 = await stego_security_tool.ainvoke({"file_path": seeded_path})
        if _print_result("Seeded 256×256 PNG (LSB + flag payload)", result2, expected_risk="high"):
            passed += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  Results: {passed}/{total} tests passed")
    print(f"{'═' * 60}\n")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())
