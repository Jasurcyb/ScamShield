"""
test_vision_tool.py — ScamShield integration tests for the Vision Fraud Detector.

Two test cases:
  1. Clean image  → expected risk_level: "low"
  2. Suspicious image with obvious editing artefacts → expected: "medium" / "high" / "critical"

Run:
    python test_vision_tool.py

Requires ANTHROPIC_API_KEY in .env or environment.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

# ── Ensure ScamShield root is resolvable ───────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.vision_tool import vision_fraud_tool  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# Helpers to create test images
# ──────────────────────────────────────────────────────────────────────────────

def _make_clean_photo(path: str) -> None:
    """
    Create a simple solid-gradient landscape image — no text, no UI elements.
    This should register as "low" risk since it's clearly not a document.
    """
    img = Image.new("RGB", (400, 300))
    draw = ImageDraw.Draw(img)

    # Simple sky-to-grass gradient
    for y in range(300):
        if y < 180:
            # Sky — blue gradient
            r = 100 + int(y * 0.3)
            g = 150 + int(y * 0.2)
            b = 220 - int(y * 0.15)
        else:
            # Grass — green gradient
            r = 60 + int((y - 180) * 0.3)
            g = 140 - int((y - 180) * 0.2)
            b = 50
        draw.line([(0, y), (399, y)], fill=(r, g, b))

    img.save(path, format="PNG")


def _make_suspicious_screenshot(path: str) -> None:
    """
    Create a fake 'bank transfer confirmation' screenshot with deliberate
    fraud indicators that the vision model should detect:

      • Mixed fonts/sizes for the transfer amount vs. other text
      • Misaligned elements (pasted-looking amount field)
      • Suspiciously round amount (999999.00)
      • Inconsistent date format
      • Visible white rectangle (poorly masked edit region)

    This simulates a typical scam screenshot where the transfer amount
    has been doctored.
    """
    width, height = 480, 640
    img = Image.new("RGB", (width, height), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)

    # Use default PIL font (guaranteed available everywhere)
    try:
        font_normal = ImageFont.truetype("arial.ttf", 16)
        font_bold = ImageFont.truetype("arialbd.ttf", 18)
        font_large = ImageFont.truetype("times.ttf", 32)  # Deliberately different family
        font_small = ImageFont.truetype("arial.ttf", 11)
    except (OSError, IOError):
        # Fallback — use default bitmap font at different logical sizes
        font_normal = ImageFont.load_default()
        font_bold = font_normal
        font_large = font_normal
        font_small = font_normal

    # ── Header bar ────────────────────────────────────────────────────────────
    draw.rectangle([(0, 0), (width, 56)], fill=(25, 118, 210))
    draw.text((20, 16), "✓ Transfer Confirmation", fill="white", font=font_bold)

    # ── Body fields ───────────────────────────────────────────────────────────
    y = 80
    fields = [
        ("From:", "John A. Smith"),
        ("Account:", "4276 **** **** 8901"),
        ("To:", "UNKNOWN RECIPIENT"),
        ("Bank:", "ShadowBank International"),
        ("Date:", "06/12/2026"),      # Normal date
        ("Reference:", "TX-00000001"),
    ]
    for label, value in fields:
        draw.text((20, y), label, fill=(100, 100, 100), font=font_small)
        draw.text((120, y), value, fill=(30, 30, 30), font=font_normal)
        y += 34

    # ── Suspicious amount field ───────────────────────────────────────────────
    # Simulate a poorly-edited amount: white rectangle + different font
    amount_y = y + 20
    # White "cover-up" rectangle (editing artefact)
    draw.rectangle([(110, amount_y - 5), (440, amount_y + 40)], fill=(255, 255, 255))
    # Amount label in normal font
    draw.text((20, amount_y + 4), "Amount:", fill=(100, 100, 100), font=font_small)
    # Amount value in a DIFFERENT font family and size (fraud indicator)
    draw.text((125, amount_y - 2), "$999,999.00", fill=(200, 30, 30), font=font_large)

    # ── Conflicting second date ───────────────────────────────────────────────
    y2 = amount_y + 60
    draw.text((20, y2), "Processed:", fill=(100, 100, 100), font=font_small)
    # Date in a completely different format — inconsistency indicator
    draw.text((120, y2), "2025-13-45 28:99", fill=(30, 30, 30), font=font_normal)

    # ── Fake QR code block (just a noisy square to simulate low-res QR) ──────
    qr_x, qr_y = 320, y2 + 40
    draw.rectangle([(qr_x, qr_y), (qr_x + 100, qr_y + 100)], fill="black")
    # Add some white noise dots to make it look like a degraded QR
    import random
    random.seed(42)
    for _ in range(200):
        px = random.randint(qr_x + 2, qr_x + 98)
        py = random.randint(qr_y + 2, qr_y + 98)
        sz = random.randint(2, 6)
        draw.rectangle([(px, py), (px + sz, py + sz)], fill="white")

    # ── Footer with mismatched styling ────────────────────────────────────────
    draw.rectangle([(0, height - 50), (width, height)], fill=(240, 240, 240))
    draw.text(
        (20, height - 35),
        "⚠ This is NOT an official bank document",
        fill=(180, 50, 50),
        font=font_small,
    )

    img.save(path, format="PNG")


# ──────────────────────────────────────────────────────────────────────────────
# Test runner
# ──────────────────────────────────────────────────────────────────────────────

def _print_result(label: str, result: dict, expected_risks: list[str]) -> bool:
    """Pretty-print the tool output and return True if risk matches expectation."""
    sep = "-" * 60
    risk = result.get("risk_level", "unknown")
    passed = risk in expected_risks

    print(f"\n{sep}")
    print(f"TEST: {label}")
    print(f"  Expected risk level : {' or '.join(expected_risks)}")
    print(f"  Actual risk level   : {risk}  {'[PASS]' if passed else '[FAIL]'}")

    findings = result.get("visual_findings", [])
    if findings:
        print(f"  Visual findings ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            print(f"    {i}. {f}")
    else:
        print("  Visual findings     : (none)")

    print(f"\n  Summary:\n    {result.get('summary', '(no summary)')}")
    print(sep)
    return passed


def _load_env_fallback():
    # Try loading .env manually
    root_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(root_dir, ".env")
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            os.environ[parts[0].strip()] = parts[1].strip()
        except Exception:
            pass


async def run_tests() -> None:
    # ── Pre-flight check ──────────────────────────────────────────────────────
    _load_env_fallback()
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    except ImportError:
        pass

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if not anthropic_key and not gemini_key:
        print("=" * 60)
        print("[WARNING] Neither ANTHROPIC_API_KEY nor GEMINI_API_KEY found!")
        print("   Set one of them in .env or as an environment variable.")
        print("   Tests will run but return 'unknown' risk level.")
        print("=" * 60)

    passed = 0
    total = 2

    with tempfile.TemporaryDirectory() as tmpdir:

        # ── Test 1: Clean landscape photo ─────────────────────────────────────
        clean_path = os.path.join(tmpdir, "clean_landscape.png")
        _make_clean_photo(clean_path)

        print("\n[TEST] Running Test 1 — Clean landscape photo (expect: low)...")
        result1 = await vision_fraud_tool.ainvoke({"file_path": clean_path})
        if _print_result("Clean gradient landscape", result1, expected_risks=["low"]):
            passed += 1

        # ── Test 2: Suspicious bank transfer screenshot ───────────────────────
        suspicious_path = os.path.join(tmpdir, "fake_transfer.png")
        _make_suspicious_screenshot(suspicious_path)

        print("\n[TEST] Running Test 2 — Fake bank transfer screenshot (expect: medium/high/critical)...")
        result2 = await vision_fraud_tool.ainvoke({"file_path": suspicious_path})
        if _print_result(
            "Doctored bank transfer with mixed fonts & impossible date",
            result2,
            expected_risks=["medium", "high", "critical"],
        ):
            passed += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Results: {passed}/{total} tests passed")
    print(f"{'=' * 60}\n")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())
