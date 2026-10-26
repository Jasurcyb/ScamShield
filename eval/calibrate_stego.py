"""Calibrate the LSB stego detector on JPEG-realistic clean vs embedded images.

Why JPEG: on raw sensor noise a clean LSB plane and a random embedded payload
are statistically indistinguishable. The detectable signal lives in smooth
regions of COMPRESSED images (screenshots, receipts, photos), where the
natural LSB plane is correlated and a payload turns it into white noise.

Clean sample  = synthetic scene saved as JPEG (quality 85).
Stego sample   = the same JPEG with its blue-channel LSB replaced by a payload.

Reports detector statistics and FPR/TPR at the current thresholds in analyzer.py.

Usage:
    python eval/calibrate_stego.py [samples_per_class]
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import analyzer  # noqa: E402

SIZE = 320


def scenes(rng: np.random.Generator, n: int):
    """Yield synthetic grayscale scenes matching ScamShield's real artifacts:
    bank-transfer screenshots, receipts and documents (flat regions + text),
    plus a gentle gradient and a two-tone panel as controls."""
    for i in range(n):
        kind = i % 4
        h = w = SIZE
        if kind == 0:  # gentle gradient (control: smooth, no payload space)
            base = np.linspace(60, 190, w, dtype=np.float64)[None, :].repeat(h, 0)
            img = base + rng.normal(0, 0.8, (h, w))
        elif kind == 1:  # receipt: white paper + dark text lines + total block
            img = np.full((h, w), 245.0)
            for row in range(6, h - 20, 26):
                img[row:row + 12, 24:w - 60] = 35.0
            img[h - 40:h - 20, 24:w - 24] = 20.0
        elif kind == 2:  # two-tone transfer screenshot (header + body)
            img = np.full((h, w), 235.0)
            img[:56] = 40.0
            img[120:170, 30:w - 30] = 250.0
            img += rng.normal(0, 0.6, (h, w))
        else:  # document: paragraphs of text on light background
            img = np.full((h, w), 250.0)
            for _ in range(14):
                y0 = int(rng.integers(10, h - 30))
                x0 = int(rng.integers(10, w - 130))
                img[y0:y0 + 13, x0:x0 + 120] = 30.0
        yield np.clip(img, 0, 255).astype(np.uint8)


def to_rgb(gray: np.ndarray) -> np.ndarray:
    return np.stack([gray, gray, gray], axis=-1)


def embed_payload(rgb: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    out = rgb.copy()
    payload = rng.integers(0, 2, size=rgb.shape[:2], dtype=np.uint8)
    out[:, :, 2] = (out[:, :, 2] & 0xFE) | payload
    return out


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    rng = np.random.default_rng(7)

    records = {"clean": [], "stego": []}
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for i, gray in enumerate(scenes(rng, n)):
            base_jpg = tmpdir / f"base_{i}.jpg"
            Image.fromarray(to_rgb(gray)).save(base_jpg, format="JPEG", quality=85)

            # clean: detect the compressed original
            res = analyzer.check_lsb_anomaly(str(base_jpg))
            records["clean"].append(res)

            # stego: embed into the compressed original, store losslessly
            compressed = np.array(Image.open(base_jpg).convert("RGB"))
            stego_png = tmpdir / f"stego_{i}.png"
            Image.fromarray(embed_payload(compressed, rng)).save(stego_png)
            records["stego"].append(analyzer.check_lsb_anomaly(str(stego_png)))

    for label in ("clean", "stego"):
        acs = np.array([r.get("lsb_autocorr", 1.0) for r in records[label]])
        bits = np.array([r.get("lsb_smooth_bits", 0) for r in records[label]])
        flagged = sum(r.get("status") == "warning" for r in records[label])
        print(f"{label:>5}: n={len(acs)}  autocorr[median]={np.median(acs):+.4f} "
              f"smooth_bits[median]={int(np.median(bits))}  flagged={flagged}/{len(acs)}")

    fp = sum(r.get("status") == "warning" for r in records["clean"])
    tp = sum(r.get("status") == "warning" for r in records["stego"])
    fpr, tpr = fp / n, tp / n
    print(f"FPR(clean flagged)={fpr:.2%}   TPR(stego flagged)={tpr:.2%}")
    print(f"thresholds: smooth_std<={analyzer.LSB_SMOOTH_STD_MAX}, "
          f"min_bits>={analyzer.LSB_MIN_SMOOTH_BITS}, |autocorr|<={analyzer.LSB_AUTOCORR_MAX}")
    if fpr > 0.05 or tpr < 0.9:
        print("WARN: thresholds need retuning (target FPR<=5%, TPR>=90%)")
        return 1
    print("thresholds OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
