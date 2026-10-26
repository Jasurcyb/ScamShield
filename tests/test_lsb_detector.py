"""Regression tests for the calibrated LSB stego detector (document-like images)."""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

import analyzer


def _document_image(rng: np.random.Generator, size: int = 320) -> np.ndarray:
    img = np.full((size, size), 250.0)
    for row in range(6, size - 20, 26):
        img[row:row + 12, 24:size - 60] = 35.0
    img[size - 40:size - 20, 24:size - 24] = 20.0
    img += rng.normal(0, 0.6, (size, size))
    return np.clip(img, 0, 255).astype(np.uint8)


def _to_rgb(gray: np.ndarray) -> np.ndarray:
    return np.stack([gray, gray, gray], axis=-1)


def test_clean_compressed_document_is_ok(tmp_path):
    rng = np.random.default_rng(3)
    path = tmp_path / "clean.jpg"
    Image.fromarray(_to_rgb(_document_image(rng))).save(path, format="JPEG", quality=85)
    result = analyzer.check_lsb_anomaly(str(path))
    assert result["status"] == "ok"
    assert result["lsb_autocorr"] > analyzer.LSB_AUTOCORR_MAX


def test_lsb_payload_in_document_is_flagged(tmp_path):
    rng = np.random.default_rng(3)
    jpg = tmp_path / "base.jpg"
    Image.fromarray(_to_rgb(_document_image(rng))).save(jpg, format="JPEG", quality=85)
    compressed = np.array(Image.open(jpg).convert("RGB"))
    payload = rng.integers(0, 2, size=compressed.shape[:2], dtype=np.uint8)
    compressed[:, :, 2] = (compressed[:, :, 2] & 0xFE) | payload
    stego = tmp_path / "stego.png"
    Image.fromarray(compressed).save(stego)

    result = analyzer.check_lsb_anomaly(str(stego))
    assert result["status"] == "warning"
    assert abs(result["lsb_autocorr"]) <= analyzer.LSB_AUTOCORR_MAX


def test_noisy_photo_is_not_flagged(tmp_path):
    """Sensor-noisy regions are out of the detector's scope and must stay quiet."""
    rng = np.random.default_rng(5)
    noisy = np.clip(rng.normal(128, 30, (320, 320, 3)), 0, 255).astype(np.uint8)
    path = tmp_path / "noisy.png"
    Image.fromarray(noisy).save(path)
    result = analyzer.check_lsb_anomaly(str(path))
    assert result["status"] == "ok"
