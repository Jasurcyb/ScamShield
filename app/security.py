"""Security helpers for public ScamShield endpoints."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import warnings
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "20000000"))
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "10000"))
MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "30"))
MAX_CONCURRENT_ANALYSES = int(os.getenv("MAX_CONCURRENT_ANALYSES", "20"))
UPLOAD_CHUNK_BYTES = 64 * 1024

IMAGE_FORMATS = {
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".gif": "GIF",
    ".webp": "WEBP",
    ".bmp": "BMP",
}
FORENSIC_EXTENSIONS = frozenset(
    {*IMAGE_FORMATS, ".pdf", ".doc", ".docx", ".zip", ".rar", ".mp3", ".ogg", ".wav"}
)

# Bounded queue for the expensive analysis pipeline. Excess requests fail fast
# instead of piling up threads and memory — the core app-level DDoS guard.
_analysis_semaphore: asyncio.Semaphore | None = None


def get_analysis_semaphore() -> asyncio.Semaphore:
    """Lazily created per-process semaphore capping simultaneous analyses."""
    global _analysis_semaphore
    if _analysis_semaphore is None:
        _analysis_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)
    return _analysis_semaphore


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Small in-memory guard for an MVP deployment.

    For multi-instance production deployments this must be replaced by a shared
    limiter (for example, Redis-backed rate limiting).
    """

    def __init__(self, app, requests_per_minute: int = MAX_REQUESTS_PER_MINUTE):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        if request.url.path in {"/", "/docs", "/openapi.json"}:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self._lock:
            attempts = self._requests[client_ip]
            while attempts and attempts[0] <= now - 60:
                attempts.popleft()
            if len(attempts) >= self.requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Слишком много запросов. Повторите попытку через минуту."},
                )
            attempts.append(now)

        return await call_next(request)


def _extension(upload: UploadFile) -> str:
    return Path(upload.filename or "").suffix.lower()


async def save_upload_limited(
    upload: UploadFile,
    *,
    allowed_extensions: frozenset[str] | dict[str, str],
) -> tuple[str, str]:
    """Stream an upload to a temporary file and enforce size/type restrictions."""
    extension = _extension(upload)
    if extension not in allowed_extensions:
        allowed = ", ".join(sorted(allowed_extensions))
        raise HTTPException(status_code=415, detail=f"Неподдерживаемый формат. Допустимые: {allowed}.")

    descriptor, path = tempfile.mkstemp(suffix=extension)
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as destination:
            while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Размер файла превышает лимит {MAX_UPLOAD_BYTES // (1024 * 1024)} МБ.",
                    )
                destination.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="Нельзя анализировать пустой файл.")

        validate_uploaded_file(path, extension)
        return path, extension
    except Exception:
        if os.path.exists(path):
            os.unlink(path)
        raise


def _validate_image(path: str, extension: str) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                if image.format != IMAGE_FORMATS[extension]:
                    raise HTTPException(status_code=415, detail="Расширение файла не соответствует изображению.")
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise HTTPException(status_code=413, detail="Разрешение изображения превышает допустимый лимит.")
                image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise HTTPException(status_code=415, detail="Файл не является корректным изображением заявленного формата.")


def _validate_docx(path: str) -> None:
    if not zipfile.is_zipfile(path):
        raise HTTPException(status_code=415, detail="Файл не является корректным документом DOCX.")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    if "[Content_Types].xml" not in names or "word/document.xml" not in names:
        raise HTTPException(status_code=415, detail="Файл не является корректным документом DOCX.")


def validate_uploaded_file(path: str, extension: str) -> None:
    """Validate file signatures before handing data to parsers or AI providers."""
    if extension in IMAGE_FORMATS:
        _validate_image(path, extension)
        return

    with open(path, "rb") as source:
        signature = source.read(16)

    valid = {
        ".pdf": signature.startswith(b"%PDF-"),
        ".doc": signature.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
        ".zip": signature.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
        ".rar": signature.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")),
        ".mp3": signature.startswith(b"ID3") or signature[:1] == b"\xff",
        ".ogg": signature.startswith(b"OggS"),
        ".wav": signature.startswith(b"RIFF") and signature[8:12] == b"WAVE",
    }

    if extension == ".docx":
        _validate_docx(path)
    elif not valid.get(extension, False):
        raise HTTPException(status_code=415, detail="Содержимое файла не соответствует его расширению.")
