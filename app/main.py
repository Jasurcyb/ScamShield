import asyncio
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure parent directory is on sys.path so 'tools', 'analyzer', 'database' can be imported
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from app.models import VisionResponse, StegoResponse, TextResponse, FullAnalysisResponse
from app.security import (
    FORENSIC_EXTENSIONS,
    IMAGE_FORMATS,
    MAX_TEXT_CHARS,
    RateLimitMiddleware,
    get_analysis_semaphore,
    save_upload_limited,
)
from tools.vision_tool import vision_fraud_tool
from tools.stego_tool import stego_security_tool
from tools.text_url_tool import text_url_fraud_tool
from app.router import HybridRouter


@asynccontextmanager
async def lifespan(_: FastAPI):
    # The whole sync pipeline (LLM calls, PIL, forensics) runs in the default
    # thread pool; the conservative stdlib default is too small for bursts.
    loop = asyncio.get_running_loop()
    loop.set_default_executor(
        ThreadPoolExecutor(max_workers=int(os.getenv("THREAD_POOL_SIZE", "32")))
    )
    yield


app = FastAPI(
    title="ScamShield API",
    description="Multimodal Fraud Detection REST API for AMD Developer Hackathon: ACT II",
    version="2.0.0",
    lifespan=lifespan,
)

# Initialize the hybrid router
router_controller = HybridRouter()

# ── CORS Middleware ───────────────────────────────────────────────────────────
app.add_middleware(RateLimitMiddleware)

# Telegram does not require CORS. Browser access is opt-in through an explicit
# allow-list, never a wildcard combined with credentials.
allowed_origins = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if origin.strip()]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["POST", "GET"],
        allow_headers=["Content-Type", "Authorization"],
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.get("/")
def read_root():
    return {"message": "Welcome to ScamShield API. Visit /docs for Swagger documentation."}


# ── POST /analyze/vision ──────────────────────────────────────────────────────

@app.post("/analyze/vision", response_model=VisionResponse)
async def analyze_vision(file: UploadFile = File(...)):
    """
    Inspects an image (screenshot, receipt, etc.) for visual signs of forgery or manipulation.
    """
    temp_path = None
    try:
        temp_path, _ = await save_upload_limited(file, allowed_extensions=IMAGE_FORMATS)
        semaphore = get_analysis_semaphore()
        if semaphore.locked():
            raise HTTPException(status_code=503, detail="Сервер перегружен. Повторите попытку позже.")
        async with semaphore:
            result = await vision_fraud_tool(temp_path)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Анализ изображения временно недоступен. Повторите попытку позже.") from e

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


# ── POST /analyze/stego ───────────────────────────────────────────────────────

@app.post("/analyze/stego", response_model=StegoResponse)
async def analyze_stego(file: UploadFile = File(...)):
    """
    Performs multi-layered forensic steganography and threat keyword checks on the uploaded file.
    """
    temp_path = None
    try:
        temp_path, _ = await save_upload_limited(file, allowed_extensions=FORENSIC_EXTENSIONS)
        semaphore = get_analysis_semaphore()
        if semaphore.locked():
            raise HTTPException(status_code=503, detail="Сервер перегружен. Повторите попытку позже.")
        async with semaphore:
            result = await stego_security_tool(temp_path)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Анализ файла временно недоступен. Повторите попытку позже.") from e

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


# ── POST /analyze/text ────────────────────────────────────────────────────────

@app.post("/analyze/text", response_model=TextResponse)
async def analyze_text(text: str = Form("")):
    """
    Inspects text messages and URLs for phishing, urgency triggers, and typo-squatted domains.
    """
    if not text.strip():
        raise HTTPException(status_code=400, detail="Text field cannot be empty.")
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=413, detail="Текст превышает допустимый объём.")

    semaphore = get_analysis_semaphore()
    if semaphore.locked():
        raise HTTPException(status_code=503, detail="Сервер перегружен. Повторите попытку позже.")
    try:
        async with semaphore:
            result = await text_url_fraud_tool(text)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Анализ текста временно недоступен. Повторите попытку позже.") from e


# ── POST /analyze/full (Hybrid Routed Analysis) ───────────────────────────────

@app.post("/analyze/full", response_model=FullAnalysisResponse)
async def analyze_full(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None)
):
    """
    Hybrid routed endpoint that performs full multimodal analysis.
    Picks the best configured cloud provider (Anthropic/Gemini/Fireworks)
    and synthesizes a unified forensic verdict from all agents.
    """
    if not file and not text:
        raise HTTPException(
            status_code=400,
            detail="Must provide at least one input for analysis: a file (upload) or a text message (form-data)."
        )
    if text and len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=413, detail="Текст превышает допустимый объём.")

    temp_path = None
    try:
        if file:
            temp_path, _ = await save_upload_limited(file, allowed_extensions=FORENSIC_EXTENSIONS)

        semaphore = get_analysis_semaphore()
        if semaphore.locked():
            raise HTTPException(status_code=503, detail="Сервер перегружен. Повторите попытку позже.")
        # Run router controller decision
        async with semaphore:
            result = await router_controller.route_decision(file_path=temp_path, text=text)
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Анализ временно недоступен. Повторите попытку позже.") from e

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
