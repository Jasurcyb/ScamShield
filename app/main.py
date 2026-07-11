import os
import sys
import tempfile
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure parent directory is on sys.path so 'tools', 'analyzer', 'database' can be imported
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from app.models import VisionResponse, StegoResponse, TextResponse, FullAnalysisResponse
from tools.vision_tool import vision_fraud_tool
from tools.stego_tool import stego_security_tool
from tools.text_url_tool import text_url_fraud_tool
from app.router import HybridRouter

app = FastAPI(
    title="ScamShield API",
    description="Multimodal Fraud Detection REST API for AMD Developer Hackathon: ACT II",
    version="2.0.0"
)

# Initialize the hybrid router
router_controller = HybridRouter()

# ── CORS Middleware ───────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to ScamShield API. Visit /docs for Swagger documentation."}


# ── POST /analyze/vision ──────────────────────────────────────────────────────

@app.post("/analyze/vision", response_model=VisionResponse)
async def analyze_vision(file: UploadFile = File(...)):
    """
    Inspects an image (screenshot, receipt, etc.) for visual signs of forgery or manipulation.
    """
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Must be an image: PNG, JPG, JPEG, GIF, WEBP, BMP."
        )

    # Save to a temporary file
    temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
    try:
        with os.fdopen(temp_fd, 'wb') as tmp:
            content = await file.read()
            tmp.write(content)
        
        result = await vision_fraud_tool(temp_path)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Vision analysis failed: {str(e)}")

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


# ── POST /analyze/stego ───────────────────────────────────────────────────────

@app.post("/analyze/stego", response_model=StegoResponse)
async def analyze_stego(file: UploadFile = File(...)):
    """
    Performs multi-layered forensic steganography and threat keyword checks on the uploaded file.
    """
    ext = os.path.splitext(file.filename)[1].lower()
    
    # Save to a temporary file
    temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
    try:
        with os.fdopen(temp_fd, 'wb') as tmp:
            content = await file.read()
            tmp.write(content)
        
        result = await stego_security_tool(temp_path)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stego analysis failed: {str(e)}")

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


# ── POST /analyze/text ────────────────────────────────────────────────────────

@app.post("/analyze/text", response_model=TextResponse)
async def analyze_text(text: str = Form(...)):
    """
    Inspects text messages and URLs for phishing, urgency triggers, and typo-squatted domains.
    """
    if not text.strip():
        raise HTTPException(status_code=400, detail="Text field cannot be empty.")

    try:
        result = await text_url_fraud_tool(text)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text analysis failed: {str(e)}")


# ── POST /analyze/full (Hybrid Routed Analysis) ───────────────────────────────

@app.post("/analyze/full", response_model=FullAnalysisResponse)
async def analyze_full(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None)
):
    """
    Hybrid routed endpoint that performs full multimodal analysis.
    Intelligently routes LLM tasks locally (Ollama) or remotely (Fireworks/Claude/Gemini)
    to minimize token costs while maintaining high forensic accuracy.
    """
    if not file and not text:
        raise HTTPException(
            status_code=400,
            detail="Must provide at least one input for analysis: a file (upload) or a text message (form-data)."
        )

    temp_path = None
    try:
        if file:
            ext = os.path.splitext(file.filename)[1].lower()
            temp_fd, temp_path = tempfile.mkstemp(suffix=ext)
            with os.fdopen(temp_fd, 'wb') as tmp:
                content = await file.read()
                tmp.write(content)

        # Run router controller decision
        result = await router_controller.route_decision(file_path=temp_path, text=text)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full analysis failed: {str(e)}")

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
