# ScamShield — Multimodal Fraud Detection REST API

**ScamShield** is a production-ready fraud detection system built for the **AMD Developer Hackathon: ACT II**.  
It exposes an async FastAPI REST API that inspects text, URLs, documents, and images for phishing, social engineering, and forensic modifications — with a smart hybrid AI router that balances cost, speed, and accuracy.

---

## AI Providers

| Task | Model | Status |
|------|-------|--------|
| Text analysis (primary) | DeepSeek V4 Flash (Fireworks AI, AMD Instinct GPUs) | ✅ Active |
| Vision analysis (primary) | Minimax M3 (Fireworks AI, AMD Instinct GPUs) | ✅ Active |
| Text/Vision (Gemma path) | Google Gemma 4 31B IT (Fireworks AI) | 🔧 Code-ready, pending model access on current API tier |
| Offline fallback | Google Gemma 4 12B (local Ollama in Docker) | ✅ Active, $0 cost |

The router attempts **Google Gemma 4 31B IT** first; if unavailable (HTTP 404), it automatically falls back to **DeepSeek V4 Flash** (text) / **Minimax M3** (vision) on Fireworks AI, then to **local Ollama** if no API key or internet connection is present.

> **Note on Gemma Prize eligibility:** The codebase is fully written to use Google Gemma 4 31B IT as the primary model. The fallback to DeepSeek/Minimax is triggered only because the current Fireworks API tier does not expose Gemma models. If the tier is upgraded or Gemma access is granted, the system will automatically route all requests through Gemma with zero code changes.

---

## 🚀 Key Features

1. **Hybrid Provider Routing Controller** — Inspects incoming requests and intelligently routes lightweight tasks to a free local Ollama model, and complex visual/threat queries to cloud AI (Fireworks AI on AMD Instinct GPUs). Minimizes API costs while maintaining high accuracy.

2. **9-Probe Forensic Scanner** — Built-in parallel deep-scanning engine:
   - LSB steganography detection
   - Histogram combing analysis
   - Trailing data / appended payload detection
   - File entropy anomaly scoring
   - Word VBA macro extraction (AutoExec)
   - PDF JavaScript / embedded action scanning
   - Threat keyword matching
   - EXIF metadata inspection
   - File signature validation

3. **Levenshtein Typosquatting Engine** — High-performance domain similarity checking targeted at Central Asian banking platforms (Kapitalbank, Click, Payme, Uzcard, Humo) to catch phishing redirects like `kap1talbank.uz` or `payme-verif.uz`.

---

## 📐 Architecture

```
                  ┌────────────────────────────────────────┐
                  │          Client API Request            │
                  └──────────────────┬─────────────────────┘
                                     │ (JSON / File Upload)
                                     ▼
                  ┌────────────────────────────────────────┐
                  │             FastAPI Router             │
                  └──────────────────┬─────────────────────┘
                                     │
             ┌───────────────────────┴───────────────────────┐
             ▼ (Size & Keyword Heuristics)                   ▼ (Local Scan)
┌───────────────────────────┐                         ┌─────────────┐
│   Hybrid LLM Controller   │                         │  Forensics  │
└──────┬─────────────┬──────┘                         │   Engine    │
       │             │                                └──────┬──────┘
       ▼ (Cloud)     ▼ (Local)                               ▼
┌──────────────┐ ┌──────────────┐                    • LSB Stego Check
│ Fireworks AI │ │ Local Ollama │                    • Histogram Comb
│ (DeepSeek /  │ │ (Gemma 4 12B)│                    • PDF JS Check
│  Minimax M3) │ │    FREE      │                    • VBA AutoExec
└──────────────┘ └──────────────┘                    • EXIF & Entropy
```

---

## 🛠️ Setup & Running

### 1. Configure Credentials
```bash
cp .env.example .env
```
Fill in your `FIREWORKS_API_KEY`. If no key is set, the router falls back to local Ollama execution automatically.

### 2. Run with Docker Compose (Recommended)
This launches the FastAPI app and a local Ollama container. On startup, the entrypoint script automatically pulls `gemma4:12b` in the background.

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`.  
Interactive Swagger UI: `http://localhost:8000/docs`

### 3. Running Tests
```bash
docker compose run app pytest
```

---

## 📡 API Endpoints & Examples

### 1. Full Routed Scan (Image + Text)
```bash
curl -X POST "http://localhost:8000/analyze/full" \
  -F "file=@screenshot.png" \
  -F "text=Urgent verify your card details at kap1talbank.uz"
```

### 2. Text & URL Phishing Scan
```bash
curl -X POST "http://localhost:8000/analyze/text" \
  -F "text=Urgent! Send \$500 to verify your account at kap1talbank.uz within 1 hour"
```

### 3. Vision Analysis (Screenshot / Document)
```bash
curl -X POST "http://localhost:8000/analyze/vision" \
  -F "file=@bank_transfer.png"
```

### 4. Steganography / Forensics Scan
```bash
curl -X POST "http://localhost:8000/analyze/stego" \
  -F "file=@suspicious_document.pdf"
```

---

## 📁 Project Structure

```
scamshield_fastapi/
├── app/
│   ├── main.py          # FastAPI application & endpoint handlers
│   ├── models.py         # Pydantic request/response schemas
│   └── router.py         # Hybrid LLM provider routing logic
├── tools/
│   ├── llm_provider.py   # Fireworks AI / Ollama / Gemini backends
│   ├── vision_tool.py    # Image analysis via multimodal LLMs
│   ├── text_url_tool.py  # Text & URL phishing analysis
│   └── stego_tool.py     # Steganography & forensic scanning
├── analyzer.py           # Core forensic engine (9 parallel probes)
├── database.py           # SQLite scan history storage
├── Dockerfile            # Multi-stage container build
├── docker-compose.yml    # App + Ollama orchestration
├── entrypoint.sh         # Container startup (Ollama wait + model pull)
├── requirements.txt      # Python dependencies
└── .env.example          # Environment variable template
```

---

## 🔧 Tech Stack

- **Runtime:** Python 3.11, FastAPI, Uvicorn
- **Cloud AI:** Fireworks AI (DeepSeek V4 Flash, Minimax M3, Gemma 4 31B IT ready)
- **Local AI:** Ollama with Google Gemma 4 12B
- **Infrastructure:** Docker Compose, AMD Instinct GPUs (via Fireworks AI)
- **Forensics:** Pillow, python-docx, PyPDF2, numpy
- **Database:** SQLite (scan history)

---

## License

MIT
