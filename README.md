# ScamShield — Multimodal Fraud Detection REST API

**ScamShield** is a Telegram-first MVP for the **President Tech Award Incubation Track**. It helps users identify phishing, suspicious links, forged receipts, and risky files.
It exposes an async FastAPI REST API that inspects text, URLs, documents, and images for phishing, social engineering, and forensic modifications — with a smart hybrid AI router that balances cost, speed, and accuracy.

---

## AI Providers

| Task | Model | Status |
|------|-------|--------|
| Text analysis (primary) | DeepSeek V4 Flash (Fireworks AI, AMD Instinct GPUs) | ✅ Active |
| Vision analysis (primary) | Minimax M3 (Fireworks AI, AMD Instinct GPUs) | ✅ Active |
| Text/Vision (Gemma path) | Google Gemma 4 31B IT (Fireworks AI) | 🔧 Code-ready, pending model access on current API tier |

The router attempts **Google Gemma 4 31B IT** first; if unavailable (HTTP 404), it automatically falls back to **DeepSeek V4 Flash** (text) / **Minimax M3** (vision) on Fireworks AI. All inference is cloud-based — a configured cloud API key (Anthropic / Gemini / Fireworks) is required.

> **Note on Gemma Prize eligibility:** The codebase is fully written to use Google Gemma 4 31B IT as the primary model. The fallback to DeepSeek/Minimax is triggered only because the current Fireworks API tier does not expose Gemma models. If the tier is upgraded or Gemma access is granted, the system will automatically route all requests through Gemma with zero code changes.

---

## 🚀 Key Features

1. **Hybrid Provider Routing Controller** — Picks the best available cloud AI provider (Anthropic → Gemini → Fireworks on AMD Instinct GPUs) per request and synthesizes a unified verdict from all agents. Fails fast with a clear configuration error when no API key is set.

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

4. **Server-side Link Verification (SSRF-hardened)** — URLs are actually fetched: DNS is resolved and every IP must be public (loopback/private/link-local — including the 169.254.169.254 metadata address — reserved and multicast are rejected); redirects are followed manually with the same validation on every hop; shorteners like bit.ly are expanded so typosquat checks run on the **final** domain. Responses are streamed with a 64 KB cap. Known limitation: resolve-then-connect leaves a short TOCTOU window for DNS rebinding.

5. **Eval-Driven Quality** — 87 labelled cases in `eval/dataset.jsonl` with an offline scorer (`python eval/run_eval.py`): deterministic-layer accuracy 97.2%, precision 100%, recall 94.6% (see `eval/BASELINE.md`). Prompt-injection resilience is covered by a dedicated test suite where a mocked LLM complies with attacker instructions and the pipeline must still elevate risk.

6. **Feedback Loop (optional PostgreSQL)** — set `DATABASE_URL` and every verdict gets «🐟 scam / ✅ not a scam» buttons; only the verdict and feedback are stored (never message or file content). Without `DATABASE_URL` persistence is off and the bot works unchanged. `docker compose up` starts a local Postgres automatically.

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
             ▼ (Cloud LLM)                                   ▼ (Local Scan)
┌───────────────────────────┐                         ┌─────────────┐
│   Hybrid LLM Controller   │                         │  Forensics  │
└──────────────┬────────────┘                         │   Engine    │
               │                                └──────┬──────┘
               ▼                                      ▼
┌───────────────────────────┐                    • LSB Stego Check
│ Fireworks AI              │                    • Histogram Comb
│ DeepSeek V4 / Minimax M3  │                    • PDF JS Check
│ / Gemma 4 31B IT          │                    • VBA AutoExec
└───────────────────────────┘                    • EXIF & Entropy
```

---

## 🛠️ Setup & Running

### 1. Configure Credentials
```bash
cp .env.example .env
```
Fill in `TELEGRAM_BOT_TOKEN` and at least one cloud AI key (`FIREWORKS_API_KEY`, `GEMINI_API_KEY` or `ANTHROPIC_API_KEY`). Without a cloud key the API and bot fail fast with a clear configuration error.

### 2. Pull Pre-built Image
```bash
docker pull ghcr.io/jasurcyb/scamshield-amd-act2:latest
docker run -p 8000:8000 --env-file .env ghcr.io/jasurcyb/scamshield-amd-act2:latest
```

### 3. Run with Docker Compose (Recommended)
This launches the FastAPI app; all inference runs on cloud LLM providers.

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`.  
Interactive Swagger UI: `http://localhost:8000/docs`

### 4. Run the Telegram bot

Set `TELEGRAM_BOT_TOKEN` and a public `SUPPORT_CONTACT` (Telegram handle or email) in `.env`, then run:

```bash
docker compose up --build bot
```

**Commands and flow**

- `/start` — first launch shows a terms-of-use summary with an **Accept** button; analysis is blocked until the terms are accepted (hard gate). After acceptance the bot shows the mode menu and command reference.
- `/mode` — choose the analysis mode: **Full analysis (coordinator)** runs all agents and synthesizes a unified verdict, **Stego/forensics only**, **Text & links only**, and **Image only** run a single agent. The mode applies per chat until changed.
- `/language` — switch the interface language (Русский / O‘zbekcha / English). The verdict follows the choice: LLM summaries are generated in the selected language and the local stego summary uses localized templates. API defaults stay English.
- `/terms` — full user agreement; `/privacy` — pilot privacy notice.
- Every result ends with a disclaimer and a localized safety recommendation.

Per-chat state (language, mode, terms acceptance) is kept in memory and resets when the bot process restarts — acceptable for the pilot, use a persistent store before scaling.

### Capacity & load protection (≈40 concurrent users)

The async layer handles hundreds of connections; the constrained resources are the thread pool, the LLM backend and RAM. Built-in guards:

| Guard | Default | What it does |
|---|---|---|
| `MAX_CONCURRENT_ANALYSES` | 20 | Semaphore shared by API and bot; excess analyses fail fast with 503 (API) / a "server busy" message (bot) instead of piling up |
| `MAX_REQUESTS_PER_MINUTE` | 30 | Per-IP sliding window on the API (in-memory, per worker process) |
| `BOT_MAX_ANALYSES_PER_MINUTE` | 10 | Per-chat sliding window in the bot |
| `UVICORN_WORKERS` / `UVICORN_MAX_CONNECTIONS` | 2 / 120 | Worker processes and a hard cap on simultaneous connections — excess connections get an immediate 503 |
| `THREAD_POOL_SIZE` | 32 | Threads for the sync pipeline (LLM calls, PIL, forensics); keep ≈2× `MAX_CONCURRENT_ANALYSES` |

Sizing rules of thumb: with a cloud LLM (Fireworks) a full burst of 40 users completes in roughly 2 waves of single-analysis time. A 20 MP image scan costs ~5 s of CPU and ~300 MB RAM.

For deployment-grade DDoS protection put a reverse proxy (nginx/Caddy) or Cloudflare in front of the API — the app-level guards above protect the analysis pipeline, while the proxy absorbs connection floods, TLS overhead and bot traffic. The Telegram bot does not need one (polling, no public port).

The full pilot privacy notice is available through `/privacy`; it explains that the result is advisory, files are deleted after processing, and selected cloud AI providers may process text or images. Do not launch publicly until `SUPPORT_CONTACT` is set and the notices have been reviewed for the intended deployment.

For local development:

```bash
python -m bot.main
```

### 5. Running Tests
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
├── bot/
│   ├── main.py           # Telegram polling entry point
│   ├── handlers.py       # Commands and message handlers
│   └── localization.py   # Russian, Uzbek and English UI text
├── tools/
│   ├── llm_provider.py   # Fireworks AI / Gemini / Anthropic backends
│   ├── vision_tool.py    # Image analysis via multimodal LLMs
│   ├── text_url_tool.py  # Text & URL phishing analysis
│   └── stego_tool.py     # Steganography & forensic scanning
├── analyzer.py           # Core forensic engine (9 parallel probes)
├── database.py           # Curated scanner keyword configuration
├── Dockerfile            # Multi-stage container build
├── docker-compose.yml    # App + bot orchestration
├── entrypoint.sh         # Container startup (app or bot, PORT aware)
├── requirements.txt      # Python dependencies
├── requirements.lock     # Reproducible dependency versions
└── .env.example          # Environment variable template
```

---

## 🔧 Tech Stack

- **Runtime:** Python 3.11, FastAPI, Uvicorn
- **Cloud AI:** Fireworks AI (DeepSeek V4 Flash, Minimax M3, Gemma 4 31B IT ready), plus Anthropic and Gemini as configured alternatives
- **Infrastructure:** Docker Compose, AMD Instinct GPUs (via Fireworks AI)
- **Forensics:** Pillow, python-docx, PyPDF2, numpy
- **Data handling:** Uploaded files are deleted after analysis; persistent history is not enabled in the MVP.

---

## License

MIT
