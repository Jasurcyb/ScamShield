# ScamShield - Multimodal Fraud Detection REST API

ScamShield is a multi-agent fraud detection application updated for the **AMD Developer Hackathon: ACT II**. 
It exposes a clean, async FastAPI REST API that inspects text, links, documents, and images for phishing, social engineering, and forensic modifications (such as steganography).

## 🚀 Key Innovations & Features
1. **Hybrid Provider Routing Controller**: Intelligently inspects incoming files and text queries, routing lightweight tasks to local models (Ollama with `gemma:2b` or similar) and complex visual/long threat-related queries to remote APIs like **Google Gemma 4 31B IT** (via Fireworks AI, running on AMD Instinct GPUs), Claude, or Gemini to minimize token consumption and infrastructure costs.
2. **Battle-Tested Forensic Scanner**: Built-in 9 parallel deep-scanning forensic tests (LSB steganography analysis, histogram combing checks, trailing data, file entropy, Word VBA macro scans, active PDF script analysis, and threat keyword matching).
3. **Levenshtein Banking Typosquatting**: High-performance domain similarity checking targeted at Central Asian/Uzbek banking platforms to catch malicious redirects (e.g. `kap1talbank.uz`).

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
       ▼ (Routed)    ▼ (Routed)                              ▼
┌──────────────┐ ┌──────────────┐                    • LSB Stego Check
│  Fireworks / │ │ Local Ollama │                    • Histogram Comb
│ Claude/Gemini│ │ (gemma:2b)   │                    • PDF JS Check
└──────────────┘ └──────────────┘                    • VBA AutoExec
```

---

## 🛠️ Setup & Running

### 1. Configure Credentials
Copy `.env.example` to `.env` in the root `scamshield_fastapi` directory:
```bash
cp .env.example .env
```
Fill in your `FIREWORKS_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`. If no keys are set, the router falls back to local execution.

### 2. Run with Docker Compose (Recommended)
This launches the FastAPI application and a local Ollama container. On startup, the container automatically pulls the configured local model (`gemma:2b` by default) in the background.

```bash
docker compose up --build
```
The API is available at `http://localhost:8000`. Access `http://localhost:8000/docs` for the interactive Swagger UI.

### 3. Running Tests
You can run automated endpoints tests inside the docker environment:
```bash
docker compose run app pytest
```

---

## 📡 API Reference & cURL Examples

### 1. Full Routed Scan (Image + Text)
```bash
curl -X POST "http://localhost:8000/analyze/full" \
  -F "file=@fake_screenshot.png" \
  -F "text=Urgent verify your card details at kap1talbank.uz"
```

### 2. Stego/Forensics Scan Only
```bash
curl -X POST "http://localhost:8000/analyze/stego" \
  -F "file=@suspicious_document.pdf"
```

### 3. Text & URL Phishing Scan
```bash
curl -X POST "http://localhost:8000/analyze/text" \
  -F "text=Urgent! Click here: http://payme-verif.uz"
```
