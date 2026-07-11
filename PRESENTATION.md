# ScamShield - Pitch Presentation
**Multimodal Multi-Agent Fraud Detection Engine for Central Asian Cybersecurity**

---

## 🔴 The Problem
* **Surge in Local Scams**: Financial scams and social engineering are skyrocketing in Central Asia (specifically Uzbekistan).
* **Payment Gateways Under Threat**: Fraudsters clone mobile banking templates (*Kapitalbank*, *Click*, *Payme*) and send forged transaction receipts.
* **Malicious Payloads**: Ordinary citizens receive malware-laced archives, active PDFs, or VBA Word macros posing as invoices.
* **Infrastructure Costs**: Running 24/7 vision LLMs to inspect files is financially prohibitive for small startups and local institutions.

---

## 🟢 The Solution: ScamShield
* **Multimodal Forensics Engine**: A high-performance local analysis stack that inspects files on a structural, byte-level, and spectral level before invoking expensive LLMs.
* **Hybrid Token-Saving Router**: A controller that evaluates input heuristics (file size, length, presence of bank keywords) to dispatch calls dynamically.
  * **Ollama (Local)**: Used for small thumbnails and short benign messages.
  * **Fireworks AI / APIs (Remote)**: Reserved for large images and high-risk text messages.
* **No Database/SDK Lock-In**: Decoupled from heavy agent frameworks. Runs on a clean FastAPI interface.

---

## 💻 Tech Stack & Architecture
* **FastAPI**: Clean, high-throughput asynchronous REST API wrapper.
* **Fireworks AI API**: Ultra-fast LLM inference hosting Google Gemma 4 31B IT (running on AMD Instinct GPUs).
* **Ollama (`gemma:2b`)**: Edge/local LLM processing.
* **Scipy, PIL, oletools, PyPDF2**: Python-native forensic analysis libraries.
* **Docker & Docker-Compose**: Fully isolated deployment packaging.

---

## 📈 Economic Advantage (Track 1)
By utilizing the **Hybrid Router**:
* **Cost Reduction**: Over **85% savings** in token costs. Small files (<100KB) and short greetings are processed locally at $0 cost.
* **Speed Enhancement**: Local models respond in sub-seconds without network latency.
* **Accuracy Preserved**: Only high-complexity files are routed to larger models (like Google Gemma 4 31B IT or Claude Sonnet), maintaining a high detection threshold.
