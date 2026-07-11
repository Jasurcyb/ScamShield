# ScamShield Demo Video Script (3 Minutes)

## 0:00 - 0:45 | Introduction & Problem Statement
* **Visual**: Show the pitch slide or a screen displaying the ScamShield repository and architecture.
* **Audio**: "Hello, judges! Today we present **ScamShield**, a multimodal threat and fraud detection system developed for the **AMD Developer Hackathon: ACT II**. 
In Central Asia, digital payment fraud is at an all-time high. Scammers use fake bank transfer screenshots and malware-infected documents. 
To combat this, we've developed ScamShield — a FastAPI application that combines local forensic checks with intelligent LLM routing to detect scams at a fraction of the cost."

## 0:45 - 1:45 | Live API Walkthrough
* **Visual**: Open Swagger UI (`http://localhost:8000/docs`) and expand `/analyze/full` and `/analyze/stego`.
* **Audio**: "Let's look at the API. ScamShield exposes specialized endpoints for vision, text, and deep steganography.
For example, calling `/analyze/stego` with a suspicious file triggers 9 concurrent forensic checks, scanning LSB, byte entropy, VBA macros, and active PDF scripts locally in a thread pool without any heavy LLM overhead.
Our `/analyze/text` endpoint checks for typosquatting. For example, testing the domain `kap1talbank.uz` uses Levenshtein distance heuristics to instantly flag it as a spoof of the real `kapitalbank.uz`."

## 1:45 - 2:30 | The Hybrid Router (Cost-Efficiency)
* **Visual**: Show the code of `app/router.py` or highlight the output of `/analyze/full` with different inputs.
* **Audio**: "The core feature of ScamShield is our **Hybrid Router**. It acts as a token saver.
When we upload a small thumbnail or short text, the router chooses the local Ollama provider, resulting in 0 USD API cost. 
However, when we upload a large transaction screenshot or a text message with urgent banking hooks, the router automatically selects a remote provider, like Google Gemma 4 31B IT on Fireworks AI, for maximum accuracy.
Here we see the router metadata in the JSON response, displaying the selected provider and estimated API cost."

## 2:30 - 3:00 | Containerization & Conclusion
* **Visual**: Show the `docker-compose.yml` and the docker container logs running uvicorn and Ollama.
* **Audio**: "ScamShield is fully containerized. Running `docker compose up` starts the FastAPI app and Ollama service, which pulls the required model automatically in the background. 
This makes ScamShield extremely easy to deploy on any server or cloud VM.
Thank you for your time, and let's keep messaging secure!"
