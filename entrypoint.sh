#!/bin/bash
# entrypoint.sh — Pulls the required local model on startup in the background, and runs uvicorn.

python -c '
import urllib.request, time, json, os
model = os.environ.get("OLLAMA_MODEL", "gemma:2b")
print("Waiting for Ollama container at http://ollama:11434 ...")
for _ in range(60):
    try:
        urllib.request.urlopen("http://ollama:11434")
        print("Connected to Ollama!")
        print(f"Initiating background pull for model: {model}...")
        
        req = urllib.request.Request(
            "http://ollama:11434/api/pull",
            data=json.dumps({"name": model}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
        print(f"Model {model} pulled successfully!")
        break
    except Exception as e:
        time.sleep(2)
' &

echo "Starting ScamShield FastAPI application..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
