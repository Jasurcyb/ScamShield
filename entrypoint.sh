#!/bin/bash
# entrypoint.sh — Runs the FastAPI app, the Telegram bot, or an explicit command.
# All inference runs on cloud LLM providers (Anthropic / Gemini / Fireworks);
# there is no local Ollama dependency.

set -e

if [ "$1" = "bot" ]; then
    exec python -m bot.main
fi

# Any other command is executed as given (Render worker services pass their
# own command here, e.g. `python -m bot.main`).
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "Starting ScamShield FastAPI application..."
# Multi-worker mode multiplies the in-memory rate limit and analysis semaphore
# per worker process; tune via env. --limit-concurrency sheds excess connections
# with 503 instead of exhausting memory under a connection flood.
# PORT is set by PaaS platforms (Render, Heroku, Railway); defaults to 8000 locally.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" \
    --workers "${UVICORN_WORKERS:-2}" \
    --limit-concurrency "${UVICORN_MAX_CONNECTIONS:-120}" \
    --timeout-keep-alive "${UVICORN_KEEP_ALIVE_SECONDS:-5}"
