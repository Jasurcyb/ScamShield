# Build from slim Python image.
# Deliberately 3.11, not 3.13: pydub (audio analysis) imports `audioop`, which
# PEP 594 removed in Python 3.13 — the container would fail at analyzer import.
# The eMudhra CA fix is delivered by upgrading pip/certifi below, as required.
FROM python:3.11-slim

# Install system dependencies required for Pillow, oletools, rarfile, and pydub (ffmpeg)
RUN apt-get update && apt-get install -y \
    gcc \
    libgl1 \
    libglib2.0-0 \
    ffmpeg \
    unrar-free \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Copy requirements and install dependencies
# Upgrade pip itself first: pip vendors its own CA bundle, and the base image
# ships an old one that still trusts the compromised eMudhra chain (Oct 2026).
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.2" "certifi>=2026.10.19" \
    && python -m pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Copy and setup entrypoint script
RUN chmod +x entrypoint.sh

# Run as an unprivileged user: a parser bug in Pillow/oletools/pypdf/ffmpeg
# must not land in a root shell inside the container.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin scamshield \
    && mkdir -p /tmp /workspace \
    && chown -R scamshield:scamshield /workspace
USER scamshield

# Run the app through uvicorn
ENTRYPOINT ["./entrypoint.sh"]
