# Build from slim Python image
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
RUN pip install --no-cache-dir --upgrade pip "certifi>=2026.10.19" \
    && pip install --no-cache-dir -r requirements.txt

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
