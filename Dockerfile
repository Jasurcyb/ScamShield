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
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Copy and setup entrypoint script
RUN chmod +x entrypoint.sh

# Run the app through uvicorn
ENTRYPOINT ["./entrypoint.sh"]
