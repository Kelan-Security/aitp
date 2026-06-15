# =============================================
# Kelan Security — Production Dockerfile
# =============================================

FROM python:3.12-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Final lightweight image
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies (including curl for HEALTHCHECK and libpq5)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY kelan/ ./kelan/
COPY scripts/ ./scripts/
COPY .env.example .env

# Create data and logs directories
RUN mkdir -p data logs && chmod 777 data logs

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["python", "scripts/start_server.py"]
