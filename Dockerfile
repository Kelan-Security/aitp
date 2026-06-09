# ── Stage 1: Dependencies ──────────────────────
FROM python:3.11-slim AS deps

RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    gcc libpq-dev curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir \
    --user -r requirements.txt

# ── Stage 2: Runtime ───────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    libpq5 curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -r -u 1001 \
       -s /sbin/nologin kelan

WORKDIR /app

COPY --from=deps \
  /root/.local /home/kelan/.local

COPY --chown=kelan:root kelan/ ./kelan/
COPY --chown=kelan:root static/ ./static/

USER kelan

ENV PATH=/home/kelan/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 3000

HEALTHCHECK --interval=30s \
  --timeout=5s --start-period=15s \
  CMD curl -sf \
    http://localhost:3000/api/health || exit 1

CMD ["uvicorn","kelan.server:app",
     "--host","0.0.0.0",
     "--port","3000",
     "--workers","1",
     "--loop","asyncio",
     "--limit-max-requests","10000",
     "--log-level","info"]
