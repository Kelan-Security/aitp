# ══ Stage 1: Python dependencies ═══════════════════════════════
FROM python:3.12-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ══ Stage 2: Rust eBPF build (XDP only) ════════════════════════
FROM rust:1.76-slim AS rust-builder

RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY kelan-ebpf/         ./kelan-ebpf/
COPY Cargo.toml          ./
COPY Cargo.lock          ./

RUN cargo build --release -p kelan-ebpf-loader 2>&1 | tail -5 || \
    echo "eBPF build skipped (non-Linux or missing deps)"

# ══ Stage 3: Runtime ════════════════════════════════════════════
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 curl iproute2 net-tools tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python packages from Stage 1
COPY --from=deps /usr/local/lib/python3.12/site-packages \
                 /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin/uvicorn /usr/local/bin/

# Rust eBPF binary (optional — falls back to software mode)
COPY --from=rust-builder /build/target/release/kelan-ebpf-loader \
                          /usr/local/bin/kelan-ebpf-loader 2>/dev/null || true

# Python source
COPY kelan/    ./kelan/
COPY scripts/  ./scripts/
COPY .env.example .env.example

RUN mkdir -p data logs

# Environment defaults
ENV AITP_HTTP_PORT=3000
ENV AITP_HOST=0.0.0.0
ENV DATABASE_URL=sqlite+aiosqlite:///app/data/kelan.db
ENV OLLAMA_MODEL=gemma4:latest
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:3000/api/health || exit 1

CMD ["python", "scripts/start.py"]
