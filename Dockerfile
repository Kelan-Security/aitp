# Stage 1: Builder
FROM rust:1.76-slim AS builder

RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev zlib1g-dev libbpf-dev \
    linux-libc-dev pkg-config musl-tools

WORKDIR /app
COPY . .

# Build without native eBPF for portability
RUN cargo build --release -p aitp-server \
    --no-default-features 2>&1

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 ca-certificates iptables iproute2 \
    curl && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1001 -g root kelan

WORKDIR /app
COPY --from=builder /app/target/release/aitp_server .
COPY --from=builder /app/migrations ./migrations

RUN mkdir -p /var/lib/kelan && chown kelan /var/lib/kelan

# eBPF needs CAP_BPF (added via docker run, not here)
USER kelan

EXPOSE 8080
EXPOSE 9999/udp

ENV DB_URL=sqlite:/var/lib/kelan/kelan.db
ENV KELAN_MODE=auto
ENV RUST_LOG=info
ENV OLLAMA_ENDPOINT=http://localhost:11434
ENV OLLAMA_MODEL=gemma3:9b

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8080/api/health || exit 1

ENTRYPOINT ["./aitp_server"]
