# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /build

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN rustc --version && cargo --version

# The eBPF crate uses software fallback when bpf-linker is absent
ENV CARGO_PROFILE_RELEASE_OPT_LEVEL=3

# Copy the workspace root files
COPY Cargo.toml Cargo.lock ./

# Copy the Cargo.toml for every workspace member to allow caching dependencies
COPY aitp-core/Cargo.toml aitp-core/
COPY aitp-identity/Cargo.toml aitp-identity/
COPY aitp-ai-engine/Cargo.toml aitp-ai-engine/
COPY aitp-control-plane/Cargo.toml aitp-control-plane/
COPY aitp-sdk/Cargo.toml aitp-sdk/
COPY aitp-observability/Cargo.toml aitp-observability/
COPY aitp-server/Cargo.toml aitp-server/
COPY aitp-client/Cargo.toml aitp-client/
COPY kelan-ebpf/kelan-ebpf-loader/Cargo.toml kelan-ebpf/kelan-ebpf-loader/
COPY kelan-ebpf/kelan-ebpf-program/Cargo.toml kelan-ebpf/kelan-ebpf-program/

# Create dummy source files for every member to cache deps
RUN mkdir -p aitp-core/src aitp-identity/src aitp-ai-engine/src \
    aitp-sdk/src aitp-observability/src \
    aitp-server/src aitp-client/src \
    kelan-ebpf/kelan-ebpf-loader/src kelan-ebpf/kelan-ebpf-program/src && \
    echo "" > aitp-core/src/lib.rs && \
    echo "" > aitp-identity/src/lib.rs && \
    echo "" > aitp-ai-engine/src/lib.rs && \
    echo "" > aitp-sdk/src/lib.rs && \
    echo "" > aitp-observability/src/lib.rs && \
    echo "fn main(){}" > aitp-server/src/main.rs && \
    echo "fn main(){}" > aitp-client/src/main.rs && \
    echo "fn main(){}" > kelan-ebpf/kelan-ebpf-loader/src/main.rs && \
    echo "fn main(){}" > kelan-ebpf/kelan-ebpf-program/src/main.rs && \
    cargo build --release --package aitp-server 2>/dev/null || true

# Now copy real source and build
COPY . .
RUN touch aitp-server/src/main.rs && \
    cargo build --release --package aitp-server

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/aitp_server /app/aitp-server
COPY --from=builder /build/static                      /app/static

# Create directories
RUN mkdir -p /app/data /app/keys /app/logs && \
    useradd -r -s /bin/false kelan && \
    chown -R kelan:kelan /app

USER kelan

EXPOSE 3000 9999/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/stats || exit 1

ENTRYPOINT ["/app/aitp-server"]
