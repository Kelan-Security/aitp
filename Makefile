.PHONY: dev build test clean stop logs frontend backend check

# ── Default: start the full stack ────────────────────────────────────────────
dev: check
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║       Kelan Security — Dev Stack             ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) -j2 backend frontend

# ── Check prerequisites ───────────────────────────────────────────────────────
check:
	@command -v cargo  >/dev/null || (echo "ERROR: Rust not installed. Run: curl https://sh.rustup.rs | sh" && exit 1)
	@command -v node   >/dev/null || echo "WARN: Node.js not found — frontend will be skipped"
	@echo "Prerequisites OK"

# ── Backend (Intelligence Core server) ───────────────────────────────────────
backend:
	@echo "Building aitp-server..."
	@cargo build -p aitp-server 2>&1 | grep -E "^error" | head -20 || true
	@echo "Starting Intelligence Core on http://localhost:3000..."
	@RUST_LOG=aitp_server=info \
		cargo run -p aitp-server

# ── Frontend (dashboard) ──────────────────────────────────────────────────────
frontend:
	@if [ -d "aitp-dashboard" ] && command -v node >/dev/null; then \
		echo "Starting frontend on http://localhost:5173..."; \
		cd aitp-dashboard && npm install --silent && npm run dev; \
	elif [ -d "frontend" ] && command -v node >/dev/null; then \
		echo "Starting frontend on http://localhost:5173..."; \
		cd frontend && npm install --silent && npm run dev; \
	else \
		echo "No frontend directory found or Node.js not installed."; \
		echo "Dashboard is served by Axum at http://localhost:3000"; \
	fi

# ── Build release binary ─────────────────────────────────────────────────────
build:
	cargo build --release -p aitp-server
	@echo "Binary: target/release/aitp_server"

# ── Run all tests ─────────────────────────────────────────────────────────────
test:
	cargo test --workspace -- --test-threads=1

# ── Stop all running instances ────────────────────────────────────────────────
stop:
	@pkill -f aitp_server 2>/dev/null && echo "Server stopped" || echo "Server was not running"
	@pkill -f "npm run dev" 2>/dev/null || true
	@lsof -ti:3000 | xargs kill -9 2>/dev/null || true
	@lsof -ti:5173 | xargs kill -9 2>/dev/null || true
	@echo "All processes stopped. Ports 3000 and 5173 freed."

# ── Tail server logs ──────────────────────────────────────────────────────────
logs:
	@RUST_LOG=aitp_server=debug cargo run -p aitp-server

# ── Lint ─────────────────────────────────────────────────────────────────────
lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

# ── Clean build artifacts ─────────────────────────────────────────────────────
clean:
	cargo clean
	rm -f aitp-server/data/*.db aitp-server/data/*.db-shm aitp-server/data/*.db-wal
	@echo "Cleaned"

# ── Fresh start (wipe DB + restart) ──────────────────────────────────────────
fresh: stop clean
	@$(MAKE) dev

# ── Docker targets ────────────────────────────────────────────────────────────
docker-build:
	docker build -t kelan-server:local .

docker-run:
	docker run -p 3000:3000 -p 9999:9999/udp \
		-e OLLAMA_ENDPOINT=$${OLLAMA_ENDPOINT} \
		-e AITP_JWT_SECRET=$${AITP_JWT_SECRET:-$(shell openssl rand -base64 48)} \
		-v kelan_data:/app/data \
		kelan-server:local

docker-stop:
	docker ps -q --filter "ancestor=kelan-server:local" | xargs -r docker stop
