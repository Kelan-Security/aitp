.PHONY: build release test test-integration test-gemini fmt fmt-check clippy \
       docker-up docker-down docker-build validate logs clean doc dev dev-full

# ───────────────── Build ─────────────────
build:
	cargo build --workspace

release:
	cargo build --workspace --release

# ───────────────── Quality ─────────────────
test:
	cargo test --workspace

test-integration:
	cargo test --workspace -- --include-ignored

test-gemini:
	AITP_AI_ENGINE_GEMINI_API_KEY=$(AITP_GEMINI_API_KEY) \
	cargo test --package aitp-ai-engine -- --include-ignored gemini

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace -- -D warnings

# ───────────────── Documentation ─────────────────
doc:
	cargo doc --no-deps --workspace --open

doc-sdk:
	cargo doc --no-deps -p aitp-sdk --open

# ───────────────── Docker ─────────────────
docker-build:
	docker compose build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

logs:
	docker compose logs -f --tail=100

logs-nodes:
	docker compose logs -f aitp-node-alpha aitp-node-beta --tail=100

# ───────────────── Validation ─────────────────
validate:
	./scripts/validate_stack.sh

# ───────────────── Examples ─────────────────
example-echo:
	cargo run --example simple_echo_server

example-client:
	cargo run --example simple_client

example-ai:
	cargo run --example ai_model_connector

example-multi:
	cargo run --example multi_session

example-revoke:
	cargo run --example revoke_demo

# ───────────────── Clean ─────────────────
clean:
	cargo clean
	docker compose down -v --remove-orphans 2>/dev/null || true
	pkill -f "aitp_server" 2>/dev/null || true
	pkill -f "npm.*aitp-web" 2>/dev/null || true

# ───────────────── Development ─────────────────
# Start EVERYTHING: Frontend, Backend, Server, Docker, Database
dev:
	./start_all.sh --docker

# Start local only: Frontend + Backend
dev-local:
	./start_all.sh
