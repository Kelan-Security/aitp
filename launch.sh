#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  AITP Platform — Master Launch Script
#  Usage: ./launch.sh [--dev | --prod | --stop | --reset]
#  Starts: Rust backend (HTTP + WebSocket + AITP UDP) + copies frontend
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────
HTTP_PORT="${AITP_HTTP_PORT:-3000}"
UDP_PORT="${AITP_UDP_PORT:-9999}"
DB_PATH="${AITP_DB_PATH:-./data/aitp.db}"
LOG_LEVEL="${RUST_LOG:-aitp_web=info,tower_http=warn}"
MODE="${1:---dev}"
PID_FILE="./.aitp.pid"
LOG_FILE="./logs/aitp.log"
BINARY="./target/release/aitp_web"
BINARY_DEV="./target/debug/aitp_web"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

# ── Banner ────────────────────────────────────────────────────────
print_banner() {
  echo ""
  echo -e "${BOLD}${WHITE}  ╔═══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${WHITE}  ║         AITP — Intelligence Protocol Layer     ║${NC}"
  echo -e "${BOLD}${WHITE}  ║              v0.2.0  Launch Script              ║${NC}"
  echo -e "${BOLD}${WHITE}  ╚═══════════════════════════════════════════════╝${NC}"
  echo ""
}

# ── Stop existing ─────────────────────────────────────────────────
stop_existing() {
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      echo -e "  ${YELLOW}→${NC} Stopping existing process (PID: $PID)..."
      kill "$PID" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$PID_FILE"
  fi

  # Kill anything on our ports
  if command -v lsof &>/dev/null; then
    lsof -ti :"$HTTP_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti :5173 2>/dev/null | xargs kill -9 2>/dev/null || true
  fi
  
  # Kill lingering vite processes using pkill
  if command -v pkill &>/dev/null; then
    pkill -f "vite" 2>/dev/null || true
  fi
}

# ── Check deps ────────────────────────────────────────────────────
check_deps() {
  local missing=()
  command -v cargo &>/dev/null || missing+=("cargo (Rust)")
  command -v sqlite3 &>/dev/null || echo -e "  ${DIM}⚠ sqlite3 CLI not found (optional, DB still works)${NC}"

  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "  ${RED}✗ Missing required tools:${NC}"
    for m in "${missing[@]}"; do echo -e "    ${RED}• $m${NC}"; done
    echo ""
    echo -e "  Install Rust: ${CYAN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    exit 1
  fi
}

# ── Ensure .env ───────────────────────────────────────────────────
ensure_env() {
  if [ ! -f ".env" ]; then
    echo -e "  ${YELLOW}→${NC} Creating .env from .env.example..."
    if [ -f ".env.example" ]; then
      cp .env.example .env
    else
      # Create default .env
      cat > .env << 'ENV'
# AITP Platform Environment Configuration
# ─────────────────────────────────────────────────────────────────

# ── Security ──────────────────────────────────────────────────────
# IMPORTANT: Change this in production to a secure random string
AITP_JWT_SECRET=change_this_to_a_secure_random_string_in_production

# ── Network ───────────────────────────────────────────────────────
AITP_HTTP_PORT=3000
AITP_UDP_PORT=9999

# ── Database ──────────────────────────────────────────────────────
AITP_DB_PATH=./data/aitp.db

# ── AI Provider (choose one) ──────────────────────────────────────
# Default: rules (no API key needed for testing)
AITP_AI_ENGINE_PROVIDER=gemini
AITP_AI_ENGINE_TRUST_MODE=hybrid

# Google Gemini (RECOMMENDED - set your key here)
AITP_GEMINI_API_KEY=[REDACTED_GEMINI_KEY]=gemini-2.5-flash

# Anthropic Claude (alternative)
# AITP_AI_ENGINE_PROVIDER=claude
AITP_CLAUDE_API_KEY=
AITP_CLAUDE_MODEL=claude-haiku-4-5-20251001

# OpenAI (alternative)
# AITP_AI_ENGINE_PROVIDER=openai
AITP_OPENAI_API_KEY=
AITP_OPENAI_MODEL=gpt-4o-mini

# Ollama local (no key needed)
# AITP_AI_ENGINE_PROVIDER=ollama
AITP_OLLAMA_URL=http://localhost:11434
AITP_OLLAMA_MODEL=llama3.2

# ── Logging ───────────────────────────────────────────────────────
RUST_LOG=aitp_web=info,tower_http=warn
ENV
      echo -e "  ${GREEN}✓${NC} Created .env — edit it to add your Gemini API key"
    fi
  fi

  # Source .env
  set -a; source .env 2>/dev/null || true; set +a
  HTTP_PORT="${AITP_HTTP_PORT:-3000}"
  UDP_PORT="${AITP_UDP_PORT:-9999}"
  DB_PATH="${AITP_DB_PATH:-./data/aitp.db}"
}

# ── Build ─────────────────────────────────────────────────────────
build_backend() {
  echo -e "  ${BLUE}→${NC} Building AITP backend..."
  if [ "$MODE" = "--dev" ]; then
    echo -e "  ${DIM}  cargo build --bin aitp_web (debug)${NC}"
    CARGO_TERM_COLOR=always cargo build --bin aitp_web 2>&1 | \
      grep -E "(error|warning\[|Compiling aitp-web|Finished)" | \
      sed "s/^/    /" || {
      echo -e "\n  ${RED}✗ Build failed. Run: cargo build --bin aitp_web${NC}"
      exit 1
    }
    BINARY="$BINARY_DEV"
  else
    echo -e "  ${DIM}  cargo build --release --bin aitp_web${NC}"
    CARGO_TERM_COLOR=always cargo build --release --bin aitp_web 2>&1 | \
      grep -E "(error|warning\[|Compiling aitp-web|Finished)" | \
      sed "s/^/    /" || {
      echo -e "\n  ${RED}✗ Build failed. Run: cargo build --release --bin aitp_web${NC}"
      exit 1
    }
  fi
  echo -e "  ${GREEN}✓${NC} Build complete"
}

# ── Copy frontend ─────────────────────────────────────────────────
setup_frontend() {
  mkdir -p ./static

  # Check if index.html exists in static/
  if [ ! -f "./static/index.html" ]; then
    echo -e "  ${YELLOW}→${NC} No frontend found at ./static/index.html"

    # Look for it in common locations
    for candidate in \
      "./aitp_platform.html" \
      "../aitp_platform.html" \
      "./frontend/dist/index.html" \
      "./frontend/index.html"
    do
      if [ -f "$candidate" ]; then
        echo -e "  ${GREEN}→${NC} Copying frontend from $candidate"
        cp "$candidate" ./static/index.html
        break
      fi
    done

    if [ ! -f "./static/index.html" ]; then
      # Generate a minimal placeholder
      cat > ./static/index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>AITP Platform</title>
<style>
  body{font-family:system-ui;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:12px;}
  .logo{font-size:32px;font-weight:800;}
  .sub{color:#94a3b8;font-size:14px;}
  .status{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px 20px;font-family:monospace;font-size:13px;color:#4ade80;}
  a{color:#60a5fa;}
</style></head><body>
<div class="logo">⬡ AITP Platform</div>
<div class="sub">Intelligence Protocol Layer v0.2.0</div>
<div class="status">✓ Backend running — place your index.html in ./static/</div>
<div class="sub"><a href="/api/stats">View Stats API →</a></div>
</body></html>
HTML
      echo -e "  ${YELLOW}⚠${NC}  Placeholder frontend created. Copy aitp_platform.html to ./static/index.html"
    fi
  else
    echo -e "  ${GREEN}✓${NC} Frontend ready at ./static/index.html"
  fi
}

# ── Create dirs ───────────────────────────────────────────────────
ensure_dirs() {
  mkdir -p ./data ./keys ./logs ./static
}

# ── Start backend ─────────────────────────────────────────────────
start_backend() {
  echo -e "  ${BLUE}→${NC} Starting AITP backend..."

  if [ "$MODE" = "--dev" ]; then
    # Dev mode: run in foreground with live output
        echo ""
        echo -e "  ${GREEN}${BOLD}AITP Platform Starting (Dev Mode)${NC}"
        echo -e "  ${DIM}──────────────────────────────────────────${NC}"
        echo -e "  Frontend UI: ${CYAN}http://localhost:5173${NC} (Vite)"
        echo -e "  Backend API: ${CYAN}http://localhost:${HTTP_PORT}/api/${NC}"
        echo -e "  WebSocket:   ${CYAN}ws://localhost:${HTTP_PORT}/ws${NC}"
        echo -e "  AITP UDP:    ${CYAN}0.0.0.0:${UDP_PORT}${NC}"
        echo -e "  Database:    ${DIM}${DB_PATH}${NC}"
        echo -e "  ${DIM}──────────────────────────────────────────${NC}"
        echo -e "  ${DIM}Press Ctrl+C to stop${NC}"
        echo ""

        # Open browser to Vite server instead of backend
        (sleep 2 && open_browser "http://localhost:5173") &

        # Start Vite frontend
        if [ -d "aitp-web" ] && [ -f "aitp-web/package.json" ]; then
          echo -e "  ${YELLOW}→${NC} Starting frontend dev server in background..."
          (cd aitp-web && npm run dev) &
          FRONTEND_PID=$!
          # Add trap to kill frontend when backend is stopped
          trap 'kill $FRONTEND_PID 2>/dev/null' EXIT
        fi

        # Run backend in foreground
        # Run backend in foreground without exec so trap fires
    RUST_LOG="$LOG_LEVEL" \
    AITP_HTTP_PORT="$HTTP_PORT" \
    AITP_UDP_PORT="$UDP_PORT" \
    AITP_DB_PATH="$DB_PATH" \
    "$BINARY"

  else
    # Production mode: run in background
    RUST_LOG="$LOG_LEVEL" \
    AITP_HTTP_PORT="$HTTP_PORT" \
    AITP_UDP_PORT="$UDP_PORT" \
    AITP_DB_PATH="$DB_PATH" \
    nohup "$BINARY" > "$LOG_FILE" 2>&1 &

    BACKEND_PID=$!
    echo "$BACKEND_PID" > "$PID_FILE"
    echo -e "  ${GREEN}✓${NC} Backend started (PID: $BACKEND_PID)"
    echo -e "  ${DIM}  Logs: tail -f $LOG_FILE${NC}"

    # Wait for server to be ready
    echo -n "  ${BLUE}→${NC} Waiting for server"
    for i in {1..20}; do
      sleep 0.5
      if curl -sf "http://localhost:${HTTP_PORT}/api/stats" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready!${NC}"
        break
      fi
      echo -n "."
      if [ "$i" -eq 20 ]; then
        echo -e " ${YELLOW}timeout (server may still be starting)${NC}"
      fi
    done
  fi
}

# ── Open browser ──────────────────────────────────────────────────
open_browser() {
  local url="$1"
  if command -v xdg-open &>/dev/null; then
    xdg-open "$url" &>/dev/null &
  elif command -v open &>/dev/null; then
    open "$url" &>/dev/null &
  elif command -v start &>/dev/null; then
    start "$url" &>/dev/null &
  fi
}

# ── Print success info ────────────────────────────────────────────
print_success() {
  echo ""
  echo -e "  ${GREEN}${BOLD}════════════════════════════════════════${NC}"
  echo -e "  ${GREEN}${BOLD}  AITP Platform is running!${NC}"
  echo -e "  ${GREEN}${BOLD}════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${WHITE}Frontend:${NC}   ${CYAN}http://localhost:${HTTP_PORT}${NC}"
  echo -e "  ${WHITE}API Docs:${NC}   ${CYAN}http://localhost:${HTTP_PORT}/api/stats${NC}"
  echo -e "  ${WHITE}WebSocket:${NC}  ${CYAN}ws://localhost:${HTTP_PORT}/ws?token=<JWT>${NC}"
  echo -e "  ${WHITE}AITP Node:${NC}  ${CYAN}UDP 0.0.0.0:${UDP_PORT}${NC}"
  echo ""
  echo -e "  ${WHITE}Stop:${NC}  ${DIM}./launch.sh --stop${NC}"
  echo -e "  ${WHITE}Logs:${NC}  ${DIM}tail -f $LOG_FILE${NC}"
  echo ""
  echo -e "  ${DIM}Opening browser...${NC}"
  open_browser "http://localhost:${HTTP_PORT}"
  echo ""
}

# ── Handle --stop ─────────────────────────────────────────────────
if [ "${1:-}" = "--stop" ]; then
  print_banner
  echo -e "  ${YELLOW}→${NC} Stopping AITP Platform..."
  stop_existing
  echo -e "  ${GREEN}✓${NC} Stopped"
  exit 0
fi

# ── Handle --reset ────────────────────────────────────────────────
if [ "${1:-}" = "--reset" ]; then
  print_banner
  stop_existing
  echo -e "  ${RED}⚠ This will delete the database and all keys!${NC}"
  read -rp "  Are you sure? (yes/no): " confirm
  if [ "$confirm" = "yes" ]; then
    rm -rf ./data ./keys ./logs
    mkdir -p ./data ./keys ./logs
    echo -e "  ${GREEN}✓${NC} Reset complete. Run ./launch.sh to start fresh."
  else
    echo -e "  ${YELLOW}Cancelled.${NC}"
  fi
  exit 0
fi

# ── Handle --status ───────────────────────────────────────────────
if [ "${1:-}" = "--status" ]; then
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      echo -e "  ${GREEN}● AITP is running${NC} (PID: $PID)"
      curl -sf "http://localhost:${HTTP_PORT}/api/stats" | python3 -m json.tool 2>/dev/null || true
    else
      echo -e "  ${RED}● AITP is not running${NC} (stale PID file)"
    fi
  else
    echo -e "  ${RED}● AITP is not running${NC}"
  fi
  exit 0
fi

# ── MAIN LAUNCH ───────────────────────────────────────────────────
print_banner
check_deps
ensure_env
ensure_dirs
stop_existing
setup_frontend
build_backend

if [ "$MODE" = "--prod" ]; then
  start_backend
  print_success
else
  # Dev mode runs in foreground — print info first
  echo ""
  echo -e "  ${GREEN}${BOLD}AITP Platform — Dev Mode${NC}"
  echo -e "  ${DIM}────────────────────────────────────────${NC}"
  setup_frontend
  echo ""
  start_backend  # This blocks in dev mode
fi
