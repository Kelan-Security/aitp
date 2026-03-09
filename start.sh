#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# AITP — One command startup script
# Usage:
#   ./start.sh          → start server + print working token + test commands
#   ./start.sh fresh    → wipe DB, restart fresh, new signup
#   ./start.sh stop     → kill running server
#   ./start.sh token    → print a fresh token for existing account (no restart)
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/aitp-server"
PID_FILE="$SCRIPT_DIR/.aitp_server.pid"
LOG_FILE="$SCRIPT_DIR/.aitp_server.log"

# Default credentials — change these
DEFAULT_ORG="Acme Corp"
DEFAULT_EMAIL="admin@acme.com"
DEFAULT_PASS="supersecret123"

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
AMBER='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║        AITP Intelligence Core v0.3          ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""
}

# ── stop ─────────────────────────────────────────────────────────────────────
stop_server() {
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      echo -e "${AMBER}Stopping AITP server (PID $PID)...${NC}"
      kill "$PID"
      rm -f "$PID_FILE"
      echo -e "${GREEN}Stopped.${NC}"
    else
      echo "Server not running (stale PID file removed)"
      rm -f "$PID_FILE"
    fi
  else
    pkill -f "aitp_server" 2>/dev/null && echo "Server stopped" || echo "Server was not running"
  fi
}

# ── wait for server ───────────────────────────────────────────────────────────
wait_for_server() {
  echo -ne "${AMBER}Waiting for server to start${NC}"
  for i in $(seq 1 30); do
    if curl -s http://localhost:3000/api/stats > /dev/null 2>&1; then
      echo -e " ${GREEN}ready!${NC}"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo -e " ${RED}TIMEOUT${NC}"
  echo "Check logs: tail -f $LOG_FILE"
  exit 1
}

# ── get token ─────────────────────────────────────────────────────────────────
get_token() {
  local EMAIL="${1:-$DEFAULT_EMAIL}"
  local PASS="${2:-$DEFAULT_PASS}"

  # Try signin first
  local RESPONSE=$(curl -s -X POST http://localhost:3000/api/auth/signin \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")

  local TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty' 2>/dev/null)

  # If signin failed, try signup
  if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ] || [ "$TOKEN" = "" ]; then
    RESPONSE=$(curl -s -X POST http://localhost:3000/api/auth/signup \
      -H 'Content-Type: application/json' \
      -d "{\"org_name\":\"$DEFAULT_ORG\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
    TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty' 2>/dev/null)
  fi

  echo "$TOKEN"
}

# ── print ready banner ────────────────────────────────────────────────────────
print_ready() {
  local TOKEN="$1"
  echo ""
  echo -e "${GREEN}${BOLD}✓ AITP is running${NC}"
  echo ""
  echo -e "${BOLD}Dashboard:${NC}  http://localhost:3000"
  echo -e "${BOLD}API:${NC}        http://localhost:3000/api"
  echo ""
  echo -e "${BOLD}── Your token (valid 24h) ──────────────────────────────${NC}"
  echo -e "${BLUE}$TOKEN${NC}"
  echo ""
  echo -e "${BOLD}── Test commands (copy & paste) ────────────────────────${NC}"
  echo ""
  echo -e "${AMBER}# Save token:${NC}"
  echo "  TOKEN=\"$TOKEN\""
  echo ""
  echo -e "${AMBER}# Test REST:${NC}"
  echo "  curl -s http://localhost:3000/api/auth/me -H \"Authorization: Bearer \$TOKEN\" | jq"
  echo ""
  echo -e "${AMBER}# Test stats:${NC}"
  echo "  curl -s http://localhost:3000/api/stats -H \"Authorization: Bearer \$TOKEN\" | jq"
  echo ""
  echo -e "${AMBER}# Test WebSocket:${NC}"
  echo "  websocat \"ws://localhost:3000/ws?token=\$TOKEN\""
  echo ""
  echo -e "${AMBER}# Create entity:${NC}"
  echo "  curl -s -X POST http://localhost:3000/api/entities \\"
  echo "    -H \"Authorization: Bearer \$TOKEN\" \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"name\":\"Workstation-01\",\"entity_type\":\"workstation\"}' | jq"
  echo ""
  echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
  echo ""
  echo -e "${AMBER}Logs:${NC} tail -f $LOG_FILE"
  echo -e "${AMBER}Stop:${NC} ./start.sh stop"
  echo ""
}

# ── main ──────────────────────────────────────────────────────────────────────
banner

case "${1:-start}" in

  stop)
    stop_server
    exit 0
    ;;

  fresh)
    echo -e "${AMBER}Fresh start — wiping database...${NC}"
    stop_server 2>/dev/null || true
    rm -f "$SERVER_DIR/data/aitp.db"
    rm -f "$SERVER_DIR/data/aitp.db-shm"
    rm -f "$SERVER_DIR/data/aitp.db-wal"
    echo -e "${GREEN}Database wiped. Starting fresh...${NC}"
    # Fall through to start
    ;&

  start)
    # Kill any existing instance
    stop_server 2>/dev/null || true

    # Build
    echo -e "${AMBER}Building aitp-server...${NC}"
    cd "$SERVER_DIR"
    cargo build -p aitp-server --quiet 2>&1

    # Start server in background
    echo -e "${AMBER}Starting AITP Intelligence Core...${NC}"
    nohup cargo run -p aitp-server --quiet > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    # Wait until ready
    wait_for_server

    # Get token
    TOKEN=$(get_token)
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
      echo -e "${RED}ERROR: Could not get auth token. Check: $LOG_FILE${NC}"
      exit 1
    fi

    print_ready "$TOKEN"
    ;;

  token)
    # Just get a fresh token, no restart
    if ! curl -s http://localhost:3000/api/stats > /dev/null 2>&1; then
      echo -e "${RED}Server is not running. Run: ./start.sh${NC}"
      exit 1
    fi
    TOKEN=$(get_token)
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
      echo -e "${RED}Could not get token. Run: ./start.sh fresh${NC}"
      exit 1
    fi
    print_ready "$TOKEN"
    ;;

  *)
    echo "Usage: ./start.sh [start|stop|fresh|token]"
    exit 1
    ;;
esac
