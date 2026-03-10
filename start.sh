#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# AITP — One command startup script (macOS/Linux compatible)
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/aitp-server"
PID_FILE="$SCRIPT_DIR/.aitp_server.pid"
LOG_FILE="$SCRIPT_DIR/.aitp_server.log"

# Default credentials
DEFAULT_ORG="Acme Corp"
DEFAULT_EMAIL="admin@acme.com"
DEFAULT_PASS="supersecret123"

# Colors
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

stop_server() {
  echo -e "${AMBER}Cleaning up existing server instances...${NC}"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      kill "$PID" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$PID_FILE"
  fi
  
  # Kill anything on port 3000 (most robust)
  PORT_PID=$(lsof -t -i:3000)
  if [ -z "$PORT_PID" ]; then
    # Fallback to pkill if lsof empty
    pkill -f "aitp_server" 2>/dev/null || true
  else
    echo -e "${AMBER}Killing process $PORT_PID on port 3000...${NC}"
    kill -9 $PORT_PID 2>/dev/null || true
  fi
  
  sleep 1
}

wait_for_server() {
  local SERVER_PID=$!
  echo -ne "${AMBER}Waiting for server to start${NC}"
  for i in $(seq 1 30); do
    # Check if the process we just started is still alive
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo -e " ${RED}FAILED (server process died)${NC}"
      echo -e "${RED}Check logs in $LOG_FILE${NC}"
      exit 1
    fi
    
    if curl -s http://localhost:3000/api/stats > /dev/null 2>&1; then
      echo -e " ${GREEN}ready!${NC}"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo -e " ${RED}TIMEOUT${NC}"
  exit 1
}

get_token() {
  local EMAIL="${1:-$DEFAULT_EMAIL}"
  local PASS="${2:-$DEFAULT_PASS}"

  # Try signin
  local RESPONSE=$(curl -s -X POST http://localhost:3000/api/auth/signin \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")

  local TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty' 2>/dev/null)

  # If failed, try signup
  if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    RESPONSE=$(curl -s -X POST http://localhost:3000/api/auth/signup \
      -H 'Content-Type: application/json' \
      -d "{\"org_name\":\"$DEFAULT_ORG\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
    TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty' 2>/dev/null)
  fi

  echo "$TOKEN"
}

print_ready() {
  local TOKEN="$1"
  echo ""
  echo -e "${GREEN}${BOLD}✓ AITP is running${NC}"
  echo ""
  echo -e "${BOLD}Dashboard:${NC}  http://localhost:3000"
  echo -e "${BOLD}API:${NC}        http://localhost:3000/api"
  echo ""
  echo -e "${BOLD}── Your token ──────────────────────────────────────────${NC}"
  echo -e "${BLUE}$TOKEN${NC}"
  echo ""
  echo -e "${BOLD}── Test commands ───────────────────────────────────────${NC}"
  echo ""
  echo "  TOKEN=\"$TOKEN\""
  echo "  curl -s http://localhost:3000/api/auth/me -H \"Authorization: Bearer \$TOKEN\" | jq"
  echo "  websocat \"ws://localhost:3000/ws?token=\$TOKEN\""
  echo ""
  echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
  echo ""
}

start_server() {
    stop_server 2>/dev/null || true
    echo -e "${AMBER}Building aitp-server...${NC}"
    cd "$SERVER_DIR"
    cargo build -p aitp-server --quiet 2>&1
    echo -e "${AMBER}Starting AITP Intelligence Core...${NC}"
    nohup cargo run -p aitp-server --quiet > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    wait_for_server
    TOKEN=$(get_token)
    print_ready "$TOKEN"
}

banner

case "${1:-start}" in
  stop)
    stop_server
    ;;
  fresh)
    echo -e "${AMBER}Fresh start — wiping database...${NC}"
    stop_server 2>/dev/null || true
    rm -f "$SERVER_DIR/data/aitp.db"*
    start_server
    ;;
  start)
    start_server
    ;;
  token)
    TOKEN=$(get_token)
    print_ready "$TOKEN"
    ;;
  *)
    echo "Usage: ./start.sh [start|stop|fresh|token]"
    exit 1
    ;;
esac
