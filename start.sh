#!/usr/bin/env bash
# Kelan Security — One command startup
set -euo pipefail

GREEN='\033[0;32m'; AMBER='\033[0;33m'; RED='\033[0;31m'
BOLD='\033[1m'; NC='\033[0m'

ACTION="${1:-start}"

free_port() {
  local PORT=$1
  # Kill anything using this port (handles Docker leftover, old server, etc.)
  if lsof -ti:$PORT >/dev/null 2>&1; then
    echo -e "${AMBER}Freeing port $PORT...${NC}"
    lsof -ti:$PORT | xargs kill -9 2>/dev/null || true
    sleep 1
  fi
}

case "$ACTION" in
  start)
    echo -e "\n${BOLD}Kelan Security — Starting...${NC}\n"

    # Free ports before starting
    free_port 3000
    free_port 9999
    free_port 5173

    # Kill any lingering server processes
    pkill -f aitp_server 2>/dev/null || true
    sleep 1

    # Build and start server
    echo -e "${AMBER}Building aitp-server...${NC}"
    cargo build -p aitp-server --quiet

    export AITP_JWT_SECRET="${AITP_JWT_SECRET:-$(openssl rand -base64 48)}"

    echo -e "${AMBER}Starting Intelligence Core...${NC}"
    RUST_LOG=aitp_server=info cargo run -p aitp-server &
    SERVER_PID=$!
    echo $SERVER_PID > /tmp/kelan_server.pid

    # Wait for server to be ready
    echo -ne "${AMBER}Waiting for server${NC}"
    for i in $(seq 1 30); do
      if curl -s http://localhost:3000/api/stats > /dev/null 2>&1; then
        echo -e " ${GREEN}ready!${NC}"
        break
      fi
      echo -n "."
      sleep 1
    done

    # Start frontend if it exists
    if [ -d "aitp-dashboard" ] && command -v node >/dev/null 2>&1; then
      echo -e "${AMBER}Starting frontend...${NC}"
      cd aitp-dashboard
      npm install --silent 2>/dev/null || true
      npm run dev &
      cd ..
      echo -e "${GREEN}Frontend starting at http://localhost:5173${NC}"
    fi

    # Get or create a token
    SIGNUP=$(curl -s -X POST http://localhost:3000/api/auth/signup \
      -H 'Content-Type: application/json' \
      -d '{"org_name":"Kelan Dev","email":"dev@kelan.io","password":"DevPass123!"}' 2>/dev/null)
    TOKEN=$(echo $SIGNUP | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || echo "")

    if [ -z "$TOKEN" ]; then
      TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/signin \
        -H 'Content-Type: application/json' \
        -d '{"email":"dev@kelan.io","password":"DevPass123!"}' \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Kelan Security is running${NC}"
    echo ""
    echo -e "  API:       http://localhost:3000"
    echo -e "  Dashboard: http://localhost:3000"
    if [ -d "aitp-dashboard" ]; then
      echo -e "  Frontend:  http://localhost:5173"
    fi
    echo ""
    if [ -n "$TOKEN" ]; then
      echo -e "  ${BOLD}Token:${NC} ${TOKEN:0:40}..."
      echo ""
      echo -e "  ${AMBER}Test commands:${NC}"
      echo "  TOKEN=\"$TOKEN\""
      echo "  curl -s http://localhost:3000/api/auth/me -H \"Authorization: Bearer \$TOKEN\" | python3 -m json.tool"
      echo "  curl -s http://localhost:3000/api/stats   -H \"Authorization: Bearer \$TOKEN\" | python3 -m json.tool"
    fi
    echo ""
    echo -e "  ${AMBER}Stop:${NC}  ./start.sh stop  OR  make stop"
    ;;

  stop)
    echo "Stopping Kelan Security..."
    pkill -f aitp_server 2>/dev/null || true
    pkill -f "npm run dev" 2>/dev/null || true
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    lsof -ti:5173 | xargs kill -9 2>/dev/null || true
    rm -f /tmp/kelan_server.pid
    echo "Stopped."
    ;;

  fresh)
    echo "Fresh start — wiping database..."
    pkill -f aitp_server 2>/dev/null || true
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    rm -f aitp-server/data/*.db aitp-server/data/*.db-shm aitp-server/data/*.db-wal
    sleep 1
    exec "$0" start
    ;;

  token)
    TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/signin \
      -H 'Content-Type: application/json' \
      -d '{"email":"dev@kelan.io","password":"DevPass123!"}' \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
    echo "TOKEN=\"$TOKEN\""
    ;;

  *)
    echo "Usage: ./start.sh [start|stop|fresh|token]"
    ;;
esac
