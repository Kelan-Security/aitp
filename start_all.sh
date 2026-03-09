#!/usr/bin/env bash
# Starts backend + frontend + runs attack simulations

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
NC='\033[0m'

echo ""
echo -e "${BOLD}AITP — Starting full stack${NC}"
echo ""

# 1. Start backend (if not running)
if ! curl -s http://localhost:3000/api/stats > /dev/null 2>&1; then
  echo -e "${AMBER}Starting backend...${NC}"
  ./start.sh &
  sleep 8
else
  echo -e "${GREEN}✓ Backend already running${NC}"
fi

# 2. Start frontend
echo -e "${AMBER}Starting frontend (aitp-web)...${NC}"
cd aitp-web
npm run dev -- --port 5173 &
FRONTEND_PID=$!
cd ..
echo -e "${GREEN}✓ Frontend starting at http://localhost:5173${NC}"

sleep 3

# 3. Print access info
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@acme.com","password":"supersecret123"}' | jq -r '.token')

echo ""
echo -e "${GREEN}${BOLD}✓ AITP Stack Running${NC}"
echo ""
echo "  Backend API:   http://localhost:3000"
echo "  Dashboard:     http://localhost:5173"
echo ""
echo "  TOKEN=\"$TOKEN\""
echo ""
echo -e "${AMBER}Run attack simulations:${NC}"
echo "  ./simulate_attacks.sh"
echo ""
