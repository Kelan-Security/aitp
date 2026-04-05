#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════╗"
echo "║     KELAN SECURITY v0.3.0             ║"
echo "║     Kernel-Level Agentic Network      ║"
echo "║     Security System                   ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ── Prerequisites Check ──────────────────────
echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

check_cmd() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 not found. Install it first.${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ $1 found${NC}"
    fi
}

check_cmd cargo
check_cmd docker
check_cmd curl
check_cmd node   # for web terminal

# Check .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env found. Creating from template...${NC}"
    cp .env.example .env
    echo -e "${RED}IMPORTANT: Edit .env and add your GEMINI_API_KEY${NC}"
    echo "Then re-run this script."
    exit 1
fi

source .env

# ── Build ────────────────────────────────────
echo -e "${YELLOW}[2/6] Building workspace...${NC}"

cargo build --release --workspace 2>&1 | \
    grep -E "Compiling|Finished|error" || true

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Build complete${NC}"

# ── Start Infrastructure ─────────────────────
echo -e "${YELLOW}[3/6] Starting infrastructure...${NC}"

# Clean up any orphans first
docker compose down --remove-orphans 2>/dev/null \
    || true

# Start all infrastructure including postgres
docker compose up -d postgres prometheus grafana

# Wait for postgres specifically
echo "Waiting for PostgreSQL to be ready..."
POSTGRES_READY=false
for i in {1..30}; do
    if docker compose exec -T postgres \
        pg_isready -U kelan 2>/dev/null; then
        POSTGRES_READY=true
        break
    fi
    echo "  Postgres starting... ($i/30)"
    sleep 2
done

if [ "$POSTGRES_READY" = false ]; then
    echo -e "${RED}✗ PostgreSQL failed to start${NC}"
    docker compose logs postgres | tail -20
    exit 1
fi

echo -e "${GREEN}✓ PostgreSQL ready${NC}"
sleep 2
echo -e "${GREEN}✓ Infrastructure ready${NC}"

# ── Start Kelan Server ───────────────────────
echo -e "${YELLOW}[4/6] Starting Kelan AITP server...${NC}"

mkdir -p logs

# Find correct binary (underscore or hyphen)
if [ -f "./target/release/aitp_server" ]; then
    SERVER_BIN="./target/release/aitp_server"
elif [ -f "./target/release/aitp-server" ]; then
    SERVER_BIN="./target/release/aitp-server"
else
    echo -e "${RED}✗ Server binary not found${NC}"
    echo "Run: cargo build --release"
    exit 1
fi

echo "Binary: $SERVER_BIN"

# Start server
RUST_LOG=info,aitp_server=debug,kelan=debug \
    $SERVER_BIN \
    > logs/kelan-server.log 2>&1 &

SERVER_PID=$!
echo $SERVER_PID > .kelan.pid

# Show initial logs immediately
sleep 2
echo "Server startup log:"
cat logs/kelan-server.log

# Show bound ports
echo "Bound ports:"
lsof -i :3000 2>/dev/null | head -3
lsof -i :9999 2>/dev/null | head -3
lsof -p $SERVER_PID 2>/dev/null | \
    grep -E "TCP|UDP" | head -5

# Wait for HTTP health check
echo "Waiting for server to be ready..."
HTTP_PORT=${HTTP_PORT:-3000}

for i in {1..60}; do
    if curl -s \
        http://localhost:$HTTP_PORT/health \
        > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server ready (PID: $SERVER_PID)${NC}"
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "  Still waiting... ($i/60)"
        echo "  Last log: $(tail -1 logs/kelan-server.log)"
    fi
    
    # Check if process died
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${RED}✗ Server process died${NC}"
        echo "Full log:"
        cat logs/kelan-server.log
        exit 1
    fi
    
    sleep 1
done

# ── Start Web Terminal ───────────────────────
echo -e "${YELLOW}[5/6] Starting web terminal...${NC}"

# Install ttyd if not present (web terminal)
if ! command -v ttyd &> /dev/null; then
    echo "Installing ttyd (web terminal)..."
    
    # Linux
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget -q https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -O /usr/local/bin/ttyd
        chmod +x /usr/local/bin/ttyd
    fi
    
    # macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install ttyd 2>/dev/null || \
        echo "Install ttyd: brew install ttyd"
    fi
fi

# Tab 1: Server logs (port 7681)
ttyd --port 7681 \
    bash -c "tail -f logs/kelan-server.log" &
TTYD_PID1=$!
echo $TTYD_PID1 >> .kelan.pid

# Tab 2: Attack simulator (port 7682)
ttyd --port 7682 --writable \
    bash -c "
    echo 'KELAN ATTACK SIMULATOR';
    echo 'Commands:';
    echo '  cargo run --example attack_sim -- --server localhost:9999 --mode ddos';
    echo '  cargo run --example attack_sim -- --server localhost:9999 --mode replay';
    echo '  cargo run --example attack_sim -- --server localhost:9999 --mode lateral-movement';
    echo '';
    bash
    " &
TTYD_PID2=$!
echo $TTYD_PID2 >> .kelan.pid

# Tab 3: Client connector (port 7683)
ttyd --port 7683 --writable \
    bash -c "
    echo 'KELAN CLIENT TERMINAL';
    echo 'Connect to server:';
    echo '  cargo run --example basic_connect -- --server localhost:9999 --intent ModelInference';
    echo '';
    bash
    " &
TTYD_PID3=$!
echo $TTYD_PID3 >> .kelan.pid

echo -e "${GREEN}✓ Web terminal at http://localhost:7681${NC}"

# ── Start Dashboard ──────────────────────────
if [ -d "dashboard" ] || [ -d "frontend" ] || [ -d "aitp-dashboard" ]; then
    echo -e "${YELLOW}Starting dashboard...${NC}"
    
    DASH_DIR=$([ -d "aitp-dashboard" ] && echo "aitp-dashboard" || ([ -d "dashboard" ] && echo "dashboard" || echo "frontend"))
    
    cd $DASH_DIR
    npm install --silent
    npm run dev > ../logs/dashboard.log 2>&1 &
    DASH_PID=$!
    echo $DASH_PID >> ../.kelan.pid
    cd ..
    
    sleep 3
    echo -e "${GREEN}✓ Dashboard starting...${NC}"
fi

# ── Run Verification Tests ───────────────────
echo -e "${YELLOW}[6/6] Running live verification...${NC}"
echo ""

# Small delay to ensure everything is up
sleep 2

./scripts/verify.sh

echo ""
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo -e "${GREEN}  KELAN SECURITY IS RUNNING        ${NC}"
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo ""
echo "  🌐 Dashboard:     http://localhost:3000"
echo "  📺 Live Logs:     http://localhost:7681"
echo "  📊 Grafana:       http://localhost:3003"
echo "  📈 Prometheus:    http://localhost:9090"
echo ""
echo "  To stop everything: ./stop.sh"
echo ""

# Open browser automatically
sleep 2

if [[ "$OSTYPE" == "darwin"* ]]; then
    open http://localhost:7681 &
    open http://localhost:3000 &
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open http://localhost:7681 &
    xdg-open http://localhost:3000 &
fi

# Also open the terminal HTML page
if [ -f "logs/terminal.html" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open logs/terminal.html
    else
        xdg-open logs/terminal.html
    fi
fi
