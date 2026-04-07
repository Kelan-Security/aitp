#!/bin/bash
# Kelan Security — Attack Simulation Script
# Sends controlled SYN + UDP floods to validate XDP rate limiting.
# 
# Usage: bash scripts/simulate_attacks.sh [--target <ip>] [--iface <iface>]
# Default target: 127.0.0.1:9999

set -euo pipefail

# ── Config (override with env vars) ──────────────────────────────────────────
TARGET="${ATTACK_TARGET:-127.0.0.1}"
PORT="${ATTACK_PORT:-9999}"
API_BASE="${API_BASE:-http://localhost:3000}"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GRN}[✓]${NC} $*"; }
warn()  { echo -e "${YLW}[⚠]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
step()  { echo -e "${CYN}[→]${NC} $*"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  🎯 Kelan Attack Simulation — v0.3.0     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Target: $TARGET:$PORT"
echo "  API:    $API_BASE"
echo ""

# ── Dependency checks ─────────────────────────────────────────────────────────
MISSING_DEPS=()

if ! command -v hping3 &>/dev/null; then
  MISSING_DEPS+=("hping3")
fi

if ! command -v curl &>/dev/null; then
  MISSING_DEPS+=("curl")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
  error "Missing required tools: ${MISSING_DEPS[*]}"
  echo "  Install with: sudo apt-get install -y ${MISSING_DEPS[*]}"
  exit 1
fi

# ── Capture baseline stats ────────────────────────────────────────────────────
step "Capturing baseline XDP counters..."

get_stat() {
  curl -sf "$API_BASE/api/stats" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1', 0))" 2>/dev/null || echo "0"
}

BASELINE_UDP_DROPS=$(get_stat "xdp_rate_limit_udp_drops") || true
BASELINE_SYN_DROPS=$(get_stat "xdp_rate_limit_syn_drops") || true
BASELINE_PASS=$(get_stat "xdp_packets_passed") || true

echo "  Baseline — UDP drops: ${BASELINE_UDP_DROPS}, SYN drops: ${BASELINE_SYN_DROPS}, passed: ${BASELINE_PASS}"
echo ""

# ── Test 1: SYN Flood ─────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step "Test 1: SYN Flood (1000 packets at 1ms intervals for ~1s)"
echo "  Expected: first 50 packets/sec from same src pass, rest dropped by XDP"
echo ""

# hping3 --syn: TCP SYN flood
# --count 1000 -i u1000 → 1000 pkt/s (every 1000 microseconds)
# We use -a to spoof a single source IP for reproducible testing
if sudo hping3 \
    --syn \
    --count 1000 \
    --interval u1000 \
    --baseport 12345 \
    --port "$PORT" \
    -a "192.168.99.99" \
    "$TARGET" \
    2>/dev/null; then
  info "SYN flood sent"
else
  warn "hping3 SYN flood exited non-zero (may be rate limiting or needs root)"
fi

# Allow kernel to process
sleep 0.5

# ── Test 2: UDP Flood ─────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step "Test 2: UDP Flood (2000 packets at 500μs intervals for ~1s)"
echo "  Expected: first 200 packets/sec from same src pass, rest dropped by XDP"
echo ""

if sudo hping3 \
    --udp \
    --count 2000 \
    --interval u500 \
    --baseport 12345 \
    --port "$PORT" \
    -a "192.168.99.100" \
    "$TARGET" \
    2>/dev/null; then
  info "UDP flood sent"
else
  warn "hping3 UDP flood exited non-zero"
fi

sleep 0.5

# ── Test 3: Legitimate handshake (control) ────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step "Test 3: Legitimate AITP traffic (control — should pass)"

# Use curl to legit REST API to verify the server is still responsive
if curl -sf "$API_BASE/health" -o /dev/null; then
  info "Server is still responding after flood (XDP isolation working)"
else
  error "Server health check failed — possible service impact"
fi

# ── Test 4: Mixed traffic (different sources) ─────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step "Test 4: Distributed sources (rotation of 10 fake src IPs)"
echo "  Expected: each source gets its own rate bucket — most packets pass"
echo ""

for i in $(seq 1 10); do
  FAKE_IP="10.99.99.$i"
  sudo hping3 \
    --udp \
    --count 100 \
    --interval u5000 \
    --port "$PORT" \
    -a "$FAKE_IP" \
    "$TARGET" \
    2>/dev/null &
done

wait
info "Distributed flood complete"
sleep 0.5

# ── Collect final stats ───────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step "Results (check XDP counters):"
echo ""

FINAL_UDP_DROPS=$(get_stat "xdp_rate_limit_udp_drops") || true
FINAL_SYN_DROPS=$(get_stat "xdp_rate_limit_syn_drops") || true
FINAL_PASS=$(get_stat "xdp_packets_passed") || true

UDP_DELTA=$((${FINAL_UDP_DROPS:-0} - ${BASELINE_UDP_DROPS:-0}))
SYN_DELTA=$((${FINAL_SYN_DROPS:-0} - ${BASELINE_SYN_DROPS:-0}))
PASS_DELTA=$((${FINAL_PASS:-0} - ${BASELINE_PASS:-0}))

echo "  UDP packets dropped by rate limit: +${UDP_DELTA}"
echo "  SYN packets dropped by rate limit: +${SYN_DELTA}"
echo "  Legitimate packets passed:         +${PASS_DELTA}"
echo ""

# Validate expectations
if [ "$SYN_DELTA" -gt 150 ]; then
  info "SYN rate limiting WORKING (>150 SYNs dropped)"
else
  warn "SYN drops lower than expected — eBPF may be in software mode"
fi

if [ "$UDP_DELTA" -gt 1800 ]; then
  info "UDP rate limiting WORKING (>1800 UDP packets dropped)"
else
  warn "UDP drops lower than expected — check XDP attachment"
fi

echo ""
echo "────────────────────────────────────────────"
echo "  Prometheus metrics:"
echo "    ${API_BASE/health/metrics} → search kelan_xdp_rate_limit_drops_total"
echo "  Grafana dashboard port 3003 → XDP panel"
echo "────────────────────────────────────────────"
echo ""
info "Attack simulation complete"
