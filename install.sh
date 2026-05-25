#!/bin/bash
set -e

AITP_VERSION="v0.2.0"
REPO="https://github.com/Tanush-Jain/AITP"

echo "Installing AITP ${AITP_VERSION}..."

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

# Download binary (Placeholder for actual release assets)
echo "Downloading AITP node binary..."
# BINARY_URL="${REPO}/releases/download/${AITP_VERSION}/aitp_node-${OS}-${ARCH}"
# curl -fsSL "$BINARY_URL" -o /usr/local/bin/aitp_node
# chmod +x /usr/local/bin/aitp_node

# Download compose stack
echo "Downloading Docker Compose stack..."
curl -fsSL "${REPO}/raw/main/docker-compose.yml" -o aitp-docker-compose.yml
curl -fsSL "${REPO}/raw/main/.env.example" -o .env

echo ""
echo "✓ AITP installed successfully (infrastructure files)!"
echo ""
echo "Next steps:"
echo "  1. Edit .env and configure OLLAMA_ENDPOINT (optional)"
echo "  2. Run: docker compose -f aitp-docker-compose.yml up -d"
echo "  3. Open: http://localhost:3000 (Grafana dashboard)"
echo ""
echo "Docs: https://github.com/Tanush-Jain/AITP"
