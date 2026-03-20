#!/usr/bin/env bash
# Kelan Security — One-line installer for Linux and macOS
#
# Usage:
#   curl -fsSL https://install.kelan.io | bash
#   curl -fsSL https://install.kelan.io | bash -s -- --version v0.3.0
#   KELAN_INSTALL_DIR=~/.local/bin curl -fsSL https://install.kelan.io | bash
#
set -euo pipefail

REPO="kelan-security/kelan-core"
INSTALL_DIR="${KELAN_INSTALL_DIR:-/usr/local/bin}"
VERSION="${KELAN_VERSION:-latest}"

# ── Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'   # no colour

banner() {
  echo -e "${BOLD}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║    Kelan Security Installer              ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${NC}"
}

die() { echo -e "${RED}ERROR: $1${NC}" >&2; exit 1; }
info() { echo -e "  $1"; }

# ── Parse optional --version flag
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|-v) VERSION="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# ── Detect platform
detect_platform() {
  local OS ARCH
  OS=$(uname -s)
  ARCH=$(uname -m)

  case "$OS" in
    Linux)
      case "$ARCH" in
        x86_64)        echo "linux-x86_64" ;;
        aarch64|arm64) echo "linux-arm64"  ;;
        *) die "Unsupported Linux architecture: ${ARCH}" ;;
      esac ;;
    Darwin)
      case "$ARCH" in
        x86_64) echo "macos-x86_64" ;;
        arm64)  echo "macos-arm64"  ;;
        *) die "Unsupported macOS architecture: ${ARCH}" ;;
      esac ;;
    *)
      die "Unsupported OS: ${OS}. For Windows, visit github.com/${REPO}/releases" ;;
  esac
}

# ── Resolve 'latest' to a concrete tag via GitHub API
resolve_version() {
  local v
  v=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  [ -n "$v" ] || die "Could not determine latest version from GitHub API."
  echo "$v"
}

# ── Require commands
require() { command -v "$1" &>/dev/null || die "'$1' is required but not found."; }
require curl
require tar
require sha256sum 2>/dev/null || require shasum   # macOS uses shasum

# ── sha256 wrapper (sha256sum on Linux, shasum -a 256 on macOS)
verify_sha256() {
  local file="$1" expected="$2"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  fi
  [ "$actual" = "$expected" ] || die "Checksum mismatch!\n  Expected: ${expected}\n  Got:      ${actual}"
}

# ────────────────────────────────────────
banner

PLATFORM=$(detect_platform)
info "Platform:  ${GREEN}${PLATFORM}${NC}"

[ "$VERSION" = "latest" ] && VERSION=$(resolve_version)
info "Version:   ${GREEN}${VERSION}${NC}"
info "Install:   ${GREEN}${INSTALL_DIR}${NC}"

VERSION_NUM="${VERSION#v}"
ARCHIVE="kelan-${VERSION}-${PLATFORM}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
DOWNLOAD_URL="${BASE_URL}/${ARCHIVE}"
CHECKSUM_URL="${BASE_URL}/${ARCHIVE}.sha256"

echo ""
info "Downloading ${BOLD}${ARCHIVE}${NC} ..."

# ── Temp directory (cleaned up on exit)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# ── Download
curl -fsSL --progress-bar -o "${TMP_DIR}/${ARCHIVE}"         "${DOWNLOAD_URL}"
curl -fsSL                 -o "${TMP_DIR}/${ARCHIVE}.sha256" "${CHECKSUM_URL}"

# ── Verify checksum
info "Verifying checksum..."
EXPECTED_HASH=$(awk '{print $1}' "${TMP_DIR}/${ARCHIVE}.sha256")
verify_sha256 "${TMP_DIR}/${ARCHIVE}" "${EXPECTED_HASH}"
info "${GREEN}✓ Checksum verified${NC}"

# ── Extract
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
EXTRACTED_DIR="${TMP_DIR}/kelan-${VERSION_NUM}-${PLATFORM}"

# ── Determine sudo need
SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  SUDO="sudo"
  info "(sudo required for ${INSTALL_DIR})"
fi

# ── Create install dir if it doesn't exist
$SUDO mkdir -p "${INSTALL_DIR}"

# ── Install
info "Installing to ${BOLD}${INSTALL_DIR}${NC} ..."
$SUDO cp  "${EXTRACTED_DIR}/kelan-server" "${INSTALL_DIR}/kelan-server"
$SUDO cp  "${EXTRACTED_DIR}/kelan-agent"  "${INSTALL_DIR}/kelan-agent"
$SUDO chmod +x "${INSTALL_DIR}/kelan-server" "${INSTALL_DIR}/kelan-agent"

# ── Verify
INSTALLED_VERSION=$("${INSTALL_DIR}/kelan-server" --version 2>/dev/null || echo "unknown")

echo ""
echo -e "  ${GREEN}${BOLD}✓ Kelan Security installed successfully${NC}"
echo ""
echo -e "  Server:  ${BOLD}${INSTALL_DIR}/kelan-server${NC}  (${INSTALLED_VERSION})"
echo -e "  Agent:   ${BOLD}${INSTALL_DIR}/kelan-agent${NC}"
echo ""
echo -e "  ${AMBER}Next steps:${NC}"
echo "  1. Set your Gemini API key:"
echo "       export GEMINI_API_KEY=your_key_here"
echo ""
echo "  2. Start the Intelligence Core:"
echo "       kelan-server"
echo ""
echo "  3. Enroll this device as a client agent:"
echo "       kelan-agent enroll --server localhost --token <admin_token>"
echo ""
echo "  Docs:  https://docs.kelan.io"
echo "  Repo:  https://github.com/${REPO}"
echo ""
