# Installing Kelan Security

## One-line install (Linux / macOS)

```bash
curl -fsSL https://install.kelan.io | bash
```

This auto-detects your platform, downloads the latest release from GitHub,
verifies the SHA-256 checksum, and installs `kelan-server` and `kelan-agent`
to `/usr/local/bin`.

To install a specific version:
```bash
curl -fsSL https://install.kelan.io | bash -s -- --version v0.3.0
```

To install into a custom directory:
```bash
KELAN_INSTALL_DIR=~/.local/bin curl -fsSL https://install.kelan.io | bash
```

## Windows

```powershell
# Run as Administrator in PowerShell
iwr -useb https://install.kelan.io/windows | iex
```

Installs `kelan-server.exe` to `C:\Program Files\Kelan Security` and adds
it to the System PATH.

## Manual install

Download the archive for your platform from the
[Releases page](https://github.com/kelan-security/kelan-core/releases/latest):

| Platform             | File                                    |
|----------------------|-----------------------------------------|
| Linux x86_64         | `kelan-vX.Y.Z-linux-x86_64.tar.gz`     |
| Linux ARM64          | `kelan-vX.Y.Z-linux-arm64.tar.gz`      |
| macOS Intel          | `kelan-vX.Y.Z-macos-x86_64.tar.gz`     |
| macOS Apple Silicon  | `kelan-vX.Y.Z-macos-arm64.tar.gz`      |
| Windows x86_64       | `kelan-vX.Y.Z-windows-x86_64.zip`      |

### Verify checksum (Linux / macOS)

```bash
sha256sum -c kelan-vX.Y.Z-linux-x86_64.tar.gz.sha256
# or verify all at once with the combined file:
sha256sum -c SHA256SUMS
```

### Extract and install (Linux / macOS)

```bash
tar -xzf kelan-vX.Y.Z-linux-x86_64.tar.gz
cd kelan-vX.Y.Z-linux-x86_64
./install.sh
```

### Extract and install (Windows)

```powershell
Expand-Archive kelan-vX.Y.Z-windows-x86_64.zip -DestinationPath .
cd kelan-vX.Y.Z-windows-x86_64
# Run as Administrator:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1
```

## Docker (no install needed)

```bash
docker run -d \
  -p 3000:3000 \
  -p 9999:9999/udp \
  -e GEMINI_API_KEY=[REDACTED_GEMINI_KEY] \
  -e AITP_JWT_SECRET=$(openssl rand -base64 64) \
  -v kelan_data:/app/data \
  ghcr.io/kelan-security/kelan-core:latest
```

## First run

```bash
# 1. Set your Gemini API key
export GEMINI_API_KEY=[REDACTED_GEMINI_KEY]

# 2. Start the Intelligence Core
kelan-server

# 3. Create your organisation (in a second terminal)
curl -s -X POST http://localhost:3000/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"org_name":"Acme Corp","email":"admin@acme.com","password":"StrongPass123!"}' \
  | jq

# 4. Enroll this device as a client agent
kelan-agent enroll --server localhost --token <jwt_from_above>
kelan-agent start
```

## Supported platforms

| Platform              | Architecture | Notes                                 |
|-----------------------|--------------|---------------------------------------|
| Linux (glibc ≥ 2.31)  | x86_64       | Ubuntu 20.04+, Debian 10+, RHEL 8+   |
| Linux (glibc ≥ 2.31)  | ARM64        | Oracle Cloud Free Tier, AWS Graviton  |
| macOS ≥ 12 Monterey   | x86_64       | Intel Macs                            |
| macOS ≥ 12 Monterey   | ARM64        | M1/M2/M3 Macs (no Rosetta needed)     |
| Windows Server 2019+  | x86_64       | Server only — agent coming soon       |

> **Note:** The Linux/macOS archives include both `kelan-server` and `kelan-agent`.
> The Windows archive includes only `kelan-server` in the current release;
> a native Windows agent will ship in a future update.
