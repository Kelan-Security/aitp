# AITP — Adaptive Intent Transport Protocol

> TCP was built in 1984 for bytes. AITP is built for AI.

AITP is an open-source transport protocol that adds **identity**, **intent**,
and **AI-verified trust** to every network connection — natively at the
protocol level.

## Why AITP?

| TCP/IP (1984)        | AITP (2025)                    |
|----------------------|--------------------------------|
| Connects hosts       | Connects identities            |
| No intent awareness  | Every packet declares intent   |
| Trust bolted on      | Trust built into the protocol  |
| Static authorization | Continuous AI re-evaluation    |
| Manual revocation    | Sub-millisecond revocation     |

## Quickstart (5 minutes)

### Prerequisites
- Docker + Docker Compose
- Linux or macOS

### Install & Run

#### Option 1: One-line install
```bash
curl -fsSL https://get.aitp.dev | bash
```

#### Option 2: Docker Compose
```bash
git clone https://github.com/Tanush-Jain/AITP.git
cd AITP
cp .env.example .env
# Add your Gemini API key to .env (optional — runs without it)
echo "AITP_GEMINI_API_KEY=[REDACTED_GEMINI_KEY]" >> .env
docker compose up -d
```

#### Verify it's running
```bash
curl http://localhost:8080/health
```

#### Watch a live handshake between two nodes
```bash
docker compose logs -f aitp-node-alpha aitp-node-beta
```

Open Grafana: [http://localhost:3000](http://localhost:3000) (admin / aitp_admin)

## Architecture

![AITP Architecture Diagram](https://raw.githubusercontent.com/Tanush-Jain/AITP/main/docs/assets/architecture.png)

## AITP Web Dashboard

The official AITP Web Dashboard provides real-time observability, control plane identity management, and node visualization.

![AITP Dashboard Overview](https://raw.githubusercontent.com/Tanush-Jain/AITP/main/docs/assets/dashboard_overview.png)
*Live Network Graph, Trust Distribution, and Active Sessions.*

![Test Lab Simulation](https://raw.githubusercontent.com/Tanush-Jain/AITP/main/docs/assets/dashboard_testlab.png)
*Defense verification test lab simulating inbound malicious intent.*

## Documentation
- [Quick Start Guide](docs/quickstart.md)
- [Protocol Specification](docs/spec.md)
- [API Reference](docs/api.md)
- [Deployment Guide](docs/deployment.md)

## Status
![Tests](https://github.com/Tanush-Jain/AITP/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-BUSL%201.1-blue)
![Docker Pulls](https://img.shields.io/docker/pulls/tanushjain/aitp)

---
© 2026 AITP Contributors. Licensed under BSL 1.1.
