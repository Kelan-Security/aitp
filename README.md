# AITP — Adaptive Intent Transport Protocol (v0.4.2)

> **TCP was built in 1984 for bytes. AITP is built for AI.**

AITP is an AI-native transport protocol that adds **Identity**, **Intent**, and **Autonomous Logic** to every network connection. It replaces static firewall rules with a continuous, agentic reasoning loop that evaluates the "Why" behind every packet.

---

## 🚀 The AITP Advantage

| Feature | TCP/IP (Standard) | AITP (v0.4) |
|:---|:---:|:---|
| **Primary Unit** | IP Address | Cryptographic Identity |
| **Trust Model** | Perimeter-based | Continuous AI Evaluation |
| **Awareness** | Byte-stream only | Intent-Declared (Declared + Verified) |
| **Defense** | Static Filters | Agentic Threat Response (ReAct) |
| **Revocation** | Manual Firewall Ops | Sub-millisecond Autonomous Kill |

---

## 🧠 Intelligence Core: The 4-Layer Defense

AITP doesn't just "block IPs." It uses a multi-layered intelligence stack to protect your network:

1.  **Deterministic Layer**: Ed25519 signature verification and Role-Based Access Control (RBAC).
2.  **Sentinel Layer (Behavioral)**: Real-time anomaly detection based on rolling 7-day entity baselines.
3.  **Hybrid Trust Engine (LLM)**: Gemini 2.0/2.5 Flash evaluates session intent against the broader network context.
4.  **Agentic Threat Response**: When a high-severity anomaly is detected, a **ReAct AI Agent** autonomously investigates the audit chain, maps it to MITRE ATT&CK techniques, and generates a forensic report.

---

## ⚡ Quickstart (The "God-Mode" Startup)

The entire AITP stack (Backend, Frontend, Docker Infrastructure, and Database) can be started with a single command.

### 1. Prerequisites
- **Rust** (Stable)
- **Node.js** (v18+)
- **Docker Desktop**
- **Gemini API Key** (Set as `AITP_GEMINI_API_KEY` in `.env`)

### 2. Start the Stack
```bash
git clone https://github.com/Tanush-Jain/AITP.git
cd AITP
make dev
```

### 3. Access the SOC
- **Admin Dashboard**: [http://localhost:3000](http://localhost:3000) (Self-served from Intelligence Core)
- **Local Dev App**: [http://localhost:5173](http://localhost:5173)
- **Grafana Metrics**: [http://localhost:3001](http://localhost:3001)

---

## 🗄️ Database Support

AITP supports both **SQLite** and **PostgreSQL** from the same codebase.

- **SQLite (Dev)**: No setup required. Default `DATABASE_URL=sqlite://./data/aitp.db`.
- **PostgreSQL (Prod)**: High-concurrency support.
  1. Start Postgres: `docker compose -f docker-compose.dev.yml up -d`
  2. Set `DATABASE_URL=postgresql://kernex:kernex_dev@localhost:5432/kernex` in `.env`.

---

## 🛠️ Key Operational Commands

| Command | Action |
|:---|:---|
| `make dev` | **Start Everything**: Backend + Frontend + Docker + DB |
| `./simulate_attacks.sh` | Run the **Attack Suite**: Verifies AI reasoning against real exploits. |
| `make test` | Run internal unit and protocol tests. |
| `make clean` | Full cleanup of stale processes, Docker containers, and temporary logs. |

---

## 🔒 Production Hardening & TLS

AITP supports high-performance HTTPS via `tokio-rustls`. For local development, you can generate self-signed certificates:

```bash
cd aitp-server
./scripts/generate_certs.sh
```

Then, enable HTTPS in your `.env`:
```env
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem
AITP_HTTPS_PORT=8443
AITP_REDIRECT_PORT=8080
```

---

## 🏗️ Technical Architecture

- **Backend**: High-performance Rust (Axum, SQLx).
- **Core Database**: Dual-driver support for **SQLite** (Dev) and **PostgreSQL** (Prod).
- **Core Protocol**: Custom binary header (164-byte wire format) with identity-nonce binding.
- **Frontend**: Real-time SOC dashboard using WebSockets and CSS-optimized security aesthetics.
- **Infrastructure**: Containerized Prometheus/Grafana monitoring cluster.

---

## 🔒 Security Posture

AITP implements **Zero-Trust for the AI Age**:
- **Identity-First**: No session starts without an Ed25519-signed handshake.
- **Micro-segmentation**: Dynamic clearance levels enforced at the protocol header.
- **Audit Stability**: Every security event is chained and hashed for forensic integrity.

---

## 🗺️ Roadmap
- [x] v0.3: Agentic Threat Response Loop
- [x] v0.4: Integrated Admin SOC Dashboard
- [ ] v0.5: Distributed eBPF Enforcement Plane (Production hardening)
- [ ] v1.0: Multi-Cloud Intelligence Mesh

---
© 2026 AITP Contributors. Licensed under BSL 1.1.
