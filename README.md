# AITP — Adaptive Intent Transport Protocol (v0.5.0)

> **TCP was built in 1984 for bytes. AITP is built for AI.**

AITP is a production-grade, zero-trust cybersecurity platform that adds **Identity**, **Intent**, and **Autonomous Logic** to every network connection. It replaces static firewall rules with a continuous, agentic reasoning loop that evaluates the "Why" behind every packet.

---

## 🚀 The AITP Advantage

| Feature | TCP/IP (Standard) | AITP (v0.5) |
|:---|:---:|:---|
| **Primary Unit** | IP Address | Cryptographic Identity |
| **Trust Model** | Perimeter-based | Continuous AI Evaluation |
| **Awareness** | Byte-stream only | Intent-Declared + Verified |
| **Defense** | Static Filters | Agentic Threat Response (ReAct) |
| **Revocation** | Manual Firewall Ops | Sub-millisecond Autonomous Kill |

---

## ⚡ Quickstart (Docker-First)

The entire AITP stack (Backend, Frontend, Postgres, and Monitoring) can be started with a single command.

### 1. Prerequisites
- **Docker Desktop** (macOS, Linux, or Windows)
- **Gemini API Key** (Get yours at [Google AI Studio](https://aistudio.google.com/app/apikey))

### 2. Launch the Stack
```bash
# 1. Clone & Enter
git clone https://github.com/Tanush-Jain/AITP.git && cd AITP

# 2. Setup Environment
# Ensure you have your Gemini API key ready in the root .env file.
# The following command starts the Postgres DB:
docker compose -f docker-compose.dev.yml up -d

# 3. Start Everything (Backend + Frontend + Monitoring)
make dev
```

### 3. Access the SOC
- **Admin Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Frontend App**: [http://localhost:5173](http://localhost:5173)
- **Grafana Metrics**: [http://localhost:3001](http://localhost:3001) (Credentials in your `.env`)

---

## 🧪 Testing & Validation

### Internal Suite
Run all unit and protocol tests:
```bash
make test
```

### Attack Simulation
Verify the AI engine's ability to detect and block real attacks:
```bash
./simulate_attacks.sh
```

---

## 🏗️ Technical Architecture
- **`aitp-server`**: Intelligence Core (Rust/Axum). Handles AI trust and identity.
- **`aitp-client`**: Agentic Daemon. Intercepts traffic and enforces policy.
- **`kelan-crypto`**: High-performance Post-Quantum Cryptography (ML-DSA, ML-KEM).
- **`kelan-ebpf`**: Kernel-level enforcement using eBPF/XDP (Linux only).

---

## 🦙 Dedicated Ollama Inference Server Setup (macOS M4)

AITP can offload trust engine computations to a dedicated local Ollama inference server (e.g., a MacBook M4 running `gemma4:latest`). This server can be accessed remotely by AITP daemons or verification clients (such as a Kali Linux machine on the same LAN).

### 1. Host (macOS) Setup & Startup

To set up and run the Ollama server locally using the configuration files in this repository:

1. **Deploy and Load the launchd Agent**:
   Register the launchd plist to ensure Ollama starts automatically on boot/login, configured to listen on all interfaces (`0.0.0.0`) and allowing cross-origin requests:
   ```bash
   # Copy launchd configuration to user directory
   cp scripts/com.ollama.serve.plist ~/Library/LaunchAgents/com.ollama.serve.plist

   # Stop any existing Ollama UI/Daemon to prevent port binding conflicts
   killall Ollama ollama 2>/dev/null || true

   # Unload old plist (if exists) and load the new configuration
   launchctl unload ~/Library/LaunchAgents/com.ollama.serve.plist 2>/dev/null || true
   launchctl load ~/Library/LaunchAgents/com.ollama.serve.plist
   ```

2. **Enable the Keep-Alive Health Script**:
   A background daemon script has been provided to continuously monitor Ollama's availability and restart it if it encounters failures:
   ```bash
   # Make the health script executable
   chmod +x scripts/ollama-health.sh

   # Start the health check daemon in the background
   nohup ./scripts/ollama-health.sh > ~/ollama-health.log 2>&1 &
   ```

3. **Retrieve the Host IP**:
   Find the local network IP address of the macOS server:
   ```bash
   ipconfig getifaddr en0
   ```
   *(Example output: `192.168.31.70`)*

---

### 2. Client (Kali Linux) Remote Connection

To connect your Kali Linux machine or any AITP client to the dedicated macOS Ollama server over the local network:

1. **Configure Environment Variables**:
   Export the endpoint and model details to direct the trust engine to the remote host:
   ```bash
   export OLLAMA_ENDPOINT="http://<MAC_IP>:11434"
   export OLLAMA_MODEL="gemma4:latest"
   ```

2. **Verify Connectivity**:
   Test communication with the remote server's API:
   ```bash
   # 1. Fetch available models from the remote endpoint
   curl http://<MAC_IP>:11434/api/tags

   # 2. Perform a remote test inference call (JSON mode verification)
   curl -X POST http://<MAC_IP>:11434/api/generate \
     -H "Content-Type: application/json" \
     -d '{
       "model": "gemma4:latest",
       "prompt": "Respond ONLY with valid JSON: {\"verdict\":\"ALLOW\",\"confidence\":0.95,\"reason\":\"test\"}",
       "stream": false
     }' | python3 -m json.tool
   ```

---

## 🔒 Production Hardening

For production deployments:
1. Use `docker-compose.prod.yml` for managed Nginx TLS and Postgres RLS.
2. Enable full Post-Quantum verification by setting `MIN_CRYPTO_ALGORITHM=HybridPQ` in `.env`.
3. Configure **AlertManager** for Slack/Email notifications on critical anomalies.

```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## 🗺️ Roadmap
- [x] v0.4: Integrated Admin SOC Dashboard
- [x] v0.5: Post-Quantum Identity & Session Keys
- [ ] v0.6: Distributed eBPF Enforcement Plane
- [ ] v1.0: Multi-Cloud Intelligence Mesh

---
© 2026 AITP Contributors. Licensed under BSL 1.1.
