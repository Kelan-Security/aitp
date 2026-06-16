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

## Getting Started

**1. Clone and install (run once):**
```bash
git clone https://github.com/your-org/kelan-core.git
cd kelan-core
bash install.sh
```

**2. Configure:**
```bash
cp .env.example .env
# Edit .env with your settings
```

**3. Launch:**
```bash
bash launch.sh        # development mode
bash launch.sh --prod # production mode  
bash launch.sh --stop # stop all services
```

---

### Repository Structure

```
kelan-core/
├── install.sh          ← Run once on fresh clone
├── launch.sh           ← Daily driver: start/stop everything
├── scripts/            ← Internal shell scripts (don't call directly)
│   ├── start.sh
│   ├── stop.sh
│   ├── start_all.sh
│   ├── simulate_attacks.sh
│   └── simulate_attacks_throttled.sh
├── docs/               ← All documentation
│   ├── kelan_documentation.md
│   ├── CONTRIBUTING.md
│   └── ...
├── .env.example        ← Copy to .env and fill in
├── .env                ← Your local config (gitignored)
└── README.md
```

## 🧪 Testing & Validation

### Internal Suite
Run all unit and protocol tests:
```bash
make test
```

### Attack Simulation
Verify the AI engine's ability to detect and block real attacks:
```bash
./scripts/simulate_attacks.sh
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
   *(Example output: `<MAC_IP>`)*

---

### 2. Client (Kali Linux) Remote Connection

To connect your Kali Linux machine (or any other client) to the Ollama server running on your MacBook:

#### Step A: Verify Network Access from the Kali Machine
Ensure you can reach the MacBook's Ollama API:
```bash
# 1. Fetch the list of available models from the MacBook
curl http://<MAC_IP>:11434/api/tags | jq .

# 2. Run a test inference call to verify response
curl -X POST http://<MAC_IP>:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5:3b",
    "prompt": "Respond ONLY with valid JSON: {\"verdict\":\"ALLOW\",\"confidence\":0.95,\"reason\":\"test\"}",
    "stream": false
  }' | jq .
```

#### Step B: Configure the Kelan Server on Kali
Open your `.env` file in the root of `kelan-core` on the Kali machine and configure the AI trust engine settings to point to the MacBook's local network IP:
```ini
# AI Engine Configuration on Kali Linux
OLLAMA_ENDPOINT=http://<MAC_IP>:11434
OLLAMA_MODEL=qwen2.5:3b  # or gemma4:latest
OLLAMA_TIMEOUT_SECS=8.0
```

#### Step C: Start the Kelan Server on Kali Linux
Once the `.env` file is updated, start the Kelan server. It will automatically route all AI-based packet evaluation requests to the MacBook's Ollama engine:
```bash
# Run with the environment loaded
source .venv/bin/activate
make dev
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

## 🤝 Contributing, Conduct & Licensing

We welcome community involvement and support:
*   **[Contributing Guide](docs/CONTRIBUTING.md)**: Guidelines on code standards, pull requests, and testing.
*   **[Code of Conduct](docs/CODE_OF_CONDUCT.md)**: Standards of behavior we expect from participants.
*   **[Commercial Terms](docs/COMMERCIAL.md)**: Details on dual-licensing, commercial usage, and enterprise support.

---
© 2026 AITP Contributors. Licensed under BSL 1.1.
