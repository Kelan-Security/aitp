# Kernex Getting Started Guide

This guide describes how to set up the Kernex ecosystem—including the **Intelligence Core (Server)** and the **Client Agent (Daemon)**—from scratch for a new developer or security team.

---

## 1. Prerequisites

Before you begin, ensure the following are installed on your machine:

- **Rust (v1.78+)**: [Install via rustup](https://rustup.rs/)
- **Docker & Docker Compose**: For running the PostgreSQL database (optional but recommended for production testing)
- **OpenSSL**: For generating development certificates

---

## 2. Setting Up the Intelligence Core (Server)

The server is the brain of Kernex. It handles identity, trust evaluation, and policy enforcement.

### Step 2.1: Environment Configuration
1. Navigate to the project root.
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Open `.env` and set your `AITP_JWT_SECRET` (generate a random 64-character string).
4. Set your `AITP_AI_ENGINE_GEMINI_API_KEY` to enable AI trust scoring.

### Step 2.2: Database Setup
Kernex supports **SQLite** (for easy dev) and **PostgreSQL** (for production).

- **For SQLite (Default)**: Use the default line in `.env`:
  `DATABASE_URL=sqlite://./aitp-server/data/aitp.db`
- **For PostgreSQL**:
  1. Start the container: `docker compose -f docker-compose.dev.yml up -d`
  2. In `.env`, uncomment: `DATABASE_URL=postgres://kernex:kernex_dev@localhost:5432/kernex`

### Step 2.3: Development Certificates
Generate a self-signed certificate for HTTPS:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Kernex/CN=localhost"
```

### Step 2.4: Running the Server
```bash
cargo run -p aitp-server
```
*Wait for the message: `Database: ... (mode) Migrations complete` and the ASCII banner.*

---

## 3. Setting Up the Client Agent (Daemon)

The agent intercepts network traffic transparently on every host.

### Step 3.1: Build the Agent
```bash
cargo build -p aitp-client
```

### Step 3.2: Create a Local Configuration
For development, use a local config that doesn't require root permissions:
```bash
cp aitp-client/kernex-agent.toml.example local-agent.toml
```

### Step 3.3: Running the Agent
Run the agent in the foreground for testing:
```bash
./target/debug/kernex-agent --config local-agent.toml start
```
*The agent will generate a new Ed25519 identity key locally in the same directory.*

---

## 4. Connecting and Enrolling

Once both the server and agent are running, you must link them so the server trusts the agent's identity.

### Step 4.1: Enrollment
In a new terminal, run the enrollment command:
```bash
./target/debug/kernex-agent --config local-agent.toml enroll --server localhost:3000 --token [YOUR_ORG_TOKEN]
```
*(You can get a token by signing up via the API or dashboard at `https://localhost:8443`)*

---

## 5. Usage & Verification

### Check Agent Status
```bash
./target/debug/kernex-agent --config local-agent.toml status
```

### Test AI Trust Evaluation
Simulate a connection to see how the Intelligence Core evaluates it:
```bash
./target/debug/kernex-agent --config local-agent.toml test api.internal:443
```

### Transparent Interception (SOCKS5)
Point any application (like `curl`) to the agent's local proxy to have traffic secured:
```bash
curl --proxy socks5h://localhost:7654 https://google.com
```

---

## Useful Commands

| Action | Command |
|--------|---------|
| **Install as Service** | `sudo ./kernex-agent install` |
| **Stop Daemon** | `./kernex-agent stop` |
| **Reset Identity** | `./kernex-agent reset-keys` |
| **Server Stats** | `curl -k https://localhost:8443/api/stats` |
