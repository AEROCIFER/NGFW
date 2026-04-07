# AEROCIFER — AI-Powered Next-Generation Firewall (NGFW)

![AEROCIFER Banner](https://img.shields.io/badge/AEROCIFER-Next--Gen_Firewall-1da1f2?style=for-the-badge&logo=shield&logoColor=white) 
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python) 
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react) 
![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-EE4C2C?style=flat-square&logo=pytorch)

AEROCIFER is a high-performance, enterprise-grade Next-Generation Firewall built with a **Single-Pass Parallel Processing (SP3) Architecture**. It leverages Machine Learning (PyTorch) for real-time anomaly detection and features a zero-touch AI Configuration Engine powered by **Gemma 4 (via Ollama)**.

---

## 🚀 Key Features

### 🛡️ Core Security & Networking
- **SP3 Architecture**: Single-pass inspection for ultra-low latency packet processing.
- **Deep Packet Inspection (DPI)**: Layer 7 visibility into protocols like HTTP, DNS, TLS (JA3 fingerprinting), and more.
- **Zone-Based Segmentation**: Logical isolation of network segments (e.g., DMZ, Internal, IoT) with granular inter-zone policies.
- **L2 - L7 Filtering**: Support for Tap, Virtual Wire, Layer 2, and Layer 3 interface modes.
- **URL & DNS Blacklisting**: Global drop-lists for malicious hostnames and domains.

### 🧠 AI & Machine Learning
- **Anomaly Detection**: PyTorch-driven autoencoders detect sub-millisecond network deviations and zero-day threats.
- **AI Config Engine (Gemma 4)**: Control your entire firewall using natural language prompts (zones + rules + URL filtering).
- **Device Fingerprinting**: Automatically classifies connected devices (IoT, Workstation, Server) using traffic profiles.

### 📊 Advanced Management
- **Glassview Dashboard**: Modern, glassmorphic React-based UI with real-time telemetry.
- **Log Management**: High-throughput time-series logging for every processed packet.
- **Multi-DB Architecture**: 
  - **Relational**: SQLite/PostgreSQL for configuration and rules.
  - **Performance Cache**: In-memory B-Tree for sub-millisecond packet-state tracking.
  - **Analytics**: Dedicated high-speed DB for packet history.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.12, FastAPI, Scapy, PyTorch, SQLAlchemy.
- **Frontend**: React 18, Vite, TypeScript, Vanilla CSS (Glassmorphism).
- **Database**: SQLite (WAL Mode), In-memory High-speed Caches.
- **OS Support**: Windows, Linux.

---

## 📥 Installation

### 1. Prerequisites
- Python 3.10 or higher
- Node.js & npm (for the frontend)
- Npcap (Windows) or libpcap (Linux) for packet capturing
- Ollama (for Gemma 4 local inference)

### 2. Clone & Setup
```bash
git clone https://github.com/aerocifer/NGFW.git
cd NGFW

# Setup Python environment
pip install -r requirements.txt
```

### 2b. Ollama + Gemma 4
Install and start Ollama, then pull a Gemma 4 model:

```bash
ollama pull gemma4:latest
ollama list
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

---

## 🚦 Usage Guide

### 1. Starting the Backend
The backend runs the packet engine, AI models, and REST API.
```bash
# In the project root
python -m aerocifer --simulation
```
*Note: The `--simulation` flag generates mock traffic and runs in a non-disruptive mode for testing.*

#### Windows note (firewall rules)
Applying Windows Firewall (`netsh`) rules requires an **elevated / Administrator** process. If you run non-elevated, the rule engine will fall back to simulation mode.

### 2. Starting the Dashboard
```bash
# In the /frontend directory
npm run dev
```
The dashboard will be available at [http://localhost:5173](http://localhost:5173).
<img width="1919" height="990" alt="Screenshot 2026-03-24 004733" src="https://github.com/user-attachments/assets/a802b81a-333e-4a09-a93c-c8f3b7518a75" />
<img width="1919" height="1064" alt="Screenshot 2026-03-24 004714" src="https://github.com/user-attachments/assets/83e21c06-fa8e-41f7-829a-b469c53c1536" />

---

## 💬 AI Config Engine: Example Commands

AEROCIFER features a Gemma 4-powered AI engine (Ollama). Open the **AI Config Engine** tab and try:
- `"Create a zone named DMZ and restrict it to Layer 7 protocols"`
- `"Block traffic from 192.168.1.105"`
- `"Block URL malicious-site.ru"`
- `"Setup a new interface WAN as layer 3"`
- `"Assign device 10.0.0.5 to zone IoT"`

## ✅ Testing

Run backend + unit test suites:

```bash
python tests/test_foundation.py
python tests/test_dpi.py
python tests/test_ml_ai.py
python tests/simulate_ai_traffic.py
```

Verify Ollama/Gemma is reachable:

```bash
python scripts/ollama_smoke_test.py
```

## 🔌 Useful API endpoints
- `GET /api/v1/status/` — overall status
- `POST /api/v1/ai/prompt` — Gemma 4 AI config
- `GET /api/v1/network/zones` — list zones
- `POST /api/v1/security/rules` — create custom rule
- `GET /api/v1/security/rules` — list rules
- `GET /api/v1/logs/traffic` — recent traffic logs

---

## 📂 Project Structure

```text
NGFW/
├── aerocifer/          # Main Python Package
│   ├── ai/             # NLP & Intent Parsing
│   ├── api/            # FastAPI Routers & Servers
│   ├── core/           # SP3 Packet Engine & Zone Manager
│   ├── db/             # Database Models & Migrations
│   ├── ml/             # PyTorch Models & Pipeline
│   └── utils/          # Logging & Shared Utilities
├── data/               # Persistent Storage (SQLite DBs, ML Weights)
├── frontend/           # React Dashboard (Vite + TS)
└── config.yaml         # Global Firewall Configuration
```

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.

---
**Build with ❤️ by AEROCIFER**
