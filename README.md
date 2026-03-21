# AEROCIFER — AI-Powered Next-Generation Firewall (NGFW)

![AEROCIFER Banner](https://img.shields.io/badge/AEROCIFER-Next--Gen_Firewall-1da1f2?style=for-the-badge&logo=shield&logoColor=white) 
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python) 
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react) 
![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-EE4C2C?style=flat-square&logo=pytorch)

AEROCIFER is a high-performance, enterprise-grade Next-Generation Firewall built with a **Single-Pass Parallel Processing (SP3) Architecture**. It leverages Machine Learning (PyTorch) for real-time anomaly detection and features a zero-touch AI Configuration Engine powered by Natural Language Processing.

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
- **AI Config Engine**: Control your entire firewall using natural language prompts.
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

### 2. Clone & Setup
```bash
git clone https://github.com/aerocifer/NGFW.git
cd NGFW

# Setup Python environment
pip install -r requirements.txt
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

### 2. Starting the Dashboard
```bash
# In the /frontend directory
npm run dev
```
The dashboard will be available at [http://localhost:5173](http://localhost:5173).

---

## 💬 AI Config Engine: Example Commands

AEROCIFER features a zero-touch NLP engine. Open the **AI Config Engine** tab and try:
- `"Create a zone named DMZ and restrict it to Layer 7 protocols"`
- `"Block traffic from 192.168.1.105"`
- `"Block URL malicious-site.ru"`
- `"Setup a new interface WAN as layer 3"`
- `"Assign device 10.0.0.5 to zone IoT"`

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
