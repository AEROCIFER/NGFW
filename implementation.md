# NGFW
Next gen firewall

+--------------------------------------------------+
|                Management Layer                  |
|--------------------------------------------------|
|  🔹 Web Dashboard (React / Vue / Angular)         |
|       - Traffic monitor (charts, graphs)         |
|       - Blocked IPs list                         |
|       - Rule management (add/remove/update)      |
|                                                  |
|  🔹 REST API (FastAPI / Flask)                   |
|       - Interface between UI & Firewall Engine   |
+--------------------------------------------------+
                      |
                      v
+--------------------------------------------------+
|          Intelligence & Security Layer           |
|--------------------------------------------------|
|  🔹 Threat Detection Engine                      |
|       - Signature-based (blacklists)             |
|       - Anomaly-based (ML model: sklearn/TF)     |
|                                                  |
|  🔹 Data Processing                              |
|       - Traffic logs (PCAP)                      |
|       - Real-time analysis                       |
|                                                  |
|  🔹 Storage                                      |
|       - SQLite / PostgreSQL / MongoDB            |
|       - Logs, learned devices, attack history    |
+--------------------------------------------------+
                      |
                      v
+--------------------------------------------------+
|                Core Firewall Engine              |
|--------------------------------------------------|
|  🔹 Packet Capture (Scapy / tcpdump)             |
|  🔹 Protocol Inspection (IP, TCP, UDP, ICMP)     |
|  🔹 Rule Application (iptables / nftables)       |
|  🔹 Connection Learning (ARP, topology discovery)|
+--------------------------------------------------+
                      |
                      v
+--------------------------------------------------+
|            Network / Cloud Infrastructure        |
|--------------------------------------------------|
|  🔹 External Clients (Attackers, Users)          |
|  🔹 Firewall Host (Linux VM / Cloud Server)      |
|  🔹 Internal Network (Servers, Devices)          |
+--------------------------------------------------+
