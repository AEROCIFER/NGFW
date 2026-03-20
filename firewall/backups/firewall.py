import os
import sys
import time
from collections import defaultdict
import re
import netifaces
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import ARP, Ether, srp, sniff, TCP, IP, Raw, DNSQR, DNS, get_if_list, get_if_addr, conf

# === Configuration ===
THRESHOLD = 40
ROUTER_IP = "192.168.0.1"   # Change this if your router IP is different
SUBNET = "192.168.0.0/24"   # Adjust for your LAN
print("Threshold set to:", THRESHOLD)


# === Helper Functions ===
def readFile(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as file:
        return set(line.strip() for line in file)

def load_signatures(rules_dir="rules"):
    signatures = []
    if not os.path.exists(rules_dir):
        return signatures
    for filename in os.listdir(rules_dir):
        if filename.endswith(".rules"):
            with open(os.path.join(rules_dir, filename), 'r') as file:
                for line in file:
                    if "content:" in line and not line.startswith("#"):
                        matches = re.findall(r'content:"(.*?)"', line)
                        for match in matches:
                            signatures.append(match)
    return signatures

def logging(message):
    os.makedirs("logs", exist_ok=True)
    time_stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_file = os.path.join("logs", f"events.log")
    with open(log_file, 'a') as log:
        log.write(f"{time_stamp} - {message}\n")


# === Network Discovery (ARP Scan) ===
def scan_network(network=SUBNET):
    """
    Scans the local subnet using ARP and returns active devices
    """
    print(f"[*] Scanning network {network} for active devices...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def build_topology(devices, router_ip=ROUTER_IP):
    """
    Builds a router-centric graph of LAN devices
    """
    G = nx.Graph()
    G.add_node(router_ip, label="Router")

    for d in devices:
        if d['ip'] != router_ip:
            G.add_node(d['ip'], label=d['mac'])
            G.add_edge(router_ip, d['ip'])

    return G

def draw_topology(G, router_ip=ROUTER_IP):
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G, seed=42)

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, nodelist=[router_ip], node_color="red", node_size=2500, label="Router")
    nx.draw_networkx_nodes(G, pos, nodelist=[n for n in G.nodes if n != router_ip],
                           node_color="skyblue", node_size=2000)

    # Draw edges
    nx.draw_networkx_edges(G, pos, edge_color="gray")

    # Labels
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold")

    plt.title("LAN Topology Map (Router-Centric)")
    plt.show()


# === DPI Checkers ===
def inspect_http(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "Host:" in payload or "GET" in payload or "POST" in payload:
            return payload
    return None

def inspect_dns(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        return packet[DNSQR].qname.decode(errors="ignore")
    return None

def check_signatures(payload, signature_list):
    if payload:
        for sig in signature_list:
            if sig in payload:
                return sig
    return None

def is_ip_blocked(ip):
    output_file = "iptables_output.txt"
    os.system(f"sudo iptables -L -n > {output_file}")
    with open(output_file, "r") as file:
        iptables_output = file.read()
    return ip in iptables_output


# === Firewall Packet Handler ===
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if is_ip_blocked(src_ip):
        logging(f"Blocked IP: {src_ip} (already in iptables)")
        return

    detected_signature = None

    # HTTP DPI
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        http_payload = inspect_http(packet)
        detected_signature = check_signatures(http_payload, loaded_signatures)
        if detected_signature:
            logging(f"Blocked HTTP signature '{detected_signature}' from {src_ip}")
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            blacklst_ips.add(src_ip)
            return

    # DNS DPI
    dns_query = inspect_dns(packet)
    if dns_query:
        if any(sig in dns_query for sig in loaded_signatures):
            logging(f"Blocked DNS query '{dns_query}' from {src_ip}")
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            blacklst_ips.add(src_ip)
            return

    # DDoS protection logic
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            rate = count / time_interval
            if rate > THRESHOLD and ip not in blacklst_ips:
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                logging(f"Blocked IP: {ip}, Rate: {rate:.2f} pps")
                blacklst_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time


# === Main Program ===
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script needs root permissions.")
        sys.exit(1)

    # 1. Discover devices
    devices = scan_network(SUBNET)
    print("Connected devices:")
    for d in devices:
        print(f"IP: {d['ip']} | MAC: {d['mac']}")

    # 2. Build and draw topology
    G = build_topology(devices, router_ip=ROUTER_IP)
    draw_topology(G, router_ip=ROUTER_IP)

    # 3. Initialize Firewall
    whitelist_ips = readFile("whitelist.txt")
    blacklst_ips = readFile("blacklist.txt")
    loaded_signatures = load_signatures("rules")
    print(f"{len(loaded_signatures)} signatures loaded.")

    packet_count = defaultdict(int)
    start_time = [time.time()]

    print("[+] Starting NGFW with DPI...")
    sniff(filter="ip", prn=packet_callback, store=0)
    print("[-] Stopping NGFW...")
    logging("NGFW stopped.")
