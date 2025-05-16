import os
import time
import sys
from collections import defaultdict
from scapy.all import sniff, TCP, IP, Raw, DNSQR, DNS, ICMP, UDP
import re

# === Configuration ===
THRESHOLD = 40
DPI_PROTOCOLS = ["HTTP", "DNS"]
print("Threshold set to:", THRESHOLD)

# === Helper Functions ===
def readFile(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as file:
        return set(line.strip() for line in file)

def load_signatures(rules_dir="rules"):
    signatures = []
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
    time_stamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join("logs", f"events.log")
    with open(log_file, 'a') as log:
        log.write(f"{time_stamp} - {message}\n")

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

def block_ip_by_protocol(ip, proto):
    if proto == "ICMP":
        os.system(f"iptables -A INPUT -s {ip} -p icmp -j DROP")
    elif proto == "UDP":
        os.system(f"iptables -A INPUT -s {ip} -p udp -j DROP")
    elif proto == "TCP":
        os.system(f"iptables -A INPUT -s {ip} -p tcp -j DROP")
    else:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
    logging(f"Blocked {proto} traffic from {ip}")
    blacklst_ips.add(ip)

# === Packet Handler ===
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
            block_ip_by_protocol(src_ip, "TCP")
            return

    # DNS DPI
    dns_query = inspect_dns(packet)
    if dns_query:
        if any(sig in dns_query for sig in loaded_signatures):
            logging(f"Blocked DNS query '{dns_query}' from {src_ip}")
            block_ip_by_protocol(src_ip, "UDP")
            return

    # ICMP detection
    if packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(TCP):
        protocol = "TCP"
    else:
        protocol = "OTHER"

    packet_count[(src_ip, protocol)] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for (ip, proto), count in packet_count.items():
            rate = count / time_interval
            if rate > THRESHOLD and ip not in blacklst_ips:
                block_ip_by_protocol(ip, proto)
                logging(f"Blocked IP: {ip} for {proto}, Rate: {rate:.2f} pps")
        packet_count.clear()
        start_time[0] = current_time

# === Main Program ===
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script needs root permissions.")
        sys.exit(1)

    whitelist_ips = readFile("whitelist.txt")
    blacklst_ips = readFile("blacklist.txt")
    loaded_signatures = load_signatures("rules")
    print(f"{len(loaded_signatures)} signatures loaded.")

    packet_count = defaultdict(int)
    start_time = [time.time()]

    print("Starting NGFW with DPI...")
    sniff(filter="ip", prn=packet_callback, store=0)
    print("Stopping NGFW...")
    logging("NGFW stopped.")
