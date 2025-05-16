import os
import time
import sys
from collections import defaultdict
from scapy.all import sniff, TCP, IP, Raw, DNSQR, DNS
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
    log_file = os.path.join("logs", f"{time_stamp}.log")
    with open(log_file, 'a') as log:
        log.write(f"{time_stamp} - {message}\n")

# === DPI Checkers ===
def inspect_http(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "Host:" in payload or "GET" in payload or "POST" in payload:
            return payload  # Return raw HTTP headers/body
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
    output_file = " iptables_output.txt"
    os.system(f"sudo iptables -L -n > {output_file}")
    
    with open(output_file, "r") as file:
        iptables_output = file.read()
    
    return ip in iptables_output


# === Packet Handler ===
def packet_callback(packet):
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