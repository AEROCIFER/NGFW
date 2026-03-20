import scapy.all as scapy
import json
import sys

def scan_network(network="192.168.0.1/24"):
    """Scan the network and return a dict of live hosts"""
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = {}
    for element in answered:
        devices[element[1].psrc] = element[1].hwsrc
    return devices


if __name__ == "__main__":
    try:
        network = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1/24"
        devices = scan_network(network)

        # Save to topology.json
        with open("topology.json", "w") as f:
            json.dump(devices, f, indent=4)

        print(f"[Mapper] Discovered {len(devices)} devices, saved to topology.json")

    except Exception as e:
        print(f"[Mapper Error] {e}")
