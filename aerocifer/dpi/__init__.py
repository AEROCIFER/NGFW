"""
AEROCIFER NGFW — Deep Packet Inspection (DPI) Package

Provides Layer 2–7 protocol inspection:
- Layer 2: ARP spoofing, VLAN attacks, MAC anomalies
- Layer 3: IP spoofing, fragmentation attacks, ICMP abuse
- Layer 4: SYN floods, port scans, TCP flag anomalies
- Layer 7: HTTP injection attacks, DNS tunneling, TLS fingerprinting,
           MQTT/CoAP IoT protocol inspection
- Signature engine: Snort-compatible rule matching
"""

from aerocifer.dpi.layer2 import inspect_layer2
from aerocifer.dpi.layer3 import inspect_layer3
from aerocifer.dpi.layer4 import inspect_layer4
from aerocifer.dpi.layer7_http import inspect_http
from aerocifer.dpi.layer7_dns import inspect_dns
from aerocifer.dpi.layer7_tls import inspect_tls
from aerocifer.dpi.layer7_mqtt import inspect_mqtt, inspect_coap
from aerocifer.dpi.signature_engine import SignatureEngine

__all__ = [
    "inspect_layer2",
    "inspect_layer3",
    "inspect_layer4",
    "inspect_http",
    "inspect_dns",
    "inspect_tls",
    "inspect_mqtt",
    "inspect_coap",
    "SignatureEngine",
]
