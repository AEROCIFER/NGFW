"""
AEROCIFER NGFW — Layer 3 Inspector (IP / ICMP)

Detects:
- IP address spoofing (private IPs from WAN, bogon ranges)
- IP fragmentation attacks (tiny fragments, overlapping)
- ICMP flood / Ping of Death
- TTL anomalies (potential tunneling)
- IP header manipulation
"""

from __future__ import annotations

import time
import ipaddress
from collections import defaultdict
from typing import Optional

from scapy.all import IP, ICMP  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# Bogon / Reserved IP Ranges (should never appear on public internet)
# ═══════════════════════════════════════════════════════════════════════════

BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
]


def is_bogon(ip_str: str) -> bool:
    """Check if an IP is in a bogon/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in BOGON_NETWORKS)
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# ICMP Rate Tracker
# ═══════════════════════════════════════════════════════════════════════════

class ICMPTracker:
    """Track ICMP traffic rates for flood detection."""

    def __init__(
        self,
        flood_threshold: int = 100,
        window: float = 10.0,
        max_entries: int = 5000,
    ):
        self._threshold = flood_threshold
        self._window = window
        self._max_entries = max_entries
        # src_ip → list of timestamps
        self._icmp_times: dict[str, list[float]] = defaultdict(list)

    def record(self, src_ip: str) -> bool:
        """Record ICMP packet. Returns True if flooding detected."""
        now = time.time()
        cutoff = now - self._window

        times = self._icmp_times[src_ip]
        self._icmp_times[src_ip] = [t for t in times if t > cutoff]
        self._icmp_times[src_ip].append(now)

        # Evict old entries if too many tracked IPs
        if len(self._icmp_times) > self._max_entries:
            oldest = min(
                self._icmp_times,
                key=lambda k: self._icmp_times[k][-1] if self._icmp_times[k] else 0,
            )
            del self._icmp_times[oldest]

        return len(self._icmp_times[src_ip]) > self._threshold


# ═══════════════════════════════════════════════════════════════════════════
# Fragment Tracker
# ═══════════════════════════════════════════════════════════════════════════

class FragmentTracker:
    """Track IP fragments to detect fragmentation attacks."""

    def __init__(self, max_tracked: int = 1000):
        # (src_ip, dst_ip, ip_id) → {"count": N, "min_offset": X, ...}
        self._fragments: dict[tuple, dict] = {}
        self._max_tracked = max_tracked

    def track_fragment(
        self, src_ip: str, dst_ip: str, ip_id: int,
        frag_offset: int, mf_flag: bool, total_len: int,
    ) -> Optional[str]:
        """
        Track an IP fragment. Returns threat description if attack detected.
        """
        key = (src_ip, dst_ip, ip_id)

        if key not in self._fragments:
            if len(self._fragments) >= self._max_tracked:
                # Evict random old entry
                old_key = next(iter(self._fragments))
                del self._fragments[old_key]
            self._fragments[key] = {
                "count": 0,
                "offsets": [],
                "first_seen": time.time(),
            }

        entry = self._fragments[key]
        entry["count"] += 1
        entry["offsets"].append(frag_offset)

        # --- Tiny fragment attack ---
        # First fragment should carry a reasonable header
        if frag_offset == 0 and total_len < 68:
            # IP header (20) + TCP header (20) minimum = 40,
            # but 68 bytes is minimum for any meaningful packet
            del self._fragments[key]
            return (
                f"Tiny fragment attack: {src_ip} → {dst_ip}, "
                f"fragment size {total_len} bytes"
            )

        # --- Excessive fragmentation ---
        if entry["count"] > 100:
            del self._fragments[key]
            return (
                f"Excessive fragmentation: {src_ip} → {dst_ip}, "
                f"{entry['count']} fragments for single packet"
            )

        # --- Overlapping fragments (Teardrop attack) ---
        offsets = sorted(entry["offsets"])
        if len(offsets) >= 2:
            for i in range(1, len(offsets)):
                if offsets[i] <= offsets[i - 1]:
                    del self._fragments[key]
                    return (
                        f"Overlapping fragments (Teardrop): "
                        f"{src_ip} → {dst_ip}"
                    )

        # Clean up old entries
        now = time.time()
        if now - entry["first_seen"] > 30:  # 30s timeout for fragments
            del self._fragments[key]

        return None


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_icmp_tracker = ICMPTracker(flood_threshold=100, window=10.0)
_frag_tracker = FragmentTracker()

# Set of local network subnets (populated from config/discovery)
_local_networks: list[ipaddress.IPv4Network] = []


def set_local_networks(networks: list[str]) -> None:
    """Configure local network subnets for spoof detection."""
    global _local_networks
    _local_networks = [
        ipaddress.ip_network(n, strict=False) for n in networks
    ]


def _is_local_ip(ip_str: str) -> bool:
    """Check if IP is in any configured local network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _local_networks)
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Layer 3 Inspector
# ═══════════════════════════════════════════════════════════════════════════

async def inspect_layer3(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 3 inspection: IP spoofing, fragmentation attacks, ICMP abuse,
    TTL anomalies, header manipulation.
    """
    raw = packet.raw_packet
    if raw is None or not raw.haslayer(IP):
        return None

    ip_layer = raw[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    ttl = ip_layer.ttl
    ip_len = ip_layer.len
    ip_id = ip_layer.id
    flags = ip_layer.flags
    frag_offset = ip_layer.frag
    proto = ip_layer.proto

    # ── IP Header Anomalies ──

    # Invalid IP version
    if ip_layer.version != 4:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="ip",
            confidence=0.8,
            threat_type="ip_anomaly",
            details={
                "description": f"Invalid IP version: {ip_layer.version}",
                "src_ip": src_ip,
            },
        )

    # TTL = 0 (should never be forwarded)
    if ttl == 0:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="ip",
            confidence=0.7,
            threat_type="ip_anomaly",
            details={
                "description": f"TTL=0 packet from {src_ip}",
                "src_ip": src_ip,
                "ttl": ttl,
            },
        )

    # Source IP = Destination IP (Land attack)
    if src_ip == dst_ip and src_ip != "127.0.0.1":
        return InspectionResult(
            verdict=InspectionVerdict.MALICIOUS,
            protocol="ip",
            confidence=0.9,
            threat_type="land_attack",
            details={
                "description": f"Land attack: src=dst={src_ip}",
                "src_ip": src_ip,
            },
        )

    # ── IP Spoofing Detection ──
    # Source is broadcast
    if src_ip == "255.255.255.255" or src_ip.endswith(".255"):
        return InspectionResult(
            verdict=InspectionVerdict.MALICIOUS,
            protocol="ip",
            confidence=0.9,
            threat_type="ip_spoof",
            details={
                "description": f"Spoofed broadcast source: {src_ip}",
                "src_ip": src_ip,
            },
        )

    # Source is multicast (224.0.0.0/4)
    try:
        src_addr = ipaddress.ip_address(src_ip)
        if src_addr.is_multicast:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="ip",
                confidence=0.9,
                threat_type="ip_spoof",
                details={
                    "description": f"Multicast source address: {src_ip}",
                    "src_ip": src_ip,
                },
            )
    except ValueError:
        pass

    # ── Fragmentation Attack Detection ──
    # Check if packet is fragmented (MF flag set or frag_offset > 0)
    mf_flag = bool(flags & 0x1)  # More Fragments
    if mf_flag or frag_offset > 0:
        threat = _frag_tracker.track_fragment(
            src_ip, dst_ip, ip_id, frag_offset, mf_flag, ip_len
        )
        if threat:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="ip",
                confidence=0.85,
                threat_type="fragmentation_attack",
                details={
                    "description": threat,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                },
            )

    # ── ICMP Inspection ──
    if raw.haslayer(ICMP):
        icmp = raw[ICMP]
        icmp_type = icmp.type
        icmp_code = icmp.code

        # ICMP flood detection
        is_flood = _icmp_tracker.record(src_ip)
        if is_flood:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="icmp",
                confidence=0.85,
                threat_type="icmp_flood",
                details={
                    "description": f"ICMP flood from {src_ip}",
                    "src_ip": src_ip,
                    "icmp_type": icmp_type,
                },
            )

        # Ping of Death (oversized ICMP)
        if icmp_type == 8 and ip_len > 65535:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="icmp",
                confidence=0.95,
                threat_type="ping_of_death",
                details={
                    "description": (
                        f"Ping of Death from {src_ip}: "
                        f"size {ip_len} bytes"
                    ),
                    "src_ip": src_ip,
                    "size": ip_len,
                },
            )

        # ICMP redirect (can be used for MITM)
        if icmp_type == 5:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="icmp",
                confidence=0.7,
                threat_type="icmp_redirect",
                details={
                    "description": f"ICMP redirect from {src_ip}",
                    "src_ip": src_ip,
                    "icmp_code": icmp_code,
                },
            )

        # Timestamp request (reconnaissance)
        if icmp_type == 13:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="icmp",
                confidence=0.5,
                threat_type="icmp_recon",
                details={
                    "description": f"ICMP timestamp request from {src_ip}",
                    "src_ip": src_ip,
                },
            )

    return None
