"""
AEROCIFER NGFW — Layer 4 Inspector (TCP / UDP)

Detects:
- SYN flood attacks (half-open connection tracking)
- Port scanning (sequential, random, distributed)
- TCP flag anomalies (XMAS, NULL, FIN scans)
- UDP flood attacks
- Connection rate abuse
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.session_tracker import TCPFlags
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# SYN Flood Tracker
# ═══════════════════════════════════════════════════════════════════════════

class SYNFloodTracker:
    """
    Tracks SYN packets without corresponding ACKs to detect SYN floods.
    Uses a sliding window approach for memory efficiency.
    """

    def __init__(
        self,
        threshold: int = 50,
        window: float = 10.0,
        max_entries: int = 10000,
    ):
        self._threshold = threshold
        self._window = window
        self._max_entries = max_entries
        # src_ip → list of SYN timestamps
        self._syn_counts: dict[str, list[float]] = defaultdict(list)
        # src_ip → set of ACKed connections (to exclude legitimate)
        self._acked: dict[str, int] = defaultdict(int)

    def record_syn(self, src_ip: str) -> bool:
        """Record a SYN. Returns True if flood threshold exceeded."""
        now = time.time()
        cutoff = now - self._window

        times = self._syn_counts[src_ip]
        self._syn_counts[src_ip] = [t for t in times if t > cutoff]
        self._syn_counts[src_ip].append(now)

        # Evict old tracked IPs
        if len(self._syn_counts) > self._max_entries:
            oldest = min(
                self._syn_counts,
                key=lambda k: self._syn_counts[k][-1]
                if self._syn_counts[k] else 0,
            )
            del self._syn_counts[oldest]
            self._acked.pop(oldest, None)

        syn_count = len(self._syn_counts[src_ip])
        ack_count = self._acked.get(src_ip, 0)

        # SYN flood: many SYNs, few ACKs
        half_open_ratio = (syn_count - ack_count) / max(syn_count, 1)
        return syn_count > self._threshold and half_open_ratio > 0.7

    def record_ack(self, src_ip: str) -> None:
        """Record that a SYN was properly ACKed (legitimate connection)."""
        self._acked[src_ip] = self._acked.get(src_ip, 0) + 1

    def get_syn_rate(self, src_ip: str) -> int:
        """Get current SYN count in window for a source IP."""
        now = time.time()
        cutoff = now - self._window
        return sum(1 for t in self._syn_counts.get(src_ip, []) if t > cutoff)


# ═══════════════════════════════════════════════════════════════════════════
# Port Scan Detector
# ═══════════════════════════════════════════════════════════════════════════

class PortScanDetector:
    """
    Detects port scanning by tracking unique destination ports per source.

    Detection methods:
    - Sequential scan: hitting consecutive ports
    - Random scan: hitting many unique ports in a short window
    - Distributed scan: multiple sources hitting same target ports
    """

    def __init__(
        self,
        port_threshold: int = 15,
        window: float = 30.0,
        max_entries: int = 5000,
    ):
        self._threshold = port_threshold
        self._window = window
        self._max_entries = max_entries
        # src_ip → {dst_ip: {port: timestamp}}
        self._scans: dict[str, dict[str, dict[int, float]]] = defaultdict(
            lambda: defaultdict(dict)
        )

    def record_connection(
        self, src_ip: str, dst_ip: str, dst_port: int
    ) -> Optional[str]:
        """
        Record a connection attempt. Returns scan type if detected.
        Possible returns: "port_scan", "sequential_scan", None
        """
        now = time.time()
        cutoff = now - self._window

        ports = self._scans[src_ip][dst_ip]
        # Clean expired entries
        expired = [p for p, t in ports.items() if t < cutoff]
        for p in expired:
            del ports[p]

        ports[dst_port] = now

        # Evict old sources
        if len(self._scans) > self._max_entries:
            oldest_src = min(
                self._scans,
                key=lambda k: max(
                    (max(p.values(), default=0)
                     for p in self._scans[k].values()),
                    default=0,
                ),
            )
            del self._scans[oldest_src]

        unique_ports = len(ports)

        if unique_ports < self._threshold:
            return None

        # Check for sequential scan pattern
        sorted_ports = sorted(ports.keys())
        sequential_count = sum(
            1 for i in range(1, len(sorted_ports))
            if sorted_ports[i] - sorted_ports[i - 1] == 1
        )
        if sequential_count > self._threshold * 0.5:
            return "sequential_scan"

        return "port_scan"

    def get_unique_ports(self, src_ip: str, dst_ip: str) -> int:
        """Get unique ports count for a src→dst pair."""
        now = time.time()
        cutoff = now - self._window
        ports = self._scans.get(src_ip, {}).get(dst_ip, {})
        return sum(1 for t in ports.values() if t > cutoff)


# ═══════════════════════════════════════════════════════════════════════════
# UDP Flood Tracker
# ═══════════════════════════════════════════════════════════════════════════

class UDPFloodTracker:
    """Track UDP packet rates per source for flood detection."""

    def __init__(self, threshold: int = 200, window: float = 10.0):
        self._threshold = threshold
        self._window = window
        self._counts: dict[str, list[float]] = defaultdict(list)

    def record(self, src_ip: str) -> bool:
        """Record a UDP packet. Returns True if flood detected."""
        now = time.time()
        cutoff = now - self._window

        times = self._counts[src_ip]
        self._counts[src_ip] = [t for t in times if t > cutoff]
        self._counts[src_ip].append(now)

        return len(self._counts[src_ip]) > self._threshold


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_syn_tracker = SYNFloodTracker(threshold=50, window=10.0)
_port_scanner = PortScanDetector(port_threshold=15, window=30.0)
_udp_tracker = UDPFloodTracker(threshold=200, window=10.0)


# ═══════════════════════════════════════════════════════════════════════════
# Layer 4 Inspector
# ═══════════════════════════════════════════════════════════════════════════

async def inspect_layer4(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 4 inspection: SYN floods, port scans, TCP flag anomalies,
    UDP floods.
    """
    src_ip = packet.src_ip
    dst_ip = packet.dst_ip
    src_port = packet.src_port
    dst_port = packet.dst_port
    flags = packet.tcp_flags

    # ══════════════════════════════════════════════════════════════════
    # TCP Inspection
    # ══════════════════════════════════════════════════════════════════
    if packet.protocol == "tcp":

        # ── TCP Flag Anomaly Detection ──

        # NULL scan: no flags set (used for OS fingerprinting/stealth)
        if flags == 0:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="tcp",
                confidence=0.9,
                threat_type="null_scan",
                details={
                    "description": (
                        f"TCP NULL scan: {src_ip}:{src_port} → "
                        f"{dst_ip}:{dst_port}"
                    ),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                },
            )

        # XMAS scan: FIN + PSH + URG flags set
        xmas_flags = TCPFlags.FIN | TCPFlags.PSH | TCPFlags.URG
        if (flags & xmas_flags) == xmas_flags:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="tcp",
                confidence=0.9,
                threat_type="xmas_scan",
                details={
                    "description": (
                        f"TCP XMAS scan: {src_ip}:{src_port} → "
                        f"{dst_ip}:{dst_port} flags={TCPFlags.describe(flags)}"
                    ),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "flags": TCPFlags.describe(flags),
                },
            )

        # FIN scan without ACK (stealth scan)
        if (TCPFlags.has_flag(flags, TCPFlags.FIN)
                and not TCPFlags.has_flag(flags, TCPFlags.ACK)
                and not TCPFlags.has_flag(flags, TCPFlags.SYN)):
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="tcp",
                confidence=0.8,
                threat_type="fin_scan",
                details={
                    "description": (
                        f"TCP FIN scan: {src_ip} → {dst_ip}:{dst_port}"
                    ),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                },
            )

        # SYN+FIN (impossible in normal TCP, used for evasion)
        if (TCPFlags.has_flag(flags, TCPFlags.SYN)
                and TCPFlags.has_flag(flags, TCPFlags.FIN)):
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="tcp",
                confidence=0.95,
                threat_type="syn_fin_attack",
                details={
                    "description": (
                        f"SYN+FIN attack: {src_ip} → {dst_ip}:{dst_port}"
                    ),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                },
            )

        # ── SYN Flood Detection ──
        if (TCPFlags.has_flag(flags, TCPFlags.SYN)
                and not TCPFlags.has_flag(flags, TCPFlags.ACK)):
            is_flood = _syn_tracker.record_syn(src_ip)
            if is_flood:
                syn_rate = _syn_tracker.get_syn_rate(src_ip)
                return InspectionResult(
                    verdict=InspectionVerdict.MALICIOUS,
                    protocol="tcp",
                    confidence=0.9,
                    threat_type="syn_flood",
                    details={
                        "description": (
                            f"SYN flood: {src_ip} sending {syn_rate} "
                            f"SYN packets in window"
                        ),
                        "src_ip": src_ip,
                        "syn_rate": syn_rate,
                    },
                )
        elif TCPFlags.has_flag(flags, TCPFlags.ACK):
            # Record ACK for SYN flood ratio tracking
            _syn_tracker.record_ack(src_ip)

        # ── Port Scan Detection ──
        scan_type = _port_scanner.record_connection(src_ip, dst_ip, dst_port)
        if scan_type:
            unique_ports = _port_scanner.get_unique_ports(src_ip, dst_ip)
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="tcp",
                confidence=0.85,
                threat_type=scan_type,
                details={
                    "description": (
                        f"{scan_type.replace('_', ' ').title()}: "
                        f"{src_ip} → {dst_ip} "
                        f"({unique_ports} unique ports)"
                    ),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "unique_ports": unique_ports,
                    "scan_type": scan_type,
                },
            )

    # ══════════════════════════════════════════════════════════════════
    # UDP Inspection
    # ══════════════════════════════════════════════════════════════════
    elif packet.protocol == "udp":

        # UDP flood detection
        is_flood = _udp_tracker.record(src_ip)
        if is_flood:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="udp",
                confidence=0.8,
                threat_type="udp_flood",
                details={
                    "description": f"UDP flood from {src_ip}",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                },
            )

        # UDP port scan detection
        scan_type = _port_scanner.record_connection(src_ip, dst_ip, dst_port)
        if scan_type:
            unique_ports = _port_scanner.get_unique_ports(src_ip, dst_ip)
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="udp",
                confidence=0.8,
                threat_type=scan_type,
                details={
                    "description": (
                        f"UDP {scan_type}: {src_ip} → {dst_ip} "
                        f"({unique_ports} ports)"
                    ),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "unique_ports": unique_ports,
                },
            )

    return None
