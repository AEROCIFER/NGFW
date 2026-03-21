"""
AEROCIFER NGFW — Layer 2 Inspector (Ethernet / ARP / VLAN)

Detects:
- ARP spoofing (IP→MAC binding changes)
- ARP flooding (excessive ARP requests)
- Gratuitous ARP abuse
- MAC address spoofing
- VLAN hopping attempts (double-tagged 802.1Q)
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from scapy.all import ARP, Ether, Dot1Q  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# ARP Binding Table (IP → MAC history)
# ═══════════════════════════════════════════════════════════════════════════

class ARPBindingTable:
    """Tracks IP-to-MAC bindings and detects changes (ARP spoofing)."""

    def __init__(self, max_entries: int = 10000):
        # ip → (mac, first_seen, last_seen)
        self._bindings: dict[str, tuple[str, float, float]] = {}
        self._max_entries = max_entries

    def update(self, ip: str, mac: str) -> Optional[str]:
        """
        Record an IP→MAC binding.
        Returns the old MAC if it changed (potential spoof), None otherwise.
        """
        now = time.time()
        if ip in self._bindings:
            old_mac, first_seen, _ = self._bindings[ip]
            if old_mac != mac:
                self._bindings[ip] = (mac, first_seen, now)
                return old_mac
            else:
                self._bindings[ip] = (old_mac, first_seen, now)
        else:
            if len(self._bindings) >= self._max_entries:
                # Evict oldest entry
                oldest_ip = min(
                    self._bindings, key=lambda k: self._bindings[k][2]
                )
                del self._bindings[oldest_ip]
            self._bindings[ip] = (mac, now, now)
        return None

    def get_mac(self, ip: str) -> Optional[str]:
        if ip in self._bindings:
            return self._bindings[ip][0]
        return None

    @property
    def entry_count(self) -> int:
        return len(self._bindings)


# ═══════════════════════════════════════════════════════════════════════════
# ARP Rate Tracker
# ═══════════════════════════════════════════════════════════════════════════

class ARPRateTracker:
    """Tracks ARP request rates per source to detect ARP flooding."""

    def __init__(self, threshold: int = 50, window: float = 10.0):
        self._threshold = threshold
        self._window = window
        # mac → list of timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)

    def record_request(self, src_mac: str) -> bool:
        """
        Record an ARP request. Returns True if rate exceeds threshold.
        """
        now = time.time()
        cutoff = now - self._window

        timestamps = self._requests[src_mac]
        # Remove old entries
        self._requests[src_mac] = [t for t in timestamps if t > cutoff]
        self._requests[src_mac].append(now)

        return len(self._requests[src_mac]) > self._threshold


# ═══════════════════════════════════════════════════════════════════════════
# Layer 2 Inspector
# ═══════════════════════════════════════════════════════════════════════════

# Module-level state (initialized once, persists across packets)
_arp_table = ARPBindingTable()
_arp_rate = ARPRateTracker(threshold=50, window=10.0)

# Known gateway IPs that should never change MAC
_static_bindings: dict[str, str] = {}  # Populated from config or discovery


def set_static_binding(ip: str, mac: str) -> None:
    """Set a static IP→MAC binding (e.g., for gateway)."""
    _static_bindings[ip.strip()] = mac.strip().lower()


async def inspect_layer2(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 2 inspection: ARP spoofing, flooding, MAC anomalies, VLAN attacks.

    This inspector examines raw Ethernet/ARP frames for:
    - ARP cache poisoning attacks
    - ARP flooding (network reconnaissance)
    - Gratuitous ARP abuse
    - VLAN double-tagging (Q-in-Q) attacks
    """
    raw = packet.raw_packet
    if raw is None:
        return None

    # ── ARP Inspection ──
    if raw.haslayer(ARP):
        arp = raw[ARP]
        arp_op = arp.op  # 1 = request, 2 = reply
        sender_ip = arp.psrc
        sender_mac = arp.hwsrc
        target_ip = arp.pdst

        # Skip if sender IP is empty or broadcast
        if not sender_ip or sender_ip == "0.0.0.0":
            return None

        # --- ARP Spoofing Detection ---
        # Check static bindings first (gateway, critical servers)
        if sender_ip in _static_bindings:
            expected_mac = _static_bindings[sender_ip]
            if sender_mac.lower() != expected_mac:
                return InspectionResult(
                    verdict=InspectionVerdict.MALICIOUS,
                    protocol="arp",
                    confidence=0.95,
                    threat_type="arp_spoof",
                    details={
                        "description": (
                            f"ARP spoofing detected: {sender_ip} "
                            f"claims MAC {sender_mac}, expected {expected_mac}"
                        ),
                        "sender_ip": sender_ip,
                        "sender_mac": sender_mac,
                        "expected_mac": expected_mac,
                        "static_binding": True,
                    },
                )

        # Dynamic binding change detection
        old_mac = _arp_table.update(sender_ip, sender_mac)
        if old_mac is not None:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="arp",
                confidence=0.75,
                threat_type="arp_spoof",
                details={
                    "description": (
                        f"ARP binding changed: {sender_ip} was {old_mac}, "
                        f"now {sender_mac}"
                    ),
                    "sender_ip": sender_ip,
                    "old_mac": old_mac,
                    "new_mac": sender_mac,
                },
            )

        # --- Gratuitous ARP Detection ---
        if arp_op == 2 and sender_ip == target_ip:
            # Gratuitous ARP reply — can be legitimate but also used in attacks
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="arp",
                confidence=0.5,
                threat_type="gratuitous_arp",
                details={
                    "description": f"Gratuitous ARP from {sender_ip} ({sender_mac})",
                    "sender_ip": sender_ip,
                    "sender_mac": sender_mac,
                },
            )

        # --- ARP Flooding Detection ---
        if arp_op == 1:  # ARP request
            is_flooding = _arp_rate.record_request(sender_mac)
            if is_flooding:
                return InspectionResult(
                    verdict=InspectionVerdict.MALICIOUS,
                    protocol="arp",
                    confidence=0.85,
                    threat_type="arp_flood",
                    details={
                        "description": (
                            f"ARP flooding from {sender_mac}: "
                            "excessive ARP requests"
                        ),
                        "sender_mac": sender_mac,
                        "sender_ip": sender_ip,
                    },
                )

    # ── VLAN Double-Tagging Detection ──
    if raw.haslayer(Dot1Q):
        dot1q = raw[Dot1Q]
        # Check for double-tagged frames (Q-in-Q attack)
        if dot1q.payload and hasattr(dot1q.payload, 'haslayer'):
            if dot1q.payload.haslayer(Dot1Q):
                inner_vlan = dot1q.payload[Dot1Q].vlan
                outer_vlan = dot1q.vlan
                return InspectionResult(
                    verdict=InspectionVerdict.MALICIOUS,
                    protocol="vlan",
                    confidence=0.9,
                    threat_type="vlan_hopping",
                    details={
                        "description": (
                            f"VLAN double-tagging attack detected: "
                            f"outer={outer_vlan}, inner={inner_vlan}"
                        ),
                        "outer_vlan": outer_vlan,
                        "inner_vlan": inner_vlan,
                        "src_mac": packet.src_mac,
                    },
                )

    return None


def get_arp_table_status() -> dict:
    """Get ARP binding table status for monitoring."""
    return {
        "entries": _arp_table.entry_count,
        "static_bindings": len(_static_bindings),
    }
