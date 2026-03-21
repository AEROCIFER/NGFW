"""
AEROCIFER NGFW — Protocol Inspector Dispatcher

Central dispatcher that routes packets to the appropriate
DPI (Deep Packet Inspection) module based on protocol detection.

Provides a plugin-style architecture where each Layer 2–7 inspector
registers itself and the dispatcher routes packets accordingly.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Any, Callable, Awaitable
from enum import Enum

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# Inspection Result
# ═══════════════════════════════════════════════════════════════════════════

class InspectionVerdict(str, Enum):
    """Result of a protocol inspection."""
    CLEAN = "clean"           # No issues found
    SUSPICIOUS = "suspicious" # Needs further analysis
    MALICIOUS = "malicious"   # Confirmed threat
    BLOCKED = "blocked"       # Matched a blocked signature/pattern


@dataclass
class InspectionResult:
    """Result from a DPI inspector."""
    verdict: InspectionVerdict = InspectionVerdict.CLEAN
    inspector: str = ""               # Which inspector produced this
    protocol: str = ""                # Detected application protocol
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)
    signature_matched: str = ""       # If a signature was matched
    threat_type: str = ""             # Type of threat detected

    @property
    def is_threat(self) -> bool:
        return self.verdict in (
            InspectionVerdict.MALICIOUS, InspectionVerdict.BLOCKED
        )


# Type alias for inspector functions
InspectorFunc = Callable[
    [RawPacket], Awaitable[Optional[InspectionResult]]
]


# ═══════════════════════════════════════════════════════════════════════════
# Protocol Inspector Registry
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class InspectorRegistration:
    """A registered protocol inspector."""
    name: str
    func: InspectorFunc
    layer: int                         # OSI layer (2–7)
    protocols: list[str]               # Protocols this handles
    priority: int = 100                # Lower = runs first
    enabled: bool = True


class ProtocolInspector:
    """
    Central protocol inspection dispatcher.

    Inspectors register themselves with:
    - What layer they inspect (2–7)
    - What protocols they handle
    - Their inspection function

    When a packet arrives, the dispatcher:
    1. Determines likely protocols from port/header analysis
    2. Routes to matching inspectors in priority order
    3. Aggregates results and returns the worst verdict

    Usage:
        inspector = ProtocolInspector()

        # Register DPI modules
        inspector.register("http_inspector", inspect_http, layer=7,
                          protocols=["http"], ports=[80, 8080])
        inspector.register("dns_inspector", inspect_dns, layer=7,
                          protocols=["dns"], ports=[53])

        # Inspect a packet
        results = await inspector.inspect(raw_packet)
    """

    # Well-known port → protocol mapping for initial classification
    PORT_PROTOCOL_MAP: dict[int, str] = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
        80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb",
        993: "imaps", 995: "pop3s",
        1883: "mqtt", 5683: "coap",
        3306: "mysql", 5432: "postgresql",
        6379: "redis", 8080: "http-alt", 8443: "https-alt",
        8883: "mqtts", 27017: "mongodb",
    }

    def __init__(self):
        self._inspectors: list[InspectorRegistration] = []
        self._port_inspectors: dict[int, list[InspectorRegistration]] = {}
        self._protocol_inspectors: dict[str, list[InspectorRegistration]] = {}
        self._layer_inspectors: dict[int, list[InspectorRegistration]] = {}

    def register(
        self,
        name: str,
        func: InspectorFunc,
        layer: int,
        protocols: list[str],
        ports: Optional[list[int]] = None,
        priority: int = 100,
    ) -> None:
        """
        Register a protocol inspector.

        Args:
            name: Inspector name (e.g. "http_inspector")
            func: Async inspection function
            layer: OSI layer (2–7)
            protocols: List of protocols this inspector handles
            ports: Optional list of ports to match
            priority: Execution priority (lower = first)
        """
        reg = InspectorRegistration(
            name=name,
            func=func,
            layer=layer,
            protocols=protocols,
            priority=priority,
        )

        self._inspectors.append(reg)
        self._inspectors.sort(key=lambda r: (r.layer, r.priority))

        # Index by protocol
        for proto in protocols:
            self._protocol_inspectors.setdefault(proto, []).append(reg)

        # Index by port
        if ports:
            for port in ports:
                self._port_inspectors.setdefault(port, []).append(reg)

        # Index by layer
        self._layer_inspectors.setdefault(layer, []).append(reg)

        log.debug(
            f"Registered inspector '{name}' for L{layer} "
            f"protocols={protocols}"
            + (f" ports={ports}" if ports else "")
        )

    async def inspect(
        self, packet: RawPacket
    ) -> list[InspectionResult]:
        """
        Run all applicable inspectors on a packet.

        Returns list of InspectionResult (one per inspector that ran).
        Results are sorted by severity (worst first).
        """
        results: list[InspectionResult] = []

        # Determine which inspectors to run
        inspectors_to_run = self._select_inspectors(packet)

        for reg in inspectors_to_run:
            if not reg.enabled:
                continue
            try:
                result = await reg.func(packet)
                if result:
                    result.inspector = reg.name
                    results.append(result)

                    # Short-circuit on confirmed malicious
                    if result.verdict == InspectionVerdict.MALICIOUS:
                        break

            except Exception as e:
                log.error(f"Inspector '{reg.name}' error: {e}")

        # Sort: malicious first, then suspicious, then clean
        verdict_order = {
            InspectionVerdict.MALICIOUS: 0,
            InspectionVerdict.BLOCKED: 1,
            InspectionVerdict.SUSPICIOUS: 2,
            InspectionVerdict.CLEAN: 3,
        }
        results.sort(key=lambda r: verdict_order.get(r.verdict, 99))

        return results

    def detect_protocol(self, packet: RawPacket) -> str:
        """
        Detect the application-layer protocol from packet metadata.
        Uses port mapping and basic heuristics.
        """
        # Check destination port first
        proto = self.PORT_PROTOCOL_MAP.get(packet.dst_port, "")
        if proto:
            return proto

        # Check source port (for responses)
        proto = self.PORT_PROTOCOL_MAP.get(packet.src_port, "")
        if proto:
            return proto

        # Fallback to transport protocol
        return packet.protocol

    def _select_inspectors(
        self, packet: RawPacket
    ) -> list[InspectorRegistration]:
        """Select which inspectors should run for a given packet."""
        selected: list[InspectorRegistration] = []
        seen: set[str] = set()

        # Match by port
        for port in (packet.dst_port, packet.src_port):
            if port in self._port_inspectors:
                for reg in self._port_inspectors[port]:
                    if reg.name not in seen:
                        selected.append(reg)
                        seen.add(reg.name)

        # Match by detected protocol
        proto = self.detect_protocol(packet)
        if proto in self._protocol_inspectors:
            for reg in self._protocol_inspectors[proto]:
                if reg.name not in seen:
                    selected.append(reg)
                    seen.add(reg.name)

        # Always run Layer 2–3 inspectors (they check all packets)
        for layer in (2, 3):
            for reg in self._layer_inspectors.get(layer, []):
                if reg.name not in seen:
                    selected.append(reg)
                    seen.add(reg.name)

        # Sort by layer then priority
        selected.sort(key=lambda r: (r.layer, r.priority))
        return selected

    def get_registered_inspectors(self) -> list[dict[str, Any]]:
        """List all registered inspectors."""
        return [
            {
                "name": reg.name,
                "layer": reg.layer,
                "protocols": reg.protocols,
                "priority": reg.priority,
                "enabled": reg.enabled,
            }
            for reg in self._inspectors
        ]
