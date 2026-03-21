"""
AEROCIFER NGFW — Layer 7 MQTT / CoAP Inspector (IoT Protocols)

Detects:
- Unauthorized MQTT connections (missing auth)
- MQTT topic injection / wildcard abuse
- MQTT payload anomalies (oversized, high entropy)
- CoAP resource abuse
- IoT protocol-level attacks
- QoS abuse
"""

from __future__ import annotations

import math
import struct
import time
from collections import defaultdict
from typing import Optional

from scapy.all import Raw  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# MQTT Constants
# ═══════════════════════════════════════════════════════════════════════════

# MQTT Control Packet Types (upper 4 bits of first byte)
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_SUBSCRIBE = 8
MQTT_UNSUBSCRIBE = 10
MQTT_PINGREQ = 12
MQTT_DISCONNECT = 14

MQTT_TYPE_NAMES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH",
    4: "PUBACK", 8: "SUBSCRIBE", 10: "UNSUBSCRIBE",
    12: "PINGREQ", 14: "DISCONNECT",
}

# Dangerous MQTT topics patterns
_DANGEROUS_TOPICS = [
    "$SYS/#",               # System topics (info leak)
    "#",                    # Subscribe to ALL topics
    "+/+/+/+/+/+",         # Deep wildcard subscription
    "$aws/things/+/shadow", # AWS IoT shadow access
]


# ═══════════════════════════════════════════════════════════════════════════
# MQTT Parser (Lightweight)
# ═══════════════════════════════════════════════════════════════════════════

class MQTTPacketInfo:
    """Parsed MQTT packet header info."""

    def __init__(self):
        self.packet_type: int = 0
        self.packet_type_name: str = ""
        self.remaining_length: int = 0
        self.dup_flag: bool = False
        self.qos: int = 0
        self.retain: bool = False
        self.topic: str = ""
        self.payload: bytes = b""
        self.client_id: str = ""
        self.username: str = ""
        self.has_password: bool = False
        self.has_username: bool = False
        self.valid: bool = False

    @classmethod
    def parse(cls, data: bytes) -> Optional["MQTTPacketInfo"]:
        """Parse MQTT fixed header and partial variable header."""
        info = cls()
        try:
            if len(data) < 2:
                return None

            # Fixed header: byte 1
            byte1 = data[0]
            info.packet_type = (byte1 >> 4) & 0x0F
            info.packet_type_name = MQTT_TYPE_NAMES.get(
                info.packet_type, f"unknown({info.packet_type})"
            )
            info.dup_flag = bool(byte1 & 0x08)
            info.qos = (byte1 >> 1) & 0x03
            info.retain = bool(byte1 & 0x01)

            # Validate packet type
            if info.packet_type not in MQTT_TYPE_NAMES:
                return None

            # Remaining length (variable-length encoding)
            multiplier = 1
            remaining_length = 0
            pos = 1
            while pos < len(data) and pos < 5:
                encoded_byte = data[pos]
                remaining_length += (encoded_byte & 0x7F) * multiplier
                multiplier *= 128
                pos += 1
                if (encoded_byte & 0x80) == 0:
                    break

            info.remaining_length = remaining_length
            var_start = pos

            # Parse CONNECT packet
            if info.packet_type == MQTT_CONNECT:
                info._parse_connect(data, var_start)

            # Parse PUBLISH packet
            elif info.packet_type == MQTT_PUBLISH:
                info._parse_publish(data, var_start)

            # Parse SUBSCRIBE packet
            elif info.packet_type == MQTT_SUBSCRIBE:
                info._parse_subscribe(data, var_start)

            info.valid = True
            return info

        except (struct.error, IndexError, ValueError):
            return None

    def _parse_connect(self, data: bytes, pos: int) -> None:
        """Parse MQTT CONNECT variable header."""
        try:
            # Protocol Name Length
            if pos + 2 > len(data):
                return
            proto_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2 + proto_len

            # Protocol Level
            if pos >= len(data):
                return
            pos += 1  # protocol level byte

            # Connect Flags
            if pos >= len(data):
                return
            connect_flags = data[pos]
            pos += 1

            self.has_username = bool(connect_flags & 0x80)
            self.has_password = bool(connect_flags & 0x40)

            # Keep Alive
            pos += 2  # skip keep alive

            # Client ID
            if pos + 2 > len(data):
                return
            client_id_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            if pos + client_id_len <= len(data):
                self.client_id = data[pos:pos + client_id_len].decode(
                    errors="ignore"
                )
        except (struct.error, IndexError):
            pass

    def _parse_publish(self, data: bytes, pos: int) -> None:
        """Parse MQTT PUBLISH topic and payload."""
        try:
            if pos + 2 > len(data):
                return
            topic_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            if pos + topic_len <= len(data):
                self.topic = data[pos:pos + topic_len].decode(errors="ignore")
                pos += topic_len

            # Skip packet identifier if QoS > 0
            if self.qos > 0:
                pos += 2

            # Rest is payload
            if pos < len(data):
                self.payload = data[pos:]
        except (struct.error, IndexError):
            pass

    def _parse_subscribe(self, data: bytes, pos: int) -> None:
        """Parse MQTT SUBSCRIBE topic filters."""
        try:
            # Packet identifier
            pos += 2
            # First topic filter
            if pos + 2 > len(data):
                return
            topic_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            if pos + topic_len <= len(data):
                self.topic = data[pos:pos + topic_len].decode(errors="ignore")
        except (struct.error, IndexError):
            pass


# ═══════════════════════════════════════════════════════════════════════════
# MQTT Connection Tracker
# ═══════════════════════════════════════════════════════════════════════════

class MQTTConnectionTracker:
    """Track MQTT connections for abuse detection."""

    def __init__(self, max_entries: int = 2000):
        self._max_entries = max_entries
        # src_ip → {"connect_count": N, "publish_count": N, ...}
        self._clients: dict[str, dict] = {}

    def record(self, src_ip: str, packet_type: int) -> dict:
        """Record an MQTT packet. Returns metrics."""
        if src_ip not in self._clients:
            if len(self._clients) >= self._max_entries:
                oldest = min(
                    self._clients,
                    key=lambda k: self._clients[k].get("last_seen", 0),
                )
                del self._clients[oldest]

            self._clients[src_ip] = {
                "connect_count": 0,
                "publish_count": 0,
                "subscribe_count": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
            }

        c = self._clients[src_ip]
        c["last_seen"] = time.time()

        if packet_type == MQTT_CONNECT:
            c["connect_count"] = c.get("connect_count", 0) + 1
        elif packet_type == MQTT_PUBLISH:
            c["publish_count"] = c.get("publish_count", 0) + 1
        elif packet_type == MQTT_SUBSCRIBE:
            c["subscribe_count"] = c.get("subscribe_count", 0) + 1

        return c


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_mqtt_tracker = MQTTConnectionTracker()

# Blocked MQTT topics
_blocked_topics: set[str] = set()


def add_blocked_mqtt_topic(topic: str) -> None:
    """Add an MQTT topic pattern to block list."""
    _blocked_topics.add(topic)


# ═══════════════════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════════════════

def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ═══════════════════════════════════════════════════════════════════════════
# Layer 7 MQTT Inspector
# ═══════════════════════════════════════════════════════════════════════════

async def inspect_mqtt(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 7 MQTT inspection: auth checking, topic injection,
    payload anomalies, QoS abuse.
    """
    # MQTT standard ports: 1883 (unencrypted), 8883 (TLS)
    if packet.protocol not in ("tcp",):
        return None
    if packet.dst_port not in (1883, 8883):
        return None
    if not packet.has_payload or not packet.raw_packet:
        return None

    try:
        raw = packet.raw_packet
        if not raw.haslayer(Raw):
            return None
        payload = bytes(raw[Raw].load)
    except Exception:
        return None

    mqtt = MQTTPacketInfo.parse(payload)
    if not mqtt or not mqtt.valid:
        return None

    src_ip = packet.src_ip
    _mqtt_tracker.record(src_ip, mqtt.packet_type)

    # ── Unencrypted MQTT ──
    if packet.dst_port == 1883:
        # Flag but don't block — some IoT needs unencrypted
        pass  # Could add a policy-configurable alert here

    # ── CONNECT without authentication ──
    if mqtt.packet_type == MQTT_CONNECT:
        if not mqtt.has_username and not mqtt.has_password:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="mqtt",
                confidence=0.7,
                threat_type="mqtt_no_auth",
                details={
                    "description": (
                        f"MQTT CONNECT without authentication "
                        f"from {src_ip}"
                    ),
                    "src_ip": src_ip,
                    "client_id": mqtt.client_id[:100],
                    "port": packet.dst_port,
                },
            )

        # Rapid reconnection (potential brute force)
        metrics = _mqtt_tracker._clients.get(src_ip, {})
        connect_count = metrics.get("connect_count", 0)
        if connect_count > 10:
            duration = time.time() - metrics.get("first_seen", time.time())
            if duration < 60:  # 10+ connects in under 60s
                return InspectionResult(
                    verdict=InspectionVerdict.MALICIOUS,
                    protocol="mqtt",
                    confidence=0.8,
                    threat_type="mqtt_brute_force",
                    details={
                        "description": (
                            f"MQTT brute force: {connect_count} "
                            f"CONNECT in {duration:.0f}s from {src_ip}"
                        ),
                        "src_ip": src_ip,
                        "connect_count": connect_count,
                        "duration": round(duration, 1),
                    },
                )

    # ── PUBLISH inspection ──
    if mqtt.packet_type == MQTT_PUBLISH:

        # Topic injection / system topic access
        topic_lower = mqtt.topic.lower() if mqtt.topic else ""

        # Block $SYS topics (system info disclosure)
        if topic_lower.startswith("$sys"):
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="mqtt",
                confidence=0.8,
                threat_type="mqtt_sys_access",
                details={
                    "description": (
                        f"MQTT $SYS topic access from {src_ip}: "
                        f"{mqtt.topic}"
                    ),
                    "src_ip": src_ip,
                    "topic": mqtt.topic[:200],
                },
            )

        # Check blocked topics
        for blocked in _blocked_topics:
            if blocked in mqtt.topic:
                return InspectionResult(
                    verdict=InspectionVerdict.BLOCKED,
                    protocol="mqtt",
                    confidence=1.0,
                    threat_type="blocked_mqtt_topic",
                    details={
                        "description": f"Blocked MQTT topic: {mqtt.topic}",
                        "src_ip": src_ip,
                        "topic": mqtt.topic[:200],
                    },
                )

        # Oversized payload
        if len(mqtt.payload) > 262144:  # 256KB
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="mqtt",
                confidence=0.7,
                threat_type="mqtt_oversized",
                details={
                    "description": (
                        f"Oversized MQTT PUBLISH: {len(mqtt.payload)} bytes "
                        f"from {src_ip}"
                    ),
                    "src_ip": src_ip,
                    "payload_size": len(mqtt.payload),
                    "topic": mqtt.topic[:200],
                },
            )

        # High-entropy payload (potential encrypted C2 data)
        if len(mqtt.payload) > 100:
            ent = _entropy(mqtt.payload[:1024])
            if ent > 7.5:  # Near-random data
                return InspectionResult(
                    verdict=InspectionVerdict.SUSPICIOUS,
                    protocol="mqtt",
                    confidence=0.65,
                    threat_type="mqtt_encrypted_payload",
                    details={
                        "description": (
                            f"High-entropy MQTT payload ({ent:.2f}) "
                            f"on topic {mqtt.topic}"
                        ),
                        "src_ip": src_ip,
                        "entropy": round(ent, 2),
                        "topic": mqtt.topic[:200],
                        "payload_size": len(mqtt.payload),
                    },
                )

    # ── SUBSCRIBE inspection ──
    if mqtt.packet_type == MQTT_SUBSCRIBE:
        topic = mqtt.topic
        if topic:
            # Wildcard subscribe to all topics
            if topic == "#":
                return InspectionResult(
                    verdict=InspectionVerdict.SUSPICIOUS,
                    protocol="mqtt",
                    confidence=0.8,
                    threat_type="mqtt_wildcard_sub",
                    details={
                        "description": (
                            f"MQTT subscribe to ALL topics (#) "
                            f"from {src_ip}"
                        ),
                        "src_ip": src_ip,
                        "topic": topic,
                    },
                )

            # Deep wildcard subscriptions
            wildcard_depth = topic.count("/")
            if wildcard_depth > 5 and ("+" in topic or "#" in topic):
                return InspectionResult(
                    verdict=InspectionVerdict.SUSPICIOUS,
                    protocol="mqtt",
                    confidence=0.6,
                    threat_type="mqtt_deep_wildcard",
                    details={
                        "description": (
                            f"Deep wildcard subscription ({wildcard_depth} levels) "
                            f"from {src_ip}"
                        ),
                        "src_ip": src_ip,
                        "topic": topic[:200],
                        "depth": wildcard_depth,
                    },
                )

    # ── QoS Abuse ──
    if mqtt.qos > 2:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="mqtt",
            confidence=0.9,
            threat_type="mqtt_invalid_qos",
            details={
                "description": f"Invalid MQTT QoS level: {mqtt.qos}",
                "src_ip": src_ip,
                "qos": mqtt.qos,
            },
        )

    return None


# ═══════════════════════════════════════════════════════════════════════════
# CoAP Inspector (simple version — UDP-based IoT protocol)
# ═══════════════════════════════════════════════════════════════════════════

async def inspect_coap(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Basic CoAP (Constrained Application Protocol) inspection.
    CoAP runs on UDP port 5683/5684.
    """
    if packet.protocol != "udp":
        return None
    if packet.dst_port not in (5683, 5684):
        return None
    if not packet.has_payload or not packet.raw_packet:
        return None

    try:
        raw = packet.raw_packet
        if not raw.haslayer(Raw):
            return None
        payload = bytes(raw[Raw].load)
    except Exception:
        return None

    if len(payload) < 4:
        return None

    # CoAP header parsing
    byte0 = payload[0]
    coap_version = (byte0 >> 6) & 0x03
    coap_type = (byte0 >> 4) & 0x03
    token_length = byte0 & 0x0F

    # Version must be 1
    if coap_version != 1:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="coap",
            confidence=0.7,
            threat_type="coap_anomaly",
            details={
                "description": (
                    f"Invalid CoAP version {coap_version} from {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
            },
        )

    # Oversized token (max 8 bytes per spec)
    if token_length > 8:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="coap",
            confidence=0.8,
            threat_type="coap_anomaly",
            details={
                "description": (
                    f"Oversized CoAP token ({token_length} bytes) "
                    f"from {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
                "token_length": token_length,
            },
        )

    # CoAP amplification (CON type with large payload)
    if coap_type == 0 and len(payload) > 1024:  # Confirmable + large
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="coap",
            confidence=0.6,
            threat_type="coap_amplification",
            details={
                "description": (
                    f"Large CoAP confirmable request "
                    f"({len(payload)} bytes) from {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
                "payload_size": len(payload),
            },
        )

    return None
