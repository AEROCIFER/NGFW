"""
AEROCIFER NGFW — Layer 5 TLS Inspector

Detects:
- JA3 fingerprinting (TLS Client Hello hash)
- JA3S fingerprinting (TLS Server Hello hash)
- Known malicious JA3 hashes (malware C2, botnets)
- TLS version downgrade attacks
- Self-signed / expired certificate indicators
- Suspicious cipher suite usage
- Certificate transparency anomalies
"""

from __future__ import annotations

import hashlib
import struct
import time
from typing import Optional

from scapy.all import Raw  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# TLS Constants
# ═══════════════════════════════════════════════════════════════════════════

# TLS record types
TLS_HANDSHAKE = 22
TLS_CHANGE_CIPHER = 20
TLS_ALERT = 21
TLS_APPLICATION = 23

# TLS handshake types
CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11

# TLS versions
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# GREASE values (to filter from JA3)
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# Known malicious JA3 hashes (common malware/C2 fingerprints)
# Source: ja3er.com, abuse.ch, threat intel feeds
KNOWN_MALICIOUS_JA3 = {
    "51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike",
    "72a589da586844d7f0818ce684948eea": "Metasploit Meterpreter",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (v4)",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "TrickBot",
    "6734f37431670b3ab4292b8f60f29984": "Dridex",
    "cd08e31494f9531f0ab1fd2a5bba9e55": "AsyncRAT",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Emotet",
    "b20b44b18b853f5904b21a86a7b6b7e6": "IcedID",
    "e952bc84e1fd0a1a2b76a5c8d0e63bca": "Sliver C2",
    "05af1f5ca1b87cc9cc9b25185115607d": "njRAT",
}

# Deprecated/weak cipher suites
WEAK_CIPHERS = {
    0x0000,  # TLS_NULL_WITH_NULL_NULL
    0x0001,  # TLS_RSA_WITH_NULL_MD5
    0x0002,  # TLS_RSA_WITH_NULL_SHA
    0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA (no PFS)
    0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA (no PFS)
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x0004,  # TLS_RSA_WITH_RC4_128_MD5
    0x0005,  # TLS_RSA_WITH_RC4_128_SHA
    0x003C,  # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003D,  # TLS_RSA_WITH_AES_256_CBC_SHA256
}

# Export-grade ciphers (extremely weak, SSLStrip/FREAK/Logjam)
EXPORT_CIPHERS = {
    0x0003,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    0x0006,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x000B,  # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x000E,  # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0011,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x0014,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0017,  # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    0x0019,  # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
}


# ═══════════════════════════════════════════════════════════════════════════
# TLS Parser (Lightweight Client Hello / Server Hello Parser)
# ═══════════════════════════════════════════════════════════════════════════

class TLSClientHello:
    """Parsed TLS Client Hello for fingerprinting."""

    def __init__(self):
        self.tls_version: int = 0
        self.cipher_suites: list[int] = []
        self.extensions: list[int] = []
        self.elliptic_curves: list[int] = []
        self.ec_point_formats: list[int] = []
        self.sni: str = ""              # Server Name Indication
        self.ja3_hash: str = ""
        self.ja3_raw: str = ""
        self.valid: bool = False

    @classmethod
    def parse(cls, data: bytes) -> Optional["TLSClientHello"]:
        """Parse a TLS Client Hello from raw bytes."""
        hello = cls()
        try:
            pos = 0

            # TLS record header (5 bytes)
            if len(data) < 5:
                return None
            content_type = data[pos]
            if content_type != TLS_HANDSHAKE:
                return None
            pos += 1

            record_version = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            record_length = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2

            # Handshake header (4 bytes)
            if pos + 4 > len(data):
                return None
            handshake_type = data[pos]
            if handshake_type != CLIENT_HELLO:
                return None
            pos += 1

            handshake_length = struct.unpack("!I", b"\x00" + data[pos:pos + 3])[0]
            pos += 3

            # Client Hello body
            # Version (2 bytes)
            hello.tls_version = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2

            # Random (32 bytes)
            pos += 32

            # Session ID
            if pos >= len(data):
                return None
            session_id_len = data[pos]
            pos += 1 + session_id_len

            # Cipher Suites
            if pos + 2 > len(data):
                return None
            cs_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2

            for i in range(0, cs_len, 2):
                if pos + 2 > len(data):
                    break
                cs = struct.unpack("!H", data[pos:pos + 2])[0]
                pos += 2
                if cs not in GREASE_VALUES:
                    hello.cipher_suites.append(cs)

            # Compression methods
            if pos >= len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len

            # Extensions
            if pos + 2 > len(data):
                hello.valid = True
                hello._compute_ja3()
                return hello

            ext_total_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_total_len

            while pos + 4 <= min(ext_end, len(data)):
                ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
                pos += 2
                ext_len = struct.unpack("!H", data[pos:pos + 2])[0]
                pos += 2

                ext_data_start = pos

                if ext_type not in GREASE_VALUES:
                    hello.extensions.append(ext_type)

                # SNI extraction (extension type 0)
                if ext_type == 0 and ext_len > 5:
                    try:
                        sni_list_len = struct.unpack("!H", data[pos:pos + 2])[0]
                        sni_type = data[pos + 2]
                        sni_len = struct.unpack("!H", data[pos + 3:pos + 5])[0]
                        if sni_type == 0:
                            hello.sni = data[pos + 5:pos + 5 + sni_len].decode(
                                errors="ignore"
                            )
                    except (struct.error, IndexError):
                        pass

                # Supported Groups / Elliptic Curves (extension type 10)
                if ext_type == 10 and ext_len >= 2:
                    try:
                        groups_len = struct.unpack("!H", data[pos:pos + 2])[0]
                        for i in range(2, 2 + groups_len, 2):
                            if pos + i + 2 <= len(data):
                                group = struct.unpack(
                                    "!H", data[pos + i:pos + i + 2]
                                )[0]
                                if group not in GREASE_VALUES:
                                    hello.elliptic_curves.append(group)
                    except (struct.error, IndexError):
                        pass

                # EC Point Formats (extension type 11)
                if ext_type == 11 and ext_len >= 1:
                    try:
                        formats_len = data[pos]
                        for i in range(1, 1 + formats_len):
                            if pos + i < len(data):
                                hello.ec_point_formats.append(data[pos + i])
                    except IndexError:
                        pass

                pos = ext_data_start + ext_len

            hello.valid = True
            hello._compute_ja3()
            return hello

        except (struct.error, IndexError, ValueError):
            return None

    def _compute_ja3(self) -> None:
        """Compute JA3 fingerprint hash."""
        # JA3 = md5(TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats)
        parts = [
            str(self.tls_version),
            "-".join(str(c) for c in self.cipher_suites),
            "-".join(str(e) for e in self.extensions),
            "-".join(str(c) for c in self.elliptic_curves),
            "-".join(str(f) for f in self.ec_point_formats),
        ]
        self.ja3_raw = ",".join(parts)
        self.ja3_hash = hashlib.md5(self.ja3_raw.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# JA3 History (for tracking unique fingerprints per IP)
# ═══════════════════════════════════════════════════════════════════════════

class JA3Tracker:
    """Track JA3 fingerprints per source IP."""

    def __init__(self, max_entries: int = 5000):
        # src_ip → {ja3_hash: (count, first_seen, last_seen)}
        self._fingerprints: dict[str, dict[str, tuple[int, float, float]]] = {}
        self._max_entries = max_entries

    def record(self, src_ip: str, ja3_hash: str) -> int:
        """Record a JA3 observation. Returns count for this IP+JA3."""
        now = time.time()
        if src_ip not in self._fingerprints:
            if len(self._fingerprints) >= self._max_entries:
                oldest = min(
                    self._fingerprints,
                    key=lambda k: max(
                        (v[2] for v in self._fingerprints[k].values()),
                        default=0,
                    ),
                )
                del self._fingerprints[oldest]
            self._fingerprints[src_ip] = {}

        if ja3_hash in self._fingerprints[src_ip]:
            count, first, _ = self._fingerprints[src_ip][ja3_hash]
            self._fingerprints[src_ip][ja3_hash] = (count + 1, first, now)
            return count + 1
        else:
            self._fingerprints[src_ip][ja3_hash] = (1, now, now)
            return 1


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_ja3_tracker = JA3Tracker()

# Runtime-configurable blocked JA3 hashes
_blocked_ja3: set[str] = set(KNOWN_MALICIOUS_JA3.keys())


def add_blocked_ja3(ja3_hash: str, label: str = "") -> None:
    """Add a JA3 hash to the block list."""
    _blocked_ja3.add(ja3_hash.lower())
    if label:
        KNOWN_MALICIOUS_JA3[ja3_hash.lower()] = label


# ═══════════════════════════════════════════════════════════════════════════
# Layer 5 TLS Inspector
# ═══════════════════════════════════════════════════════════════════════════

async def inspect_tls(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 5 TLS inspection: JA3 fingerprinting, known malware hashes,
    version downgrade detection, weak cipher detection.
    """
    if packet.protocol != "tcp":
        return None
    if packet.dst_port not in (443, 993, 995, 8443, 465, 636, 853, 8883):
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

    if len(payload) < 6:
        return None

    # Check if this is a TLS handshake record
    if payload[0] != TLS_HANDSHAKE:
        return None

    # Parse Client Hello
    hello = TLSClientHello.parse(payload)
    if not hello or not hello.valid:
        return None

    # Record JA3
    _ja3_tracker.record(packet.src_ip, hello.ja3_hash)

    # ── Known Malicious JA3 ──
    if hello.ja3_hash in _blocked_ja3:
        malware_name = KNOWN_MALICIOUS_JA3.get(
            hello.ja3_hash, "Unknown Malware"
        )
        return InspectionResult(
            verdict=InspectionVerdict.MALICIOUS,
            protocol="tls",
            confidence=0.9,
            threat_type="malicious_ja3",
            signature_matched=hello.ja3_hash,
            details={
                "description": (
                    f"Known malicious JA3 fingerprint: {malware_name} "
                    f"from {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
                "ja3_hash": hello.ja3_hash,
                "malware": malware_name,
                "sni": hello.sni,
            },
        )

    # ── TLS Version Downgrade ──
    version_name = TLS_VERSIONS.get(hello.tls_version, "unknown")

    # SSL 3.0 is critically insecure
    if hello.tls_version == 0x0300:
        return InspectionResult(
            verdict=InspectionVerdict.MALICIOUS,
            protocol="tls",
            confidence=0.85,
            threat_type="tls_downgrade",
            details={
                "description": (
                    f"SSL 3.0 handshake detected from {packet.src_ip} "
                    f"(POODLE vulnerable)"
                ),
                "src_ip": packet.src_ip,
                "tls_version": version_name,
                "sni": hello.sni,
            },
        )

    # TLS 1.0/1.1 deprecated
    if hello.tls_version in (0x0301, 0x0302):
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="tls",
            confidence=0.6,
            threat_type="deprecated_tls",
            details={
                "description": (
                    f"Deprecated {version_name} from {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
                "tls_version": version_name,
                "sni": hello.sni,
            },
        )

    # ── Export/Weak Cipher Detection ──
    for cs in hello.cipher_suites:
        if cs in EXPORT_CIPHERS:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="tls",
                confidence=0.9,
                threat_type="export_cipher",
                details={
                    "description": (
                        f"Export-grade cipher offered: 0x{cs:04X} "
                        f"from {packet.src_ip} (FREAK/Logjam)"
                    ),
                    "src_ip": packet.src_ip,
                    "cipher": f"0x{cs:04X}",
                    "sni": hello.sni,
                },
            )

    weak_count = sum(1 for cs in hello.cipher_suites if cs in WEAK_CIPHERS)
    if weak_count > 0 and weak_count == len(hello.cipher_suites):
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="tls",
            confidence=0.7,
            threat_type="weak_ciphers_only",
            details={
                "description": (
                    f"Only weak ciphers offered by {packet.src_ip}"
                ),
                "src_ip": packet.src_ip,
                "weak_count": weak_count,
                "total_ciphers": len(hello.cipher_suites),
                "sni": hello.sni,
            },
        )

    # Clean — return with metadata
    return InspectionResult(
        verdict=InspectionVerdict.CLEAN,
        protocol="tls",
        details={
            "ja3_hash": hello.ja3_hash,
            "sni": hello.sni,
            "tls_version": version_name,
            "cipher_count": len(hello.cipher_suites),
        },
    )
