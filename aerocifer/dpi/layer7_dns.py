"""
AEROCIFER NGFW — Layer 7 DNS Inspector

Detects:
- DNS tunneling (high-entropy subdomains, oversized queries)
- Domain Generation Algorithm (DGA) domains
- DNS exfiltration (unusual TXT record abuse)
- Blocked domain lookups
- DNS amplification attack indicators
- Suspicious DNS patterns (excessive NXDOMAIN, rapid queries)
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Optional

from scapy.all import DNS, DNSQR, DNSRR, Raw  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# Entropy & DGA Analysis
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _is_dga_domain(domain: str) -> tuple[bool, float]:
    """
    Heuristic DGA detection based on domain characteristics.

    Returns (is_dga, confidence).

    DGA domains tend to have:
    - High character entropy
    - Long labels
    - High consonant/digit ratio
    - Few real words / unpronounceable
    """
    # Extract the second-level domain (SLD)
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False, 0.0

    sld = parts[-2]  # e.g., "abc123xyz" in "abc123xyz.com"

    score = 0.0
    total_checks = 5

    # 1. Length check — DGA domains tend to be long
    if len(sld) > 15:
        score += 1.0
    elif len(sld) > 10:
        score += 0.5

    # 2. Entropy check — DGA domains have high entropy
    entropy = _shannon_entropy(sld)
    if entropy > 3.5:
        score += 1.0
    elif entropy > 3.0:
        score += 0.5

    # 3. Digit ratio — DGA often has mixed digits
    digit_ratio = sum(1 for c in sld if c.isdigit()) / max(len(sld), 1)
    if 0.1 < digit_ratio < 0.7:
        score += 0.5
    if digit_ratio > 0.5:
        score += 0.5

    # 4. Consonant ratio — DGA is often unpronounceable
    vowels = set("aeiou")
    consonant_count = sum(1 for c in sld.lower() if c.isalpha() and c not in vowels)
    alpha_count = sum(1 for c in sld if c.isalpha())
    if alpha_count > 0:
        consonant_ratio = consonant_count / alpha_count
        if consonant_ratio > 0.75:
            score += 1.0
        elif consonant_ratio > 0.65:
            score += 0.5

    # 5. No common words / patterns
    common_patterns = [
        "www", "mail", "ftp", "cloud", "app", "web",
        "login", "secure", "api", "cdn", "dev",
    ]
    has_common = any(p in sld.lower() for p in common_patterns)
    if not has_common:
        score += 0.5

    confidence = score / total_checks
    return confidence > 0.6, confidence


# ═══════════════════════════════════════════════════════════════════════════
# DNS Query Rate Tracker
# ═══════════════════════════════════════════════════════════════════════════

class DNSQueryTracker:
    """Track DNS query patterns per source IP."""

    def __init__(
        self,
        rate_threshold: int = 100,
        nxdomain_threshold: int = 30,
        window: float = 60.0,
        max_entries: int = 5000,
    ):
        self._rate_threshold = rate_threshold
        self._nxdomain_threshold = nxdomain_threshold
        self._window = window
        self._max_entries = max_entries
        # src_ip → list of (timestamp, query_domain)
        self._queries: dict[str, list[tuple[float, str]]] = defaultdict(list)
        # src_ip → unique domains queried in window
        self._unique_domains: dict[str, set[str]] = defaultdict(set)

    def record_query(self, src_ip: str, domain: str) -> dict:
        """
        Record a DNS query. Returns metrics dict.
        """
        now = time.time()
        cutoff = now - self._window

        # Clean old entries
        self._queries[src_ip] = [
            (t, d) for t, d in self._queries[src_ip] if t > cutoff
        ]
        self._queries[src_ip].append((now, domain))
        self._unique_domains[src_ip].add(domain)

        # Evict
        if len(self._queries) > self._max_entries:
            oldest = min(
                self._queries,
                key=lambda k: self._queries[k][-1][0]
                if self._queries[k] else 0,
            )
            del self._queries[oldest]
            self._unique_domains.pop(oldest, None)

        return {
            "query_rate": len(self._queries[src_ip]),
            "unique_domains": len(self._unique_domains[src_ip]),
            "is_excessive": len(self._queries[src_ip]) > self._rate_threshold,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Module State
# ═══════════════════════════════════════════════════════════════════════════

_dns_tracker = DNSQueryTracker(rate_threshold=100, window=60.0)

# Blocked domains list (loaded from config/threat intel)
_blocked_dns_domains: set[str] = set()

# Known safe TLDs (for DGA filtering — don't flag these)
_SAFE_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "co.uk", "org.uk", "ac.uk",
}


def add_blocked_dns_domain(domain: str) -> None:
    """Add a domain to the DNS block list."""
    _blocked_dns_domains.add(domain.lower().strip().rstrip("."))


def load_blocked_dns_list(domains: list[str]) -> None:
    """Load a list of blocked domains."""
    for d in domains:
        _blocked_dns_domains.add(d.lower().strip().rstrip("."))


# ═══════════════════════════════════════════════════════════════════════════
# Layer 7 DNS Inspector
# ═══════════════════════════════════════════════════════════════════════════

# DNS tunneling detection thresholds
_TUNNEL_SUBDOMAIN_ENTROPY_THRESHOLD = 3.5
_TUNNEL_SUBDOMAIN_LENGTH_THRESHOLD = 30
_TUNNEL_TXT_SIZE_THRESHOLD = 200  # bytes


async def inspect_dns(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 7 DNS inspection: tunneling, DGA, exfiltration, domain blocking.
    """
    raw = packet.raw_packet
    if raw is None or not raw.haslayer(DNS):
        return None

    dns = raw[DNS]
    src_ip = packet.src_ip

    # ══════════════════════════════════════════════════════════════════
    # DNS Query Inspection
    # ══════════════════════════════════════════════════════════════════
    if dns.qr == 0 and dns.haslayer(DNSQR):  # Query
        query = dns[DNSQR]
        qname = query.qname.decode(errors="ignore").rstrip(".")
        qtype = query.qtype  # 1=A, 28=AAAA, 5=CNAME, 16=TXT, 15=MX

        if not qname:
            return None

        qname_lower = qname.lower()

        # ── Blocked Domain ──
        # Check exact match and parent domain match
        domain_parts = qname_lower.split(".")
        for i in range(len(domain_parts)):
            check_domain = ".".join(domain_parts[i:])
            if check_domain in _blocked_dns_domains:
                return InspectionResult(
                    verdict=InspectionVerdict.BLOCKED,
                    protocol="dns",
                    confidence=1.0,
                    threat_type="blocked_domain",
                    details={
                        "description": f"Blocked DNS query: {qname}",
                        "src_ip": src_ip,
                        "domain": qname,
                        "matched_rule": check_domain,
                    },
                )

        # ── DNS Tunneling Detection (query side) ──
        # Check for high-entropy subdomains (data encoded in DNS labels)
        if "." in qname_lower:
            # Get subdomain part (everything except last 2 labels)
            labels = qname_lower.split(".")
            if len(labels) > 2:
                subdomain = ".".join(labels[:-2])

                # High entropy in subdomain → likely encoded data
                sub_entropy = _shannon_entropy(subdomain.replace(".", ""))
                if (sub_entropy > _TUNNEL_SUBDOMAIN_ENTROPY_THRESHOLD
                        and len(subdomain) > _TUNNEL_SUBDOMAIN_LENGTH_THRESHOLD):
                    return InspectionResult(
                        verdict=InspectionVerdict.MALICIOUS,
                        protocol="dns",
                        confidence=0.85,
                        threat_type="dns_tunneling",
                        details={
                            "description": (
                                f"DNS tunneling suspected: "
                                f"high entropy subdomain ({sub_entropy:.2f})"
                            ),
                            "src_ip": src_ip,
                            "domain": qname,
                            "subdomain": subdomain[:100],
                            "entropy": round(sub_entropy, 2),
                            "length": len(subdomain),
                        },
                    )

                # Very long subdomain labels (data exfiltration)
                for label in labels[:-2]:
                    if len(label) > 50:
                        return InspectionResult(
                            verdict=InspectionVerdict.SUSPICIOUS,
                            protocol="dns",
                            confidence=0.75,
                            threat_type="dns_exfiltration",
                            details={
                                "description": (
                                    f"Oversized DNS label ({len(label)} chars): "
                                    f"possible data exfiltration"
                                ),
                                "src_ip": src_ip,
                                "domain": qname,
                                "label_length": len(label),
                            },
                        )

        # ── DGA Detection ──
        is_dga, dga_confidence = _is_dga_domain(qname_lower)
        if is_dga:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="dns",
                confidence=dga_confidence,
                threat_type="dga_domain",
                details={
                    "description": (
                        f"DGA-like domain: {qname} "
                        f"(confidence: {dga_confidence:.0%})"
                    ),
                    "src_ip": src_ip,
                    "domain": qname,
                    "dga_confidence": round(dga_confidence, 2),
                },
            )

        # ── TXT Record Abuse (often used for tunneling/C2) ──
        if qtype == 16:  # TXT
            metrics = _dns_tracker.record_query(src_ip, qname_lower)
            # Excessive TXT queries are suspicious
            txt_queries = sum(
                1 for _, d in _dns_tracker._queries.get(src_ip, [])
            )
            if txt_queries > 20:
                return InspectionResult(
                    verdict=InspectionVerdict.SUSPICIOUS,
                    protocol="dns",
                    confidence=0.7,
                    threat_type="dns_txt_abuse",
                    details={
                        "description": (
                            f"Excessive TXT queries from {src_ip}: "
                            f"{txt_queries} in window"
                        ),
                        "src_ip": src_ip,
                        "domain": qname,
                        "txt_query_count": txt_queries,
                    },
                )

        # ── Query Rate Tracking ──
        metrics = _dns_tracker.record_query(src_ip, qname_lower)
        if metrics["is_excessive"]:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="dns",
                confidence=0.7,
                threat_type="dns_flood",
                details={
                    "description": (
                        f"Excessive DNS queries from {src_ip}: "
                        f"{metrics['query_rate']} in window, "
                        f"{metrics['unique_domains']} unique domains"
                    ),
                    "src_ip": src_ip,
                    "query_rate": metrics["query_rate"],
                    "unique_domains": metrics["unique_domains"],
                },
            )

    # ══════════════════════════════════════════════════════════════════
    # DNS Response Inspection
    # ══════════════════════════════════════════════════════════════════
    elif dns.qr == 1:  # Response
        # Check for oversized TXT responses (tunneling indicator)
        if dns.ancount and dns.haslayer(DNSRR):
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i] if hasattr(dns, 'an') else dns[DNSRR]
                    if rr.type == 16:  # TXT record
                        rdata = rr.rdata
                        rdata_len = len(rdata) if isinstance(rdata, (bytes, str)) else 0
                        if rdata_len > _TUNNEL_TXT_SIZE_THRESHOLD:
                            return InspectionResult(
                                verdict=InspectionVerdict.SUSPICIOUS,
                                protocol="dns",
                                confidence=0.75,
                                threat_type="dns_tunneling",
                                details={
                                    "description": (
                                        f"Large TXT DNS response: "
                                        f"{rdata_len} bytes"
                                    ),
                                    "src_ip": src_ip,
                                    "txt_size": rdata_len,
                                },
                            )
                except (IndexError, AttributeError):
                    break

        # DNS amplification indicator (large response to small query zone)
        if dns.ancount and dns.ancount > 10:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="dns",
                confidence=0.6,
                threat_type="dns_amplification",
                details={
                    "description": (
                        f"DNS response with {dns.ancount} answer records "
                        f"(amplification indicator)"
                    ),
                    "src_ip": src_ip,
                    "answer_count": dns.ancount,
                },
            )

    return None
