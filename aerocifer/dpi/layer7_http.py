"""
AEROCIFER NGFW — Layer 7 HTTP Inspector

Detects:
- SQL injection attempts
- Cross-Site Scripting (XSS)
- Path traversal / directory traversal
- Command injection
- HTTP header anomalies (oversized, missing host)
- Suspicious User-Agents (known attack tools)
- HTTP request smuggling indicators
- URL-based blocking (domain/path filtering)
"""

from __future__ import annotations

import re
from typing import Optional

from scapy.all import Raw  # type: ignore[import-untyped]

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# Attack Signature Patterns (compiled regex for performance)
# ═══════════════════════════════════════════════════════════════════════════

# SQL Injection patterns
_SQL_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*\b(FROM|INTO|SET|TABLE|DATABASE)\b)",
        r"(\bUNION\b\s+(ALL\s+)?SELECT\b)",
        r"(\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)",
        r"(--\s*$|;\s*--)",
        r"(\b(WAITFOR|BENCHMARK|SLEEP)\b)",
        r"([\'\"];\s*(DROP|DELETE|INSERT|UPDATE)\b)",
        r"(\bHAVING\b\s+\d+\s*=\s*\d+)",
        r"(\bORDER\s+BY\s+\d+)",
        r"(\/\*.*\*\/)",  # SQL comments
    ]
]

# XSS patterns
_XSS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(<\s*script[^>]*>)",
        r"(javascript\s*:)",
        r"(on(load|error|click|mouseover|submit|focus|blur)\s*=)",
        r"(<\s*img[^>]+\bonerror\b)",
        r"(<\s*iframe)",
        r"(<\s*object)",
        r"(<\s*embed)",
        r"(<\s*svg[^>]*\bonload\b)",
        r"(document\.(cookie|location|write))",
        r"(eval\s*\()",
        r"(alert\s*\()",
    ]
]

# Path traversal patterns
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(\.\.[\\/])",                   # ../  or ..\
        r"(\.\.%2[fF])",                  # URL-encoded ../
        r"(%2[eE]%2[eE][\\/])",          # Double URL-encoded
        r"(\.\.%5[cC])",                  # URL-encoded ..\
        r"(/etc/(passwd|shadow|hosts))",
        r"(/proc/self/)",
        r"(C:\\Windows\\)",
        r"(boot\.ini)",
    ]
]

# Command injection patterns
_CMD_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"([;&|]\s*(cat|ls|dir|pwd|whoami|id|uname|netstat|wget|curl)\b)",
        r"(\$\(.*\))",                    # Command substitution
        r"(`[^`]+`)",                      # Backtick execution
        r"(\|\s*(bash|sh|cmd|powershell)\b)",
        r"(;\s*(rm|del|format|mkfs)\b)",
        r"(\bnc\s+-\w*[elp])",           # Netcat reverse shell
    ]
]

# Suspicious User-Agent strings (attack tools)
_SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "wfuzz", "hydra", "medusa", "burpsuite",
    "zaproxy", "acunetix", "nessus", "openvas", "metasploit",
    "havij", "w3af", "skipfish", "arachni", "whatweb",
]

# Blocked file extensions in URLs
_BLOCKED_EXTENSIONS = {
    ".php.bak", ".sql.bak", ".env", ".git", ".svn",
    ".htaccess", ".htpasswd", ".DS_Store", ".config",
    ".ini.bak", ".conf.bak", ".yml.bak",
}


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Parser (lightweight)
# ═══════════════════════════════════════════════════════════════════════════

class HTTPRequest:
    """Parsed HTTP request from raw payload."""

    def __init__(self, payload: str):
        self.method: str = ""
        self.path: str = ""
        self.version: str = ""
        self.host: str = ""
        self.user_agent: str = ""
        self.content_type: str = ""
        self.content_length: int = 0
        self.headers: dict[str, str] = {}
        self.body: str = ""
        self.raw: str = payload

        self._parse(payload)

    def _parse(self, payload: str) -> None:
        """Parse HTTP request from raw text."""
        lines = payload.split("\r\n")
        if not lines:
            return

        # Request line
        request_line = lines[0].split(" ", 2)
        if len(request_line) >= 2:
            self.method = request_line[0].upper()
            self.path = request_line[1]
            if len(request_line) >= 3:
                self.version = request_line[2]

        # Headers
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                self.headers[key] = value

                if key == "host":
                    self.host = value
                elif key == "user-agent":
                    self.user_agent = value
                elif key == "content-type":
                    self.content_type = value
                elif key == "content-length":
                    try:
                        self.content_length = int(value)
                    except ValueError:
                        pass

        # Body
        if body_start > 0 and body_start < len(lines):
            self.body = "\r\n".join(lines[body_start:])

    @property
    def is_valid(self) -> bool:
        return bool(self.method and self.path)

    @property
    def full_url(self) -> str:
        return f"{self.host}{self.path}" if self.host else self.path


# ═══════════════════════════════════════════════════════════════════════════
# Layer 7 HTTP Inspector
# ═══════════════════════════════════════════════════════════════════════════

# Runtime configuration — can be updated via API
_blocked_domains: set[str] = set()
_blocked_paths: set[str] = set()


def add_blocked_domain(domain: str) -> None:
    """Add a domain to the block list."""
    _blocked_domains.add(domain.lower().strip())


def add_blocked_path(path: str) -> None:
    """Add a URL path to the block list."""
    _blocked_paths.add(path.lower().strip())


async def inspect_http(packet: RawPacket) -> Optional[InspectionResult]:
    """
    Layer 7 HTTP inspection: injection attacks, XSS, path traversal,
    suspicious user-agents, URL filtering.
    """
    # Only inspect HTTP traffic (port 80, 8080, or detected HTTP)
    if packet.protocol != "tcp":
        return None
    if packet.dst_port not in (80, 8080, 8000, 3000, 5000):
        return None
    if not packet.has_payload or not packet.raw_packet:
        return None

    try:
        raw = packet.raw_packet
        if not raw.haslayer(Raw):
            return None
        payload = raw[Raw].load.decode(errors="ignore")
    except Exception:
        return None

    # Check if this is actually HTTP
    if not any(payload.startswith(m) for m in
               ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
                "HEAD ", "OPTIONS ", "CONNECT ")):
        return None

    # Parse HTTP request
    http = HTTPRequest(payload)
    if not http.is_valid:
        return None

    # Combined text to scan (URL path + query + body)
    scan_text = f"{http.path} {http.body}"

    # ── SQL Injection ──
    for pattern in _SQL_INJECTION_PATTERNS:
        match = pattern.search(scan_text)
        if match:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="http",
                confidence=0.9,
                threat_type="sql_injection",
                signature_matched=match.group(0)[:100],
                details={
                    "description": (
                        f"SQL injection attempt: "
                        f"{http.method} {http.full_url}"
                    ),
                    "src_ip": packet.src_ip,
                    "method": http.method,
                    "url": http.full_url[:200],
                    "matched": match.group(0)[:100],
                },
            )

    # ── XSS ──
    for pattern in _XSS_PATTERNS:
        match = pattern.search(scan_text)
        if match:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="http",
                confidence=0.85,
                threat_type="xss",
                signature_matched=match.group(0)[:100],
                details={
                    "description": (
                        f"XSS attempt: {http.method} {http.full_url}"
                    ),
                    "src_ip": packet.src_ip,
                    "method": http.method,
                    "url": http.full_url[:200],
                    "matched": match.group(0)[:100],
                },
            )

    # ── Path Traversal ──
    for pattern in _PATH_TRAVERSAL_PATTERNS:
        match = pattern.search(http.path)
        if match:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="http",
                confidence=0.9,
                threat_type="path_traversal",
                signature_matched=match.group(0)[:100],
                details={
                    "description": (
                        f"Path traversal: {http.method} {http.path}"
                    ),
                    "src_ip": packet.src_ip,
                    "path": http.path[:200],
                },
            )

    # ── Command Injection ──
    for pattern in _CMD_INJECTION_PATTERNS:
        match = pattern.search(scan_text)
        if match:
            return InspectionResult(
                verdict=InspectionVerdict.MALICIOUS,
                protocol="http",
                confidence=0.85,
                threat_type="command_injection",
                signature_matched=match.group(0)[:100],
                details={
                    "description": (
                        f"Command injection: {http.method} {http.full_url}"
                    ),
                    "src_ip": packet.src_ip,
                    "matched": match.group(0)[:100],
                },
            )

    # ── Suspicious User-Agent ──
    if http.user_agent:
        ua_lower = http.user_agent.lower()
        for tool in _SUSPICIOUS_USER_AGENTS:
            if tool in ua_lower:
                return InspectionResult(
                    verdict=InspectionVerdict.SUSPICIOUS,
                    protocol="http",
                    confidence=0.8,
                    threat_type="attack_tool",
                    details={
                        "description": (
                            f"Attack tool detected: {tool} "
                            f"from {packet.src_ip}"
                        ),
                        "src_ip": packet.src_ip,
                        "user_agent": http.user_agent[:200],
                        "tool": tool,
                    },
                )

    # ── Domain Blocking ──
    if http.host and http.host.lower() in _blocked_domains:
        return InspectionResult(
            verdict=InspectionVerdict.BLOCKED,
            protocol="http",
            confidence=1.0,
            threat_type="blocked_domain",
            details={
                "description": f"Blocked domain: {http.host}",
                "src_ip": packet.src_ip,
                "host": http.host,
            },
        )

    # ── Path Blocking ──
    path_lower = http.path.lower()
    for blocked_path in _blocked_paths:
        if blocked_path in path_lower:
            return InspectionResult(
                verdict=InspectionVerdict.BLOCKED,
                protocol="http",
                confidence=1.0,
                threat_type="blocked_path",
                details={
                    "description": f"Blocked path: {http.path}",
                    "src_ip": packet.src_ip,
                    "path": http.path[:200],
                },
            )

    # ── Blocked Extensions ──
    for ext in _BLOCKED_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="http",
                confidence=0.7,
                threat_type="sensitive_file_access",
                details={
                    "description": (
                        f"Sensitive file access: {http.path}"
                    ),
                    "src_ip": packet.src_ip,
                    "path": http.path[:200],
                    "extension": ext,
                },
            )

    # ── HTTP Header Anomalies ──

    # Missing Host header (HTTP/1.1 requires it)
    if not http.host and "1.1" in http.version:
        return InspectionResult(
            verdict=InspectionVerdict.SUSPICIOUS,
            protocol="http",
            confidence=0.6,
            threat_type="http_anomaly",
            details={
                "description": "HTTP/1.1 request without Host header",
                "src_ip": packet.src_ip,
                "method": http.method,
                "path": http.path[:200],
            },
        )

    # Oversized headers (potential buffer overflow)
    if len(payload) > 16384:  # 16KB header limit
        header_section = payload.split("\r\n\r\n", 1)[0]
        if len(header_section) > 8192:
            return InspectionResult(
                verdict=InspectionVerdict.SUSPICIOUS,
                protocol="http",
                confidence=0.7,
                threat_type="oversized_headers",
                details={
                    "description": (
                        f"Oversized HTTP headers: {len(header_section)} bytes"
                    ),
                    "src_ip": packet.src_ip,
                    "header_size": len(header_section),
                },
            )

    # Return clean with protocol detected
    return InspectionResult(
        verdict=InspectionVerdict.CLEAN,
        protocol="http",
    )
