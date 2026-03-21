"""
AEROCIFER NGFW — Signature Engine

Rule-based signature matching for known attack patterns.
Loads rules from .rules files (Snort-compatible subset) and
integrates with the DPI pipeline.

Supports:
- Content-based matching (string patterns in payload)
- PCRE regex patterns
- Byte-match patterns
- Multi-pattern matching with priority
- Rule management (enable/disable/reload)
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from aerocifer.utils.logger import get_logger
from aerocifer.core.packet_engine import RawPacket
from aerocifer.core.protocol_inspector import InspectionResult, InspectionVerdict

log = get_logger("dpi")


# ═══════════════════════════════════════════════════════════════════════════
# Signature Rule Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SignatureRule:
    """A single signature detection rule."""
    sid: int                           # Signature ID
    name: str                          # Rule name
    description: str = ""
    severity: str = "medium"           # low, medium, high, critical
    category: str = ""                 # e.g., "malware", "exploit", "policy"
    content_patterns: list[str] = field(default_factory=list)  # String matches
    pcre_patterns: list[re.Pattern] = field(default_factory=list)  # Regex
    protocol: str = "any"              # tcp, udp, icmp, any
    src_port: int = 0
    dst_port: int = 0
    direction: str = "any"             # inbound, outbound, any
    enabled: bool = True
    nocase: bool = True                # Case-insensitive content match
    priority: int = 100


# ═══════════════════════════════════════════════════════════════════════════
# Signature Engine
# ═══════════════════════════════════════════════════════════════════════════

class SignatureEngine:
    """
    Loads and matches traffic against signature rules.

    Usage:
        engine = SignatureEngine()
        engine.load_rules_dir("/path/to/rules/")
        result = await engine.match(raw_packet)
    """

    def __init__(self):
        self._rules: list[SignatureRule] = []
        self._rules_by_sid: dict[int, SignatureRule] = {}
        self._rules_by_port: dict[int, list[SignatureRule]] = {}

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rules_dir(self, rules_dir: str) -> int:
        """
        Load all .rules files from a directory.
        Returns count of rules loaded.
        """
        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            log.warning(f"Signature rules directory not found: {rules_dir}")
            return 0

        total = 0
        for rule_file in sorted(rules_path.glob("*.rules")):
            count = self.load_rules_file(str(rule_file))
            total += count
            log.info(f"Loaded {count} rules from {rule_file.name}")

        log.info(f"Signature engine: {total} total rules loaded")
        return total

    def load_rules_file(self, filepath: str) -> int:
        """Load rules from a single .rules file."""
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    rule = self._parse_rule(line, filepath, line_num)
                    if rule:
                        self._add_rule(rule)
                        count += 1
        except OSError as e:
            log.error(f"Cannot read rules file {filepath}: {e}")
        return count

    def _parse_rule(
        self, line: str, filepath: str, line_num: int
    ) -> Optional[SignatureRule]:
        """
        Parse a rule line. Supports a simplified Snort-like format:

        Format:
            alert <protocol> <src> <srcport> -> <dst> <dstport> (options)

        Options supported:
            msg:"description"; content:"pattern"; pcre:"/regex/i";
            sid:12345; priority:1; classtype:trojan-activity;
        """
        try:
            # Split header and options
            paren_start = line.find("(")
            if paren_start == -1:
                return None

            header = line[:paren_start].strip()
            options_str = line[paren_start + 1:].rstrip(")")

            # Parse header
            header_parts = header.split()
            if len(header_parts) < 7:
                return None

            action = header_parts[0]  # alert, drop, pass, etc.
            protocol = header_parts[1].lower()

            # Parse options
            rule = SignatureRule(
                sid=0,
                name="",
                protocol=protocol,
            )

            # Simple option parser
            options = self._parse_options(options_str)

            for key, value in options:
                if key == "msg":
                    rule.name = value.strip('"')
                    rule.description = rule.name
                elif key == "content":
                    content = value.strip('"')
                    rule.content_patterns.append(content)
                elif key == "pcre":
                    # Parse /pattern/flags format
                    pcre_match = re.match(r'"/(.*)/(\w*)"', value)
                    if pcre_match:
                        pattern = pcre_match.group(1)
                        flags_str = pcre_match.group(2)
                        re_flags = 0
                        if "i" in flags_str:
                            re_flags |= re.IGNORECASE
                        if "s" in flags_str:
                            re_flags |= re.DOTALL
                        try:
                            compiled = re.compile(pattern, re_flags)
                            rule.pcre_patterns.append(compiled)
                        except re.error:
                            pass
                elif key == "sid":
                    rule.sid = int(value)
                elif key == "priority":
                    rule.priority = int(value)
                elif key == "classtype":
                    rule.category = value
                elif key == "nocase":
                    rule.nocase = True

            if rule.sid == 0:
                rule.sid = hash(line) & 0xFFFFFFFF

            if not rule.name:
                rule.name = f"Rule SID {rule.sid}"

            # Map severity from priority
            if rule.priority <= 1:
                rule.severity = "critical"
            elif rule.priority <= 3:
                rule.severity = "high"
            elif rule.priority <= 5:
                rule.severity = "medium"
            else:
                rule.severity = "low"

            return rule

        except (ValueError, IndexError) as e:
            log.debug(
                f"Error parsing rule at {filepath}:{line_num}: {e}"
            )
            return None

    def _parse_options(self, options_str: str) -> list[tuple[str, str]]:
        """Parse semicolon-separated rule options."""
        options: list[tuple[str, str]] = []
        current_key = ""
        current_value = ""
        in_quotes = False
        in_key = True
        escape_next = False

        for ch in options_str:
            if escape_next:
                current_value += ch
                escape_next = False
                continue

            if ch == "\\":
                escape_next = True
                current_value += ch
                continue

            if ch == '"':
                in_quotes = not in_quotes
                current_value += ch
                continue

            if not in_quotes:
                if ch == ":" and in_key:
                    in_key = False
                    continue
                elif ch == ";":
                    key = current_key.strip()
                    val = current_value.strip()
                    if key:
                        options.append((key, val))
                    current_key = ""
                    current_value = ""
                    in_key = True
                    continue

            if in_key:
                current_key += ch
            else:
                current_value += ch

        # Last option (no trailing semicolon)
        key = current_key.strip()
        val = current_value.strip()
        if key:
            options.append((key, val))

        return options

    def _add_rule(self, rule: SignatureRule) -> None:
        """Add a rule to the engine indices."""
        self._rules.append(rule)
        self._rules_by_sid[rule.sid] = rule

        if rule.dst_port:
            self._rules_by_port.setdefault(rule.dst_port, []).append(rule)

    def add_inline_rule(
        self,
        sid: int,
        name: str,
        content_patterns: Optional[list[str]] = None,
        pcre_patterns: Optional[list[str]] = None,
        severity: str = "high",
        protocol: str = "any",
        dst_port: int = 0,
    ) -> None:
        """Add a rule programmatically (not from file)."""
        rule = SignatureRule(
            sid=sid,
            name=name,
            description=name,
            severity=severity,
            protocol=protocol,
            dst_port=dst_port,
            content_patterns=content_patterns or [],
        )

        if pcre_patterns:
            for p in pcre_patterns:
                try:
                    rule.pcre_patterns.append(
                        re.compile(p, re.IGNORECASE)
                    )
                except re.error:
                    pass

        self._add_rule(rule)

    async def match(
        self, packet: RawPacket
    ) -> Optional[InspectionResult]:
        """
        Match a packet against all loaded signature rules.
        Returns InspectionResult if a rule matches, None otherwise.
        """
        if not self._rules:
            return None

        if not packet.has_payload or not packet.raw_packet:
            return None

        try:
            from scapy.all import Raw as ScapyRaw  # type: ignore
            raw = packet.raw_packet
            if not raw.haslayer(ScapyRaw):
                return None
            payload = raw[ScapyRaw].load
            payload_str = payload.decode(errors="ignore")
        except Exception:
            return None

        # Select applicable rules
        candidates = self._select_rules(packet)

        for rule in candidates:
            if not rule.enabled:
                continue
            if self._matches_rule(rule, payload_str, payload):
                severity_to_verdict = {
                    "critical": InspectionVerdict.MALICIOUS,
                    "high": InspectionVerdict.MALICIOUS,
                    "medium": InspectionVerdict.SUSPICIOUS,
                    "low": InspectionVerdict.SUSPICIOUS,
                }
                return InspectionResult(
                    verdict=severity_to_verdict.get(
                        rule.severity, InspectionVerdict.SUSPICIOUS
                    ),
                    protocol=rule.protocol,
                    confidence=0.85,
                    threat_type=rule.category or "signature_match",
                    signature_matched=f"SID:{rule.sid} {rule.name}",
                    details={
                        "description": rule.description,
                        "sid": rule.sid,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category,
                        "src_ip": packet.src_ip,
                    },
                )

        return None

    def _select_rules(self, packet: RawPacket) -> list[SignatureRule]:
        """Select rules that could match this packet."""
        candidates: list[SignatureRule] = []
        seen_sids: set[int] = set()

        # Port-specific rules first
        for port in (packet.dst_port, packet.src_port):
            for rule in self._rules_by_port.get(port, []):
                if rule.sid not in seen_sids:
                    candidates.append(rule)
                    seen_sids.add(rule.sid)

        # Protocol-matched or "any" rules
        for rule in self._rules:
            if rule.sid in seen_sids:
                continue
            if rule.protocol in ("any", packet.protocol):
                if not rule.dst_port:  # Non-port-specific
                    candidates.append(rule)
                    seen_sids.add(rule.sid)

        return candidates

    def _matches_rule(
        self, rule: SignatureRule, payload_str: str, payload_bytes: bytes
    ) -> bool:
        """Check if a payload matches a rule's patterns."""
        # All content patterns must match (AND logic)
        for content in rule.content_patterns:
            if rule.nocase:
                if content.lower() not in payload_str.lower():
                    return False
            else:
                if content not in payload_str:
                    return False

        # PCRE patterns (any match is sufficient if content matched)
        if rule.pcre_patterns:
            pcre_matched = any(
                p.search(payload_str) for p in rule.pcre_patterns
            )
            if not pcre_matched:
                return False

        # Must have at least one pattern
        return bool(rule.content_patterns or rule.pcre_patterns)

    def enable_rule(self, sid: int) -> bool:
        """Enable a rule by SID."""
        rule = self._rules_by_sid.get(sid)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, sid: int) -> bool:
        """Disable a rule by SID."""
        rule = self._rules_by_sid.get(sid)
        if rule:
            rule.enabled = False
            return True
        return False

    def get_stats(self) -> dict:
        """Get signature engine statistics."""
        enabled = sum(1 for r in self._rules if r.enabled)
        categories = {}
        for r in self._rules:
            cat = r.category or "uncategorized"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_rules": len(self._rules),
            "enabled_rules": enabled,
            "disabled_rules": len(self._rules) - enabled,
            "categories": categories,
        }
