"""
AEROCIFER NGFW — Input Validation Utilities

Validates IPs, ports, zone names, MAC addresses, CIDR subnets, and
firewall rule parameters. All validation functions raise ValueError
with descriptive messages on invalid input.
"""

from __future__ import annotations

import re
import ipaddress
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════
# IP Address Validation
# ═══════════════════════════════════════════════════════════════════════════

def validate_ip(ip: str) -> str:
    """
    Validate and normalize an IPv4 or IPv6 address.
    Returns the normalized string representation.

    Raises:
        ValueError: If the IP address is invalid.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip}'")


def validate_subnet(subnet: str) -> str:
    """
    Validate and normalize a CIDR subnet (e.g. '192.168.1.0/24').
    Returns the normalized network string.

    Raises:
        ValueError: If the subnet is invalid.
    """
    try:
        network = ipaddress.ip_network(subnet.strip(), strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Invalid subnet: '{subnet}'")


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range (RFC 1918)."""
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def ip_in_subnet(ip: str, subnet: str) -> bool:
    """Check if an IP address belongs to a given subnet."""
    try:
        return ipaddress.ip_address(ip.strip()) in ipaddress.ip_network(
            subnet.strip(), strict=False
        )
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Port Validation
# ═══════════════════════════════════════════════════════════════════════════

def validate_port(port: int) -> int:
    """
    Validate a TCP/UDP port number (1–65535).

    Raises:
        ValueError: If port is out of range.
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Invalid port number: {port} (must be 1–65535)")
    return port


def validate_port_range(port_range: str) -> tuple[int, int]:
    """
    Validate a port range string like '80-443' or '8080'.
    Returns (start, end) inclusive.

    Raises:
        ValueError: If the range is invalid.
    """
    port_range = port_range.strip()

    if "-" in port_range:
        parts = port_range.split("-", 1)
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
        except ValueError:
            raise ValueError(f"Invalid port range: '{port_range}'")

        validate_port(start)
        validate_port(end)

        if start > end:
            raise ValueError(
                f"Invalid port range: start ({start}) > end ({end})"
            )
        return (start, end)
    else:
        try:
            port = int(port_range)
        except ValueError:
            raise ValueError(f"Invalid port: '{port_range}'")
        validate_port(port)
        return (port, port)


# ═══════════════════════════════════════════════════════════════════════════
# MAC Address Validation
# ═══════════════════════════════════════════════════════════════════════════

_MAC_PATTERN = re.compile(
    r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"
)


def validate_mac(mac: str) -> str:
    """
    Validate and normalize a MAC address to colon-separated lowercase.
    Accepts formats: 'AA:BB:CC:DD:EE:FF' or 'AA-BB-CC-DD-EE-FF'.

    Returns:
        Normalized MAC string (lowercase, colon-separated).

    Raises:
        ValueError: If the MAC address is invalid.
    """
    mac = mac.strip()
    if not _MAC_PATTERN.match(mac):
        raise ValueError(f"Invalid MAC address: '{mac}'")
    return mac.replace("-", ":").lower()


def get_mac_oui(mac: str) -> str:
    """
    Extract the OUI (Organizationally Unique Identifier) from a MAC address.
    The OUI is the first 3 octets, identifying the manufacturer.
    """
    normalized = validate_mac(mac)
    return normalized[:8]  # "aa:bb:cc"


# ═══════════════════════════════════════════════════════════════════════════
# Zone Name Validation
# ═══════════════════════════════════════════════════════════════════════════

_ZONE_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{1,62}$")


def validate_zone_name(name: str) -> str:
    """
    Validate a zone name.
    Rules:
      - 2–63 characters
      - Starts with a letter
      - Contains only letters, digits, underscores, hyphens

    Returns:
        The validated zone name (stripped).

    Raises:
        ValueError: If the zone name is invalid.
    """
    name = name.strip()
    if not _ZONE_NAME_PATTERN.match(name):
        raise ValueError(
            f"Invalid zone name: '{name}'. Must be 2–63 chars, "
            "start with a letter, and contain only [a-zA-Z0-9_-]."
        )
    return name


# ═══════════════════════════════════════════════════════════════════════════
# Protocol Validation
# ═══════════════════════════════════════════════════════════════════════════

VALID_PROTOCOLS = frozenset({
    "tcp", "udp", "icmp", "icmpv6", "sctp",
    "http", "https", "dns", "smtp", "ftp", "ssh",
    "mqtt", "coap", "tls", "any",
})


def validate_protocol(protocol: str) -> str:
    """
    Validate a protocol name.

    Returns:
        Normalized lowercase protocol name.

    Raises:
        ValueError: If the protocol is not recognized.
    """
    protocol = protocol.strip().lower()
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(
            f"Unknown protocol: '{protocol}'. "
            f"Valid protocols: {', '.join(sorted(VALID_PROTOCOLS))}"
        )
    return protocol


# ═══════════════════════════════════════════════════════════════════════════
# Firewall Rule Validation
# ═══════════════════════════════════════════════════════════════════════════

VALID_ACTIONS = frozenset({"accept", "drop", "reject", "log"})
VALID_DIRECTIONS = frozenset({"inbound", "outbound", "forward", "any"})
VALID_CHAINS = frozenset({"input", "output", "forward"})


def validate_rule_action(action: str) -> str:
    """Validate a firewall rule action (accept/drop/reject/log)."""
    action = action.strip().lower()
    if action not in VALID_ACTIONS:
        raise ValueError(
            f"Invalid rule action: '{action}'. "
            f"Valid actions: {', '.join(sorted(VALID_ACTIONS))}"
        )
    return action


def validate_rule_direction(direction: str) -> str:
    """Validate a firewall rule direction."""
    direction = direction.strip().lower()
    if direction not in VALID_DIRECTIONS:
        raise ValueError(
            f"Invalid direction: '{direction}'. "
            f"Valid directions: {', '.join(sorted(VALID_DIRECTIONS))}"
        )
    return direction


def sanitize_shell_arg(value: str) -> str:
    """
    Sanitize a string to prevent shell injection in subprocess calls.
    Only allows alphanumeric characters, dots, colons, slashes, hyphens,
    and underscores.

    Raises:
        ValueError: If the string contains forbidden characters.
    """
    if not re.match(r"^[a-zA-Z0-9.:/_\-]+$", value):
        raise ValueError(
            f"Input contains forbidden characters: '{value}'. "
            "Only [a-zA-Z0-9.:/_-] are allowed."
        )
    return value
