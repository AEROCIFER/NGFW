"""
AEROCIFER NGFW — Database Models

Dataclass-based models representing all persistent entities:
devices, zones, rules, flow records, threats, and events.
Each model can serialize to/from database rows (tuples/dicts).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Any


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════

class DeviceType(str, Enum):
    UNKNOWN = "unknown"
    WORKSTATION = "workstation"
    SERVER = "server"
    PRINTER = "printer"
    PHONE = "phone"
    TABLET = "tablet"
    IOT_SENSOR = "iot_sensor"
    IOT_CAMERA = "iot_camera"
    IOT_THERMOSTAT = "iot_thermostat"
    IOT_GATEWAY = "iot_gateway"
    NETWORK_DEVICE = "network_device"
    SMART_TV = "smart_tv"
    GAMING_CONSOLE = "gaming_console"


class ThreatType(str, Enum):
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    ARP_SPOOF = "arp_spoof"
    DNS_TUNNEL = "dns_tunnel"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    BRUTE_FORCE = "brute_force"
    DATA_EXFIL = "data_exfiltration"
    ANOMALY = "anomaly"
    SIGNATURE_MATCH = "signature_match"
    PROTOCOL_VIOLATION = "protocol_violation"


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"


class FlowState(str, Enum):
    NEW = "new"
    ESTABLISHED = "established"
    RELATED = "related"
    CLOSING = "closing"
    CLOSED = "closed"
    TIMEOUT = "timeout"


class ZonePolicy(str, Enum):
    RESTRICTIVE = "restrictive"
    STANDARD = "standard"
    PERMISSIVE = "permissive"
    CUSTOM = "custom"


# ═══════════════════════════════════════════════════════════════════════════
# Helper
# ═══════════════════════════════════════════════════════════════════════════

def _gen_id() -> str:
    """Generate a short unique identifier."""
    return uuid.uuid4().hex[:12]


def _now() -> float:
    """Unix timestamp (float) for current time."""
    return time.time()


# ═══════════════════════════════════════════════════════════════════════════
# Device Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Device:
    """A network device discovered on the network."""
    ip: str
    mac: str
    id: str = field(default_factory=_gen_id)
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    vendor: str = ""                    # OUI-derived manufacturer
    os_fingerprint: str = ""            # OS guess from traffic patterns
    zone_id: Optional[str] = None       # Assigned zone
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    open_ports: str = ""                # JSON list of open ports
    traffic_profile: str = ""           # JSON summary of traffic patterns
    is_active: bool = True
    confidence: float = 0.0            # ML classification confidence

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["device_type"] = self.device_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        data = dict(data)  # shallow copy
        if "device_type" in data and isinstance(data["device_type"], str):
            data["device_type"] = DeviceType(data["device_type"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Zone Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Zone:
    """A network security zone."""
    name: str
    id: str = field(default_factory=_gen_id)
    description: str = ""
    subnet: str = ""                    # CIDR notation
    vlan_id: Optional[int] = None
    policy: ZonePolicy = ZonePolicy.STANDARD
    allowed_protocols: str = "[]"       # JSON list
    blocked_protocols: str = "[]"       # JSON list
    max_bandwidth_mbps: Optional[int] = None
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)
    is_active: bool = True
    device_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["policy"] = self.policy.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Zone:
        data = dict(data)
        if "policy" in data and isinstance(data["policy"], str):
            data["policy"] = ZonePolicy(data["policy"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# InterZone Rule Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class InterZoneRule:
    """Rule governing traffic between two zones."""
    source_zone_id: str
    dest_zone_id: str
    action: RuleAction = RuleAction.DROP
    id: str = field(default_factory=_gen_id)
    protocol: str = "any"
    src_port: str = ""                  # Port or range
    dst_port: str = ""
    description: str = ""
    priority: int = 100                 # Lower = higher priority
    enabled: bool = True
    created_at: float = field(default_factory=_now)
    hit_count: int = 0                  # How many times rule was matched

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InterZoneRule:
        data = dict(data)
        if "action" in data and isinstance(data["action"], str):
            data["action"] = RuleAction(data["action"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Firewall Rule Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FirewallRule:
    """A standalone firewall rule (IP-based blocking, etc.)."""
    action: RuleAction
    id: str = field(default_factory=_gen_id)
    direction: str = "inbound"          # inbound, outbound, forward
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = "any"
    zone_id: Optional[str] = None
    description: str = ""
    priority: int = 100
    enabled: bool = True
    auto_generated: bool = False        # True if ML/AI created this rule
    expires_at: Optional[float] = None  # Auto-expire timestamp
    created_at: float = field(default_factory=_now)
    hit_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FirewallRule:
        data = dict(data)
        if "action" in data and isinstance(data["action"], str):
            data["action"] = RuleAction(data["action"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Flow Record Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FlowRecord:
    """A network flow (connection/session) record."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    id: str = field(default_factory=_gen_id)
    state: FlowState = FlowState.NEW
    # Counters
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    # Timing
    start_time: float = field(default_factory=_now)
    last_activity: float = field(default_factory=_now)
    duration: float = 0.0
    # Analysis
    application: str = ""               # Detected application (HTTP, SSH, etc.)
    ja3_hash: str = ""                   # TLS fingerprint
    dns_query: str = ""
    ml_label: str = ""                   # ML classification result
    ml_confidence: float = 0.0
    is_anomalous: bool = False
    anomaly_score: float = 0.0
    # Feature vector (JSON) for ML
    features: str = ""
    # Zone info
    src_zone_id: Optional[str] = None
    dst_zone_id: Optional[str] = None

    @property
    def flow_key(self) -> tuple:
        """Unique key for this flow (5-tuple)."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                self.protocol)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FlowRecord:
        data = dict(data)
        if "state" in data and isinstance(data["state"], str):
            data["state"] = FlowState(data["state"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Threat Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Threat:
    """A detected security threat."""
    threat_type: ThreatType
    severity: ThreatSeverity
    source_ip: str
    id: str = field(default_factory=_gen_id)
    dest_ip: str = ""
    description: str = ""
    evidence: str = ""                  # JSON with detection details
    action_taken: str = ""              # What the firewall did
    rule_id: Optional[str] = None       # Rule that was triggered/created
    flow_id: Optional[str] = None
    ml_confidence: float = 0.0
    is_false_positive: Optional[bool] = None  # Admin feedback
    detected_at: float = field(default_factory=_now)
    resolved_at: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Threat:
        data = dict(data)
        if "threat_type" in data and isinstance(data["threat_type"], str):
            data["threat_type"] = ThreatType(data["threat_type"])
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = ThreatSeverity(data["severity"])
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Event / Audit Log Model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Event:
    """A system event for audit logging."""
    event_type: str                     # e.g. "rule_created", "zone_modified"
    message: str
    id: str = field(default_factory=_gen_id)
    component: str = "main"             # core, dpi, ml, api, etc.
    severity: str = "info"              # debug, info, warning, error, critical
    details: str = ""                   # JSON with extra data
    user: str = "system"                # Who triggered this event
    timestamp: float = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════
# Training Sample Model (for ML self-training)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TrainingSample:
    """A labeled sample for ML model training."""
    features: str                       # JSON feature vector
    label: str                          # Ground truth or pseudo-label
    id: str = field(default_factory=_gen_id)
    source: str = "auto"                # auto, admin, dataset
    confidence: float = 0.0             # Labeling confidence
    flow_id: Optional[str] = None
    model_version: str = ""
    created_at: float = field(default_factory=_now)
    used_in_training: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrainingSample:
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})
