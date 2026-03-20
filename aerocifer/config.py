"""
AEROCIFER NGFW — Central Configuration System

Loads configuration from YAML file with sane defaults.
All components reference this single source of truth.
"""

from __future__ import annotations

import os
import sys
import copy
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

# ---------------------------------------------------------------------------
# Determine base directory: installed package vs development checkout
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
BASE_DIR = _THIS_DIR.parent  # NGFW project root

# Default paths (relative to BASE_DIR)
DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"
DEFAULT_DATA_DIR = BASE_DIR / "data"
DEFAULT_LOG_DIR = BASE_DIR / "logs"
DEFAULT_DB_PATH = BASE_DIR / "data" / "aerocifer.db"
DEFAULT_MODEL_DIR = _THIS_DIR / "ml" / "models"
DEFAULT_RULES_DIR = BASE_DIR / "data" / "signatures"


# ═══════════════════════════════════════════════════════════════════════════
# Configuration Dataclasses
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkConfig:
    """Packet capture and network settings."""
    interfaces: list[str] = field(default_factory=lambda: ["eth0"])
    promiscuous: bool = True
    snap_length: int = 65535          # Max bytes captured per packet
    capture_filter: str = "ip"        # BPF filter
    batch_size: int = 64              # Packets processed per batch
    queue_max_size: int = 10000       # Max packets in processing queue
    worker_count: int = 4             # Async worker count
    topology_scan_timeout: int = 30   # Seconds for initial ARP scan
    topology_scan_network: str = ""   # Auto-detect if empty


@dataclass
class SecurityConfig:
    """Threat detection thresholds and policies."""
    ddos_threshold_pps: int = 100     # Packets-per-second before DDoS flag
    ddos_window_seconds: float = 1.0  # Measurement window
    syn_flood_threshold: int = 50     # SYN packets / second from single IP
    port_scan_threshold: int = 15     # Unique ports / 10s from single IP
    arp_spoof_detection: bool = True
    auto_block: bool = True           # Automatically block detected threats
    block_duration_seconds: int = 3600  # 1 hour default block
    whitelist_file: str = ""
    blacklist_file: str = ""


@dataclass
class DPIConfig:
    """Deep Packet Inspection settings."""
    enabled: bool = True
    inspect_http: bool = True
    inspect_https: bool = True
    inspect_dns: bool = True
    inspect_tls: bool = True          # JA3/JA4 fingerprinting
    inspect_smtp: bool = False
    inspect_mqtt: bool = True         # IoT
    inspect_coap: bool = True         # IoT
    max_payload_inspect_bytes: int = 4096
    signature_rules_dir: str = ""


@dataclass
class MLConfig:
    """Machine Learning engine settings."""
    enabled: bool = True
    model_dir: str = ""
    # Traffic classifier
    traffic_model_file: str = "traffic_model.pt"
    traffic_confidence_threshold: float = 0.85
    # Anomaly detector
    anomaly_model_file: str = "anomaly_model.pt"
    anomaly_threshold: float = 0.95   # Reconstruction error threshold
    # Device fingerprinter
    device_model_file: str = "device_model.pkl"
    # Self-training
    self_training_enabled: bool = True
    training_buffer_size: int = 5000  # Samples before retrain
    retrain_interval_seconds: int = 3600  # Min time between retrains
    # Performance
    inference_batch_size: int = 32
    use_onnx_runtime: bool = False    # ONNX for optimized inference


@dataclass
class ZoneConfig:
    """Zone-based segmentation defaults."""
    enabled: bool = True
    default_inter_zone_policy: str = "deny"  # deny | allow
    auto_classify_devices: bool = True


@dataclass
class DatabaseConfig:
    """Database connection settings."""
    engine: str = "sqlite"            # sqlite | postgresql
    path: str = ""                    # SQLite file path
    # PostgreSQL (for future scaling)
    host: str = "localhost"
    port: int = 5432
    name: str = "aerocifer"
    user: str = "aerocifer"
    password: str = ""
    # Performance
    wal_mode: bool = True             # SQLite WAL for concurrent access
    pool_size: int = 5
    max_overflow: int = 10


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"               # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_dir: str = ""
    console_output: bool = True
    file_output: bool = True
    json_format: bool = False         # Structured JSON logging
    max_file_size_mb: int = 50
    backup_count: int = 5             # Rotated log file count
    log_packets: bool = False         # Verbose packet logging (debug only)


@dataclass
class APIConfig:
    """REST API settings."""
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8443
    api_key: str = ""                 # Auto-generated if empty
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    rate_limit_per_minute: int = 60


@dataclass
class AerociferConfig:
    """Root configuration — contains all sub-configs."""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    dpi: DPIConfig = field(default_factory=DPIConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    zones: ZoneConfig = field(default_factory=ZoneConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    api: APIConfig = field(default_factory=APIConfig)

    def __post_init__(self):
        """Fill in default paths that depend on BASE_DIR."""
        if not self.database.path:
            self.database.path = str(DEFAULT_DB_PATH)
        if not self.logging.log_dir:
            self.logging.log_dir = str(DEFAULT_LOG_DIR)
        if not self.ml.model_dir:
            self.ml.model_dir = str(DEFAULT_MODEL_DIR)
        if not self.dpi.signature_rules_dir:
            self.dpi.signature_rules_dir = str(DEFAULT_RULES_DIR)


# ═══════════════════════════════════════════════════════════════════════════
# Configuration Loader
# ═══════════════════════════════════════════════════════════════════════════

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _dict_to_config(data: dict) -> AerociferConfig:
    """Convert a flat/nested dict to the typed AerociferConfig."""
    cfg = AerociferConfig()

    section_map = {
        "network": (cfg.network, NetworkConfig),
        "security": (cfg.security, SecurityConfig),
        "dpi": (cfg.dpi, DPIConfig),
        "ml": (cfg.ml, MLConfig),
        "zones": (cfg.zones, ZoneConfig),
        "database": (cfg.database, DatabaseConfig),
        "logging": (cfg.logging, LoggingConfig),
        "api": (cfg.api, APIConfig),
    }

    for section_name, (section_obj, section_cls) in section_map.items():
        section_data = data.get(section_name, {})
        if not isinstance(section_data, dict):
            continue
        for field_name, value in section_data.items():
            if hasattr(section_obj, field_name):
                expected_type = section_cls.__dataclass_fields__[field_name].type
                try:
                    setattr(section_obj, field_name, value)
                except (TypeError, ValueError):
                    pass  # Keep default if type doesn't match

    return cfg


def load_config(config_path: Optional[str | Path] = None) -> AerociferConfig:
    """
    Load configuration from a YAML file.

    Priority:
        1. Environment variable AEROCIFER_CONFIG pointing to a YAML file
        2. Explicit config_path argument
        3. Default config.yaml in project root
        4. Built-in defaults (no file needed)

    Returns:
        AerociferConfig with all settings resolved.
    """
    path = None

    # Priority 1: Environment variable
    env_path = os.environ.get("AEROCIFER_CONFIG")
    if env_path and os.path.isfile(env_path):
        path = Path(env_path)

    # Priority 2: Explicit argument
    if path is None and config_path is not None:
        p = Path(config_path)
        if p.is_file():
            path = p

    # Priority 3: Default location
    if path is None and DEFAULT_CONFIG_PATH.is_file():
        path = DEFAULT_CONFIG_PATH

    # Load from file or use pure defaults
    if path is not None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            config = _dict_to_config(raw)
        except (yaml.YAMLError, OSError) as exc:
            print(f"[AEROCIFER] Warning: Failed to load config from {path}: {exc}",
                  file=sys.stderr)
            print("[AEROCIFER] Using default configuration.", file=sys.stderr)
            config = AerociferConfig()
    else:
        config = AerociferConfig()

    return config


def save_config(config: AerociferConfig, path: Optional[str | Path] = None) -> Path:
    """Save current configuration to a YAML file."""
    save_path = Path(path) if path else DEFAULT_CONFIG_PATH
    save_path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(config)
    with open(save_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)

    return save_path


def generate_default_config(path: Optional[str | Path] = None) -> Path:
    """Generate a default config.yaml with all options documented."""
    return save_config(AerociferConfig(), path)
