"""
AEROCIFER NGFW — Database Layer

Async SQLite database with:
- Schema auto-creation and migration
- WAL mode for concurrent read/write performance
- Generic CRUD operations for all models
- Connection pooling via context managers
- Thread-safe operations for mixed sync/async usage
"""

from __future__ import annotations

import json
import asyncio
import sqlite3
from pathlib import Path
from typing import Optional, Any
from contextlib import asynccontextmanager

import aiosqlite

from aerocifer.utils.logger import get_logger
from aerocifer.db.models import (
    Device, Zone, InterZoneRule, FirewallRule,
    FlowRecord, Threat, Event, TrainingSample,
)

log = get_logger("db")


# ═══════════════════════════════════════════════════════════════════════════
# SQL Schema Definitions
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

-- Discovered network devices
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    device_type TEXT DEFAULT 'unknown',
    vendor TEXT DEFAULT '',
    os_fingerprint TEXT DEFAULT '',
    zone_id TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    open_ports TEXT DEFAULT '[]',
    traffic_profile TEXT DEFAULT '{}',
    is_active INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.0,
    FOREIGN KEY (zone_id) REFERENCES zones(id)
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_zone ON devices(zone_id);

-- Security zones
CREATE TABLE IF NOT EXISTS zones (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    subnet TEXT DEFAULT '',
    vlan_id INTEGER,
    policy TEXT DEFAULT 'standard',
    allowed_protocols TEXT DEFAULT '[]',
    blocked_protocols TEXT DEFAULT '[]',
    max_bandwidth_mbps INTEGER,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    is_active INTEGER DEFAULT 1,
    device_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_zones_name ON zones(name);

-- Inter-zone rules
CREATE TABLE IF NOT EXISTS inter_zone_rules (
    id TEXT PRIMARY KEY,
    source_zone_id TEXT NOT NULL,
    dest_zone_id TEXT NOT NULL,
    action TEXT DEFAULT 'drop',
    protocol TEXT DEFAULT 'any',
    src_port TEXT DEFAULT '',
    dst_port TEXT DEFAULT '',
    description TEXT DEFAULT '',
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1,
    created_at REAL NOT NULL,
    hit_count INTEGER DEFAULT 0,
    FOREIGN KEY (source_zone_id) REFERENCES zones(id),
    FOREIGN KEY (dest_zone_id) REFERENCES zones(id)
);
CREATE INDEX IF NOT EXISTS idx_izr_zones ON inter_zone_rules(source_zone_id, dest_zone_id);

-- Firewall rules (IP-based)
CREATE TABLE IF NOT EXISTS firewall_rules (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    direction TEXT DEFAULT 'inbound',
    src_ip TEXT DEFAULT '',
    dst_ip TEXT DEFAULT '',
    src_port TEXT DEFAULT '',
    dst_port TEXT DEFAULT '',
    protocol TEXT DEFAULT 'any',
    zone_id TEXT,
    description TEXT DEFAULT '',
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1,
    auto_generated INTEGER DEFAULT 0,
    expires_at REAL,
    created_at REAL NOT NULL,
    hit_count INTEGER DEFAULT 0,
    FOREIGN KEY (zone_id) REFERENCES zones(id)
);
CREATE INDEX IF NOT EXISTS idx_rules_src ON firewall_rules(src_ip);
CREATE INDEX IF NOT EXISTS idx_rules_dst ON firewall_rules(dst_ip);
CREATE INDEX IF NOT EXISTS idx_rules_expires ON firewall_rules(expires_at);

-- Flow records (network sessions)
CREATE TABLE IF NOT EXISTS flow_records (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT DEFAULT 'new',
    packets_sent INTEGER DEFAULT 0,
    packets_recv INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    start_time REAL NOT NULL,
    last_activity REAL NOT NULL,
    duration REAL DEFAULT 0.0,
    application TEXT DEFAULT '',
    ja3_hash TEXT DEFAULT '',
    dns_query TEXT DEFAULT '',
    ml_label TEXT DEFAULT '',
    ml_confidence REAL DEFAULT 0.0,
    is_anomalous INTEGER DEFAULT 0,
    anomaly_score REAL DEFAULT 0.0,
    features TEXT DEFAULT '',
    src_zone_id TEXT,
    dst_zone_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flow_records(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flow_records(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flow_records(start_time);
CREATE INDEX IF NOT EXISTS idx_flows_anomalous ON flow_records(is_anomalous);

-- Detected threats
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT DEFAULT '',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '{}',
    action_taken TEXT DEFAULT '',
    rule_id TEXT,
    flow_id TEXT,
    ml_confidence REAL DEFAULT 0.0,
    is_false_positive INTEGER,
    detected_at REAL NOT NULL,
    resolved_at REAL
);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_src ON threats(source_ip);
CREATE INDEX IF NOT EXISTS idx_threats_time ON threats(detected_at);

-- Audit event log
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    component TEXT DEFAULT 'main',
    severity TEXT DEFAULT 'info',
    details TEXT DEFAULT '{}',
    user TEXT DEFAULT 'system',
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);

-- ML training samples
CREATE TABLE IF NOT EXISTS training_samples (
    id TEXT PRIMARY KEY,
    features TEXT NOT NULL,
    label TEXT NOT NULL,
    source TEXT DEFAULT 'auto',
    confidence REAL DEFAULT 0.0,
    flow_id TEXT,
    model_version TEXT DEFAULT '',
    created_at REAL NOT NULL,
    used_in_training INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_training_label ON training_samples(label);
CREATE INDEX IF NOT EXISTS idx_training_used ON training_samples(used_in_training);

-- Traffic statistics (aggregated per minute for dashboard)
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    interval_seconds INTEGER DEFAULT 60,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    unique_src_ips INTEGER DEFAULT 0,
    unique_dst_ips INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    avg_packet_size REAL DEFAULT 0.0,
    protocol_breakdown TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_stats_time ON traffic_stats(timestamp);

-- Network Interfaces
CREATE TABLE IF NOT EXISTS interfaces (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    interface_type TEXT DEFAULT 'Layer 3',
    ip_assignment TEXT DEFAULT 'DHCP',
    ip_address TEXT DEFAULT '',
    gateway TEXT DEFAULT '',
    zone_id TEXT,
    logs_allowed INTEGER DEFAULT 1,
    status TEXT DEFAULT 'UP',
    speed TEXT DEFAULT '1000Mbps'
);

-- URL Drop Filters
CREATE TABLE IF NOT EXISTS url_filters (
    id TEXT PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL
);

-- SP3 Analytics Logs
CREATE TABLE IF NOT EXISTS sp3_logs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    src_ip TEXT DEFAULT '',
    dst_ip TEXT DEFAULT '',
    protocol TEXT DEFAULT '',
    service TEXT DEFAULT '',
    policy_action TEXT DEFAULT '',
    details TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sp3_time ON sp3_logs(timestamp);
"""


# ═══════════════════════════════════════════════════════════════════════════
# Database Manager
# ═══════════════════════════════════════════════════════════════════════════

class Database:
    """
    Async SQLite database manager.

    Usage:
        db = Database("/path/to/aerocifer.db")
        await db.initialize()

        # Insert
        device = Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        await db.insert_device(device)

        # Query
        devices = await db.get_all_devices()

        # Cleanup
        await db.close()
    """

    def __init__(self, db_path: str, wal_mode: bool = True):
        self._db_path = db_path
        self._wal_mode = wal_mode
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Open database and create schema if needed."""
        # Ensure parent directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row

        # Performance optimizations
        if self._wal_mode:
            await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA cache_size=-64000")   # 64MB cache
        await self._db.execute("PRAGMA temp_store=MEMORY")
        await self._db.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
        await self._db.execute("PRAGMA foreign_keys=ON")

        # Create schema
        await self._db.executescript(SCHEMA_SQL)
        await self._db.commit()

        log.info(f"Database initialized at {self._db_path}")

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None
            log.info("Database connection closed")

    @asynccontextmanager
    async def _conn(self):
        """Get a database connection (context manager for safety)."""
        if self._db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        yield self._db

    # ───────────────────────────────────────────────────────────────────
    # Device CRUD
    # ───────────────────────────────────────────────────────────────────

    async def insert_device(self, device: Device) -> None:
        async with self._conn() as db:
            d = device.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO devices
                   (id, ip, mac, hostname, device_type, vendor, os_fingerprint,
                    zone_id, first_seen, last_seen, open_ports, traffic_profile,
                    is_active, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["ip"], d["mac"], d["hostname"], d["device_type"],
                 d["vendor"], d["os_fingerprint"], d["zone_id"],
                 d["first_seen"], d["last_seen"], d["open_ports"],
                 d["traffic_profile"], int(d["is_active"]), d["confidence"]),
            )
            await db.commit()

    async def get_device_by_ip(self, ip: str) -> Optional[Device]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM devices WHERE ip = ? AND is_active = 1", (ip,)
            )
            row = await cursor.fetchone()
            return Device.from_dict(dict(row)) if row else None

    async def get_device_by_mac(self, mac: str) -> Optional[Device]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM devices WHERE mac = ? AND is_active = 1",
                (mac.lower(),),
            )
            row = await cursor.fetchone()
            return Device.from_dict(dict(row)) if row else None

    async def get_all_devices(self, active_only: bool = True) -> list[Device]:
        async with self._conn() as db:
            query = "SELECT * FROM devices"
            if active_only:
                query += " WHERE is_active = 1"
            query += " ORDER BY last_seen DESC"
            cursor = await db.execute(query)
            rows = await cursor.fetchall()
            return [Device.from_dict(dict(r)) for r in rows]

    async def get_devices_in_zone(self, zone_id: str) -> list[Device]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM devices WHERE zone_id = ? AND is_active = 1",
                (zone_id,),
            )
            rows = await cursor.fetchall()
            return [Device.from_dict(dict(r)) for r in rows]

    async def update_device_last_seen(self, ip: str) -> None:
        async with self._conn() as db:
            import time
            await db.execute(
                "UPDATE devices SET last_seen = ? WHERE ip = ?",
                (time.time(), ip),
            )
            await db.commit()

    async def assign_device_to_zone(
        self, device_id: str, zone_id: str
    ) -> None:
        async with self._conn() as db:
            await db.execute(
                "UPDATE devices SET zone_id = ? WHERE id = ?",
                (zone_id, device_id),
            )
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # Zone CRUD
    # ───────────────────────────────────────────────────────────────────

    async def insert_zone(self, zone: Zone) -> None:
        async with self._conn() as db:
            d = zone.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO zones
                   (id, name, description, subnet, vlan_id, policy,
                    allowed_protocols, blocked_protocols, max_bandwidth_mbps,
                    created_at, updated_at, is_active, device_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["name"], d["description"], d["subnet"],
                 d["vlan_id"], d["policy"], d["allowed_protocols"],
                 d["blocked_protocols"], d["max_bandwidth_mbps"],
                 d["created_at"], d["updated_at"], int(d["is_active"]),
                 d["device_count"]),
            )
            await db.commit()

    async def get_zone_by_name(self, name: str) -> Optional[Zone]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM zones WHERE name = ? AND is_active = 1", (name,)
            )
            row = await cursor.fetchone()
            return Zone.from_dict(dict(row)) if row else None

    async def get_zone_by_id(self, zone_id: str) -> Optional[Zone]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM zones WHERE id = ?", (zone_id,)
            )
            row = await cursor.fetchone()
            return Zone.from_dict(dict(row)) if row else None

    async def get_all_zones(self) -> list[Zone]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM zones WHERE is_active = 1 ORDER BY name"
            )
            rows = await cursor.fetchall()
            return [Zone.from_dict(dict(r)) for r in rows]

    async def delete_zone(self, zone_id: str) -> None:
        async with self._conn() as db:
            await db.execute(
                "UPDATE zones SET is_active = 0 WHERE id = ?", (zone_id,)
            )
            # Un-assign devices from this zone
            await db.execute(
                "UPDATE devices SET zone_id = NULL WHERE zone_id = ?",
                (zone_id,),
            )
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # Firewall Rule CRUD
    # ───────────────────────────────────────────────────────────────────

    async def insert_rule(self, rule: FirewallRule) -> None:
        async with self._conn() as db:
            d = rule.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO firewall_rules
                   (id, action, direction, src_ip, dst_ip, src_port, dst_port,
                    protocol, zone_id, description, priority, enabled,
                    auto_generated, expires_at, created_at, hit_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["action"], d["direction"], d["src_ip"], d["dst_ip"],
                 d["src_port"], d["dst_port"], d["protocol"], d["zone_id"],
                 d["description"], d["priority"], int(d["enabled"]),
                 int(d["auto_generated"]), d["expires_at"], d["created_at"],
                 d["hit_count"]),
            )
            await db.commit()

    async def get_active_rules(self) -> list[FirewallRule]:
        async with self._conn() as db:
            cursor = await db.execute(
                """SELECT * FROM firewall_rules
                   WHERE enabled = 1
                   AND (expires_at IS NULL OR expires_at > ?)
                   ORDER BY priority ASC""",
                (asyncio.get_event_loop().time(),),
            )
            rows = await cursor.fetchall()
            return [FirewallRule.from_dict(dict(r)) for r in rows]

    async def increment_rule_hit(self, rule_id: str) -> None:
        async with self._conn() as db:
            await db.execute(
                "UPDATE firewall_rules SET hit_count = hit_count + 1 WHERE id = ?",
                (rule_id,),
            )
            await db.commit()

    async def cleanup_expired_rules(self) -> int:
        """Remove expired auto-generated rules. Returns count removed."""
        import time
        async with self._conn() as db:
            cursor = await db.execute(
                """DELETE FROM firewall_rules
                   WHERE auto_generated = 1
                   AND expires_at IS NOT NULL
                   AND expires_at < ?""",
                (time.time(),),
            )
            await db.commit()
            return cursor.rowcount

    # ───────────────────────────────────────────────────────────────────
    # Inter-Zone Rule CRUD
    # ───────────────────────────────────────────────────────────────────

    async def insert_inter_zone_rule(self, rule: InterZoneRule) -> None:
        async with self._conn() as db:
            d = rule.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO inter_zone_rules
                   (id, source_zone_id, dest_zone_id, action, protocol,
                    src_port, dst_port, description, priority, enabled,
                    created_at, hit_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["source_zone_id"], d["dest_zone_id"], d["action"],
                 d["protocol"], d["src_port"], d["dst_port"], d["description"],
                 d["priority"], int(d["enabled"]), d["created_at"],
                 d["hit_count"]),
            )
            await db.commit()

    async def get_inter_zone_rules(
        self,
        src_zone_id: Optional[str] = None,
        dst_zone_id: Optional[str] = None,
    ) -> list[InterZoneRule]:
        async with self._conn() as db:
            query = "SELECT * FROM inter_zone_rules WHERE enabled = 1"
            params: list[Any] = []
            if src_zone_id:
                query += " AND source_zone_id = ?"
                params.append(src_zone_id)
            if dst_zone_id:
                query += " AND dest_zone_id = ?"
                params.append(dst_zone_id)
            query += " ORDER BY priority ASC"
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [InterZoneRule.from_dict(dict(r)) for r in rows]

    # ───────────────────────────────────────────────────────────────────
    # Flow Records
    # ───────────────────────────────────────────────────────────────────

    async def insert_flow(self, flow: FlowRecord) -> None:
        async with self._conn() as db:
            d = flow.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO flow_records
                   (id, src_ip, dst_ip, src_port, dst_port, protocol, state,
                    packets_sent, packets_recv, bytes_sent, bytes_recv,
                    start_time, last_activity, duration, application,
                    ja3_hash, dns_query, ml_label, ml_confidence,
                    is_anomalous, anomaly_score, features,
                    src_zone_id, dst_zone_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["src_ip"], d["dst_ip"], d["src_port"],
                 d["dst_port"], d["protocol"], d["state"],
                 d["packets_sent"], d["packets_recv"], d["bytes_sent"],
                 d["bytes_recv"], d["start_time"], d["last_activity"],
                 d["duration"], d["application"], d["ja3_hash"],
                 d["dns_query"], d["ml_label"], d["ml_confidence"],
                 int(d["is_anomalous"]), d["anomaly_score"], d["features"],
                 d["src_zone_id"], d["dst_zone_id"]),
            )
            await db.commit()

    async def get_recent_flows(
        self, limit: int = 100, anomalous_only: bool = False
    ) -> list[FlowRecord]:
        async with self._conn() as db:
            query = "SELECT * FROM flow_records"
            if anomalous_only:
                query += " WHERE is_anomalous = 1"
            query += " ORDER BY start_time DESC LIMIT ?"
            cursor = await db.execute(query, (limit,))
            rows = await cursor.fetchall()
            return [FlowRecord.from_dict(dict(r)) for r in rows]

    # ───────────────────────────────────────────────────────────────────
    # Threats
    # ───────────────────────────────────────────────────────────────────

    async def insert_threat(self, threat: Threat) -> None:
        async with self._conn() as db:
            d = threat.to_dict()
            fp_val = None
            if d["is_false_positive"] is not None:
                fp_val = int(d["is_false_positive"])
            await db.execute(
                """INSERT INTO threats
                   (id, threat_type, severity, source_ip, dest_ip, description,
                    evidence, action_taken, rule_id, flow_id, ml_confidence,
                    is_false_positive, detected_at, resolved_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["threat_type"], d["severity"], d["source_ip"],
                 d["dest_ip"], d["description"], d["evidence"],
                 d["action_taken"], d["rule_id"], d["flow_id"],
                 d["ml_confidence"], fp_val, d["detected_at"],
                 d["resolved_at"]),
            )
            await db.commit()

    async def get_recent_threats(
        self, limit: int = 50, severity: Optional[str] = None
    ) -> list[Threat]:
        async with self._conn() as db:
            query = "SELECT * FROM threats"
            params: list[Any] = []
            if severity:
                query += " WHERE severity = ?"
                params.append(severity)
            query += " ORDER BY detected_at DESC LIMIT ?"
            params.append(limit)
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [Threat.from_dict(dict(r)) for r in rows]

    async def mark_false_positive(
        self, threat_id: str, is_fp: bool
    ) -> None:
        async with self._conn() as db:
            await db.execute(
                "UPDATE threats SET is_false_positive = ? WHERE id = ?",
                (int(is_fp), threat_id),
            )
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # Events (Audit Log)
    # ───────────────────────────────────────────────────────────────────

    async def insert_event(self, event: Event) -> None:
        async with self._conn() as db:
            d = event.to_dict()
            await db.execute(
                """INSERT INTO events
                   (id, event_type, message, component, severity, details,
                    user, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["event_type"], d["message"], d["component"],
                 d["severity"], d["details"], d["user"], d["timestamp"]),
            )
            await db.commit()

    async def get_recent_events(
        self, limit: int = 100, component: Optional[str] = None
    ) -> list[Event]:
        async with self._conn() as db:
            query = "SELECT * FROM events"
            params: list[Any] = []
            if component:
                query += " WHERE component = ?"
                params.append(component)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [Event.from_dict(dict(r)) for r in rows]

    # ───────────────────────────────────────────────────────────────────
    # Training Samples
    # ───────────────────────────────────────────────────────────────────

    async def insert_training_sample(self, sample: TrainingSample) -> None:
        async with self._conn() as db:
            d = sample.to_dict()
            await db.execute(
                """INSERT INTO training_samples
                   (id, features, label, source, confidence, flow_id,
                    model_version, created_at, used_in_training)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["features"], d["label"], d["source"],
                 d["confidence"], d["flow_id"], d["model_version"],
                 d["created_at"], int(d["used_in_training"])),
            )
            await db.commit()

    async def get_unused_training_samples(
        self, limit: int = 5000
    ) -> list[TrainingSample]:
        async with self._conn() as db:
            cursor = await db.execute(
                """SELECT * FROM training_samples
                   WHERE used_in_training = 0
                   ORDER BY created_at ASC
                   LIMIT ?""",
                (limit,),
            )
            rows = await cursor.fetchall()
            return [TrainingSample.from_dict(dict(r)) for r in rows]

    async def mark_samples_used(self, sample_ids: list[str]) -> None:
        if not sample_ids:
            return
        async with self._conn() as db:
            placeholders = ",".join("?" for _ in sample_ids)
            await db.execute(
                f"UPDATE training_samples SET used_in_training = 1 WHERE id IN ({placeholders})",
                sample_ids,
            )
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # Traffic Statistics
    # ───────────────────────────────────────────────────────────────────

    async def insert_traffic_stats(
        self,
        total_packets: int,
        total_bytes: int,
        unique_src_ips: int,
        unique_dst_ips: int,
        blocked_count: int,
        threats_detected: int,
        avg_packet_size: float,
        protocol_breakdown: dict,
    ) -> None:
        import time
        async with self._conn() as db:
            await db.execute(
                """INSERT INTO traffic_stats
                   (timestamp, total_packets, total_bytes, unique_src_ips,
                    unique_dst_ips, blocked_count, threats_detected,
                    avg_packet_size, protocol_breakdown)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (time.time(), total_packets, total_bytes, unique_src_ips,
                 unique_dst_ips, blocked_count, threats_detected,
                 avg_packet_size, json.dumps(protocol_breakdown)),
            )
            await db.commit()

    async def get_traffic_stats(
        self, hours: int = 24
    ) -> list[dict[str, Any]]:
        import time
        since = time.time() - (hours * 3600)
        async with self._conn() as db:
            cursor = await db.execute(
                """SELECT * FROM traffic_stats
                   WHERE timestamp > ?
                   ORDER BY timestamp ASC""",
                (since,),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ───────────────────────────────────────────────────────────────────
    # Maintenance
    # ───────────────────────────────────────────────────────────────────

    async def vacuum(self) -> None:
        """Reclaim unused space in the database."""
        async with self._conn() as db:
            await db.execute("VACUUM")
        log.info("Database vacuumed")

    async def get_table_counts(self) -> dict[str, int]:
        """Get row counts for all tables (for monitoring)."""
        tables = [
            "devices", "zones", "firewall_rules", "inter_zone_rules",
            "flow_records", "threats", "events", "training_samples",
            "traffic_stats",
        ]
        counts = {}
        async with self._conn() as db:
            for table in tables:
                cursor = await db.execute(f"SELECT COUNT(*) FROM {table}")
                row = await cursor.fetchone()
                counts[table] = row[0] if row else 0
        return counts

    # ───────────────────────────────────────────────────────────────────
    # Interfaces
    # ───────────────────────────────────────────────────────────────────
    async def delete_interface(self, interface_id: str) -> None:
        async with self._conn() as db:
            await db.execute("DELETE FROM interfaces WHERE id = ?", (interface_id,))
            await db.commit()

    async def update_interface_status(self, interface_id: str, status: str) -> None:
        async with self._conn() as db:
            await db.execute("UPDATE interfaces SET status = ? WHERE id = ?", (status, interface_id,))
            await db.commit()

    async def get_all_interfaces(self) -> list[Any]:
        async with self._conn() as db:
            cursor = await db.execute("SELECT * FROM interfaces")
            rows = await cursor.fetchall()
            from aerocifer.db.models import NetworkInterface
            return [NetworkInterface.from_dict(dict(r)) for r in rows]

    async def insert_interface(self, iface: Any) -> None:
        async with self._conn() as db:
            d = iface.to_dict()
            await db.execute(
                """INSERT OR REPLACE INTO interfaces
                   (id, name, interface_type, ip_assignment, ip_address, gateway,
                    zone_id, logs_allowed, status, speed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["name"], d["interface_type"], d["ip_assignment"],
                 d["ip_address"], d["gateway"], d["zone_id"],
                 int(d["logs_allowed"]), d["status"], d["speed"]),
            )
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # URL Filters
    # ───────────────────────────────────────────────────────────────────
    async def get_url_filters(self) -> list[str]:
        async with self._conn() as db:
            cursor = await db.execute("SELECT url FROM url_filters")
            rows = await cursor.fetchall()
            return [r[0] for r in rows]

    async def insert_url_filter(self, url: str) -> None:
        import time, uuid
        uid = uuid.uuid4().hex[:12]
        now = time.time()
        async with self._conn() as db:
            await db.execute(
                "INSERT OR IGNORE INTO url_filters (id, url, created_at) VALUES (?, ?, ?)",
                (uid, url, now)
            )
            await db.commit()

    async def delete_url_filter(self, url: str) -> None:
        async with self._conn() as db:
            await db.execute("DELETE FROM url_filters WHERE url = ?", (url,))
            await db.commit()

    # ───────────────────────────────────────────────────────────────────
    # SP3 Logger (High Throughput)
    # ───────────────────────────────────────────────────────────────────
    async def insert_sp3_log(self, log_record: Any) -> None:
        async with self._conn() as db:
            d = log_record.to_dict()
            await db.execute(
                """INSERT INTO sp3_logs
                   (id, timestamp, src_ip, dst_ip, protocol, service, policy_action, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["timestamp"], d["src_ip"], d["dst_ip"],
                 d["protocol"], d["service"], d["policy_action"], d["details"])
            )
            await db.commit()

    async def get_recent_sp3_logs(self, limit: int = 100) -> list[Any]:
        async with self._conn() as db:
            cursor = await db.execute(
                "SELECT * FROM sp3_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            from aerocifer.db.models import Sp3Log
            return [Sp3Log.from_dict(dict(r)) for r in rows]
