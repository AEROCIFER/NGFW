"""
AEROCIFER NGFW — Zone Manager

Network segmentation with zone-based security policies:
- Zone CRUD with database persistence
- Device-to-zone assignment (manual + auto via ML)
- Inter-zone traffic policy enforcement
- Subnet and VLAN management
- Zone-aware packet filtering
"""

from __future__ import annotations

import json
import asyncio
import time
from typing import Optional, Any

from aerocifer.utils.logger import get_logger
from aerocifer.utils.validators import (
    validate_zone_name, validate_subnet, validate_ip, ip_in_subnet,
)
from aerocifer.db.models import (
    Zone, Device, InterZoneRule, ZonePolicy, RuleAction,
)

log = get_logger("core")


class ZoneManager:
    """
    Manages network security zones.

    A zone represents a logical network segment with its own security policy.
    Devices are assigned to zones, and inter-zone traffic is governed by
    inter-zone rules.

    Usage:
        zm = ZoneManager(db)
        await zm.initialize()

        # Create zones
        iot_zone = await zm.create_zone("iot_network", subnet="192.168.10.0/24",
                                         policy=ZonePolicy.RESTRICTIVE)

        # Assign device
        await zm.assign_device("192.168.10.5", iot_zone.id)

        # Check inter-zone policy
        action = await zm.check_inter_zone(src_zone_id, dst_zone_id, "tcp")
    """

    def __init__(self, db: Any = None):
        self._db = db
        # In-memory caches
        self._zones: dict[str, Zone] = {}           # zone_id → Zone
        self._zone_by_name: dict[str, str] = {}     # name → zone_id
        self._device_zones: dict[str, str] = {}     # device_ip → zone_id
        self._inter_zone_rules: list[InterZoneRule] = []
        self._initialized = False

    @property
    def zones(self) -> dict[str, Zone]:
        return dict(self._zones)

    @property
    def zone_count(self) -> int:
        return len(self._zones)

    async def initialize(self) -> None:
        """Load zones, devices, and inter-zone rules from database."""
        if self._db:
            zones = await self._db.get_all_zones()
            for zone in zones:
                self._zones[zone.id] = zone
                self._zone_by_name[zone.name.lower()] = zone.id

            # Load device→zone mappings
            devices = await self._db.get_all_devices()
            for device in devices:
                if device.zone_id:
                    self._device_zones[device.ip] = device.zone_id

            # Load inter-zone rules
            self._inter_zone_rules = await self._db.get_inter_zone_rules()

            log.info(
                f"Zone manager initialized: {len(self._zones)} zones, "
                f"{len(self._device_zones)} device mappings, "
                f"{len(self._inter_zone_rules)} inter-zone rules"
            )

        self._initialized = True

    # ───────────────────────────────────────────────────────────────────
    # Zone CRUD
    # ───────────────────────────────────────────────────────────────────

    async def create_zone(
        self,
        name: str,
        description: str = "",
        subnet: str = "",
        vlan_id: Optional[int] = None,
        policy: ZonePolicy = ZonePolicy.STANDARD,
        allowed_protocols: Optional[list[str]] = None,
        blocked_protocols: Optional[list[str]] = None,
        max_bandwidth_mbps: Optional[int] = None,
    ) -> Zone:
        """
        Create a new security zone.

        Args:
            name: Unique zone name (e.g. "iot_network")
            description: Human-readable description
            subnet: CIDR subnet for this zone
            vlan_id: Optional VLAN ID
            policy: Security policy level
            allowed_protocols: Whitelist of allowed protocols
            blocked_protocols: Blacklist of blocked protocols
            max_bandwidth_mbps: Optional bandwidth limit

        Returns:
            The created Zone object

        Raises:
            ValueError: If zone name is invalid or already exists
        """
        name = validate_zone_name(name)

        if name.lower() in self._zone_by_name:
            raise ValueError(f"Zone '{name}' already exists")

        if subnet:
            subnet = validate_subnet(subnet)

        zone = Zone(
            name=name,
            description=description,
            subnet=subnet,
            vlan_id=vlan_id,
            policy=policy,
            allowed_protocols=json.dumps(allowed_protocols or []),
            blocked_protocols=json.dumps(blocked_protocols or []),
            max_bandwidth_mbps=max_bandwidth_mbps,
        )

        # Persist
        if self._db:
            await self._db.insert_zone(zone)

        # Cache
        self._zones[zone.id] = zone
        self._zone_by_name[name.lower()] = zone.id

        log.info(
            f"Zone created: {name} (id={zone.id}, subnet={subnet}, "
            f"policy={policy.value})",
            extra={"zone": name},
        )
        return zone

    async def update_zone(
        self, zone_id: str, **kwargs: Any
    ) -> Optional[Zone]:
        """Update zone properties."""
        zone = self._zones.get(zone_id)
        if not zone:
            log.warning(f"Zone not found: {zone_id}")
            return None

        for key, value in kwargs.items():
            if hasattr(zone, key):
                if key == "name":
                    value = validate_zone_name(value)
                    # Update name index
                    old_name = zone.name.lower()
                    self._zone_by_name.pop(old_name, None)
                    self._zone_by_name[value.lower()] = zone_id
                elif key == "subnet" and value:
                    value = validate_subnet(value)
                elif key == "allowed_protocols" and isinstance(value, list):
                    value = json.dumps(value)
                elif key == "blocked_protocols" and isinstance(value, list):
                    value = json.dumps(value)
                setattr(zone, key, value)

        zone.updated_at = time.time()

        if self._db:
            await self._db.insert_zone(zone)  # UPSERT

        log.info(f"Zone updated: {zone.name} ({zone_id})")
        return zone

    async def delete_zone(self, zone_id: str) -> bool:
        """Soft-delete a zone and unassign its devices."""
        zone = self._zones.pop(zone_id, None)
        if not zone:
            return False

        self._zone_by_name.pop(zone.name.lower(), None)

        # Un-assign devices
        ips_to_remove = [
            ip for ip, zid in self._device_zones.items() if zid == zone_id
        ]
        for ip in ips_to_remove:
            self._device_zones.pop(ip, None)

        if self._db:
            await self._db.delete_zone(zone_id)

        log.info(
            f"Zone deleted: {zone.name} ({zone_id}), "
            f"unassigned {len(ips_to_remove)} devices"
        )
        return True

    def get_zone_by_name(self, name: str) -> Optional[Zone]:
        """Look up a zone by name."""
        zone_id = self._zone_by_name.get(name.lower())
        if zone_id:
            return self._zones.get(zone_id)
        return None

    def get_zone_by_id(self, zone_id: str) -> Optional[Zone]:
        """Look up a zone by ID."""
        return self._zones.get(zone_id)

    # ───────────────────────────────────────────────────────────────────
    # Device-to-Zone Assignment
    # ───────────────────────────────────────────────────────────────────

    async def assign_device(
        self, device_ip: str, zone_id: str
    ) -> bool:
        """Assign a device to a zone."""
        if zone_id not in self._zones:
            log.warning(f"Cannot assign device to unknown zone: {zone_id}")
            return False

        validate_ip(device_ip)
        old_zone = self._device_zones.get(device_ip)
        self._device_zones[device_ip] = zone_id

        if self._db:
            device = await self._db.get_device_by_ip(device_ip)
            if device:
                await self._db.assign_device_to_zone(device.id, zone_id)

        zone = self._zones[zone_id]
        log.info(
            f"Device {device_ip} assigned to zone '{zone.name}'"
            + (f" (was in zone '{self._zones.get(old_zone, Zone(name='none')).name}')"
               if old_zone else ""),
            extra={"zone": zone.name},
        )
        return True

    async def unassign_device(self, device_ip: str) -> None:
        """Remove a device from its zone."""
        self._device_zones.pop(device_ip, None)
        if self._db:
            device = await self._db.get_device_by_ip(device_ip)
            if device:
                await self._db.assign_device_to_zone(device.id, "")

    def get_device_zone(self, device_ip: str) -> Optional[str]:
        """Get the zone ID for a device IP."""
        zone_id = self._device_zones.get(device_ip)
        if zone_id:
            return zone_id

        # Fall back to subnet matching
        for zone in self._zones.values():
            if zone.subnet and ip_in_subnet(device_ip, zone.subnet):
                return zone.id

        return None

    def get_zone_for_ip(self, ip: str) -> Optional[Zone]:
        """Get the Zone object for an IP address."""
        zone_id = self.get_device_zone(ip)
        if zone_id:
            return self._zones.get(zone_id)
        return None

    # ───────────────────────────────────────────────────────────────────
    # Inter-Zone Policy
    # ───────────────────────────────────────────────────────────────────

    async def add_inter_zone_rule(
        self,
        src_zone_id: str,
        dst_zone_id: str,
        action: RuleAction = RuleAction.DROP,
        protocol: str = "any",
        description: str = "",
        priority: int = 100,
    ) -> InterZoneRule:
        """Add a rule governing traffic between two zones."""
        if src_zone_id not in self._zones:
            raise ValueError(f"Source zone not found: {src_zone_id}")
        if dst_zone_id not in self._zones:
            raise ValueError(f"Destination zone not found: {dst_zone_id}")

        rule = InterZoneRule(
            source_zone_id=src_zone_id,
            dest_zone_id=dst_zone_id,
            action=action,
            protocol=protocol,
            description=description,
            priority=priority,
        )

        self._inter_zone_rules.append(rule)
        self._inter_zone_rules.sort(key=lambda r: r.priority)

        if self._db:
            await self._db.insert_inter_zone_rule(rule)

        src_name = self._zones[src_zone_id].name
        dst_name = self._zones[dst_zone_id].name
        log.info(
            f"Inter-zone rule: {src_name} -> {dst_name} = "
            f"{action.value} ({protocol})"
        )
        return rule

    def check_inter_zone(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "any",
    ) -> RuleAction:
        """
        Check the inter-zone policy for traffic between two IPs.
        Returns the action to take (ACCEPT, DROP, etc.)
        """
        src_zone_id = self.get_device_zone(src_ip)
        dst_zone_id = self.get_device_zone(dst_ip)

        # Same zone or unknown zones → allow
        if not src_zone_id or not dst_zone_id:
            return RuleAction.ACCEPT
        if src_zone_id == dst_zone_id:
            return RuleAction.ACCEPT

        # Check inter-zone rules (sorted by priority)
        for rule in self._inter_zone_rules:
            if not rule.enabled:
                continue
            if rule.source_zone_id == src_zone_id and rule.dest_zone_id == dst_zone_id:
                if rule.protocol == "any" or rule.protocol == protocol:
                    return rule.action

        # Default inter-zone policy (deny by default)
        return RuleAction.DROP

    def is_protocol_allowed_in_zone(
        self, zone_id: str, protocol: str
    ) -> bool:
        """Check if a protocol is allowed in a specific zone."""
        zone = self._zones.get(zone_id)
        if not zone:
            return True  # Unknown zone → allow

        # Check blocklist first
        blocked = json.loads(zone.blocked_protocols)
        if blocked and protocol.lower() in [p.lower() for p in blocked]:
            return False

        # Check allowlist (if defined, only listed protocols are allowed)
        allowed = json.loads(zone.allowed_protocols)
        if allowed:
            return protocol.lower() in [p.lower() for p in allowed]

        # No explicit lists → allow based on policy
        return True

    # ───────────────────────────────────────────────────────────────────
    # Auto-Classification Support (for AI module)
    # ───────────────────────────────────────────────────────────────────

    async def auto_assign_device(
        self, device_ip: str, device_type: str, confidence: float = 0.0
    ) -> Optional[str]:
        """
        Automatically assign a device to the most appropriate zone
        based on its classified device type.

        Returns the zone_id it was assigned to, or None.
        """
        # Build a mapping of device types to zones
        type_zone_map: dict[str, str] = {}
        for zone in self._zones.values():
            name_lower = zone.name.lower()
            if "iot" in name_lower:
                for dt in ["iot_sensor", "iot_camera", "iot_thermostat",
                           "iot_gateway", "smart_tv"]:
                    type_zone_map[dt] = zone.id
            elif "server" in name_lower:
                type_zone_map["server"] = zone.id
            elif any(kw in name_lower for kw in
                     ["basic", "user", "workstation", "office"]):
                for dt in ["workstation", "phone", "tablet",
                           "gaming_console", "printer"]:
                    type_zone_map[dt] = zone.id

        target_zone = type_zone_map.get(device_type)
        if target_zone:
            await self.assign_device(device_ip, target_zone)
            log.info(
                f"Auto-assigned {device_ip} (type={device_type}, "
                f"confidence={confidence:.2f}) to zone "
                f"'{self._zones[target_zone].name}'"
            )
            return target_zone

        return None

    # ───────────────────────────────────────────────────────────────────
    # Status
    # ───────────────────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get zone manager status."""
        zone_summaries = []
        for zone in self._zones.values():
            device_count = sum(
                1 for zid in self._device_zones.values() if zid == zone.id
            )
            zone_summaries.append({
                "id": zone.id,
                "name": zone.name,
                "subnet": zone.subnet,
                "policy": zone.policy.value,
                "device_count": device_count,
                "vlan_id": zone.vlan_id,
            })

        return {
            "initialized": self._initialized,
            "zone_count": len(self._zones),
            "device_assignments": len(self._device_zones),
            "inter_zone_rules": len(self._inter_zone_rules),
            "zones": zone_summaries,
        }
