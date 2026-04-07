"""
Tests for AEROCIFER NGFW Foundation Components

Validates:
- Configuration loading and defaults
- Database schema creation and CRUD
- Validator functions
- Session tracker flow tracking and feature extraction
- Zone manager operations
- Rule engine cache behavior
"""

import asyncio
import os
import sys
import json
import tempfile
import time

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def run_async(coro):
    """Helper to run async tests."""
    return asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════════════════
# Configuration Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_config_defaults():
    """Test that default configuration loads correctly."""
    from aerocifer.config import AerociferConfig
    config = AerociferConfig()

    assert config.network.batch_size == 64
    assert config.security.ddos_threshold_pps == 100
    assert config.dpi.enabled is True
    assert config.ml.enabled is True
    assert config.zones.default_inter_zone_policy == "deny"
    assert config.database.engine == "sqlite"
    assert config.logging.level == "INFO"
    assert config.api.port == 8443
    print("[OK] test_config_defaults PASSED")


def test_config_load_from_yaml():
    """Test loading config from a YAML file."""
    from aerocifer.config import load_config, save_config, AerociferConfig

    config = AerociferConfig()
    config.network.batch_size = 128
    config.security.ddos_threshold_pps = 200

    with tempfile.NamedTemporaryFile(
        suffix=".yaml", delete=False, mode="w"
    ) as f:
        path = f.name

    try:
        save_config(config, path)
        loaded = load_config(path)
        assert loaded.network.batch_size == 128
        assert loaded.security.ddos_threshold_pps == 200
        print("[OK] test_config_load_from_yaml PASSED")
    finally:
        os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════
# Validator Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_validators():
    """Test input validators."""
    from aerocifer.utils.validators import (
        validate_ip, validate_subnet, validate_port,
        validate_mac, validate_zone_name, validate_protocol,
        validate_port_range, sanitize_shell_arg,
        ip_in_subnet, is_private_ip,
    )

    # IP validation
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_ip("::1") == "::1"
    try:
        validate_ip("not_an_ip")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    # Subnet
    assert validate_subnet("192.168.1.0/24") == "192.168.1.0/24"

    # Port
    assert validate_port(80) == 80
    try:
        validate_port(99999)
        assert False
    except ValueError:
        pass

    # Port range
    assert validate_port_range("80-443") == (80, 443)
    assert validate_port_range("8080") == (8080, 8080)

    # MAC
    assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert validate_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    # Zone name
    assert validate_zone_name("iot_network") == "iot_network"
    try:
        validate_zone_name("1bad")
        assert False
    except ValueError:
        pass

    # Protocol
    assert validate_protocol("TCP") == "tcp"

    # Shell sanitization
    assert sanitize_shell_arg("192.168.1.1") == "192.168.1.1"
    try:
        sanitize_shell_arg("192.168.1.1; rm -rf /")
        assert False
    except ValueError:
        pass

    # IP in subnet
    assert ip_in_subnet("192.168.1.5", "192.168.1.0/24") is True
    assert ip_in_subnet("10.0.0.1", "192.168.1.0/24") is False

    # Private IP
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("8.8.8.8") is False

    print("[OK] test_validators PASSED")


# ═══════════════════════════════════════════════════════════════════════════
# Database Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_database():
    """Test database schema creation and CRUD operations."""

    async def _test():
        from aerocifer.db.database import Database
        from aerocifer.db.models import (
            Device, Zone, FirewallRule, RuleAction,
            Threat, ThreatType, ThreatSeverity, Event,
            DeviceType, ZonePolicy,
        )

        with tempfile.NamedTemporaryFile(
            suffix=".db", delete=False
        ) as f:
            db_path = f.name

        try:
            db = Database(db_path)
            await db.initialize()

            # --- Device CRUD ---
            device = Device(
                ip="192.168.1.10",
                mac="aa:bb:cc:dd:ee:ff",
                hostname="test-device",
                device_type=DeviceType.IOT_SENSOR,
            )
            await db.insert_device(device)

            fetched = await db.get_device_by_ip("192.168.1.10")
            assert fetched is not None
            assert fetched.mac == "aa:bb:cc:dd:ee:ff"
            assert fetched.device_type == DeviceType.IOT_SENSOR

            all_devices = await db.get_all_devices()
            assert len(all_devices) == 1

            # --- Zone CRUD ---
            zone = Zone(
                name="iot_network",
                subnet="192.168.10.0/24",
                policy=ZonePolicy.RESTRICTIVE,
            )
            await db.insert_zone(zone)

            fetched_zone = await db.get_zone_by_name("iot_network")
            assert fetched_zone is not None
            assert fetched_zone.subnet == "192.168.10.0/24"

            # --- Firewall Rule ---
            rule = FirewallRule(
                action=RuleAction.DROP,
                src_ip="10.0.0.5",
                description="Test block",
            )
            await db.insert_rule(rule)

            # --- Threat ---
            threat = Threat(
                threat_type=ThreatType.DDOS,
                severity=ThreatSeverity.HIGH,
                source_ip="10.0.0.5",
                description="Test DDoS",
            )
            await db.insert_threat(threat)

            threats = await db.get_recent_threats()
            assert len(threats) == 1

            # --- Event ---
            event = Event(
                event_type="test",
                message="Test event",
            )
            await db.insert_event(event)

            # --- Table counts ---
            counts = await db.get_table_counts()
            assert counts["devices"] == 1
            assert counts["zones"] == 1
            assert counts["threats"] == 1

            await db.close()
            print("[OK] test_database PASSED")
        finally:
            os.unlink(db_path)

    run_async(_test())


# ═══════════════════════════════════════════════════════════════════════════
# Session Tracker Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_session_tracker():
    """Test flow tracking and feature extraction."""
    from aerocifer.core.session_tracker import SessionTracker, FlowEntry

    tracker = SessionTracker()

    # Track a forward packet
    flow = tracker.track_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=45678,
        dst_port=80,
        protocol="tcp",
        packet_size=500,
        tcp_flags=0x02,  # SYN
    )

    assert flow.src_ip == "192.168.1.10"
    assert flow.fwd_packets == 1
    assert flow.fwd_bytes == 500
    assert flow.syn_count == 1

    # Track reverse packet (SYN-ACK)
    flow2 = tracker.track_packet(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=45678,
        protocol="tcp",
        packet_size=60,
        tcp_flags=0x12,  # SYN+ACK
    )

    # Should be the same flow (bidirectional)
    assert flow2 is flow
    assert flow.bwd_packets == 1
    assert flow.total_packets == 2

    # Track more forward packets
    for _ in range(10):
        tracker.track_packet(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=45678,
            dst_port=80,
            protocol="tcp",
            packet_size=1400,
            tcp_flags=0x18,  # PSH+ACK
            payload_size=1360,
        )

    assert flow.fwd_packets == 11
    assert flow.total_packets == 12
    assert tracker.active_flow_count == 1

    # Extract ML features
    features = flow.extract_features()
    assert "total_packets" in features
    assert features["total_packets"] == 12.0
    assert "packets_per_second" in features
    assert "payload_entropy" in features
    assert "syn_ratio" in features
    assert "fwd_bwd_ratio" in features
    assert features["is_tcp"] == 1.0
    assert features["dst_port"] == 80.0
    assert len(features) > 40  # Should have 40+ features

    print("[OK] test_session_tracker PASSED")


# ═══════════════════════════════════════════════════════════════════════════
# Rule Engine Cache Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_rule_cache():
    """Test the in-memory rule cache."""

    async def _test():
        from aerocifer.core.rule_engine import RuleCache
        from aerocifer.db.models import FirewallRule, RuleAction

        cache = RuleCache()

        # Add block rule
        rule = FirewallRule(
            action=RuleAction.DROP,
            src_ip="10.0.0.5",
            description="Test block",
        )
        await cache.add_rule(rule)

        # Fast check
        assert cache.is_blocked("10.0.0.5") is True
        assert cache.is_blocked("10.0.0.6") is False

        # Full match
        match = cache.match_packet("10.0.0.5", "192.168.1.1", 0, 80, "tcp")
        assert match is not None
        assert match.action == RuleAction.DROP

        # No match for different IP
        match = cache.match_packet("10.0.0.6", "192.168.1.1", 0, 80, "tcp")
        assert match is None

        # Add expiring rule
        rule2 = FirewallRule(
            action=RuleAction.DROP,
            src_ip="10.0.0.7",
            expires_at=time.time() - 10,  # Already expired
        )
        await cache.add_rule(rule2)

        # Expired rule should not match
        match = cache.match_packet("10.0.0.7", "192.168.1.1", 0, 80, "tcp")
        assert match is None  # Expired

        # Remove rule
        await cache.remove_rule(rule.id)
        assert cache.is_blocked("10.0.0.5") is False

        print("[OK] test_rule_cache PASSED")

    run_async(_test())


# ═══════════════════════════════════════════════════════════════════════════
# Zone Manager Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_zone_manager():
    """Test zone management operations."""

    async def _test():
        from aerocifer.core.zone_manager import ZoneManager
        from aerocifer.db.models import ZonePolicy, RuleAction

        zm = ZoneManager()  # No DB for testing

        # Create zones
        iot_zone = await zm.create_zone(
            name="iot_network",
            subnet="192.168.10.0/24",
            policy=ZonePolicy.RESTRICTIVE,
            allowed_protocols=["mqtt", "coap", "https"],
        )
        basic_zone = await zm.create_zone(
            name="basic_devices",
            subnet="192.168.20.0/24",
            policy=ZonePolicy.STANDARD,
        )

        assert zm.zone_count == 2

        # Assign devices
        await zm.assign_device("192.168.10.5", iot_zone.id)
        await zm.assign_device("192.168.20.10", basic_zone.id)

        # Check device zone
        assert zm.get_device_zone("192.168.10.5") == iot_zone.id
        assert zm.get_device_zone("192.168.20.10") == basic_zone.id

        # Subnet-based zone detection
        assert zm.get_device_zone("192.168.10.99") == iot_zone.id

        # Inter-zone policy (default deny)
        action = zm.check_inter_zone("192.168.10.5", "192.168.20.10")
        assert action == RuleAction.DROP  # Different zones → deny

        # Same zone → allow
        action = zm.check_inter_zone("192.168.10.5", "192.168.10.99")
        assert action == RuleAction.ACCEPT

        # Add inter-zone rule
        await zm.add_inter_zone_rule(
            iot_zone.id, basic_zone.id,
            action=RuleAction.ACCEPT,
            protocol="https",
        )

        # Now IoT → Basic allowed for HTTPS
        action = zm.check_inter_zone(
            "192.168.10.5", "192.168.20.10", "https"
        )
        assert action == RuleAction.ACCEPT

        # Protocol check
        assert zm.is_protocol_allowed_in_zone(iot_zone.id, "mqtt") is True
        assert zm.is_protocol_allowed_in_zone(iot_zone.id, "ftp") is False

        # Duplicate zone name
        try:
            await zm.create_zone("iot_network")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

        # Delete zone
        result = await zm.delete_zone(iot_zone.id)
        assert result is True
        assert zm.zone_count == 1

        print("[OK] test_zone_manager PASSED")

    run_async(_test())


# ═══════════════════════════════════════════════════════════════════════════
# Model Serialization Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_model_serialization():
    """Test model to_dict/from_dict roundtrip."""
    from aerocifer.db.models import (
        Device, DeviceType, Zone, ZonePolicy,
        FirewallRule, RuleAction, Threat, ThreatType, ThreatSeverity,
    )

    # Device roundtrip
    device = Device(
        ip="192.168.1.1",
        mac="aa:bb:cc:dd:ee:ff",
        device_type=DeviceType.IOT_CAMERA,
    )
    d = device.to_dict()
    assert d["device_type"] == "iot_camera"
    restored = Device.from_dict(d)
    assert restored.device_type == DeviceType.IOT_CAMERA
    assert restored.ip == "192.168.1.1"

    # Zone roundtrip
    zone = Zone(name="test", policy=ZonePolicy.RESTRICTIVE)
    d = zone.to_dict()
    restored = Zone.from_dict(d)
    assert restored.policy == ZonePolicy.RESTRICTIVE

    # Threat roundtrip
    threat = Threat(
        threat_type=ThreatType.DDOS,
        severity=ThreatSeverity.CRITICAL,
        source_ip="10.0.0.1",
    )
    d = threat.to_dict()
    assert d["threat_type"] == "ddos"
    restored = Threat.from_dict(d)
    assert restored.threat_type == ThreatType.DDOS

    print("[OK] test_model_serialization PASSED")


# ═══════════════════════════════════════════════════════════════════════════
# Logger Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_logger():
    """Test structured logging system."""
    from aerocifer.utils.logger import get_logger, setup_logging

    setup_logging(level="DEBUG", console_output=True, file_output=False)

    log = get_logger("core")
    log.debug("Debug message from core")
    log.info("Info message from core")
    log.warning("Warning message", extra={"src_ip": "10.0.0.1"})

    log2 = get_logger("dpi")
    log2.info("DPI module loaded")

    log3 = get_logger("ml")
    log3.info("ML engine initialized")

    print("[OK] test_logger PASSED")


# ═══════════════════════════════════════════════════════════════════════════
# Run All Tests
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AEROCIFER NGFW — Foundation Test Suite")
    print("=" * 60 + "\n")

    tests = [
        ("Configuration", test_config_defaults),
        ("Config YAML", test_config_load_from_yaml),
        ("Validators", test_validators),
        ("Logger", test_logger),
        ("Model Serialization", test_model_serialization),
        ("Database", test_database),
        ("Session Tracker", test_session_tracker),
        ("Rule Cache", test_rule_cache),
        ("Zone Manager", test_zone_manager),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            print(f"\nRunning: {name}...")
            test_func()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
