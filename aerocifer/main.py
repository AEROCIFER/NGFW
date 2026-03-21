"""
AEROCIFER NGFW — Main Entry Point

Orchestrates all components with:
- Async event loop with graceful shutdown
- Component initialization in correct dependency order
- Signal handling (SIGINT, SIGTERM)
- Health monitoring
- Central packet processing pipeline

This is the single entry point for the entire firewall engine.

Usage:
    python -m aerocifer.main
    python -m aerocifer.main --config /path/to/config.yaml
    python -m aerocifer.main --generate-config
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
import platform
from typing import Optional

# Ensure the project root is in the path
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from aerocifer import __version__
from aerocifer.config import load_config, generate_default_config, AerociferConfig
from aerocifer.utils.logger import setup_logging, get_logger, timed_operation
from aerocifer.db.database import Database
from aerocifer.db.models import (
    Device, Event, Threat, ThreatType, ThreatSeverity, RuleAction,
)
from aerocifer.core.packet_engine import PacketEngine, RawPacket
from aerocifer.core.rule_engine import RuleEngine
from aerocifer.core.session_tracker import SessionTracker
from aerocifer.core.zone_manager import ZoneManager
from aerocifer.core.protocol_inspector import ProtocolInspector
from aerocifer.ml.anomaly_detector import TrafficAnomalyDetector
from aerocifer.ml.device_classifier import DeviceZoneClassifier

log = get_logger("main")


# ═══════════════════════════════════════════════════════════════════════════
# NGFW Application
# ═══════════════════════════════════════════════════════════════════════════

class AerociferNGFW:
    """
    Main application class that wires all components together.

    Component Initialization Order:
        1. Configuration
        2. Logging
        3. Database
        4. Rule Engine (loads rules from DB)
        5. Zone Manager (loads zones from DB)
        6. Session Tracker
        7. Protocol Inspector (registers DPI modules)
        8. Packet Engine (starts capture + processing)
        9. API Server (optional)

    Packet Processing Pipeline:
        Capture → Queue → Worker → Pipeline:
            1. Rule Check (is IP blocked?)
            2. Zone Policy Check (inter-zone allowed?)
            3. Session Tracking (update flow table)
            4. Protocol Inspection (DPI)
            5. ML Inference (anomaly/classification)
            6. Threat Response (block if needed)
    """

    def __init__(self, config: AerociferConfig):
        self.config = config
        self._running = False
        self._start_time: float = 0

        # Components (initialized in start())
        self.db: Optional[Database] = None
        self.rule_engine: Optional[RuleEngine] = None
        self.zone_manager: Optional[ZoneManager] = None
        self.session_tracker: Optional[SessionTracker] = None
        self.protocol_inspector: Optional[ProtocolInspector] = None
        self.packet_engine: Optional[PacketEngine] = None
        self.anomaly_detector: Optional[TrafficAnomalyDetector] = None
        self.device_classifier: Optional[DeviceZoneClassifier] = None

        # Statistics
        self._threats_blocked = 0
        self._packets_allowed = 0
        self._packets_dropped = 0

    @property
    def uptime(self) -> float:
        if self._start_time:
            return time.time() - self._start_time
        return 0

    # ───────────────────────────────────────────────────────────────────
    # Startup
    # ───────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize and start all components."""
        self._start_time = time.time()
        self._running = True

        log.info("=" * 60)
        log.info(f"  AEROCIFER NGFW v{__version__}")
        log.info(f"  AI-Powered Next-Generation Firewall")
        log.info(f"  Platform: {platform.system()} {platform.release()}")
        log.info("=" * 60)

        # 1. Database
        log.info("Initializing database...")
        self.db = Database(
            db_path=self.config.database.path,
            wal_mode=self.config.database.wal_mode,
        )
        await self.db.initialize()

        # Log startup event
        await self.db.insert_event(Event(
            event_type="system_start",
            message=f"AEROCIFER NGFW v{__version__} starting",
            component="main",
            severity="info",
        ))

        # 2. Rule Engine
        log.info("Initializing rule engine...")
        self.rule_engine = RuleEngine(
            db=self.db,
            default_block_duration=self.config.security.block_duration_seconds,
        )
        await self.rule_engine.initialize()

        # 3. Zone Manager
        log.info("Initializing zone manager...")
        self.zone_manager = ZoneManager(db=self.db)
        await self.zone_manager.initialize()

        # 4. Session Tracker
        log.info("Initializing session tracker...")
        self.session_tracker = SessionTracker(
            db=self.db,
            on_flow_complete=self._on_flow_complete,
        )
        await self.session_tracker.start()

        # 5. ML Models
        log.info("Initializing Machine Learning models...")
        ml_flags = getattr(self.config, 'ml', None)
        default_model_dir = (ml_flags.model_dir if ml_flags and getattr(ml_flags, 'model_dir', None) else "data/models")
        
        self.anomaly_detector = TrafficAnomalyDetector(
            model_dir=default_model_dir,
            threshold=0.5
        )
        self.device_classifier = DeviceZoneClassifier(
            model_dir=default_model_dir
        )
        
        # 6. Protocol Inspector
        log.info("Initializing protocol inspector...")
        self.protocol_inspector = ProtocolInspector()
        self._register_default_inspectors()

        # 7. Packet Engine
        log.info("Initializing packet engine...")
        self.packet_engine = PacketEngine(
            interfaces=self.config.network.interfaces,
            capture_filter=self.config.network.capture_filter,
            queue_max_size=self.config.network.queue_max_size,
            batch_size=self.config.network.batch_size,
            worker_count=self.config.network.worker_count,
            promiscuous=self.config.network.promiscuous,
        )

        # Register the main packet processing pipeline
        self.packet_engine.add_handler(self._process_packet)

        # Start packet capture
        await self.packet_engine.start()

        # 7. Start periodic tasks
        asyncio.create_task(self._stats_reporter())
        asyncio.create_task(self._rule_cleanup_task())

        log.info("=" * 60)
        log.info("  AEROCIFER NGFW is ACTIVE and protecting the network")
        log.info(f"  Rule Engine: {self.rule_engine.get_status()}")
        log.info(f"  Zone Manager: {self.zone_manager.zone_count} zones")
        log.info(f"  Interfaces: {self.config.network.interfaces}")
        log.info("=" * 60)

    # ───────────────────────────────────────────────────────────────────
    # Shutdown
    # ───────────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        """Gracefully stop all components."""
        if not self._running:
            return

        log.info("Initiating graceful shutdown...")
        self._running = False

        # Stop in reverse order
        if self.packet_engine:
            await self.packet_engine.stop()

        if self.session_tracker:
            await self.session_tracker.stop()

        # Log shutdown event
        if self.db:
            await self.db.insert_event(Event(
                event_type="system_stop",
                message=(
                    f"AEROCIFER NGFW stopped after "
                    f"{self.uptime:.0f}s uptime. "
                    f"Threats blocked: {self._threats_blocked}"
                ),
                component="main",
                severity="info",
            ))
            await self.db.close()

        log.info(
            f"AEROCIFER NGFW stopped. Uptime: {self.uptime:.0f}s, "
            f"Packets processed: {self._packets_allowed + self._packets_dropped}, "
            f"Threats blocked: {self._threats_blocked}"
        )

    # ───────────────────────────────────────────────────────────────────
    # Main Packet Processing Pipeline
    # ───────────────────────────────────────────────────────────────────

    async def _process_packet(self, packet: RawPacket) -> None:
        """
        Central packet processing pipeline.
        Called by packet engine workers for each captured packet.
        """
        assert self.rule_engine is not None
        assert self.zone_manager is not None
        assert self.session_tracker is not None
        assert self.protocol_inspector is not None

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        # ---- Step 1: Fast rule check ----
        if self.rule_engine.is_ip_blocked(src_ip):
            self._packets_dropped += 1
            return

        rule_match = self.rule_engine.check_packet(
            src_ip, dst_ip, packet.src_port,
            packet.dst_port, packet.protocol
        )
        if rule_match and rule_match.action == RuleAction.DROP:
            self._packets_dropped += 1
            return

        # ---- Step 2: Zone policy check ----
        if self.config.zones.enabled:
            zone_action = self.zone_manager.check_inter_zone(
                src_ip, dst_ip, packet.protocol
            )
            if zone_action == RuleAction.DROP:
                self._packets_dropped += 1
                return

        # ---- Step 3: Session / flow tracking ----
        payload_bytes = b""
        payload_size = 0
        if packet.has_payload and packet.raw_packet:
            try:
                from scapy.all import Raw  # type: ignore[import-untyped]
                if packet.raw_packet.haslayer(Raw):
                    payload_bytes = bytes(packet.raw_packet[Raw].load)
                    payload_size = len(payload_bytes)
            except Exception:
                pass

        flow = self.session_tracker.track_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            packet_size=packet.length,
            tcp_flags=packet.tcp_flags,
            payload_size=payload_size,
            payload=payload_bytes,
        )

        # Attach zone info to flow
        flow.src_zone_id = self.zone_manager.get_device_zone(src_ip)
        flow.dst_zone_id = self.zone_manager.get_device_zone(dst_ip)

        # ---- Step 4: Protocol inspection (DPI) ----
        if self.config.dpi.enabled:
            results = await self.protocol_inspector.inspect(packet)
            for result in results:
                if result.protocol and not flow.application:
                    flow.application = result.protocol

                if result.is_threat:
                    await self._handle_threat(packet, flow, result)
                    return

        # ---- Step 5: DDoS detection (rate-based) ----
        stats = self.packet_engine.stats if self.packet_engine else None
        if stats and stats.packets_per_second > self.config.security.ddos_threshold_pps:
            # Check if this specific IP is responsible
            flows = self.session_tracker.get_flows_for_ip(src_ip)
            ip_pps = sum(f.fwd_packets for f in flows) / max(
                max(f.duration for f in flows) if flows else 1, 0.1
            )
            if ip_pps > self.config.security.ddos_threshold_pps:
                await self._handle_ddos(src_ip, ip_pps)
                return

        # ---- Step 6: ML inference (Anomaly Detection) ----
        if self.anomaly_detector and flow.total_packets >= 5:
            # We only evaluate flows that have some meat to them
            is_anomaly, loss = self.anomaly_detector.predict(flow)
            if is_anomaly:
                # Mock result object since it didn't come from DPI
                class MLAnomalyResult:
                    threat_type = "ml_behavior_anomaly"
                    inspector = "TrafficAutoencoder"
                    details = {"reconstruction_error": loss}
                    signature_matched = f"Loss {loss:.2f} > Threshold {self.anomaly_detector.threshold}"
                    
                await self._handle_threat(packet, flow, MLAnomalyResult())
                return

        self._packets_allowed += 1

    async def _handle_threat(
        self, packet: RawPacket, flow: any, result: any
    ) -> None:
        """Handle a detected threat from DPI."""
        assert self.rule_engine is not None
        assert self.db is not None

        self._threats_blocked += 1
        self._packets_dropped += 1

        # Block the source IP
        if self.config.security.auto_block:
            await self.rule_engine.block_ip(
                packet.src_ip,
                reason=f"DPI: {result.signature_matched or result.threat_type}",
                duration=self.config.security.block_duration_seconds,
            )

        # Record threat
        threat = Threat(
            threat_type=ThreatType.SIGNATURE_MATCH,
            severity=ThreatSeverity.HIGH,
            source_ip=packet.src_ip,
            dest_ip=packet.dst_ip,
            description=(
                f"Threat detected by {result.inspector}: "
                f"{result.signature_matched or result.details}"
            ),
            action_taken="blocked",
            flow_id=flow.flow_id if hasattr(flow, 'flow_id') else "",
        )
        await self.db.insert_threat(threat)

        log.warning(
            f"THREAT DETECTED: {result.threat_type} from {packet.src_ip} "
            f"(inspector: {result.inspector})",
            extra={
                "src_ip": packet.src_ip,
                "threat_type": result.threat_type,
                "action": "blocked",
            },
        )

    async def _handle_ddos(self, src_ip: str, pps: float) -> None:
        """Handle detected DDoS attack."""
        assert self.rule_engine is not None
        assert self.db is not None

        self._threats_blocked += 1

        await self.rule_engine.block_ip(
            src_ip,
            reason=f"DDoS: {pps:.0f} pps",
            duration=self.config.security.block_duration_seconds,
        )

        threat = Threat(
            threat_type=ThreatType.DDOS,
            severity=ThreatSeverity.CRITICAL,
            source_ip=src_ip,
            description=f"DDoS attack detected: {pps:.0f} packets/second",
            action_taken="blocked",
        )
        await self.db.insert_threat(threat)

        log.critical(
            f"DDoS BLOCKED: {src_ip} at {pps:.0f} pps",
            extra={"src_ip": src_ip, "threat_type": "ddos"},
        )

    async def _on_flow_complete(self, flow: any) -> None:
        """
        Called when a flow expires or closes.
        Feeds the flow features into the Autoencoder to literally learn over time
        what regular/baseline traffic looks like.
        """
        assert self.anomaly_detector is not None
        assert self.device_classifier is not None
        assert self.zone_manager is not None
        
        # 1. Continual Learning: Fine-tune the Autoencoder on legitimate completed traffic
        # Assuming if it completed naturally and wasn't blocked, it's safe (heuristic)
        if flow.total_packets > 3:  
            await asyncio.to_thread(self.anomaly_detector.train_on_flow, flow)
            
        # 2. Automated Device Classification: Periodically check flows to identify devices
        # (E.g., mapping IP to "IoT" or "Basic")
        flows_history = self.session_tracker.get_flows_for_ip(flow.src_ip)
        if len(flows_history) > 10:
            category, confidence = await asyncio.to_thread(
                self.device_classifier.classify_device, flows_history
            )
            
            if confidence > 0.8:
                # AI Suggestion / Auto-assignment
                current_zone = self.zone_manager.get_device_zone(flow.src_ip)
                if not current_zone or category.lower() not in current_zone.lower():
                    # For Sprint 3 demo, we just log it as a powerful suggestion, 
                    # but it forms the foundation for the NLP command handler
                    log.info(f"[AI Scanner] Device {flow.src_ip} highly likely to be an "
                             f"'{category}' (conf: {confidence:.2f}). "
                             f"Current Zone: {current_zone or 'None'}")

    # ───────────────────────────────────────────────────────────────────
    # Default Inspector Registration
    # ───────────────────────────────────────────────────────────────────

    def _register_default_inspectors(self) -> None:
        """Register built-in DPI inspectors across all layers."""
        assert self.protocol_inspector is not None

        from aerocifer.dpi.layer2 import inspect_layer2
        from aerocifer.dpi.layer3 import inspect_layer3
        from aerocifer.dpi.layer4 import inspect_layer4
        from aerocifer.dpi.layer7_http import inspect_http
        from aerocifer.dpi.layer7_dns import inspect_dns
        from aerocifer.dpi.layer7_tls import inspect_tls
        from aerocifer.dpi.layer7_mqtt import inspect_mqtt, inspect_coap
        from aerocifer.dpi.signature_engine import SignatureEngine

        # ── Layer 2: Ethernet / ARP / VLAN ──
        self.protocol_inspector.register(
            name="layer2_inspector",
            func=inspect_layer2,
            layer=2,
            protocols=["arp", "ethernet", "vlan"],
            priority=10,
        )

        # ── Layer 3: IP / ICMP ──
        self.protocol_inspector.register(
            name="layer3_inspector",
            func=inspect_layer3,
            layer=3,
            protocols=["ip", "icmp"],
            priority=20,
        )

        # ── Layer 4: TCP / UDP ──
        self.protocol_inspector.register(
            name="layer4_inspector",
            func=inspect_layer4,
            layer=4,
            protocols=["tcp", "udp"],
            priority=30,
        )

        # ── Layer 7: HTTP ──
        if self.config.dpi.inspect_http:
            self.protocol_inspector.register(
                name="http_inspector",
                func=inspect_http,
                layer=7,
                protocols=["http", "http-alt"],
                ports=[80, 8080, 8000, 3000, 5000],
                priority=50,
            )

        # ── Layer 7: DNS ──
        if self.config.dpi.inspect_dns:
            self.protocol_inspector.register(
                name="dns_inspector",
                func=inspect_dns,
                layer=7,
                protocols=["dns"],
                ports=[53],
                priority=50,
            )

        # ── Layer 5: TLS / SSL ──
        if self.config.dpi.inspect_tls:
            self.protocol_inspector.register(
                name="tls_inspector",
                func=inspect_tls,
                layer=5,
                protocols=["tls", "https"],
                ports=[443, 993, 995, 8443, 465, 636, 853, 8883],
                priority=40,
            )

        # ── Layer 7: MQTT (IoT) ──
        if self.config.dpi.inspect_mqtt:
            self.protocol_inspector.register(
                name="mqtt_inspector",
                func=inspect_mqtt,
                layer=7,
                protocols=["mqtt", "mqtts"],
                ports=[1883, 8883],
                priority=60,
            )

        # ── Layer 7: CoAP (IoT) ──
        if self.config.dpi.inspect_coap:
            self.protocol_inspector.register(
                name="coap_inspector",
                func=inspect_coap,
                layer=7,
                protocols=["coap"],
                ports=[5683, 5684],
                priority=70,
            )

        # ── Signature Engine (cross-layer) ──
        sig_engine = SignatureEngine()
        sig_dir = self.config.dpi.signature_rules_dir
        if sig_dir:
            sig_engine.load_rules_dir(sig_dir)
        else:
            # Try default location
            import pathlib
            default_dir = (
                pathlib.Path(__file__).resolve().parent.parent
                / "data" / "signatures"
            )
            if default_dir.is_dir():
                sig_engine.load_rules_dir(str(default_dir))

        self.protocol_inspector.register(
            name="signature_engine",
            func=sig_engine.match,
            layer=7,
            protocols=["tcp", "udp"],
            priority=90,  # Run after protocol-specific inspectors
        )

        registered = self.protocol_inspector.get_registered_inspectors()
        log.info(
            f"DPI inspectors registered: {len(registered)} modules "
            f"across layers 2-7"
        )
        for r in registered:
            log.debug(
                f"  L{r['layer']} {r['name']}: "
                f"protocols={r['protocols']}"
            )

    # ───────────────────────────────────────────────────────────────────
    # Periodic Tasks
    # ───────────────────────────────────────────────────────────────────

    async def _stats_reporter(self) -> None:
        """Periodically log traffic statistics."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Every minute
                if not self._running:
                    break

                if self.packet_engine:
                    stats = self.packet_engine.stats.get_summary()
                    log.info(
                        f"Traffic stats: {stats['packets_per_second']:.0f} pps, "
                        f"{stats['total_captured']} captured, "
                        f"{stats['total_dropped']} dropped, "
                        f"queue: {stats['queue_size']}"
                    )

                if self.session_tracker:
                    sess_stats = self.session_tracker.get_stats()
                    log.info(
                        f"Sessions: {sess_stats['active_flows']} active, "
                        f"{sess_stats['total_created']} total"
                    )

                # Persist aggregated stats
                if self.db and self.packet_engine:
                    pkt_stats = self.packet_engine.stats
                    await self.db.insert_traffic_stats(
                        total_packets=pkt_stats.total_captured,
                        total_bytes=pkt_stats.total_bytes,
                        unique_src_ips=pkt_stats.unique_src_ips,
                        unique_dst_ips=pkt_stats.unique_dst_ips,
                        blocked_count=self._packets_dropped,
                        threats_detected=self._threats_blocked,
                        avg_packet_size=(
                            pkt_stats.total_bytes
                            / max(pkt_stats.total_captured, 1)
                        ),
                        protocol_breakdown=dict(pkt_stats.protocol_counts),
                    )
                    pkt_stats.reset_window_counters()

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Stats reporter error: {e}")

    async def _rule_cleanup_task(self) -> None:
        """Periodically clean up expired rules."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                if not self._running:
                    break

                if self.rule_engine:
                    removed = await self.rule_engine.cleanup_expired()
                    if removed > 0:
                        log.info(f"Cleaned up {removed} expired rules")

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Rule cleanup error: {e}")

    # ───────────────────────────────────────────────────────────────────
    # Status / Health
    # ───────────────────────────────────────────────────────────────────

    async def get_status(self) -> dict:
        """Get comprehensive system status."""
        status: dict = {
            "version": __version__,
            "uptime_seconds": round(self.uptime, 1),
            "running": self._running,
            "packets_allowed": self._packets_allowed,
            "packets_dropped": self._packets_dropped,
            "threats_blocked": self._threats_blocked,
        }

        if self.packet_engine:
            status["packet_engine"] = self.packet_engine.stats.get_summary()

        if self.rule_engine:
            status["rule_engine"] = self.rule_engine.get_status()

        if self.zone_manager:
            status["zone_manager"] = self.zone_manager.get_status()

        if self.session_tracker:
            status["session_tracker"] = self.session_tracker.get_stats()

        if self.db:
            status["database"] = await self.db.get_table_counts()

        return status


# ═══════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aerocifer",
        description="AEROCIFER NGFW — AI-Powered Next-Generation Firewall",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to config.yaml file",
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate a default config.yaml and exit",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"AEROCIFER NGFW v{__version__}",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Network interface to capture on (overrides config)",
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Run in simulation mode (no actual firewall rules applied)",
    )
    return parser.parse_args()


async def run(config: AerociferConfig) -> None:
    """Run the NGFW until interrupted."""
    ngfw = AerociferNGFW(config)

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler():
        log.info("Shutdown signal received")
        shutdown_event.set()

    # Register signal handlers (Unix-only for SIGTERM)
    if platform.system() != "Windows":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)
    else:
        # Windows: handle SIGINT via KeyboardInterrupt
        pass

    try:
        await ngfw.start()

        # Start API Control Plane
        from aerocifer.api.server import start_api_server
        api_task = asyncio.create_task(start_api_server(ngfw, host="0.0.0.0", port=8000))

        # Wait for shutdown signal
        try:
            await shutdown_event.wait()
        except KeyboardInterrupt:
            pass

    except KeyboardInterrupt:
        log.info("Keyboard interrupt received")
    except Exception as e:
        log.critical(f"Fatal error: {e}", exc_info=True)
    finally:
        await ngfw.stop()


def main() -> None:
    """CLI entry point."""
    args = parse_args()

    # Generate config and exit
    if args.generate_config:
        path = generate_default_config()
        print(f"Default configuration written to: {path}")
        return

    # Load config
    config = load_config(args.config)

    # CLI overrides
    if args.debug:
        config.logging.level = "DEBUG"
    if args.interface:
        config.network.interfaces = [args.interface]
    if args.simulation:
        # Force simulation mode
        pass

    # Setup logging
    setup_logging(
        level=config.logging.level,
        log_dir=config.logging.log_dir,
        console_output=config.logging.console_output,
        file_output=config.logging.file_output,
        json_format=config.logging.json_format,
        max_file_size_mb=config.logging.max_file_size_mb,
        backup_count=config.logging.backup_count,
    )

    # Run
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print("\nAEROCIFER NGFW shut down.")


if __name__ == "__main__":
    main()
