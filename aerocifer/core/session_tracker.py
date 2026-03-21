"""
AEROCIFER NGFW — Stateful Session / Flow Tracker

Tracks all active network flows (TCP/UDP sessions) with:
- 5-tuple flow identification (src_ip, dst_ip, src_port, dst_port, protocol)
- TCP state machine tracking (SYN → ESTABLISHED → FIN/RST → CLOSED)
- Flow statistics (packet counts, byte counts, inter-arrival times)
- Flow feature extraction for ML model input
- TTL-based flow expiration for memory management
- Bidirectional flow merging
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Any

from aerocifer.utils.logger import get_logger
from aerocifer.db.models import FlowRecord, FlowState

log = get_logger("core")


# ═══════════════════════════════════════════════════════════════════════════
# TCP Flags
# ═══════════════════════════════════════════════════════════════════════════

class TCPFlags:
    """TCP flag bitmask constants."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    @staticmethod
    def has_flag(flags: int, flag: int) -> bool:
        return bool(flags & flag)

    @staticmethod
    def describe(flags: int) -> str:
        names = []
        for name, val in [
            ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
            ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
        ]:
            if flags & val:
                names.append(name)
        return "|".join(names) if names else "NONE"


# ═══════════════════════════════════════════════════════════════════════════
# Flow Entry (in-memory tracking)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FlowEntry:
    """
    In-memory representation of an active network flow.
    Tracks statistics needed for ML feature extraction.
    """
    # Identity
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flow_id: str = ""

    # State
    state: FlowState = FlowState.NEW
    start_time: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    # Counters — forward direction (src → dst)
    fwd_packets: int = 0
    fwd_bytes: int = 0
    fwd_payload_bytes: int = 0

    # Counters — reverse direction (dst → src)
    bwd_packets: int = 0
    bwd_bytes: int = 0
    bwd_payload_bytes: int = 0

    # TCP-specific
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # Timing — inter-arrival times (IAT) in seconds
    _fwd_timestamps: list[float] = field(default_factory=list)
    _bwd_timestamps: list[float] = field(default_factory=list)

    # Packet sizes
    _fwd_packet_sizes: list[int] = field(default_factory=list)
    _bwd_packet_sizes: list[int] = field(default_factory=list)

    # Payload entropy (Shannon entropy)
    _payload_byte_freq: dict[int, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    _total_payload_bytes_for_entropy: int = 0

    # DPI results
    application: str = ""
    ja3_hash: str = ""
    dns_query: str = ""

    # ML results
    ml_label: str = ""
    ml_confidence: float = 0.0
    is_anomalous: bool = False
    anomaly_score: float = 0.0

    # Zone info
    src_zone_id: Optional[str] = None
    dst_zone_id: Optional[str] = None

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                self.protocol)

    @property
    def reverse_key(self) -> tuple:
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port,
                self.protocol)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        return self.last_activity - self.start_time

    def update_forward(self, packet_size: int, tcp_flags: int = 0,
                       payload_size: int = 0, payload: bytes = b"") -> None:
        """Update flow with a forward-direction packet."""
        now = time.time()
        self.last_activity = now
        self.fwd_packets += 1
        self.fwd_bytes += packet_size
        self.fwd_payload_bytes += payload_size

        self._fwd_timestamps.append(now)
        self._fwd_packet_sizes.append(packet_size)

        # TCP flags
        if tcp_flags:
            self._count_tcp_flags(tcp_flags)

        # Payload entropy tracking (sample first 4KB)
        if payload and self._total_payload_bytes_for_entropy < 4096:
            for byte in payload[:4096 - self._total_payload_bytes_for_entropy]:
                self._payload_byte_freq[byte] += 1
            self._total_payload_bytes_for_entropy += min(
                len(payload), 4096 - self._total_payload_bytes_for_entropy
            )

        # Limit stored timestamps/sizes to prevent memory growth
        if len(self._fwd_timestamps) > 1000:
            self._fwd_timestamps = self._fwd_timestamps[-500:]
        if len(self._fwd_packet_sizes) > 1000:
            self._fwd_packet_sizes = self._fwd_packet_sizes[-500:]

    def update_backward(self, packet_size: int, tcp_flags: int = 0,
                        payload_size: int = 0) -> None:
        """Update flow with a backward-direction (response) packet."""
        now = time.time()
        self.last_activity = now
        self.bwd_packets += 1
        self.bwd_bytes += packet_size
        self.bwd_payload_bytes += payload_size

        self._bwd_timestamps.append(now)
        self._bwd_packet_sizes.append(packet_size)

        if tcp_flags:
            self._count_tcp_flags(tcp_flags)

        if len(self._bwd_timestamps) > 1000:
            self._bwd_timestamps = self._bwd_timestamps[-500:]
        if len(self._bwd_packet_sizes) > 1000:
            self._bwd_packet_sizes = self._bwd_packet_sizes[-500:]

    def _count_tcp_flags(self, flags: int) -> None:
        if TCPFlags.has_flag(flags, TCPFlags.SYN):
            self.syn_count += 1
        if TCPFlags.has_flag(flags, TCPFlags.ACK):
            self.ack_count += 1
        if TCPFlags.has_flag(flags, TCPFlags.FIN):
            self.fin_count += 1
        if TCPFlags.has_flag(flags, TCPFlags.RST):
            self.rst_count += 1
        if TCPFlags.has_flag(flags, TCPFlags.PSH):
            self.psh_count += 1
        if TCPFlags.has_flag(flags, TCPFlags.URG):
            self.urg_count += 1

    def update_tcp_state(self, tcp_flags: int, is_forward: bool) -> None:
        """Update TCP connection state based on received flags."""
        if self.state == FlowState.NEW:
            if TCPFlags.has_flag(tcp_flags, TCPFlags.SYN):
                if not TCPFlags.has_flag(tcp_flags, TCPFlags.ACK):
                    self.state = FlowState.NEW  # SYN sent
                else:
                    self.state = FlowState.ESTABLISHED  # SYN-ACK
        elif self.state in (FlowState.NEW, FlowState.ESTABLISHED):
            if TCPFlags.has_flag(tcp_flags, TCPFlags.ACK):
                self.state = FlowState.ESTABLISHED
            if TCPFlags.has_flag(tcp_flags, TCPFlags.FIN):
                self.state = FlowState.CLOSING
            if TCPFlags.has_flag(tcp_flags, TCPFlags.RST):
                self.state = FlowState.CLOSED
        elif self.state == FlowState.CLOSING:
            if TCPFlags.has_flag(tcp_flags, TCPFlags.ACK):
                self.state = FlowState.CLOSED
            if TCPFlags.has_flag(tcp_flags, TCPFlags.FIN):
                self.state = FlowState.CLOSED

    # ───────────────────────────────────────────────────────────────────
    # Feature Extraction (for ML model input)
    # ───────────────────────────────────────────────────────────────────

    def extract_features(self) -> dict[str, float]:
        """
        Extract a feature vector for ML model inference.
        Returns a dict of feature_name → float_value.

        These features are inspired by CICFlowMeter and are designed
        to capture both volumetric and behavioral characteristics.
        """
        duration = max(self.duration, 0.001)  # Avoid div by zero

        features: dict[str, float] = {}

        # --- Volumetric features ---
        features["total_packets"] = float(self.total_packets)
        features["total_bytes"] = float(self.total_bytes)
        features["fwd_packets"] = float(self.fwd_packets)
        features["bwd_packets"] = float(self.bwd_packets)
        features["fwd_bytes"] = float(self.fwd_bytes)
        features["bwd_bytes"] = float(self.bwd_bytes)

        # --- Rate features ---
        features["flow_duration"] = duration
        features["packets_per_second"] = self.total_packets / duration
        features["bytes_per_second"] = self.total_bytes / duration
        features["fwd_packets_per_sec"] = self.fwd_packets / duration
        features["bwd_packets_per_sec"] = self.bwd_packets / duration

        # --- Packet size statistics ---
        features.update(self._size_stats(
            self._fwd_packet_sizes, "fwd_pkt_size"
        ))
        features.update(self._size_stats(
            self._bwd_packet_sizes, "bwd_pkt_size"
        ))

        all_sizes = self._fwd_packet_sizes + self._bwd_packet_sizes
        features.update(self._size_stats(all_sizes, "pkt_size"))

        # --- Inter-Arrival Time statistics ---
        fwd_iats = self._compute_iats(self._fwd_timestamps)
        bwd_iats = self._compute_iats(self._bwd_timestamps)
        all_iats = fwd_iats + bwd_iats

        features.update(self._iat_stats(fwd_iats, "fwd_iat"))
        features.update(self._iat_stats(bwd_iats, "bwd_iat"))
        features.update(self._iat_stats(all_iats, "flow_iat"))

        # --- TCP flag ratios ---
        total = max(self.total_packets, 1)
        features["syn_ratio"] = self.syn_count / total
        features["ack_ratio"] = self.ack_count / total
        features["fin_ratio"] = self.fin_count / total
        features["rst_ratio"] = self.rst_count / total
        features["psh_ratio"] = self.psh_count / total
        features["urg_ratio"] = self.urg_count / total

        # --- Bidirectional ratio ---
        features["fwd_bwd_ratio"] = (
            self.fwd_packets / max(self.bwd_packets, 1)
        )
        features["fwd_bwd_bytes_ratio"] = (
            self.fwd_bytes / max(self.bwd_bytes, 1)
        )

        # --- Payload features ---
        features["has_payload"] = float(self.fwd_payload_bytes > 0)
        features["avg_payload_size"] = (
            (self.fwd_payload_bytes + self.bwd_payload_bytes)
            / max(self.total_packets, 1)
        )
        features["payload_entropy"] = self._compute_payload_entropy()

        # --- Port features ---
        features["dst_port"] = float(self.dst_port)
        features["src_port"] = float(self.src_port)
        features["is_well_known_port"] = float(self.dst_port < 1024)

        # --- Protocol encoding ---
        features["is_tcp"] = float(self.protocol == "tcp")
        features["is_udp"] = float(self.protocol == "udp")
        features["is_icmp"] = float(self.protocol == "icmp")

        return features

    def _size_stats(
        self, sizes: list[int], prefix: str
    ) -> dict[str, float]:
        """Compute min/max/mean/std for a list of sizes."""
        if not sizes:
            return {
                f"{prefix}_min": 0.0,
                f"{prefix}_max": 0.0,
                f"{prefix}_mean": 0.0,
                f"{prefix}_std": 0.0,
            }
        n = len(sizes)
        mean = sum(sizes) / n
        var = sum((s - mean) ** 2 for s in sizes) / max(n, 1)
        return {
            f"{prefix}_min": float(min(sizes)),
            f"{prefix}_max": float(max(sizes)),
            f"{prefix}_mean": mean,
            f"{prefix}_std": math.sqrt(var),
        }

    def _compute_iats(self, timestamps: list[float]) -> list[float]:
        """Compute inter-arrival times from timestamp list."""
        if len(timestamps) < 2:
            return []
        return [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

    def _iat_stats(
        self, iats: list[float], prefix: str
    ) -> dict[str, float]:
        """Compute IAT statistics."""
        if not iats:
            return {
                f"{prefix}_min": 0.0,
                f"{prefix}_max": 0.0,
                f"{prefix}_mean": 0.0,
                f"{prefix}_std": 0.0,
            }
        n = len(iats)
        mean = sum(iats) / n
        var = sum((t - mean) ** 2 for t in iats) / max(n, 1)
        return {
            f"{prefix}_min": min(iats),
            f"{prefix}_max": max(iats),
            f"{prefix}_mean": mean,
            f"{prefix}_std": math.sqrt(var),
        }

    def _compute_payload_entropy(self) -> float:
        """Compute Shannon entropy of payload bytes."""
        total = self._total_payload_bytes_for_entropy
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in self._payload_byte_freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    def to_flow_record(self) -> FlowRecord:
        """Convert to a FlowRecord for database persistence."""
        features = self.extract_features()
        return FlowRecord(
            id=self.flow_id,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            state=self.state,
            packets_sent=self.fwd_packets,
            packets_recv=self.bwd_packets,
            bytes_sent=self.fwd_bytes,
            bytes_recv=self.bwd_bytes,
            start_time=self.start_time,
            last_activity=self.last_activity,
            duration=self.duration,
            application=self.application,
            ja3_hash=self.ja3_hash,
            dns_query=self.dns_query,
            ml_label=self.ml_label,
            ml_confidence=self.ml_confidence,
            is_anomalous=self.is_anomalous,
            anomaly_score=self.anomaly_score,
            features=json.dumps(features),
            src_zone_id=self.src_zone_id,
            dst_zone_id=self.dst_zone_id,
        )


# ═══════════════════════════════════════════════════════════════════════════
# Session Tracker
# ═══════════════════════════════════════════════════════════════════════════

class SessionTracker:
    """
    Manages all active network flows/sessions.

    Features:
    - Bidirectional flow tracking (merges src→dst and dst→src)
    - TCP state machine per connection
    - Automatic flow expiration (TTL-based cleanup)
    - Feature extraction for ML pipeline
    - Flow completion callbacks

    Usage:
        tracker = SessionTracker()
        await tracker.start()

        # Process a packet
        flow = tracker.track_packet(raw_packet)

        # Get flow features for ML
        features = flow.extract_features()

        await tracker.stop()
    """

    # TTL for inactive flows
    TCP_TIMEOUT = 300       # 5 minutes for established TCP
    UDP_TIMEOUT = 120       # 2 minutes for UDP
    ICMP_TIMEOUT = 30       # 30 seconds for ICMP
    DEFAULT_TIMEOUT = 60    # 1 minute default

    # Cleanup interval
    CLEANUP_INTERVAL = 30   # Check every 30 seconds

    def __init__(
        self,
        db: Any = None,
        on_flow_complete: Optional[Any] = None,
    ):
        self._db = db
        self._on_flow_complete = on_flow_complete

        # Active flows: flow_key → FlowEntry
        self._flows: dict[tuple, FlowEntry] = {}
        self._flow_count = 0
        self._total_flows_created = 0
        self._total_flows_expired = 0

        self._running = False
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    @property
    def total_flows_tracked(self) -> int:
        return self._total_flows_created

    def track_packet(
        self, src_ip: str, dst_ip: str, src_port: int,
        dst_port: int, protocol: str, packet_size: int,
        tcp_flags: int = 0, payload_size: int = 0,
        payload: bytes = b"",
    ) -> FlowEntry:
        """
        Track a packet in the flow table.
        Creates a new flow or updates an existing one.
        Returns the FlowEntry for this packet's flow.
        """
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        # Check if this is a forward or reverse packet
        if flow_key in self._flows:
            flow = self._flows[flow_key]
            flow.update_forward(packet_size, tcp_flags, payload_size, payload)
            if protocol == "tcp":
                flow.update_tcp_state(tcp_flags, is_forward=True)
            return flow

        if reverse_key in self._flows:
            flow = self._flows[reverse_key]
            flow.update_backward(packet_size, tcp_flags, payload_size)
            if protocol == "tcp":
                flow.update_tcp_state(tcp_flags, is_forward=False)
            return flow

        # New flow
        from aerocifer.db.models import _gen_id
        flow = FlowEntry(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            flow_id=_gen_id(),
        )
        flow.update_forward(packet_size, tcp_flags, payload_size, payload)
        if protocol == "tcp":
            flow.update_tcp_state(tcp_flags, is_forward=True)

        self._flows[flow_key] = flow
        self._total_flows_created += 1

        return flow

    def get_flow(
        self, src_ip: str, dst_ip: str, src_port: int,
        dst_port: int, protocol: str
    ) -> Optional[FlowEntry]:
        """Look up an existing flow by 5-tuple."""
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self._flows.get(key)
        if flow:
            return flow
        # Check reverse
        rkey = (dst_ip, src_ip, dst_port, src_port, protocol)
        return self._flows.get(rkey)

    def get_flows_for_ip(self, ip: str) -> list[FlowEntry]:
        """Get all active flows involving a specific IP."""
        result = []
        for flow in self._flows.values():
            if flow.src_ip == ip or flow.dst_ip == ip:
                result.append(flow)
        return result

    async def start(self) -> None:
        """Start the session tracker with periodic cleanup."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("Session tracker started")

    async def stop(self) -> None:
        """Stop the session tracker and persist remaining flows."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Persist remaining active flows
        if self._db:
            persisted = 0
            for flow in self._flows.values():
                if flow.total_packets > 1:  # Skip single-packet flows
                    try:
                        await self._db.insert_flow(flow.to_flow_record())
                        persisted += 1
                    except Exception as e:
                        log.error(f"Failed to persist flow: {e}")
            log.info(f"Persisted {persisted} active flows on shutdown")

        self._flows.clear()
        log.info(
            f"Session tracker stopped. Total tracked: "
            f"{self._total_flows_created}, expired: "
            f"{self._total_flows_expired}"
        )

    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired flows."""
        while self._running:
            try:
                await asyncio.sleep(self.CLEANUP_INTERVAL)
                await self._expire_flows()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Cleanup loop error: {e}")

    async def _expire_flows(self) -> None:
        """Remove flows that have been inactive beyond their TTL."""
        now = time.time()
        expired_keys = []

        for key, flow in self._flows.items():
            timeout = self._get_timeout(flow)
            if now - flow.last_activity > timeout:
                expired_keys.append(key)
            elif flow.state == FlowState.CLOSED:
                expired_keys.append(key)

        for key in expired_keys:
            flow = self._flows.pop(key, None)
            if flow is None:
                continue

            flow.state = (
                flow.state if flow.state == FlowState.CLOSED
                else FlowState.TIMEOUT
            )
            self._total_flows_expired += 1

            # Persist completed flows with significant traffic
            if self._db and flow.total_packets > 2:
                try:
                    await self._db.insert_flow(flow.to_flow_record())
                except Exception as e:
                    log.debug(f"Failed to persist expired flow: {e}")

            # Notify callback (for ML pipeline)
            if self._on_flow_complete:
                try:
                    await self._on_flow_complete(flow)
                except Exception as e:
                    log.error(f"Flow completion callback error: {e}")

        if expired_keys:
            log.debug(
                f"Expired {len(expired_keys)} flows "
                f"(active: {len(self._flows)})"
            )

    def _get_timeout(self, flow: FlowEntry) -> float:
        """Get the appropriate timeout for a flow based on protocol/state."""
        if flow.protocol == "tcp":
            if flow.state == FlowState.ESTABLISHED:
                return self.TCP_TIMEOUT
            if flow.state == FlowState.CLOSING:
                return 30  # Short timeout for closing connections
            return 60  # SYN sent but not established
        if flow.protocol == "udp":
            return self.UDP_TIMEOUT
        if flow.protocol == "icmp":
            return self.ICMP_TIMEOUT
        return self.DEFAULT_TIMEOUT

    def get_stats(self) -> dict[str, Any]:
        """Get session tracker statistics."""
        protocol_counts = defaultdict(int)
        state_counts = defaultdict(int)
        for flow in self._flows.values():
            protocol_counts[flow.protocol] += 1
            state_counts[flow.state.value] += 1

        return {
            "active_flows": len(self._flows),
            "total_created": self._total_flows_created,
            "total_expired": self._total_flows_expired,
            "by_protocol": dict(protocol_counts),
            "by_state": dict(state_counts),
        }
