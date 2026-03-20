"""
AEROCIFER NGFW — Async Packet Capture & Processing Engine

High-performance packet processing with:
- Scapy capture running in a dedicated thread (non-blocking)
- Async queue for packet distribution to workers
- Batch processing for throughput optimization
- Platform detection (Linux optimized, Windows compatible)
- Statistics tracking for monitoring
- Graceful shutdown support
"""

from __future__ import annotations

import asyncio
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable, Any

from scapy.all import (  # type: ignore[import-untyped]
    sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS, Raw,
    get_if_list, get_if_addr, conf,
)

from aerocifer.utils.logger import get_logger, timed_operation

log = get_logger("core")


# ═══════════════════════════════════════════════════════════════════════════
# Packet Statistics Tracker
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PacketStats:
    """Real-time packet processing statistics."""
    total_captured: int = 0
    total_processed: int = 0
    total_dropped: int = 0          # Dropped due to full queue
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    queue_size: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    protocol_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    _start_time: float = field(default_factory=time.time)
    _last_update: float = field(default_factory=time.time)
    _src_ips: set = field(default_factory=set)
    _dst_ips: set = field(default_factory=set)
    _window_packets: int = 0
    _window_bytes: int = 0

    def record_packet(self, packet_len: int, protocol: str,
                      src_ip: str = "", dst_ip: str = "") -> None:
        self.total_captured += 1
        self.total_bytes += packet_len
        self._window_packets += 1
        self._window_bytes += packet_len
        self.protocol_counts[protocol] += 1

        if src_ip:
            self._src_ips.add(src_ip)
        if dst_ip:
            self._dst_ips.add(dst_ip)

        # Update rates every second
        now = time.time()
        elapsed = now - self._last_update
        if elapsed >= 1.0:
            self.packets_per_second = self._window_packets / elapsed
            self.bytes_per_second = self._window_bytes / elapsed
            self.unique_src_ips = len(self._src_ips)
            self.unique_dst_ips = len(self._dst_ips)
            self._window_packets = 0
            self._window_bytes = 0
            self._last_update = now

    def record_drop(self) -> None:
        self.total_dropped += 1

    def record_processed(self) -> None:
        self.total_processed += 1

    def get_summary(self) -> dict[str, Any]:
        uptime = time.time() - self._start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "total_captured": self.total_captured,
            "total_processed": self.total_processed,
            "total_dropped": self.total_dropped,
            "total_bytes": self.total_bytes,
            "packets_per_second": round(self.packets_per_second, 1),
            "bytes_per_second": round(self.bytes_per_second, 1),
            "queue_size": self.queue_size,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "protocol_counts": dict(self.protocol_counts),
            "drop_rate_pct": round(
                (self.total_dropped / max(self.total_captured, 1)) * 100, 2
            ),
        }

    def reset_window_counters(self) -> None:
        """Reset per-interval counters (called by stats aggregator)."""
        self._src_ips.clear()
        self._dst_ips.clear()


# ═══════════════════════════════════════════════════════════════════════════
# Raw Packet Wrapper
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RawPacket:
    """
    Lightweight wrapper around a Scapy packet for queue transport.
    Extracts key metadata eagerly to minimize lock contention.
    """
    timestamp: float
    length: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    src_mac: str
    dst_mac: str
    tcp_flags: int
    has_payload: bool
    raw_packet: Any  # The actual Scapy packet object

    @classmethod
    def from_scapy(cls, packet: Any) -> Optional[RawPacket]:
        """Extract metadata from a Scapy packet. Returns None if not IP."""
        try:
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = len(packet)

            # Determine protocol and ports
            protocol = "unknown"
            src_port = 0
            dst_port = 0
            tcp_flags = 0

            if packet.haslayer(TCP):
                protocol = "tcp"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = int(tcp_layer.flags)
            elif packet.haslayer(UDP):
                protocol = "udp"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif packet.haslayer(ICMP):
                protocol = "icmp"

            # MAC addresses
            src_mac = ""
            dst_mac = ""
            if packet.haslayer(Ether):
                eth = packet[Ether]
                src_mac = eth.src
                dst_mac = eth.dst

            return cls(
                timestamp=time.time(),
                length=length,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                src_mac=src_mac,
                dst_mac=dst_mac,
                tcp_flags=tcp_flags,
                has_payload=packet.haslayer(Raw),
                raw_packet=packet,
            )
        except Exception as e:
            log.debug(f"Failed to parse packet: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Packet Processing Pipeline
# ═══════════════════════════════════════════════════════════════════════════

# Type alias for packet handler callbacks
PacketHandler = Callable[[RawPacket], Awaitable[None]]


class PacketEngine:
    """
    High-performance async packet capture and processing engine.

    Architecture:
        [Scapy Thread] → [AsyncIO Queue] → [N Worker Tasks]
                                               ↓
                                          [Handler Chain]
                                               ↓
                                    [Session Tracker, DPI, ML, Rules]

    Usage:
        engine = PacketEngine(config)
        engine.add_handler(my_handler_coroutine)
        await engine.start()
        # ... runs until stopped
        await engine.stop()
    """

    def __init__(
        self,
        interfaces: list[str] | None = None,
        capture_filter: str = "ip",
        queue_max_size: int = 10000,
        batch_size: int = 64,
        worker_count: int = 4,
        promiscuous: bool = True,
        snap_length: int = 65535,
    ):
        self._interfaces = interfaces or ["eth0"]
        self._capture_filter = capture_filter
        self._queue: asyncio.Queue[Optional[RawPacket]] = asyncio.Queue(
            maxsize=queue_max_size
        )
        self._batch_size = batch_size
        self._worker_count = worker_count
        self._promiscuous = promiscuous
        self._snap_length = snap_length

        self._handlers: list[PacketHandler] = []
        self._stats = PacketStats()
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._worker_tasks: list[asyncio.Task] = []
        self._stop_event = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def stats(self) -> PacketStats:
        return self._stats

    @property
    def is_running(self) -> bool:
        return self._running

    def add_handler(self, handler: PacketHandler) -> None:
        """
        Register a packet handler coroutine.
        Handlers are called in order for each packet.
        """
        self._handlers.append(handler)
        log.debug(f"Registered packet handler: {handler.__name__}")

    def remove_handler(self, handler: PacketHandler) -> None:
        """Remove a previously registered handler."""
        self._handlers = [h for h in self._handlers if h is not handler]

    # ───────────────────────────────────────────────────────────────────
    # Capture Thread (runs Scapy in a dedicated thread)
    # ───────────────────────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        """Scapy packet capture running in a dedicated thread."""
        log.info(
            f"Capture thread started on interfaces: {self._interfaces}"
        )
        try:
            for iface in self._interfaces:
                if self._stop_event.is_set():
                    break
                log.info(f"Starting capture on {iface}")
                try:
                    sniff(
                        iface=iface,
                        filter=self._capture_filter,
                        prn=self._on_packet_captured,
                        store=0,
                        stop_filter=lambda _: self._stop_event.is_set(),
                        promisc=self._promiscuous,
                        # Keep checking stop event
                        timeout=1,
                    )
                except PermissionError:
                    log.error(
                        f"Permission denied for interface {iface}. "
                        "Run with root/admin privileges."
                    )
                except Exception as e:
                    log.error(f"Capture error on {iface}: {e}")

                # If using timeout-based loop, restart unless stopped
                while not self._stop_event.is_set():
                    try:
                        sniff(
                            iface=iface,
                            filter=self._capture_filter,
                            prn=self._on_packet_captured,
                            store=0,
                            stop_filter=lambda _: self._stop_event.is_set(),
                            promisc=self._promiscuous,
                            timeout=5,
                        )
                    except Exception as e:
                        if not self._stop_event.is_set():
                            log.error(f"Capture restart error: {e}")
                            time.sleep(1)
                        break

        except Exception as e:
            log.critical(f"Capture thread crashed: {e}")
        finally:
            log.info("Capture thread stopped")

    def _on_packet_captured(self, scapy_packet: Any) -> None:
        """
        Callback from Scapy capture thread.
        Converts to RawPacket and pushes to async queue.
        """
        raw = RawPacket.from_scapy(scapy_packet)
        if raw is None:
            return

        self._stats.record_packet(
            raw.length, raw.protocol, raw.src_ip, raw.dst_ip
        )

        # Non-blocking put to avoid slowing capture
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(
                    self._queue_put_nowait, raw
                )
            except RuntimeError:
                # Loop is closed
                pass

    def _queue_put_nowait(self, raw: RawPacket) -> None:
        """Put packet in queue, drop if full (back-pressure)."""
        try:
            self._queue.put_nowait(raw)
            self._stats.queue_size = self._queue.qsize()
        except asyncio.QueueFull:
            self._stats.record_drop()

    # ───────────────────────────────────────────────────────────────────
    # Async Worker Tasks
    # ───────────────────────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        """
        Async worker that pulls packets from the queue and runs handlers.
        Supports both single-packet and batch processing.
        """
        log.debug(f"Worker-{worker_id} started")
        batch: list[RawPacket] = []

        while self._running:
            try:
                # Wait for a packet with timeout
                try:
                    packet = await asyncio.wait_for(
                        self._queue.get(), timeout=0.5
                    )
                except asyncio.TimeoutError:
                    # Process any accumulated batch
                    if batch:
                        await self._process_batch(batch)
                        batch.clear()
                    continue

                if packet is None:
                    # Poison pill — shutdown signal
                    break

                batch.append(packet)

                # Process batch when full
                if len(batch) >= self._batch_size:
                    await self._process_batch(batch)
                    batch.clear()

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Worker-{worker_id} error: {e}")

        # Process remaining batch
        if batch:
            await self._process_batch(batch)

        log.debug(f"Worker-{worker_id} stopped")

    async def _process_batch(self, batch: list[RawPacket]) -> None:
        """Process a batch of packets through all handlers."""
        for packet in batch:
            for handler in self._handlers:
                try:
                    await handler(packet)
                except Exception as e:
                    log.error(
                        f"Handler {handler.__name__} error: {e}",
                        extra={"src_ip": packet.src_ip},
                    )
            self._stats.record_processed()

    # ───────────────────────────────────────────────────────────────────
    # Start / Stop
    # ───────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the packet capture engine."""
        if self._running:
            log.warning("Packet engine is already running")
            return

        self._running = True
        self._stop_event.clear()
        self._loop = asyncio.get_running_loop()

        # Detect available interfaces
        available = get_available_interfaces()
        if available:
            valid_ifaces = []
            for iface in self._interfaces:
                if iface in available:
                    valid_ifaces.append(iface)
                else:
                    log.warning(
                        f"Interface '{iface}' not found. "
                        f"Available: {list(available.keys())}"
                    )
            if not valid_ifaces and available:
                # Fallback to first available with an IP
                for name, ip in available.items():
                    if ip and ip != "0.0.0.0":
                        valid_ifaces = [name]
                        log.info(f"Auto-selected interface: {name} ({ip})")
                        break
            if valid_ifaces:
                self._interfaces = valid_ifaces

        # Start worker tasks
        for i in range(self._worker_count):
            task = asyncio.create_task(self._worker(i))
            self._worker_tasks.append(task)

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="aerocifer-capture",
            daemon=True,
        )
        self._capture_thread.start()

        log.info(
            f"Packet engine started: {self._worker_count} workers, "
            f"interfaces: {self._interfaces}"
        )

    async def stop(self) -> None:
        """Gracefully stop the packet capture engine."""
        if not self._running:
            return

        log.info("Stopping packet engine...")
        self._running = False
        self._stop_event.set()

        # Wait for capture thread
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        # Send poison pills to workers
        for _ in self._worker_tasks:
            try:
                self._queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

        # Wait for workers
        if self._worker_tasks:
            await asyncio.gather(
                *self._worker_tasks, return_exceptions=True
            )
            self._worker_tasks.clear()

        log.info(
            f"Packet engine stopped. "
            f"Processed {self._stats.total_processed} packets, "
            f"dropped {self._stats.total_dropped}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Interface Discovery
# ═══════════════════════════════════════════════════════════════════════════

def get_available_interfaces() -> dict[str, str]:
    """
    Discover available network interfaces and their IPs.
    Returns {interface_name: ip_address}.
    """
    interfaces = {}
    try:
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                interfaces[iface] = ip
            except Exception:
                interfaces[iface] = ""
    except Exception as e:
        log.warning(f"Failed to enumerate interfaces: {e}")
    return interfaces
