"""
AEROCIFER NGFW — Structured Logging System

Provides:
- Colored console output for human readability
- Rotating file logs for persistence
- Optional JSON structured logging for log aggregation (ELK, Splunk)
- Performance timing context manager
- Separate loggers per component (core, dpi, ml, api, etc.)
"""

from __future__ import annotations

import os
import sys
import json
import time
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Any
from contextlib import contextmanager
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════════════════════
# Color Codes for Console Output
# ═══════════════════════════════════════════════════════════════════════════

class _Colors:
    """ANSI color codes — disabled automatically on Windows without ANSI support."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Log levels
    DEBUG = "\033[36m"      # Cyan
    INFO = "\033[32m"       # Green
    WARNING = "\033[33m"    # Yellow
    ERROR = "\033[31m"      # Red
    CRITICAL = "\033[41m"   # Red background

    # Components
    CORE = "\033[34m"       # Blue
    DPI = "\033[35m"        # Magenta
    ML = "\033[36m"         # Cyan
    AI = "\033[33m"         # Yellow
    API = "\033[32m"        # Green
    DB = "\033[37m"         # White

    @classmethod
    def supports_color(cls) -> bool:
        """Check if the terminal supports ANSI colors."""
        if os.environ.get("NO_COLOR"):
            return False
        if sys.platform == "win32":
            # Windows 10+ supports ANSI if virtual terminal processing is enabled
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                # Enable virtual terminal processing
                handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_ulong()
                kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                return True
            except Exception:
                return False
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# Disable colors if terminal doesn't support them
if not _Colors.supports_color():
    for attr in dir(_Colors):
        if attr.isupper() and not attr.startswith("_"):
            setattr(_Colors, attr, "")


# ═══════════════════════════════════════════════════════════════════════════
# Custom Formatters
# ═══════════════════════════════════════════════════════════════════════════

LEVEL_COLORS = {
    "DEBUG": _Colors.DEBUG,
    "INFO": _Colors.INFO,
    "WARNING": _Colors.WARNING,
    "ERROR": _Colors.ERROR,
    "CRITICAL": _Colors.CRITICAL,
}

COMPONENT_COLORS = {
    "core": _Colors.CORE,
    "dpi": _Colors.DPI,
    "ml": _Colors.ML,
    "ai": _Colors.AI,
    "api": _Colors.API,
    "db": _Colors.DB,
}


class ColoredFormatter(logging.Formatter):
    """Human-readable colored console formatter."""

    FORMAT = (
        f"{_Colors.DIM}%(asctime)s{_Colors.RESET} "
        "%(level_color)s%(levelname)-8s%(reset)s "
        "%(comp_color)s[%(component)s]%(reset)s "
        "%(message)s"
    )

    def __init__(self):
        super().__init__(datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # Ensure custom attributes exist
        if not hasattr(record, "component"):
            record.component = "main"  # type: ignore[attr-defined]

        record.level_color = LEVEL_COLORS.get(record.levelname, "")  # type: ignore[attr-defined]
        record.comp_color = COMPONENT_COLORS.get(  # type: ignore[attr-defined]
            getattr(record, "component", ""), ""
        )
        record.reset = _Colors.RESET  # type: ignore[attr-defined]

        self._fmt = self.FORMAT
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for log aggregation systems."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "component": getattr(record, "component", "main"),
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "Unknown",
                "message": str(record.exc_info[1]),
            }

        # Include extra fields
        for key in ("src_ip", "dst_ip", "protocol", "action", "zone",
                     "threat_type", "confidence", "device_type", "rule_id"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        return json.dumps(log_entry, ensure_ascii=False)


class FileFormatter(logging.Formatter):
    """Clean plain-text formatter for log files."""

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s [%(component)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "component"):
            record.component = "main"  # type: ignore[attr-defined]
        return super().format(record)


# ═══════════════════════════════════════════════════════════════════════════
# Component Logger Adapter
# ═══════════════════════════════════════════════════════════════════════════

class ComponentLogger(logging.LoggerAdapter):
    """
    Logger adapter that automatically injects the component name
    into every log record.

    Usage:
        log = get_logger("core")
        log.info("Packet engine started")
        log.warning("High traffic detected", extra={"src_ip": "10.0.0.5"})
    """

    def __init__(self, logger: logging.Logger, component: str):
        super().__init__(logger, {"component": component})
        self._component = component

    def process(
        self, msg: str, kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        extra = kwargs.get("extra", {})
        extra["component"] = self._component
        kwargs["extra"] = extra
        return msg, kwargs


# ═══════════════════════════════════════════════════════════════════════════
# Logger Setup & Factory
# ═══════════════════════════════════════════════════════════════════════════

_initialized = False
_root_logger: Optional[logging.Logger] = None
_loggers: dict[str, ComponentLogger] = {}


def setup_logging(
    level: str = "INFO",
    log_dir: str = "",
    console_output: bool = True,
    file_output: bool = True,
    json_format: bool = False,
    max_file_size_mb: int = 50,
    backup_count: int = 5,
) -> None:
    """
    Initialize the logging system. Should be called once at startup.

    Args:
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        console_output: Enable colored console output
        file_output: Enable rotating file output
        json_format: Use JSON format for file logs
        max_file_size_mb: Max size per log file before rotation
        backup_count: Number of rotated files to keep
    """
    global _initialized, _root_logger

    if _initialized:
        return

    _root_logger = logging.getLogger("aerocifer")
    _root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    _root_logger.propagate = False

    # Remove any existing handlers
    _root_logger.handlers.clear()

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter())
        _root_logger.addHandler(console_handler)

    # File handler
    if file_output and log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        log_file = log_path / "aerocifer.log"

        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(log_file),
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(
            JSONFormatter() if json_format else FileFormatter()
        )
        _root_logger.addHandler(file_handler)

        # Separate file for security events
        security_file = log_path / "security.log"
        security_handler = logging.handlers.RotatingFileHandler(
            filename=str(security_file),
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.setFormatter(
            JSONFormatter() if json_format else FileFormatter()
        )
        _root_logger.addHandler(security_handler)

    _initialized = True


def get_logger(component: str = "main") -> ComponentLogger:
    """
    Get a component-specific logger.

    Args:
        component: Component name (core, dpi, ml, ai, api, db, main)

    Returns:
        ComponentLogger that auto-injects the component name.
    """
    global _root_logger

    if component in _loggers:
        return _loggers[component]

    if _root_logger is None:
        # Auto-initialize with defaults if setup_logging wasn't called
        setup_logging()
    assert _root_logger is not None

    adapter = ComponentLogger(_root_logger, component)
    _loggers[component] = adapter
    return adapter


# ═══════════════════════════════════════════════════════════════════════════
# Performance Timing Utility
# ═══════════════════════════════════════════════════════════════════════════

@contextmanager
def timed_operation(operation_name: str, component: str = "main"):
    """
    Context manager to measure and log operation duration.

    Usage:
        with timed_operation("packet_batch_processing", "core"):
            process_batch(packets)
    """
    log = get_logger(component)
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000
        log.debug(f"{operation_name} completed in {elapsed_ms:.2f}ms")
