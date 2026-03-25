"""Syslog integration — forward Cashel log records to a remote syslog server.

Supports UDP (RFC 3164, default) and TCP transports.  A structured app-name
prefix is prepended to every message so SIEM platforms can filter by source.

Usage
-----
Call ``configure_syslog(settings)`` once on startup (and again after settings
are saved) to install or reconfigure the handler on the root logger.
"""

import logging
import logging.handlers
import socket

logger = logging.getLogger(__name__)

# Facility name → SysLogHandler constant.
_FACILITY_MAP: dict[str, int] = {
    "kernel": logging.handlers.SysLogHandler.LOG_KERN,
    "user": logging.handlers.SysLogHandler.LOG_USER,
    "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
    "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
    "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
    "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
    "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
    "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
    "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
    "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
    "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
}
VALID_FACILITIES = tuple(_FACILITY_MAP.keys())
VALID_PROTOCOLS = ("udp", "tcp")

# Live reference so we can tear down and replace on settings changes.
_active_handler: logging.handlers.SysLogHandler | None = None


def _remove_active() -> None:
    global _active_handler
    if _active_handler is not None:
        logging.root.removeHandler(_active_handler)
        try:
            _active_handler.close()
        except Exception:
            pass
        _active_handler = None


def configure_syslog(settings: dict) -> None:
    """Install (or tear down) the syslog handler based on *settings*.

    Safe to call multiple times — always replaces the previous handler cleanly.
    """
    global _active_handler
    _remove_active()

    if not settings.get("syslog_enabled"):
        return

    host = (settings.get("syslog_host") or "localhost").strip()
    port = int(settings.get("syslog_port") or 514)
    protocol = (settings.get("syslog_protocol") or "udp").lower()
    facility_key = (settings.get("syslog_facility") or "local0").lower()

    if protocol not in VALID_PROTOCOLS:
        protocol = "udp"
    facility = _FACILITY_MAP.get(
        facility_key, logging.handlers.SysLogHandler.LOG_LOCAL0
    )
    socktype = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM

    try:
        handler = logging.handlers.SysLogHandler(
            address=(host, port),
            facility=facility,
            socktype=socktype,
        )
    except OSError as exc:
        logger.warning("Syslog: could not connect to %s:%s — %s", host, port, exc)
        return

    # RFC 5424-style message: "APPNAME LEVEL LOGGER MESSAGE"
    handler.setFormatter(
        logging.Formatter(
            fmt="cashel %(levelname)s %(name)s %(message)s",
        )
    )
    handler.setLevel(logging.INFO)

    logging.root.addHandler(handler)
    _active_handler = handler
    logger.info(
        "Syslog handler active: %s %s:%s facility=%s",
        protocol.upper(),
        host,
        port,
        facility_key,
    )


def syslog_active() -> bool:
    """Return True if a syslog handler is currently installed."""
    return _active_handler is not None
