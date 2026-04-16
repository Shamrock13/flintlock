"""Auth audit log — record security events (logins, key failures, user changes).

Follows the same pattern as activity_log.py but targets the auth_events table.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from flask import has_request_context
from flask import request as _flask_request

from .db import get_conn

# Event type constants
AUTH_LOGIN_SUCCESS = "login_success"
AUTH_LOGIN_FAILURE = "login_failure"
AUTH_ACCOUNT_LOCKOUT = "account_lockout"
AUTH_LOGOUT = "logout"
AUTH_INVALID_API_KEY = "invalid_api_key"
AUTH_USER_CREATED = "user_created"
AUTH_USER_DELETED = "user_deleted"
AUTH_PASSWORD_CHANGED = "password_changed"
AUTH_API_KEY_GENERATED = "api_key_generated"
AUTH_API_KEY_REVOKED = "api_key_revoked"
AUTH_SETTINGS_CHANGED = "settings_changed"
AUTH_LICENSE_CHANGED = "license_changed"


def log_auth_event(
    event: str,
    actor: str = "",
    target: str = "",
    success: bool = True,
    details: dict | None = None,
) -> str:
    """Append a security event. Returns the new event ID."""
    event_id = uuid.uuid4().hex[:12]
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    ip = ""
    ua = ""
    if has_request_context():
        # Prefer X-Real-IP set by nginx/Caddy so logs show the real client IP,
        # not the proxy's loopback address.
        ip = _flask_request.headers.get("X-Real-IP") or _flask_request.remote_addr or ""
        ua = _flask_request.headers.get("User-Agent", "")[:256]

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO auth_events
            (id, event, actor, target, ip_address, user_agent, success, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            event,
            actor or "",
            target or "",
            ip,
            ua,
            1 if success else 0,
            json.dumps(details or {}),
            timestamp,
        ),
    )
    conn.commit()
    return event_id


def list_auth_events(limit: int = 200) -> list:
    """Return auth events sorted newest-first, up to limit entries."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM auth_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def clear_auth_events() -> int:
    """Delete all auth event entries. Returns count deleted."""
    conn = get_conn()
    cur = conn.execute("DELETE FROM auth_events")
    conn.commit()
    return cur.rowcount


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["success"] = bool(d["success"])
    d["details"] = json.loads(d["details"]) if d.get("details") else {}
    return d
