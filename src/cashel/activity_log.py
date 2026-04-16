"""Activity log — record every user action (audits, SSH attempts, diffs) including failures."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from .db import get_conn

# Action type constants
ACTION_FILE_AUDIT = "file_audit"
ACTION_SSH_CONNECT = "ssh_connect"
ACTION_CONFIG_DIFF = "config_diff"
ACTION_COMPARISON = "archive_compare"


def log_activity(
    action_type: str,
    label: str,
    vendor: str | None = None,
    success: bool = True,
    error: str | None = None,
    details: dict | None = None,
) -> str:
    """
    Append an activity event.

    Returns the new event ID.
    """
    event_id = uuid.uuid4().hex[:12]
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO activity (id, action, label, vendor, success, error, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            action_type,
            label,
            vendor or "",
            1 if success else 0,
            error or "",
            json.dumps(details or {}),
            timestamp,
        ),
    )
    conn.commit()
    return event_id


def list_activity(limit: int = 200) -> list:
    """Return activity events sorted newest-first, up to *limit* entries."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM activity ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def delete_activity_entry(event_id: str) -> bool:
    """Delete a single activity log entry. Returns True if deleted."""
    safe_id = "".join(c for c in event_id if c.isalnum())
    conn = get_conn()
    cur = conn.execute("DELETE FROM activity WHERE id=?", (safe_id,))
    conn.commit()
    return cur.rowcount > 0


def clear_activity() -> int:
    """Delete all activity log entries. Returns count deleted."""
    conn = get_conn()
    cur = conn.execute("DELETE FROM activity")
    conn.commit()
    return cur.rowcount


# ── Internal helpers ───────────────────────────────────────────────────────────


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["success"] = bool(d["success"])
    d["details"] = json.loads(d["details"]) if d.get("details") else {}
    return d
