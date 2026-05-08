"""Schedule store — persists scheduled SSH audit jobs in SQLite.

Passwords are encrypted with Fernet symmetric encryption via crypto.py.
The key lives at CASHEL_KEY_FILE (default /data/cashel.key) and is
generated automatically on first use. Legacy base64-encoded passwords
are transparently migrated to Fernet on next write.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from .crypto import encrypt, decrypt
from .db import get_conn

VALID_VENDORS = (
    "asa",
    "cisco",
    "ftd",
    "fortinet",
    "iptables",
    "juniper",
    "nftables",
    "paloalto",
    "pfsense",
)
VALID_FREQS = ("hourly", "daily", "weekly")
VALID_FRAMEWORKS = ("", "cis", "hipaa", "nist", "pci", "soc2", "stig")
VALID_DOW = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


# ── Input validation helpers ───────────────────────────────────────────────────


class ScheduleValidationError(ValueError):
    """Raised when a schedule field fails validation."""


def _validate_int_range(value, name: str, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ScheduleValidationError(f"'{name}' must be an integer, got {value!r}")
    if not lo <= v <= hi:
        raise ScheduleValidationError(
            f"'{name}' must be between {lo} and {hi}, got {v}"
        )
    return v


def _validate_schedule_fields(data: dict) -> dict:
    """Validate and coerce all user-supplied schedule fields.

    Returns a clean dict of validated values.  Raises ScheduleValidationError
    on any invalid input so the caller can return a 400 response.
    """
    vendor = str(data.get("vendor", "asa")).strip().lower()
    frequency = str(data.get("frequency", "daily")).strip().lower()
    day_of_week = str(data.get("day_of_week", "mon")).strip().lower()
    compliance = str(data.get("compliance", "")).strip().lower()

    if vendor not in VALID_VENDORS:
        raise ScheduleValidationError(
            f"Invalid vendor '{vendor}'. Allowed: {', '.join(VALID_VENDORS)}"
        )
    if frequency not in VALID_FREQS:
        raise ScheduleValidationError(
            f"Invalid frequency '{frequency}'. Allowed: {', '.join(VALID_FREQS)}"
        )
    if day_of_week not in VALID_DOW:
        raise ScheduleValidationError(
            f"Invalid day_of_week '{day_of_week}'. Allowed: {', '.join(VALID_DOW)}"
        )
    if compliance and compliance not in VALID_FRAMEWORKS:
        raise ScheduleValidationError(f"Invalid compliance framework '{compliance}'.")

    hour = _validate_int_range(data.get("hour", 2), "hour", 0, 23)
    minute = _validate_int_range(data.get("minute", 0), "minute", 0, 59)
    port = _validate_int_range(data.get("port", 22), "port", 1, 65535)

    return {
        "vendor": vendor,
        "frequency": frequency,
        "day_of_week": day_of_week,
        "compliance": compliance,
        "hour": hour,
        "minute": minute,
        "port": port,
    }


# ── Internal helpers ───────────────────────────────────────────────────────────


def _encode_password(password: str) -> str:
    return encrypt(password)


def _decode_password(encoded: str) -> str:
    return decrypt(encoded)


def _strip_password(schedule: dict) -> dict:
    """Return a copy of the schedule dict without the stored password."""
    s = {k: v for k, v in schedule.items() if k != "password_enc"}
    s["has_password"] = bool(schedule.get("password_enc"))
    return s


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a plain dict, restoring Python types."""
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    d["notify_on_critical"] = bool(d.get("notify_on_critical", False))
    d["notify_on_finding"] = bool(d["notify_on_finding"])
    d["notify_on_error"] = bool(d["notify_on_error"])
    return d


# ── Public CRUD ────────────────────────────────────────────────────────────────


def list_schedules(include_password: bool = False) -> list:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM schedules ORDER BY created_at").fetchall()
    result = []
    for row in rows:
        data = _row_to_dict(row)
        result.append(data if include_password else _strip_password(data))
    return result


def get_schedule(entry_id: str, include_password: bool = False) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM schedules WHERE id=?", (entry_id,)).fetchone()
    if row is None:
        return None
    data = _row_to_dict(row)
    return data if include_password else _strip_password(data)


def create_schedule(data: dict) -> dict:
    """Create and persist a new schedule.  Raises ScheduleValidationError on bad input."""
    validated = _validate_schedule_fields(data)
    entry_id = uuid.uuid4().hex
    created_at = datetime.utcnow().isoformat()

    schedule = {
        "id": entry_id,
        "name": str(data.get("name", "Unnamed Schedule"))[:80],
        "vendor": validated["vendor"],
        "host": str(data.get("host", "")),
        "port": validated["port"],
        "username": str(data.get("username", "")),
        "password_enc": _encode_password(str(data.get("password", ""))),
        "tag": str(data.get("tag", ""))[:64],
        "compliance": validated["compliance"],
        "frequency": validated["frequency"],
        "hour": validated["hour"],
        "minute": validated["minute"],
        "day_of_week": validated["day_of_week"],
        "enabled": bool(data.get("enabled", True)),
        "notify_on_critical": bool(
            data.get("notify_on_critical", data.get("notify_on_finding", False))
        ),
        "notify_on_finding": bool(data.get("notify_on_finding", False)),
        "notify_on_error": bool(data.get("notify_on_error", False)),
        "notify_slack_webhook": str(data.get("notify_slack_webhook", ""))[:512],
        "notify_teams_webhook": str(data.get("notify_teams_webhook", ""))[:512],
        "notify_email": str(data.get("notify_email", ""))[:254],
        "last_run": None,
        "last_status": None,
        "last_error": None,
        "created_at": created_at,
    }

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO schedules (
            id, name, vendor, host, port, username, password_enc, tag, compliance,
            frequency, hour, minute, day_of_week, enabled, notify_on_critical,
            notify_on_finding, notify_on_error, notify_slack_webhook,
            notify_teams_webhook, notify_email, last_run, last_status, last_error,
            created_at
        ) VALUES (
            :id, :name, :vendor, :host, :port, :username, :password_enc, :tag,
            :compliance, :frequency, :hour, :minute, :day_of_week,
            :enabled, :notify_on_critical, :notify_on_finding, :notify_on_error,
            :notify_slack_webhook, :notify_teams_webhook, :notify_email,
            :last_run, :last_status, :last_error, :created_at
        )
        """,
        {
            **schedule,
            "enabled": 1 if schedule["enabled"] else 0,
            "notify_on_critical": 1 if schedule["notify_on_critical"] else 0,
            "notify_on_finding": 1 if schedule["notify_on_finding"] else 0,
            "notify_on_error": 1 if schedule["notify_on_error"] else 0,
        },
    )
    conn.commit()
    return _strip_password(schedule)


def update_schedule(entry_id: str, data: dict) -> dict | None:
    """Update a schedule.  Raises ScheduleValidationError on bad input."""
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return None

    # Merge incoming data with current values so partial updates still validate.
    merged = {**schedule, **data}
    validated = _validate_schedule_fields(merged)

    for key in (
        "name",
        "host",
        "username",
        "tag",
        "notify_on_critical",
        "notify_on_finding",
        "notify_on_error",
        "notify_slack_webhook",
        "notify_teams_webhook",
        "notify_email",
    ):
        if key in data:
            schedule[key] = data[key]

    schedule["vendor"] = validated["vendor"]
    schedule["compliance"] = validated["compliance"]
    schedule["frequency"] = validated["frequency"]
    schedule["day_of_week"] = validated["day_of_week"]
    schedule["hour"] = validated["hour"]
    schedule["minute"] = validated["minute"]
    schedule["port"] = validated["port"]

    if "enabled" in data:
        schedule["enabled"] = bool(data["enabled"])
    if data.get("password"):
        schedule["password_enc"] = _encode_password(str(data["password"]))

    conn = get_conn()
    conn.execute(
        """
        UPDATE schedules SET
            name=:name, vendor=:vendor, host=:host, port=:port,
            username=:username, password_enc=:password_enc, tag=:tag,
            compliance=:compliance, frequency=:frequency, hour=:hour,
            minute=:minute, day_of_week=:day_of_week, enabled=:enabled,
            notify_on_critical=:notify_on_critical,
            notify_on_finding=:notify_on_finding, notify_on_error=:notify_on_error,
            notify_slack_webhook=:notify_slack_webhook,
            notify_teams_webhook=:notify_teams_webhook, notify_email=:notify_email
        WHERE id=:id
        """,
        {
            **schedule,
            "enabled": 1 if schedule["enabled"] else 0,
            "notify_on_critical": 1 if schedule["notify_on_critical"] else 0,
            "notify_on_finding": 1 if schedule["notify_on_finding"] else 0,
            "notify_on_error": 1 if schedule["notify_on_error"] else 0,
        },
    )
    conn.commit()
    return _strip_password(schedule)


def delete_schedule(entry_id: str) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM schedules WHERE id=?", (entry_id,))
    conn.commit()
    return cur.rowcount > 0


def record_run(entry_id: str, status: str, error: str | None = None):
    """Update last_run, last_status, last_error after a job executes."""
    conn = get_conn()
    conn.execute(
        """
        UPDATE schedules SET last_run=?, last_status=?, last_error=?
        WHERE id=?
        """,
        (datetime.utcnow().isoformat(), status, error, entry_id),
    )
    conn.commit()


def get_password(entry_id: str) -> str:
    conn = get_conn()
    row = conn.execute(
        "SELECT password_enc FROM schedules WHERE id=?", (entry_id,)
    ).fetchone()
    if row is None:
        return ""
    return _decode_password(row["password_enc"])
