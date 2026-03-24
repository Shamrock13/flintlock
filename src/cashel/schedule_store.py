"""Schedule store — persists scheduled SSH audit jobs as individual JSON files.

Passwords are encrypted with Fernet symmetric encryption via crypto.py.
The key lives at CASHEL_KEY_FILE (default /data/cashel.key) and is
generated automatically on first use. Legacy base64-encoded passwords
are transparently migrated to Fernet on next write.
"""
import json
import os
import uuid
from datetime import datetime

from .crypto import encrypt, decrypt

SCHEDULES_FOLDER = os.environ.get("SCHEDULES_FOLDER", "/tmp/cashel_schedules")

VALID_VENDORS    = ("asa", "cisco", "ftd", "fortinet", "iptables", "juniper", "nftables", "paloalto", "pfsense")
VALID_FREQS      = ("hourly", "daily", "weekly")
VALID_FRAMEWORKS = ("", "cis", "hipaa", "nist", "pci", "soc2", "stig")
VALID_DOW        = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


# ── Input validation helpers ───────────────────────────────────────────────────

class ScheduleValidationError(ValueError):
    """Raised when a schedule field fails validation."""


def _validate_int_range(value, name: str, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ScheduleValidationError(f"'{name}' must be an integer, got {value!r}")
    if not lo <= v <= hi:
        raise ScheduleValidationError(f"'{name}' must be between {lo} and {hi}, got {v}")
    return v


def _validate_schedule_fields(data: dict) -> dict:
    """Validate and coerce all user-supplied schedule fields.

    Returns a clean dict of validated values.  Raises ScheduleValidationError
    on any invalid input so the caller can return a 400 response.
    """
    vendor     = str(data.get("vendor", "asa")).strip().lower()
    frequency  = str(data.get("frequency", "daily")).strip().lower()
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
        raise ScheduleValidationError(
            f"Invalid compliance framework '{compliance}'."
        )

    hour   = _validate_int_range(data.get("hour",   2),  "hour",   0, 23)
    minute = _validate_int_range(data.get("minute", 0),  "minute", 0, 59)
    port   = _validate_int_range(data.get("port",  22),  "port",   1, 65535)

    return {
        "vendor":      vendor,
        "frequency":   frequency,
        "day_of_week": day_of_week,
        "compliance":  compliance,
        "hour":        hour,
        "minute":      minute,
        "port":        port,
    }


# ── Internal helpers ───────────────────────────────────────────────────────────

def _path(entry_id: str) -> str:
    return os.path.join(SCHEDULES_FOLDER, f"{entry_id}.json")


def _encode_password(password: str) -> str:
    return encrypt(password)


def _decode_password(encoded: str) -> str:
    return decrypt(encoded)


def _strip_password(schedule: dict) -> dict:
    """Return a copy of the schedule dict without the stored password."""
    s = {k: v for k, v in schedule.items() if k != "password_enc"}
    s["has_password"] = bool(schedule.get("password_enc"))
    return s


# ── Public CRUD ────────────────────────────────────────────────────────────────

def list_schedules(include_password: bool = False) -> list:
    os.makedirs(SCHEDULES_FOLDER, exist_ok=True)
    result = []
    for fname in sorted(os.listdir(SCHEDULES_FOLDER)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(SCHEDULES_FOLDER, fname)) as f:
                data = json.load(f)
            result.append(data if include_password else _strip_password(data))
        except Exception:
            pass
    return result


def get_schedule(entry_id: str, include_password: bool = False) -> dict | None:
    try:
        with open(_path(entry_id)) as f:
            data = json.load(f)
        return data if include_password else _strip_password(data)
    except FileNotFoundError:
        return None


def create_schedule(data: dict) -> dict:
    """Create and persist a new schedule.  Raises ScheduleValidationError on bad input."""
    validated = _validate_schedule_fields(data)
    os.makedirs(SCHEDULES_FOLDER, exist_ok=True)
    entry_id = uuid.uuid4().hex
    schedule = {
        "id":           entry_id,
        "name":         str(data.get("name", "Unnamed Schedule"))[:80],
        "vendor":       validated["vendor"],
        "host":         str(data.get("host", "")),
        "port":         validated["port"],
        "username":     str(data.get("username", "")),
        "password_enc": _encode_password(str(data.get("password", ""))),
        "tag":          str(data.get("tag", ""))[:64],
        "compliance":   validated["compliance"],
        "frequency":    validated["frequency"],
        "hour":         validated["hour"],
        "minute":       validated["minute"],
        "day_of_week":  validated["day_of_week"],
        "enabled":               bool(data.get("enabled", True)),
        # Notification settings
        "notify_on_finding":     bool(data.get("notify_on_finding", False)),
        "notify_on_error":       bool(data.get("notify_on_error", False)),
        "notify_slack_webhook":  str(data.get("notify_slack_webhook", ""))[:512],
        "notify_teams_webhook":  str(data.get("notify_teams_webhook", ""))[:512],
        "notify_email":          str(data.get("notify_email", ""))[:254],
        "last_run":     None,
        "last_status":  None,
        "last_error":   None,
        "created_at":   datetime.utcnow().isoformat(),
    }
    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)
    return _strip_password(schedule)


def update_schedule(entry_id: str, data: dict) -> dict | None:
    """Update a schedule.  Raises ScheduleValidationError on bad input."""
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return None

    # Merge incoming data with current values so partial updates still validate.
    merged = {**schedule, **data}
    validated = _validate_schedule_fields(merged)

    for key in ("name", "host", "tag",
                "notify_on_finding", "notify_on_error",
                "notify_slack_webhook", "notify_teams_webhook", "notify_email"):
        if key in data:
            schedule[key] = data[key]

    schedule["vendor"]      = validated["vendor"]
    schedule["compliance"]  = validated["compliance"]
    schedule["frequency"]   = validated["frequency"]
    schedule["day_of_week"] = validated["day_of_week"]
    schedule["hour"]        = validated["hour"]
    schedule["minute"]      = validated["minute"]
    schedule["port"]        = validated["port"]

    if "enabled" in data:
        schedule["enabled"] = bool(data["enabled"])
    if data.get("password"):
        schedule["password_enc"] = _encode_password(str(data["password"]))

    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)
    return _strip_password(schedule)


def delete_schedule(entry_id: str) -> bool:
    try:
        os.remove(_path(entry_id))
        return True
    except FileNotFoundError:
        return False


def record_run(entry_id: str, status: str, error: str | None = None):
    """Update last_run, last_status, last_error after a job executes."""
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return
    schedule["last_run"]    = datetime.utcnow().isoformat()
    schedule["last_status"] = status
    schedule["last_error"]  = error
    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)


def get_password(entry_id: str) -> str:
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return ""
    return _decode_password(schedule.get("password_enc", ""))
