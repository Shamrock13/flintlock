"""Activity log — record every user action (audits, SSH attempts, diffs) including failures."""
import os
import json
import uuid
from datetime import datetime

ACTIVITY_FOLDER = os.environ.get("ACTIVITY_FOLDER", "/tmp/flintlock_activity")
os.makedirs(ACTIVITY_FOLDER, exist_ok=True)

# Action type constants
ACTION_FILE_AUDIT   = "file_audit"
ACTION_SSH_CONNECT  = "ssh_connect"
ACTION_CONFIG_DIFF  = "config_diff"
ACTION_COMPARISON   = "archive_compare"


def log_activity(action_type: str, label: str, vendor: str | None = None,
                 success: bool = True, error: str | None = None,
                 details: dict | None = None) -> str:
    """
    Append an activity event.

    Returns the new event ID.
    """
    event_id = uuid.uuid4().hex[:12]
    event = {
        "id":          event_id,
        "action":      action_type,
        "label":       label,
        "vendor":      vendor or "",
        "success":     success,
        "error":       error or "",
        "details":     details or {},
        "timestamp":   datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = os.path.join(ACTIVITY_FOLDER, f"{event_id}.json")
    with open(path, "w") as f:
        json.dump(event, f, indent=2)
    return event_id


def list_activity(limit: int = 200) -> list:
    """Return activity events sorted newest-first, up to *limit* entries."""
    events = []
    for fname in os.listdir(ACTIVITY_FOLDER):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(ACTIVITY_FOLDER, fname)) as f:
                events.append(json.load(f))
        except Exception:
            pass
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events[:limit]


def delete_activity_entry(event_id: str) -> bool:
    """Delete a single activity log entry. Returns True if deleted."""
    safe_id = "".join(c for c in event_id if c.isalnum())
    path = os.path.join(ACTIVITY_FOLDER, f"{safe_id}.json")
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def clear_activity() -> int:
    """Delete all activity log entries. Returns count deleted."""
    count = 0
    for fname in os.listdir(ACTIVITY_FOLDER):
        if fname.endswith(".json"):
            try:
                os.remove(os.path.join(ACTIVITY_FOLDER, fname))
                count += 1
            except Exception:
                pass
    return count
