"""Archival review system — persist and compare historical audit results."""

import os
import json
import hashlib
import uuid
from datetime import datetime

ARCHIVE_FOLDER = os.environ.get("ARCHIVE_FOLDER", "/tmp/cashel_archive")
os.makedirs(ARCHIVE_FOLDER, exist_ok=True)


def _fingerprint(filepath):
    """Return a short SHA-256 fingerprint of a file's content."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


# ── Persistence ───────────────────────────────────────────────────────────────


def save_audit(filename, vendor, findings, summary, config_path=None, tag=None):
    """
    Save an audit result to the archive.
    Returns (entry_id, entry_dict).
    """
    entry_id = uuid.uuid4().hex[:12]
    fingerprint = (
        _fingerprint(config_path)
        if config_path and os.path.exists(config_path)
        else None
    )

    # Auto-version: find max version for same tag+vendor, increment
    version = 1
    if tag:
        existing = list_archive()
        prior = [
            e for e in existing if e.get("tag") == tag and e.get("vendor") == vendor
        ]
        if prior:
            version = max(e.get("version", 1) for e in prior) + 1

    entry = {
        "id": entry_id,
        "filename": filename,
        "vendor": vendor,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint": fingerprint,
        "summary": summary,
        "findings": findings,
        "tag": tag or None,
        "version": version,
    }
    path = os.path.join(ARCHIVE_FOLDER, f"{entry_id}.json")
    with open(path, "w") as f:
        json.dump(entry, f, indent=2)
    return entry_id, entry


def list_archive():
    """Return all archived entries sorted newest-first."""
    entries = []
    for fname in os.listdir(ARCHIVE_FOLDER):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(ARCHIVE_FOLDER, fname)) as f:
                entries.append(json.load(f))
        except Exception:
            pass
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries


def get_entry(entry_id):
    """Return a single archive entry by ID, or None."""
    # Sanitize
    safe_id = "".join(c for c in entry_id if c.isalnum())
    path = os.path.join(ARCHIVE_FOLDER, f"{safe_id}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def delete_entry(entry_id):
    """Delete an archive entry. Returns True if deleted."""
    safe_id = "".join(c for c in entry_id if c.isalnum())
    path = os.path.join(ARCHIVE_FOLDER, f"{safe_id}.json")
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


# ── Comparison ────────────────────────────────────────────────────────────────


def compare_entries(id_a, id_b):
    """
    Compare two archived audits (A = baseline / older, B = current / newer).

    Returns (result_dict, error_str_or_None).

    result keys:
      entry_a, entry_b       – full entry dicts
      delta                  – {high, medium, total}  (positive = more issues)
      new_findings           – issues in B not in A
      resolved_findings      – issues in A not in B
      improved               – bool (total delta < 0)
    """
    entry_a = get_entry(id_a)
    entry_b = get_entry(id_b)
    if not entry_a or not entry_b:
        return None, "One or both archive entries not found."

    if entry_a.get("vendor") != entry_b.get("vendor"):
        return (
            None,
            "Cannot compare audits from different vendors. Both entries must be the same vendor.",
        )

    s_a, s_b = entry_a["summary"], entry_b["summary"]
    set_a = set(entry_a.get("findings", []))
    set_b = set(entry_b.get("findings", []))

    return {
        "entry_a": entry_a,
        "entry_b": entry_b,
        "delta": {
            "high": s_b.get("high", 0) - s_a.get("high", 0),
            "medium": s_b.get("medium", 0) - s_a.get("medium", 0),
            "total": s_b.get("total", 0) - s_a.get("total", 0),
        },
        "new_findings": sorted(set_b - set_a),
        "resolved_findings": sorted(set_a - set_b),
        "improved": s_b.get("total", 0) < s_a.get("total", 0),
    }, None
