"""Archival review system — persist and compare historical audit results."""

import hashlib
import json
import os
import uuid
from datetime import datetime

from .db import get_conn


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
    Uses a SQLite transaction to prevent version collisions under concurrent requests.
    """
    entry_id = uuid.uuid4().hex[:12]
    fingerprint = (
        _fingerprint(config_path)
        if config_path and os.path.exists(config_path)
        else None
    )
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    # Auto-version inside a transaction
    with conn:
        version = 1
        if tag:
            row = conn.execute(
                "SELECT MAX(version) FROM audits WHERE tag=? AND vendor=?",
                (tag, vendor),
            ).fetchone()
            if row and row[0] is not None:
                version = row[0] + 1

        conn.execute(
            """
            INSERT INTO audits (id, filename, vendor, timestamp, fingerprint,
                                summary, findings, tag, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                filename,
                vendor,
                timestamp,
                fingerprint,
                json.dumps(summary),
                json.dumps(findings),
                tag or None,
                version,
            ),
        )

    entry = {
        "id": entry_id,
        "filename": filename,
        "vendor": vendor,
        "timestamp": timestamp,
        "fingerprint": fingerprint,
        "summary": summary,
        "findings": findings,
        "tag": tag or None,
        "version": version,
    }

    from cashel import webhooks

    webhooks.dispatch_event(
        "audit.complete",
        {
            "audit_id": entry_id,
            "filename": filename,
            "vendor": vendor,
            "score": summary.get("score"),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "total": summary.get("total", 0),
            "tag": tag,
            "timestamp": entry.get("timestamp"),
        },
    )

    return entry_id, entry


def list_archive():
    """Return all archived entries sorted newest-first."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audits ORDER BY timestamp DESC").fetchall()
    return [_row_to_dict(row) for row in rows]


def get_entry(entry_id):
    """Return a single archive entry by ID, or None."""
    safe_id = "".join(c for c in entry_id if c.isalnum())
    conn = get_conn()
    row = conn.execute("SELECT * FROM audits WHERE id=?", (safe_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def delete_entry(entry_id):
    """Delete an archive entry. Returns True if deleted."""
    safe_id = "".join(c for c in entry_id if c.isalnum())
    conn = get_conn()
    cur = conn.execute("DELETE FROM audits WHERE id=?", (safe_id,))
    conn.commit()
    return cur.rowcount > 0


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


# ── Internal helpers ───────────────────────────────────────────────────────────


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["summary"] = json.loads(d["summary"]) if d.get("summary") else {}
    d["findings"] = json.loads(d["findings"]) if d.get("findings") else []
    return d
