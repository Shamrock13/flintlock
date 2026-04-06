"""SQLite connection, schema, and JSON migration helpers.

Single source of truth for the database.  All other modules call get_conn()
and init_db() — they never open sqlite3.connect() themselves.
"""

import json
import os
import sqlite3
import threading

DB_PATH = os.environ.get("CASHEL_DB", "/data/cashel.db")

_local = threading.local()  # per-thread connection


def get_conn() -> sqlite3.Connection:
    """Return the thread-local SQLite connection, creating it if needed."""
    if not getattr(_local, "conn", None):
        db_path = DB_PATH  # read module-level at call time (tests can swap it)
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


def init_db() -> None:
    """Create tables if they don't exist.  Safe to call on every startup."""
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS audits (
            id          TEXT PRIMARY KEY,
            filename    TEXT NOT NULL,
            vendor      TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            fingerprint TEXT,
            summary     TEXT NOT NULL,   -- JSON blob: {high, medium, total}
            findings    TEXT NOT NULL,   -- JSON array of finding dicts
            tag         TEXT,
            version     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS activity (
            id          TEXT PRIMARY KEY,
            action      TEXT NOT NULL,
            label       TEXT NOT NULL,
            vendor      TEXT NOT NULL DEFAULT '',
            success     INTEGER NOT NULL DEFAULT 1,  -- 0/1 boolean
            error       TEXT NOT NULL DEFAULT '',
            details     TEXT NOT NULL DEFAULT '{}',  -- JSON blob
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id                      TEXT PRIMARY KEY,
            name                    TEXT NOT NULL,
            vendor                  TEXT NOT NULL,
            host                    TEXT NOT NULL,
            port                    INTEGER NOT NULL DEFAULT 22,
            username                TEXT NOT NULL,
            password_enc            TEXT NOT NULL DEFAULT '',
            tag                     TEXT NOT NULL DEFAULT '',
            compliance              TEXT NOT NULL DEFAULT '',
            frequency               TEXT NOT NULL DEFAULT 'daily',
            hour                    INTEGER NOT NULL DEFAULT 2,
            minute                  INTEGER NOT NULL DEFAULT 0,
            day_of_week             TEXT NOT NULL DEFAULT 'mon',
            enabled                 INTEGER NOT NULL DEFAULT 1,
            notify_on_finding       INTEGER NOT NULL DEFAULT 0,
            notify_on_error         INTEGER NOT NULL DEFAULT 0,
            notify_slack_webhook    TEXT NOT NULL DEFAULT '',
            notify_teams_webhook    TEXT NOT NULL DEFAULT '',
            notify_email            TEXT NOT NULL DEFAULT '',
            last_run                TEXT,
            last_status             TEXT,
            last_error              TEXT,
            created_at              TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'viewer',
            api_key_enc   TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
    """)
    conn.commit()
    _migrate_json_to_sqlite()


# ── JSON → SQLite auto-migration ──────────────────────────────────────────────


def _import_json_folder(conn, folder, table, map_fn):
    """Read every .json file in *folder* and INSERT via *map_fn*."""
    for fname in os.listdir(folder):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(folder, fname)
        try:
            with open(path) as f:
                data = json.load(f)
            row = map_fn(data)
            if row is None:
                continue
            placeholders = ", ".join("?" * len(row))
            cols = ", ".join(row.keys())
            conn.execute(
                f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({placeholders})",
                list(row.values()),
            )
        except Exception:
            pass  # skip corrupt files


def _map_audit_row(data: dict) -> dict:
    return {
        "id": data.get("id", ""),
        "filename": data.get("filename", ""),
        "vendor": data.get("vendor", ""),
        "timestamp": data.get("timestamp", ""),
        "fingerprint": data.get("fingerprint"),
        "summary": json.dumps(data.get("summary", {})),
        "findings": json.dumps(data.get("findings", [])),
        "tag": data.get("tag"),
        "version": data.get("version", 1),
    }


def _map_activity_row(data: dict) -> dict:
    return {
        "id": data.get("id", ""),
        "action": data.get("action", ""),
        "label": data.get("label", ""),
        "vendor": data.get("vendor", ""),
        "success": 1 if data.get("success", True) else 0,
        "error": data.get("error", ""),
        "details": json.dumps(data.get("details", {})),
        "timestamp": data.get("timestamp", ""),
    }


def _map_schedule_row(data: dict) -> dict:
    return {
        "id": data.get("id", ""),
        "name": data.get("name", ""),
        "vendor": data.get("vendor", ""),
        "host": data.get("host", ""),
        "port": data.get("port", 22),
        "username": data.get("username", ""),
        "password_enc": data.get("password_enc", ""),
        "tag": data.get("tag", ""),
        "compliance": data.get("compliance", ""),
        "frequency": data.get("frequency", "daily"),
        "hour": data.get("hour", 2),
        "minute": data.get("minute", 0),
        "day_of_week": data.get("day_of_week", "mon"),
        "enabled": 1 if data.get("enabled", True) else 0,
        "notify_on_finding": 1 if data.get("notify_on_finding", False) else 0,
        "notify_on_error": 1 if data.get("notify_on_error", False) else 0,
        "notify_slack_webhook": data.get("notify_slack_webhook", ""),
        "notify_teams_webhook": data.get("notify_teams_webhook", ""),
        "notify_email": data.get("notify_email", ""),
        "last_run": data.get("last_run"),
        "last_status": data.get("last_status"),
        "last_error": data.get("last_error"),
        "created_at": data.get("created_at", ""),
    }


def _migrate_json_to_sqlite() -> None:
    """Import existing JSON files into SQLite on first run.  Idempotent."""
    conn = get_conn()

    # Archive
    archive_folder = os.environ.get("ARCHIVE_FOLDER", "/tmp/cashel_archive")
    if os.path.isdir(archive_folder):
        count = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
        if count == 0:
            _import_json_folder(conn, archive_folder, "audits", _map_audit_row)

    # Activity
    activity_folder = os.environ.get("ACTIVITY_FOLDER", "/tmp/cashel_activity")
    if os.path.isdir(activity_folder):
        count = conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0]
        if count == 0:
            _import_json_folder(conn, activity_folder, "activity", _map_activity_row)

    # Schedules
    schedules_folder = os.environ.get("SCHEDULES_FOLDER", "/tmp/cashel_schedules")
    if os.path.isdir(schedules_folder):
        count = conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0]
        if count == 0:
            _import_json_folder(
                conn, schedules_folder, "schedules", _map_schedule_row
            )

    conn.commit()
