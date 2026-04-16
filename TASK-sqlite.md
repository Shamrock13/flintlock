# TASK: SQLite Migration

**Status:** 🔵 Active
**Branch:** `cld/sqlite-migration` (cut from `staging`)
**Assigned to:** Builder
**Architect sign-off required before merge:** Yes

---

## Context

Cashel currently stores audit history, activity events, and scheduled jobs as individual JSON files in `/tmp` directories. This causes:
- No atomic list reads (concurrent writes can corrupt a read mid-scan)
- fcntl file locking only in `archive.py` (activity and schedules have none)
- No real queries — every list operation scans all files
- No transactions — partial writes leave orphaned files

Replace all three collection stores with a single `cashel.db` SQLite file. The public API of each module (function signatures, return dict shapes) must remain **identical** — callers in `web.py` blueprints and tests must require zero changes.

**Settings (`settings.py`) stays as JSON.** It is a single-row flat config, not a collection.

---

## Database Location

```python
DB_PATH = os.environ.get("CASHEL_DB", "/data/cashel.db")
```

- `/data/` is already the conventional persistent volume path in Dockerfile
- Env var `CASHEL_DB` allows override for testing and Docker deployments
- Create parent directory with `os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)` on init

---

## New Module: `db.py`

Create `src/cashel/db.py` — the single place that owns the SQLite connection and schema.

```python
import os
import sqlite3
import threading

DB_PATH = os.environ.get("CASHEL_DB", "/data/cashel.db")

_local = threading.local()  # per-thread connection

def get_conn() -> sqlite3.Connection:
    """Return the thread-local SQLite connection, creating it if needed."""
    if not getattr(_local, "conn", None):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # concurrent reads + writes
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn

def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
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
    """)
    conn.commit()
```

Call `init_db()` once at app startup (in `web.py`, after blueprint registration).

---

## Migration: `archive.py`

### Current public API (preserve exactly)

```python
def save_audit(filename, vendor, findings, summary, config_path=None, tag=None) -> tuple[str, dict]
def list_archive() -> list
def get_entry(entry_id: str) -> dict | None
def delete_entry(entry_id: str) -> bool
def compare_entries(id_a: str, id_b: str) -> tuple[dict | None, str | None]
```

### Return dict shape (unchanged)

```python
{
    "id": str,           # 12-char hex
    "filename": str,
    "vendor": str,
    "timestamp": str,    # ISO 8601 UTC
    "fingerprint": str | None,
    "summary": dict,     # {"high": int, "medium": int, "total": int}
    "findings": list,
    "tag": str | None,
    "version": int,
}
```

### Implementation notes

- `save_audit`: replace fcntl lock with SQLite transaction. Auto-version logic:
  `SELECT MAX(version) FROM audits WHERE tag=? AND vendor=?` inside the transaction.
- `list_archive`: `SELECT * FROM audits ORDER BY timestamp DESC`
- `get_entry`: `SELECT * FROM audits WHERE id=?` — sanitize id (alphanumeric only) before query
- `delete_entry`: `DELETE FROM audits WHERE id=?`
- `compare_entries`: call `get_entry` twice, then apply existing comparison logic (no change to that logic)
- `summary` and `findings` stored as JSON strings; deserialize on read with `json.loads()`
- Remove all `ARCHIVE_FOLDER`, `os.makedirs`, fcntl imports — no longer needed
- Keep `_fingerprint()` helper (pure function, still needed)

---

## Migration: `activity_log.py`

### Current public API (preserve exactly)

```python
def log_activity(action_type, label, vendor=None, success=True, error=None, details=None) -> str
def list_activity(limit: int = 200) -> list
def delete_activity_entry(event_id: str) -> bool
def clear_activity() -> int
```

### Return dict shape (unchanged)

```python
{
    "id": str,
    "action": str,
    "label": str,
    "vendor": str,
    "success": bool,
    "error": str,
    "details": dict,
    "timestamp": str,
}
```

### Implementation notes

- `log_activity`: `INSERT INTO activity ...` — convert `success` bool to 0/1 int for storage
- `list_activity`: `SELECT * FROM activity ORDER BY timestamp DESC LIMIT ?`
- `delete_activity_entry`: `DELETE FROM activity WHERE id=?`
- `clear_activity`: `DELETE FROM activity` — return `rowcount` from cursor
- On read: convert `success` int back to bool; `details` JSON string → dict
- Remove `ACTIVITY_FOLDER`, `os.makedirs`, all file I/O

---

## Migration: `schedule_store.py`

### Current public API (preserve exactly)

```python
def list_schedules(include_password=False) -> list
def get_schedule(entry_id, include_password=False) -> dict | None
def create_schedule(data: dict) -> dict
def update_schedule(entry_id, data: dict) -> dict | None
def delete_schedule(entry_id: str) -> bool
def record_run(entry_id, status, error=None) -> None
def get_password(entry_id: str) -> str
```

### Return dict shape (unchanged)

All schedule dicts: all fields from the schema above. When `include_password=False`, omit `password_enc` and add `has_password: bool`.

### Implementation notes

- `create_schedule`: validate via `_validate_schedule_fields()` (keep as-is), then `INSERT`
- `update_schedule`: `SELECT` existing row, merge, re-validate, then `UPDATE`
- `get_password`: `SELECT password_enc FROM schedules WHERE id=?`, then `_decode_password()`
- `_encode_password` / `_decode_password` / `_strip_password` / `_validate_schedule_fields` — keep all unchanged
- Boolean fields (`enabled`, `notify_on_finding`, `notify_on_error`): store as 0/1 int, convert back to bool on read
- Remove `SCHEDULES_FOLDER`, `os.makedirs`, fcntl, all file I/O
- 32-char hex IDs (keep as-is — `uuid.uuid4().hex`)

---

## JSON → SQLite Auto-Migration

On first startup after upgrade, if the old JSON directories contain files, import them into SQLite and leave the originals in place (do not delete — rollback safety).

Add `_migrate_json_to_sqlite()` to `db.py`, called from `init_db()` only when the respective table is empty:

```python
def _migrate_json_to_sqlite() -> None:
    """Import existing JSON files into SQLite on first run. Idempotent."""
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
            _import_json_folder(conn, schedules_folder, "schedules", _map_schedule_row)

    conn.commit()
```

Each `_map_*_row` function converts a parsed JSON dict to the column tuple expected by the INSERT.

---

## web.py Changes

Add to `web.py` after blueprint registration:

```python
from .db import init_db
init_db()
```

That's the only change to `web.py`.

---

## Testing

### Existing tests
Run `python -m pytest tests/ -v` after each module migration step. All 181 must continue to pass.

### New test file: `tests/test_db.py`

Follow the same pattern as other test files (`sys.path.insert`, pure unittest, standalone runner).

Use a temp file for the DB in every test:
```python
import tempfile, os
import cashel.db as db_mod

def _tmp_db(fn):
    def wrapper(*args, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        try:
            orig = db_mod.DB_PATH
            db_mod.DB_PATH = tmp
            db_mod._local.conn = None  # force new connection to tmp path
            db_mod.init_db()
            return fn(*args, **kwargs)
        finally:
            db_mod.DB_PATH = orig
            db_mod._local.conn = None
            os.unlink(tmp)
    wrapper.__name__ = fn.__name__
    return wrapper
```

**Tests to write:**

Archive:
- `test_save_and_retrieve_audit`
- `test_list_archive_newest_first`
- `test_delete_entry`
- `test_auto_versioning_same_tag_vendor`
- `test_compare_entries_same_vendor`
- `test_compare_entries_vendor_mismatch_returns_error`

Activity:
- `test_log_and_list_activity`
- `test_list_activity_respects_limit`
- `test_delete_activity_entry`
- `test_clear_activity_returns_count`
- `test_success_stored_as_bool`

Schedules:
- `test_create_and_retrieve_schedule`
- `test_list_schedules_strips_password`
- `test_list_schedules_include_password`
- `test_update_schedule_partial`
- `test_delete_schedule`
- `test_record_run_updates_fields`
- `test_get_password_decrypts`
- `test_create_schedule_validation_error`

Migration:
- `test_json_migration_imports_archive_files`
- `test_json_migration_skips_if_table_not_empty`

---

## Migration Order (Lowest Risk First)

Run `python -m pytest tests/ -v` after each step.

1. **Create `db.py`** with `get_conn()`, `init_db()`, schema, migration helpers
2. **Migrate `activity_log.py`** — simplest module, no encryption, no locking
3. **Migrate `archive.py`** — adds auto-versioning logic
4. **Migrate `schedule_store.py`** — most complex; has encryption and validation
5. **Wire `init_db()` into `web.py`** — one import + one call
6. **Write `tests/test_db.py`** — full coverage of all three migrated modules

---

## Acceptance Criteria (Definition of Done)

- [ ] `db.py` exists with schema, `get_conn()`, `init_db()`, `_migrate_json_to_sqlite()`
- [ ] `archive.py`, `activity_log.py`, `schedule_store.py` use SQLite — no JSON file I/O
- [ ] Public API of all three modules is identical — zero changes to callers
- [ ] `web.py` calls `init_db()` on startup
- [ ] All 181 existing tests pass with no changes to test files
- [ ] `tests/test_db.py` passes (new tests)
- [ ] `ruff check src/ tests/` clean
- [ ] Auto-migration runs on first startup with existing JSON files
- [ ] `SESSION-CHECKPOINT.md` updated at completion

---

## Branch and PR

```bash
git checkout -b cld/sqlite-migration origin/staging
# ... implement ...
python -m pytest tests/ -v
ruff check src/ tests/
git push origin cld/sqlite-migration
# PR → staging (not main)
```
