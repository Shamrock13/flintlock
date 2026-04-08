"""Tests for SQLite-backed archive, activity_log, and schedule_store modules.

Run with:  python -m pytest tests/test_db.py -v
       or:  python tests/test_db.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.db as db_mod
from cashel import archive, activity_log, schedule_store


# ── Test decorator — isolated temp DB per test ────────────────────────────────


def _tmp_db(fn):
    def wrapper(*args, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        orig_path = db_mod.DB_PATH
        orig_conn = getattr(db_mod._local, "conn", None)
        try:
            db_mod.DB_PATH = tmp
            db_mod._local.conn = None  # force new connection to tmp path
            db_mod.init_db()
            return fn(*args, **kwargs)
        finally:
            # close the temp connection
            conn = getattr(db_mod._local, "conn", None)
            if conn:
                conn.close()
            db_mod.DB_PATH = orig_path
            db_mod._local.conn = orig_conn
            try:
                os.unlink(tmp)
            except OSError:
                pass

    wrapper.__name__ = fn.__name__
    return wrapper


# ── Archive tests ─────────────────────────────────────────────────────────────


class TestArchive(unittest.TestCase):
    @_tmp_db
    def test_save_and_retrieve_audit(self):
        summary = {"high": 1, "medium": 2, "total": 3}
        findings = ["finding-a", "finding-b"]
        entry_id, entry = archive.save_audit(
            filename="fw.cfg",
            vendor="asa",
            findings=findings,
            summary=summary,
        )
        self.assertIsNotNone(entry_id)
        fetched = archive.get_entry(entry_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], entry_id)
        self.assertEqual(fetched["filename"], "fw.cfg")
        self.assertEqual(fetched["vendor"], "asa")
        self.assertEqual(fetched["summary"], summary)
        self.assertEqual(fetched["findings"], findings)
        self.assertIsNone(fetched["tag"])
        self.assertEqual(fetched["version"], 1)

    @_tmp_db
    def test_list_archive_newest_first(self):
        archive.save_audit("a.cfg", "asa", [], {"high": 0, "medium": 0, "total": 0})
        archive.save_audit("b.cfg", "asa", [], {"high": 0, "medium": 0, "total": 0})
        archive.save_audit("c.cfg", "asa", [], {"high": 0, "medium": 0, "total": 0})
        entries = archive.list_archive()
        self.assertEqual(len(entries), 3)
        # Timestamps should be in descending order
        timestamps = [e["timestamp"] for e in entries]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))

    @_tmp_db
    def test_delete_entry(self):
        entry_id, _ = archive.save_audit(
            "fw.cfg", "asa", [], {"high": 0, "medium": 0, "total": 0}
        )
        self.assertTrue(archive.delete_entry(entry_id))
        self.assertIsNone(archive.get_entry(entry_id))
        # Double-delete returns False
        self.assertFalse(archive.delete_entry(entry_id))

    @_tmp_db
    def test_auto_versioning_same_tag_vendor(self):
        summary = {"high": 0, "medium": 0, "total": 0}
        _, e1 = archive.save_audit("fw.cfg", "asa", [], summary, tag="prod")
        _, e2 = archive.save_audit("fw.cfg", "asa", [], summary, tag="prod")
        _, e3 = archive.save_audit("fw.cfg", "asa", [], summary, tag="prod")
        self.assertEqual(e1["version"], 1)
        self.assertEqual(e2["version"], 2)
        self.assertEqual(e3["version"], 3)

    @_tmp_db
    def test_compare_entries_same_vendor(self):
        summary_a = {"high": 2, "medium": 1, "total": 3}
        summary_b = {"high": 1, "medium": 0, "total": 1}
        id_a, _ = archive.save_audit("a.cfg", "asa", ["f1", "f2"], summary_a)
        id_b, _ = archive.save_audit("b.cfg", "asa", ["f1", "f3"], summary_b)
        result, err = archive.compare_entries(id_a, id_b)
        self.assertIsNone(err)
        self.assertEqual(result["delta"]["high"], -1)
        self.assertEqual(result["delta"]["total"], -2)
        self.assertIn("f3", result["new_findings"])
        self.assertIn("f2", result["resolved_findings"])
        self.assertTrue(result["improved"])

    @_tmp_db
    def test_compare_entries_vendor_mismatch_returns_error(self):
        summary = {"high": 0, "medium": 0, "total": 0}
        id_a, _ = archive.save_audit("a.cfg", "asa", [], summary)
        id_b, _ = archive.save_audit("b.cfg", "juniper", [], summary)
        result, err = archive.compare_entries(id_a, id_b)
        self.assertIsNone(result)
        self.assertIn("different vendors", err)


# ── Activity log tests ────────────────────────────────────────────────────────


class TestActivityLog(unittest.TestCase):
    @_tmp_db
    def test_log_and_list_activity(self):
        event_id = activity_log.log_activity(
            "file_audit", "fw.cfg", vendor="asa", success=True, details={"lines": 100}
        )
        self.assertIsNotNone(event_id)
        events = activity_log.list_activity()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["id"], event_id)
        self.assertEqual(ev["action"], "file_audit")
        self.assertEqual(ev["label"], "fw.cfg")
        self.assertEqual(ev["vendor"], "asa")
        self.assertTrue(ev["success"])
        self.assertEqual(ev["details"], {"lines": 100})

    @_tmp_db
    def test_list_activity_respects_limit(self):
        for i in range(10):
            activity_log.log_activity("file_audit", f"fw{i}.cfg")
        events = activity_log.list_activity(limit=5)
        self.assertEqual(len(events), 5)

    @_tmp_db
    def test_delete_activity_entry(self):
        event_id = activity_log.log_activity("file_audit", "fw.cfg")
        self.assertTrue(activity_log.delete_activity_entry(event_id))
        self.assertEqual(activity_log.list_activity(), [])
        # Double-delete returns False
        self.assertFalse(activity_log.delete_activity_entry(event_id))

    @_tmp_db
    def test_clear_activity_returns_count(self):
        for i in range(5):
            activity_log.log_activity("file_audit", f"fw{i}.cfg")
        count = activity_log.clear_activity()
        self.assertEqual(count, 5)
        self.assertEqual(activity_log.list_activity(), [])

    @_tmp_db
    def test_success_stored_as_bool(self):
        activity_log.log_activity("file_audit", "ok.cfg", success=True)
        activity_log.log_activity("file_audit", "fail.cfg", success=False)
        events = activity_log.list_activity()
        successes = {e["label"]: e["success"] for e in events}
        self.assertIs(successes["ok.cfg"], True)
        self.assertIs(successes["fail.cfg"], False)


# ── Schedule store tests ──────────────────────────────────────────────────────


_BASE_SCHEDULE = {
    "name": "Test Schedule",
    "vendor": "asa",
    "host": "192.0.2.1",
    "port": 22,
    "username": "admin",
    "password": "s3cr3t",
    "frequency": "daily",
    "hour": 2,
    "minute": 0,
    "day_of_week": "mon",
    "enabled": True,
}


class TestScheduleStore(unittest.TestCase):
    @_tmp_db
    def test_create_and_retrieve_schedule(self):
        created = schedule_store.create_schedule(_BASE_SCHEDULE)
        entry_id = created["id"]
        fetched = schedule_store.get_schedule(entry_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], entry_id)
        self.assertEqual(fetched["vendor"], "asa")
        self.assertEqual(fetched["host"], "192.0.2.1")
        self.assertNotIn("password_enc", fetched)
        self.assertIn("has_password", fetched)
        self.assertTrue(fetched["has_password"])

    @_tmp_db
    def test_list_schedules_strips_password(self):
        schedule_store.create_schedule(_BASE_SCHEDULE)
        schedules = schedule_store.list_schedules()
        self.assertEqual(len(schedules), 1)
        self.assertNotIn("password_enc", schedules[0])
        self.assertIn("has_password", schedules[0])

    @_tmp_db
    def test_list_schedules_include_password(self):
        schedule_store.create_schedule(_BASE_SCHEDULE)
        schedules = schedule_store.list_schedules(include_password=True)
        self.assertEqual(len(schedules), 1)
        self.assertIn("password_enc", schedules[0])
        self.assertNotIn("has_password", schedules[0])

    @_tmp_db
    def test_update_schedule_partial(self):
        created = schedule_store.create_schedule(_BASE_SCHEDULE)
        entry_id = created["id"]
        updated = schedule_store.update_schedule(entry_id, {"host": "10.0.0.1"})
        self.assertEqual(updated["host"], "10.0.0.1")
        self.assertEqual(updated["vendor"], "asa")  # unchanged

    @_tmp_db
    def test_delete_schedule(self):
        created = schedule_store.create_schedule(_BASE_SCHEDULE)
        entry_id = created["id"]
        self.assertTrue(schedule_store.delete_schedule(entry_id))
        self.assertIsNone(schedule_store.get_schedule(entry_id))
        self.assertFalse(schedule_store.delete_schedule(entry_id))

    @_tmp_db
    def test_record_run_updates_fields(self):
        created = schedule_store.create_schedule(_BASE_SCHEDULE)
        entry_id = created["id"]
        schedule_store.record_run(entry_id, "success")
        fetched = schedule_store.get_schedule(entry_id)
        self.assertIsNotNone(fetched["last_run"])
        self.assertEqual(fetched["last_status"], "success")
        self.assertIsNone(fetched["last_error"])

    @_tmp_db
    def test_get_password_decrypts(self):
        created = schedule_store.create_schedule(_BASE_SCHEDULE)
        entry_id = created["id"]
        password = schedule_store.get_password(entry_id)
        self.assertEqual(password, "s3cr3t")

    @_tmp_db
    def test_create_schedule_validation_error(self):
        bad = {**_BASE_SCHEDULE, "vendor": "cisco-invalid"}
        with self.assertRaises(schedule_store.ScheduleValidationError):
            schedule_store.create_schedule(bad)


# ── JSON migration tests ──────────────────────────────────────────────────────


class TestJsonMigration(unittest.TestCase):
    @_tmp_db
    def test_json_migration_imports_archive_files(self):
        import json
        import tempfile

        summary = {"high": 1, "medium": 0, "total": 1}
        entry = {
            "id": "aabbcc001122",
            "filename": "fw.cfg",
            "vendor": "asa",
            "timestamp": "2026-01-01T00:00:00Z",
            "fingerprint": None,
            "summary": summary,
            "findings": ["finding-x"],
            "tag": None,
            "version": 1,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "aabbcc001122.json")
            with open(path, "w") as f:
                json.dump(entry, f)

            orig_env = os.environ.get("ARCHIVE_FOLDER")
            os.environ["ARCHIVE_FOLDER"] = folder
            try:
                # Force table empty, then call migration
                conn = db_mod.get_conn()
                conn.execute("DELETE FROM audits")
                conn.commit()
                db_mod._migrate_json_to_sqlite()
                fetched = archive.get_entry("aabbcc001122")
            finally:
                if orig_env is None:
                    os.environ.pop("ARCHIVE_FOLDER", None)
                else:
                    os.environ["ARCHIVE_FOLDER"] = orig_env

        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["vendor"], "asa")
        self.assertEqual(fetched["summary"], summary)

    @_tmp_db
    def test_json_migration_skips_if_table_not_empty(self):
        import json
        import tempfile

        # Pre-populate the table
        archive.save_audit(
            "existing.cfg", "asa", [], {"high": 0, "medium": 0, "total": 0}
        )

        # Create a JSON folder with a different entry
        migrated_entry = {
            "id": "ffff00001111",
            "filename": "migrated.cfg",
            "vendor": "juniper",
            "timestamp": "2026-01-01T00:00:00Z",
            "fingerprint": None,
            "summary": {"high": 0, "medium": 0, "total": 0},
            "findings": [],
            "tag": None,
            "version": 1,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "ffff00001111.json")
            with open(path, "w") as f:
                json.dump(migrated_entry, f)

            orig_env = os.environ.get("ARCHIVE_FOLDER")
            os.environ["ARCHIVE_FOLDER"] = folder
            try:
                db_mod._migrate_json_to_sqlite()
                # Migration should be skipped — JSON entry should NOT appear
                fetched = archive.get_entry("ffff00001111")
            finally:
                if orig_env is None:
                    os.environ.pop("ARCHIVE_FOLDER", None)
                else:
                    os.environ["ARCHIVE_FOLDER"] = orig_env

        self.assertIsNone(fetched)


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
