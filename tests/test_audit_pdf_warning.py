"""Tests for audit upload limits and non-fatal PDF report failures."""

from __future__ import annotations

import io
import os
import tempfile

import cashel.db as db_mod
from cashel import user_store as us
from cashel._helpers import MAX_FILE_MB, _MAX_FILE_BYTES


ASA_SAMPLE = b"""\
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended deny ip any any
"""


def _make_client():
    import cashel.web as web_mod

    app = web_mod.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    return app.test_client()


def _setup_app(tmp_path):
    import cashel.settings as settings_mod
    import cashel.blueprints.audit as audit_mod

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name

    orig_db_path = db_mod.DB_PATH
    orig_db_conn = getattr(db_mod._local, "conn", None)
    db_mod.DB_PATH = tmp_db
    db_mod._local.conn = None
    db_mod.init_db()

    orig_settings_file = settings_mod.SETTINGS_FILE
    settings_mod.SETTINGS_FILE = str(tmp_path / "settings.json")

    orig_reports_folder = audit_mod.REPORTS_FOLDER
    audit_mod.REPORTS_FOLDER = str(tmp_path / "reports")
    os.makedirs(audit_mod.REPORTS_FOLDER, exist_ok=True)

    us.create_user("auditadmin", "supersecretpass1", "admin")
    return tmp_db, orig_db_path, orig_db_conn, orig_settings_file, orig_reports_folder


def _teardown_app(state):
    import cashel.settings as settings_mod
    import cashel.blueprints.audit as audit_mod

    tmp_db, orig_db_path, orig_db_conn, orig_settings_file, orig_reports_folder = state
    conn = getattr(db_mod._local, "conn", None)
    if conn:
        conn.close()
    db_mod.DB_PATH = orig_db_path
    db_mod._local.conn = orig_db_conn
    settings_mod.SETTINGS_FILE = orig_settings_file
    audit_mod.REPORTS_FOLDER = orig_reports_folder
    try:
        os.unlink(tmp_db)
    except OSError:
        pass


def test_upload_limit_is_25_mb():
    assert MAX_FILE_MB == 25
    assert _MAX_FILE_BYTES == 25 * 1024 * 1024


def test_audit_returns_findings_when_pdf_generation_fails(monkeypatch, tmp_path):
    import cashel.blueprints.audit as audit_mod

    state = _setup_app(tmp_path)
    try:

        def fail_report(*_args, **_kwargs):
            raise RuntimeError("Chromium executable missing")

        monkeypatch.setattr(audit_mod, "generate_report", fail_report)
        client = _make_client()

        resp = client.post(
            "/audit",
            data={
                "vendor": "asa",
                "report": "1",
                "config": (io.BytesIO(ASA_SAMPLE), "edge.cfg"),
            },
            content_type="multipart/form-data",
        )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report"] is None
        assert data["report_warning"].startswith(
            "Audit completed, but PDF report generation failed:"
        )
        assert data["findings"]
        assert data["summary"]["total"] >= 1
    finally:
        _teardown_app(state)


def test_pdf_warning_does_not_prevent_archive(monkeypatch, tmp_path):
    import cashel.blueprints.audit as audit_mod

    state = _setup_app(tmp_path)
    try:

        def fail_report(*_args, **_kwargs):
            raise RuntimeError("Chromium executable missing")

        monkeypatch.setattr(audit_mod, "generate_report", fail_report)
        client = _make_client()

        resp = client.post(
            "/audit",
            data={
                "vendor": "asa",
                "report": "1",
                "archive": "1",
                "config": (io.BytesIO(ASA_SAMPLE), "edge.cfg"),
            },
            content_type="multipart/form-data",
        )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["archive_id"]
        assert data["report"] is None
        assert data["report_warning"]
        assert data["summary"]["total"] >= 1
    finally:
        _teardown_app(state)
