"""Lightweight CI hardening smoke tests for app startup and core workflows."""

from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path

import pytest

import cashel.db as db_mod
from cashel import user_store as us
from cashel.export import to_csv, to_json, to_sarif
from cashel.remediation import generate_plan
from cashel.reporter import generate_report, write_report_sidecar


ASA_SAMPLE = b"""\
hostname edge-fw
access-list OUTSIDE_IN permit ip any any
access-list OUTSIDE_IN permit tcp any host 10.0.0.1 eq 443
access-list OUTSIDE_IN deny ip any any
telnet 0.0.0.0 0.0.0.0 mgmt
"""


@pytest.fixture
def ci_client(tmp_path, monkeypatch):
    import cashel.blueprints.audit as audit_mod
    import cashel.blueprints.reports as reports_mod
    import cashel.settings as settings_mod
    import cashel.webhooks as webhooks_mod

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name

    orig_db_path = db_mod.DB_PATH
    orig_db_conn = getattr(db_mod._local, "conn", None)
    orig_settings_file = settings_mod.SETTINGS_FILE
    orig_audit_reports = audit_mod.REPORTS_FOLDER
    orig_reports_folder = reports_mod.REPORTS_FOLDER
    orig_reports_env = os.environ.get("REPORTS_FOLDER")

    reports_folder = tmp_path / "reports"
    settings_file = tmp_path / "settings.json"

    db_mod.DB_PATH = tmp_db
    db_mod._local.conn = None
    db_mod.init_db()
    settings_mod.SETTINGS_FILE = str(settings_file)
    audit_mod.REPORTS_FOLDER = str(reports_folder)
    reports_mod.REPORTS_FOLDER = str(reports_folder)
    os.environ["REPORTS_FOLDER"] = str(reports_folder)
    reports_folder.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(webhooks_mod, "dispatch_event", lambda *_args, **_kwargs: None)

    import cashel.web as web_mod

    web_mod.app.config["TESTING"] = True
    web_mod.app.config["WTF_CSRF_ENABLED"] = False
    web_mod.app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    web_mod.app.config["RATELIMIT_ENABLED"] = False
    client = web_mod.app.test_client()
    us.create_user("ciadmin", "supersecretpass1", "admin")

    try:
        yield client
    finally:
        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = orig_db_path
        db_mod._local.conn = orig_db_conn
        settings_mod.SETTINGS_FILE = orig_settings_file
        audit_mod.REPORTS_FOLDER = orig_audit_reports
        reports_mod.REPORTS_FOLDER = orig_reports_folder
        if orig_reports_env is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = orig_reports_env
        try:
            os.unlink(tmp_db)
        except OSError:
            pass


def _audit_upload(filename: str = "edge.cfg"):
    return io.BytesIO(ASA_SAMPLE), filename


def _post_single_audit(client, **form):
    return client.post(
        "/audit",
        data={"vendor": "asa", "config": _audit_upload(), **form},
        content_type="multipart/form-data",
    )


def test_flask_app_starts_and_serves_health(ci_client):
    resp = ci_client.get("/health")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "version" in data
    assert "uptime_seconds" in data


def test_single_file_audit_smoke(ci_client):
    resp = _post_single_audit(ci_client, archive="1")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["detected_vendor"] == "asa"
    assert data["archive_id"]
    assert data["summary"]["total"] >= 1
    assert data["enriched_findings"]


def test_bulk_audit_smoke(ci_client):
    resp = ci_client.post(
        "/bulk_audit",
        data={
            "vendor": "asa",
            "configs[]": [
                _audit_upload("edge-a.cfg"),
                _audit_upload("edge-b.cfg"),
            ],
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200
    results = resp.get_json()
    assert len(results) == 2
    assert {item["status"] for item in results} == {"ok"}
    assert all(item["summary"]["total"] >= 1 for item in results)


def test_remediation_plan_generation_smoke(ci_client):
    audit_resp = _post_single_audit(ci_client)
    findings = audit_resp.get_json()["enriched_findings"]

    resp = ci_client.post(
        "/remediation-plan?fmt=json",
        json={"vendor": "asa", "filename": "edge.cfg", "findings": findings},
    )

    assert resp.status_code == 200
    plan = resp.get_json()
    assert plan["total_steps"] >= 1
    assert plan["phases"][0]["steps"][0]["guidance"]


def test_api_audit_endpoint_smoke(ci_client):
    resp = ci_client.post(
        "/api/v1/audit",
        data={"vendor": "asa", "archive": "1", "config": _audit_upload()},
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["ok"] is True
    assert payload["data"]["vendor"] == "asa"
    assert payload["data"]["summary"]["total"] >= 1
    assert payload["data"]["archive_id"]


def test_remediation_pdf_generation_smoke(ci_client):
    audit_resp = _post_single_audit(ci_client)
    findings = audit_resp.get_json()["enriched_findings"]

    resp = ci_client.post(
        "/remediation-plan?fmt=pdf&inline=1",
        json={"vendor": "asa", "filename": "edge.cfg", "findings": findings},
    )

    assert resp.status_code == 200
    assert resp.data.startswith(b"%PDF")
    assert "application/pdf" in resp.content_type


def test_report_and_export_smoke(ci_client, tmp_path):
    audit_resp = _post_single_audit(ci_client)
    data = audit_resp.get_json()
    findings = data["enriched_findings"]
    summary = data["summary"]
    report_path = tmp_path / "audit-report.pdf"

    generated = generate_report(
        findings,
        "edge.cfg",
        "asa",
        output_path=str(report_path),
        summary=summary,
    )
    sidecar = write_report_sidecar(
        generated,
        findings=findings,
        filename="edge.cfg",
        vendor="asa",
        compliance=None,
        summary=summary,
    )
    entry = {
        "filename": "edge.cfg",
        "vendor": "asa",
        "timestamp": "2026-05-08T00:00:00Z",
        "summary": summary,
        "findings": findings,
    }

    assert Path(generated).read_bytes().startswith(b"%PDF")
    assert Path(sidecar).exists()
    assert '"vendor": "asa"' in to_json(entry)
    assert "severity" in to_csv(entry)
    assert '"version": "2.1.0"' in to_sarif(entry)
    assert generate_plan(findings, "asa", filename="edge.cfg")["total_steps"] >= 1
