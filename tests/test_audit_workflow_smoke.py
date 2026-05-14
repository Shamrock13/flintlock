"""Smoke tests for the main file-audit UI workflow."""

from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path

import pytest

import cashel.db as db_mod
from cashel import user_store as us
from cashel.archive import get_entry


ASA_SAMPLE = b"""\
access-list OUTSIDE_IN permit ip any any
access-list OUTSIDE_IN permit tcp any host 10.0.0.1 eq 443
access-list OUTSIDE_IN deny ip any any
"""


@pytest.fixture
def isolated_app(tmp_path, monkeypatch):
    import cashel.blueprints.audit as audit_mod
    import cashel.settings as settings_mod
    import cashel.webhooks as webhooks_mod

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name

    orig_db_path = db_mod.DB_PATH
    orig_db_conn = getattr(db_mod._local, "conn", None)
    orig_settings_file = settings_mod.SETTINGS_FILE
    orig_reports_folder = audit_mod.REPORTS_FOLDER

    db_mod.DB_PATH = tmp_db
    db_mod._local.conn = None
    db_mod.init_db()
    settings_mod.SETTINGS_FILE = str(tmp_path / "settings.json")
    audit_mod.REPORTS_FOLDER = str(tmp_path / "reports")
    os.makedirs(audit_mod.REPORTS_FOLDER, exist_ok=True)
    monkeypatch.setattr(webhooks_mod, "dispatch_event", lambda *_args, **_kwargs: None)

    import cashel.web as web_mod

    web_mod.app.config["TESTING"] = True
    web_mod.app.config["WTF_CSRF_ENABLED"] = False
    web_mod.app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    client = web_mod.app.test_client()

    try:
        yield client
    finally:
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


def _post_asa_audit(client, **form):
    data = {
        "vendor": "asa",
        "config": (io.BytesIO(ASA_SAMPLE), "edge.cfg"),
        **form,
    }
    return client.post(
        "/audit",
        data=data,
        content_type="multipart/form-data",
    )


def _create_admin():
    return us.create_user("auditadmin", "supersecretpass1", "admin")


def _index_template() -> str:
    return Path("src/cashel/templates/index.html").read_text(encoding="utf-8")


def test_file_audit_requires_setup_or_test_auth_setup_works(isolated_app):
    resp = _post_asa_audit(isolated_app)
    assert resp.status_code == 302
    assert "/setup" in resp.headers["Location"]

    _create_admin()
    resp = _post_asa_audit(isolated_app)

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["summary"]["total"] >= 1
    assert data["findings"]


def test_single_file_asa_audit_returns_findings_summary_and_enriched_findings(
    isolated_app,
):
    _create_admin()

    resp = _post_asa_audit(isolated_app)

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["report"] is None
    assert data["report_warning"] is None
    assert data["summary"]["total"] >= 1
    assert data["findings"]
    assert data["enriched_findings"]

    finding = data["enriched_findings"][0]
    for key in (
        "id",
        "severity",
        "category",
        "message",
        "evidence",
        "verification",
        "rollback",
        "suggested_commands",
        "affected_object",
    ):
        assert finding.get(key), key


def test_single_file_asa_audit_pdf_failure_is_non_fatal(
    isolated_app,
    monkeypatch,
):
    import cashel.blueprints.audit as audit_mod

    _create_admin()

    def fail_report(*_args, **_kwargs):
        raise RuntimeError("Chromium executable missing")

    monkeypatch.setattr(audit_mod, "generate_report", fail_report)

    resp = _post_asa_audit(isolated_app, report="1")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["report"] is None
    assert data["report_warning"].startswith(
        "Audit completed, but PDF report generation failed:"
    )
    assert data["summary"]["total"] >= 1
    assert data["findings"]
    assert data["enriched_findings"]


def test_file_audit_archive_path_saves_enriched_findings(isolated_app):
    _create_admin()

    resp = _post_asa_audit(isolated_app, archive="1", tag="edge-smoke")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["archive_id"]
    entry = get_entry(data["archive_id"])
    assert entry is not None
    assert entry["filename"] == "edge.cfg"
    assert entry["vendor"] == "asa"
    assert entry["summary"]["total"] == data["summary"]["total"]
    assert entry["findings"] == data["enriched_findings"]
    assert entry["findings"][0]["evidence"]


def test_index_template_has_detailed_compact_and_legacy_result_paths():
    body = _index_template()

    assert '<button aria-pressed="true" id="viewDetailed">Detailed</button>' in body
    assert '<button aria-pressed="false" id="viewCompact">Compact</button>' in body
    assert "if (compactView)" in body
    assert "finding-detailed" in body
    assert "normalizeFindingsPayload(data)" in body
    assert (
        "if (Array.isArray(data.enriched_findings)) return data.enriched_findings;"
        in body
    )
    assert "if (Array.isArray(data.findings)) return data.findings;" in body
    assert 'if (typeof f !== "object" || f === null) return String(f || "");' in body


def test_index_template_renders_enriched_finding_detail_fields():
    body = _index_template()

    for expected in (
        'detailRow("Finding ID", findingId)',
        'detailRow("Evidence", isObj ? f.evidence : "", { copyable: true })',
        'detailRow("Verification", isObj ? f.verification : "")',
        'detailRow("Rollback", isObj ? f.rollback : "")',
        'detailRow("Suggested commands", findingCommands(f), { copyable: true })',
        "findingAffected(f)",
        "findingCommands(f)",
        "findingMetadataRows(f)",
    ):
        assert expected in body


def test_index_template_batches_frontend_redraws_and_delegates_list_actions():
    body = _index_template()

    assert "let findingsRenderQueued = false;" in body
    assert "requestAnimationFrame(() => {" in body
    assert "function renderFindingsNow()" in body
    assert "const FINDING_PAGE_SIZE_OPTIONS = [10, 25, 50, 75, 100];" in body
    assert "function renderPagedFindingList(findings, listEl, pagerEl, state, emptyHTML)" in body
    assert '<div id="connFindingsPagination" class="findings-pagination hidden"></div>' in body
    assert 'wireFindingPager("connFindingsPagination", connFindingPager, renderConnectFindingsPage)' in body
    assert 'id="bulkDetailFindingsPagination"' in body
    assert "let filteredHistoryData = [];" in body
    assert "const historyPager = { page: 1, pageSize: 25 };" in body
    assert "filteredHistoryData = entries;" in body
    assert "const pageEntries = entries.slice(startIndex, startIndex + historyPager.pageSize);" in body
    assert "function renderHistoryPagination(total, totalPages, startIndex)" in body
    assert 'document.getElementById("historyList")?.addEventListener("click", async function(e)' in body
    assert 'document.getElementById("historyList")?.addEventListener("change", function(e)' in body
    assert "function debounce(fn, delay = 200)" in body
    assert (
        'document.getElementById("historySearch")?.addEventListener("input", '
        "applyHistoryFiltersDebounced)"
    ) in body
    assert "Loading audit history&hellip;" in body
    assert 'document.getElementById("sideRecentRuns")?.addEventListener("click"' in body
    assert 'document.getElementById("activityList")?.addEventListener("click"' in body
    assert 'document.getElementById("webhooksTable")?.addEventListener("click"' in body


def test_browser_exports_preserve_enriched_fields():
    body = _index_template()

    assert (
        "findings:  lastAuditData.enriched_findings || lastAuditData.findings || []"
        in body
    )
    assert (
        '["id","vendor","severity","category","title","message","remediation",'
        '"evidence","affected_object","rule_name","confidence"]'
    ) in body
    assert "const findings = lastAuditData.enriched_findings || [];" in body
    assert (
        '["vendor","category","evidence","affected_object","rule_name","confidence","verification","rollback"]'
        in body
    )
    assert (
        "if (remediation) result.fixes = [{description: {text: remediation}}];" in body
    )


def test_remediation_modal_receives_enriched_findings():
    body = _index_template()

    assert (
        'document.getElementById("remediationPlanBtn")?.addEventListener("click"'
        in body
    )
    assert "fetchAndShowPlan({" in body
    assert (
        "findings: lastAuditData.enriched_findings || lastAuditData.findings || []"
        in body
    )
    assert 'fetch("/remediation-plan?fmt=json"' in body
