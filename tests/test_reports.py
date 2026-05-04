"""Route tests for /remediation-plan and /demo/sample-report.pdf."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_client():
    import cashel.web as web_mod

    app = web_mod.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    return app.test_client()


def _ensure_user_exists():
    """Create a test user so has_users() returns True and the auth gate passes."""
    from cashel import user_store as us
    from cashel.user_store import UserValidationError

    try:
        us.create_user("testadmin", "TestPass123!", "admin")
    except UserValidationError:
        pass  # user already exists — fine


SAMPLE_PAYLOAD = {
    "findings": [
        {
            "id": "CASHEL-ASA-EXPOSURE-001",
            "vendor": "asa",
            "severity": "HIGH",
            "category": "exposure",
            "title": "Any-any rule",
            "message": "[HIGH] permit ip any any",
            "evidence": "access-list OUTSIDE_IN permit ip any any",
            "affected_object": "OUTSIDE_IN",
            "confidence": "high",
            "verification": "Re-run the audit after replacing the rule.",
            "rollback": "Restore the prior ACL line from backup.",
            "suggested_commands": ["no access-list <ACL_NAME> permit ip any any"],
            "metadata": {"acl": "OUTSIDE_IN"},
            "remediation": "Replace with specific rules.",
        }
    ],
    "vendor": "asa",
    "filename": "test.txt",
}

SAMPLE_SUMMARY = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 0,
    "total": 6,
    "score": 51,
}


class TestRemediationPdfInline(unittest.TestCase):
    def setUp(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        # Isolated temp DB so tests pass regardless of execution order.
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self._tmp_db_path = f.name
        self._orig_db_path = db_mod.DB_PATH
        self._orig_db_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = self._tmp_db_path
        db_mod._local.conn = None
        db_mod.init_db()

        # Use an isolated temp settings file with auth disabled so routes are
        # reachable without a login session.
        self.tmp_dir = tempfile.mkdtemp()
        self._tmp_settings = os.path.join(self.tmp_dir, "settings.json")
        self._orig_settings_file = settings_mod.SETTINGS_FILE
        settings_mod.SETTINGS_FILE = self._tmp_settings

        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = self.tmp_dir

        self.client = _make_client()
        _ensure_user_exists()

    def tearDown(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = self._orig_db_path
        db_mod._local.conn = self._orig_db_conn
        try:
            os.unlink(self._tmp_db_path)
        except OSError:
            pass

        settings_mod.SETTINGS_FILE = self._orig_settings_file

        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def test_pdf_inline_returns_pdf_content_type(self):
        resp = self.client.post(
            "/remediation-plan?fmt=pdf&inline=1",
            json=SAMPLE_PAYLOAD,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/pdf", resp.content_type)

    def test_pdf_inline_does_not_set_attachment_disposition(self):
        resp = self.client.post(
            "/remediation-plan?fmt=pdf&inline=1",
            json=SAMPLE_PAYLOAD,
        )
        cd = resp.headers.get("Content-Disposition", "")
        self.assertNotIn("attachment", cd)

    def test_pdf_attachment_still_works(self):
        """Default (no inline=1) must remain attachment for backward compat."""
        resp = self.client.post(
            "/remediation-plan?fmt=pdf",
            json=SAMPLE_PAYLOAD,
        )
        self.assertEqual(resp.status_code, 200)
        cd = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", cd)

    def test_remediation_pdf_uses_platform_version(self):
        from cashel.html_pdf import render_report_html

        resp = self.client.post(
            "/remediation-plan?fmt=pdf",
            json={**SAMPLE_PAYLOAD, "summary": SAMPLE_SUMMARY},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data.startswith(b"%PDF"))

        html = render_report_html(
            "remediation_report_pdf.html",
            report={
                "filename": "test.txt",
                "vendor_label": "Cisco",
                "compliance": "Basic hygiene",
                "generated_date": "May 1, 2026",
                "generated_time": "12:00:00 UTC",
                "summary": SAMPLE_SUMMARY,
                "total_steps": 1,
                "phases": [],
                "disclaimer": "Review commands before applying them.",
                "tool_version": "2.0.0",
            },
        )
        self.assertIn("Cashel", html)
        self.assertIn("Remediation report", html)
        self.assertIn("2.0.0", html)


class TestReportViewer(unittest.TestCase):
    def setUp(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self._tmp_db_path = f.name
        self._orig_db_path = db_mod.DB_PATH
        self._orig_db_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = self._tmp_db_path
        db_mod._local.conn = None
        db_mod.init_db()

        self.tmp_dir = tempfile.mkdtemp()
        self._tmp_settings = os.path.join(self.tmp_dir, "settings.json")
        self._orig_settings_file = settings_mod.SETTINGS_FILE
        settings_mod.SETTINGS_FILE = self._tmp_settings

        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = self.tmp_dir
        self.client = _make_client()
        _ensure_user_exists()

    def tearDown(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = self._orig_db_path
        db_mod._local.conn = self._orig_db_conn
        try:
            os.unlink(self._tmp_db_path)
        except OSError:
            pass

        settings_mod.SETTINGS_FILE = self._orig_settings_file

        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def _write_report_with_sidecar(self):
        from cashel.reporter import (
            generate_report,
            report_sidecar_path,
            write_report_sidecar,
        )

        path = os.path.join(self.tmp_dir, "cashel_report_test.pdf")
        findings = SAMPLE_PAYLOAD["findings"]
        generate_report(
            findings,
            "edge-fw.txt",
            "asa",
            "cis",
            output_path=path,
            summary=SAMPLE_SUMMARY,
        )
        sidecar = write_report_sidecar(
            path,
            findings=findings,
            filename="edge-fw.txt",
            vendor="asa",
            compliance="cis",
            summary=SAMPLE_SUMMARY,
            report_id="csh_test_123",
            generated_at="2026-05-01T12:56:00+00:00",
        )
        self.assertEqual(sidecar, report_sidecar_path(path))
        self.assertTrue(os.path.exists(sidecar))
        return path

    def test_report_viewer_returns_html_with_dynamic_data(self):
        self._write_report_with_sidecar()
        resp = self.client.get("/reports/cashel_report_test.pdf/view")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        body = resp.data.decode()
        self.assertIn("edge-fw.txt", body)
        self.assertIn("Cisco", body)
        self.assertIn("51", body)
        self.assertIn("permit ip any any", body)
        self.assertIn("CASHEL-ASA-EXPOSURE-001", body)
        self.assertIn("Re-run the audit after replacing the rule.", body)
        self.assertIn("no access-list", body)
        self.assertIn("csh_test_123", body)

    def test_report_viewer_falls_back_without_sidecar(self):
        path = os.path.join(self.tmp_dir, "legacy.pdf")
        with open(path, "wb") as fh:
            fh.write(b"%PDF-1.4\n")

        resp = self.client.get("/reports/legacy.pdf/view")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        body = resp.data.decode()
        self.assertIn("Limited report metadata", body)
        self.assertIn("legacy.pdf", body)


class TestDemoSampleReport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.audit as a

        a.REPORTS_FOLDER = self.tmp_dir
        self.client = _make_client()

    def tearDown(self):
        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.audit as a

        a.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def test_sample_report_returns_200(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertEqual(resp.status_code, 200)

    def test_sample_report_content_type_is_pdf(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertIn("application/pdf", resp.content_type)

    def test_sample_report_is_inline_not_attachment(self):
        resp = self.client.get("/demo/sample-report.pdf")
        cd = resp.headers.get("Content-Disposition", "")
        self.assertNotIn("attachment", cd)

    def test_sample_report_returns_non_empty_pdf(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertTrue(resp.data[:4] == b"%PDF")


class TestModalMarkup(unittest.TestCase):
    def _index_template(self):
        template_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "templates", "index.html"
        )
        with open(template_path, encoding="utf-8") as fh:
            return fh.read()

    def test_webhook_and_remediation_modals_use_scoped_layouts(self):
        body = self._index_template()

        self.assertIn("modal webhook-modal", body)
        self.assertIn("event-picker", body)
        self.assertIn("modal remediation-modal", body)
        self.assertIn("rem-summary-bar", body)
        self.assertNotIn('class="modal remediation-modal" style=', body)
        self.assertNotIn('class="modal" style="max-width:520px"', body)

    def test_audit_result_actions_are_glyph_free_and_grouped(self):
        body = self._index_template()

        self.assertIn(">View Report<", body)
        self.assertIn(">View Remediation Plan<", body)
        self.assertIn(">Download<", body)
        self.assertIn("downloadMenuPanel", body)
        for label in (
            ">Report PDF<",
            ">Remediation PDF<",
            ">JSON<",
            ">CSV<",
            ">SARIF<",
            ">Markdown<",
        ):
            self.assertIn(label, body)
        action_area = body[
            body.index('<div class="actions-row">') : body.index(
                '<div class="archive-row hidden" id="archiveRow">'
            )
        ]
        for glyph in ("&#8681;", "&#128196;", "&#10003;"):
            self.assertNotIn(glyph, action_area)

    def test_browser_exports_preserve_enriched_finding_fields(self):
        body = self._index_template()

        self.assertIn(
            '[["id","vendor","severity","category","title","message","remediation","evidence","affected_object","rule_name","confidence"]]',
            body,
        )
        self.assertIn(
            'const ruleId     = (!isStr && f.id) || "FLK-" + category.toUpperCase();',
            body,
        )
        self.assertIn(
            '["vendor","category","evidence","affected_object","rule_name","confidence","verification","rollback"]',
            body,
        )

    def test_download_menu_flows_right_from_pill(self):
        style_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "static", "style.css"
        )
        with open(style_path, encoding="utf-8") as fh:
            css = fh.read()

        self.assertIn(
            ".download-menu-panel { position: absolute; top: calc(100% + 10px); left: 0;",
            css,
        )
        self.assertNotIn(
            ".download-menu-panel { position: absolute; top: calc(100% + 10px); right: 0;",
            css,
        )

    def test_bulk_results_use_modal_actions_not_details(self):
        body = self._index_template()
        bulk_fn = body[
            body.index("function renderBulkResults") : body.index(
                "// ══════════════════════════════════════════════════════ SCHEDULES"
            )
        ]

        self.assertIn("bulk-item", bulk_fn)
        self.assertIn("View Results", bulk_fn)
        self.assertIn("View Remediation Plan", bulk_fn)
        self.assertIn("window._openBulkResults", body)
        self.assertIn("modal bulk-result-modal", body)
        self.assertNotIn("<details", bulk_fn)

    def test_remediation_modal_has_branding_and_glyph_free_tools(self):
        body = self._index_template()
        rem_modal = body[
            body.index(
                '<div class="modal-overlay hidden" id="remediationModal"'
            ) : body.index('<div id="remediationModalBody">')
        ]

        self.assertIn("<span>Cashel</span>", rem_modal)
        self.assertIn('<span class="kind">Remediation report</span>', rem_modal)
        self.assertIn(">Open PDF<", rem_modal)
        self.assertIn(">Download PDF<", rem_modal)
        self.assertIn(">Markdown<", rem_modal)
        for glyph in ("&#x2197;", "&#8681;"):
            self.assertNotIn(glyph, rem_modal)

    def test_remediation_open_pdf_uses_synchronous_blank_tab(self):
        body = self._index_template()

        self.assertIn('const win = window.open("about:blank", "_blank");', body)
        self.assertIn("win.location.href = url;", body)
        self.assertNotIn("Popup blocked", body)

    def test_recent_runs_and_shortcuts_are_wired(self):
        body = self._index_template()

        self.assertIn("let recentRunCache = []", body)
        self.assertIn("function addRecentRun(run)", body)
        self.assertIn("addRecentRun(data);", body)
        self.assertIn('data-shortcut-action="run"', body)
        self.assertIn('data-shortcut-action="report"', body)
        self.assertIn('data-shortcut-action="theme"', body)
        self.assertIn('data-shortcut-action="clear"', body)
        self.assertIn("Alt</kbd><kbd>Enter", body)

    def test_history_and_schedule_actions_are_clickable(self):
        body = self._index_template()

        self.assertIn('data-rem-archive="${escHtml(e.id)}"', body)
        self.assertIn(">Remediation</button>", body)
        self.assertNotIn(">Plan</button>", body)
        self.assertIn("window._openArchiveRemediation", body)
        self.assertIn("data-sched-menu", body)
        self.assertIn("data-sched-run", body)
        self.assertIn("data-sched-edit", body)
        self.assertIn("data-sched-del", body)
        self.assertIn("data-sched-toggle", body)

    def test_schedule_form_sections_and_notification_targets(self):
        body = self._index_template()
        schedule = body[
            body.index('<form id="scheduleForm">') : body.index(
                "</form>", body.index('<form id="scheduleForm">')
            )
        ]
        labels = [
            '<div class="label">Name &amp; platform</div>',
            '<div class="label">Endpoint</div>',
            '<div class="label">Device label</div>',
            '<div class="label">Authentication</div>',
            '<div class="label">Cadence</div>',
            '<div class="label">Notifications</div>',
            '<div class="label">Notification targets <span class="opt-tag">Optional</span></div>',
            '<div class="label">Status</div>',
        ]
        positions = [schedule.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Alert on CRITICAL findings", schedule)
        self.assertIn("Alert on HIGH findings", schedule)
        self.assertIn("Alert on audit errors", schedule)
        self.assertIn("schedTargetSlack", schedule)
        self.assertIn("schedTargetTeams", schedule)
        self.assertIn("schedTargetEmail", schedule)
        self.assertIn(">Save schedule<", schedule)

    def test_activity_and_security_logs_use_colored_tags(self):
        body = self._index_template()
        style_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "static", "style.css"
        )
        with open(style_path, encoding="utf-8") as fh:
            css = fh.read()

        self.assertIn(
            'class="log-tag ${e.action ? escHtml(e.action) : ""}${ok ? "" : " fail"}"',
            body,
        )
        self.assertIn(
            'class="log-tag ${e.event ? escHtml(e.event) : ""}${ok ? "" : " fail"}"',
            body,
        )
        for selector in (
            ".log-tag.file_audit",
            ".log-tag.ssh_connect",
            ".log-tag.config_diff",
            ".log-tag.login_success",
            ".log-tag.user_created",
            ".log-tag.login_failure",
        ):
            self.assertIn(selector, css)

    def test_license_purchase_and_activate_button_are_polished(self):
        body = self._index_template()
        style_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "static", "style.css"
        )
        with open(style_path, encoding="utf-8") as fh:
            css = fh.read()

        self.assertIn('href="https://shamrock13.gumroad.com/l/cashel"', body)
        self.assertIn('class="btn-outline action-pill-control license-buy-link"', body)
        self.assertIn("support@cashel.app", body)
        self.assertNotIn("support@cashel.dev", body)
        self.assertIn(
            'class="btn-primary action-pill-control btn-activate-license" id="activateLicenseBtn">Activate</button>',
            body,
        )
        self.assertIn(".license-activation-field .ctrl", css)
        self.assertIn(".btn-activate-license", css)
        self.assertIn(".license-buy-link", css)
        self.assertIn(".settings-footer .btn-primary", css)
        self.assertIn(".action-pill-control", css)

    def test_smtp_actions_are_inline_and_pill_sized(self):
        body = self._index_template()
        style_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "static", "style.css"
        )
        with open(style_path, encoding="utf-8") as fh:
            css = fh.read()

        self.assertIn('class="smtp-actions"', body)
        self.assertIn('id="testSmtpBtn"', body)
        self.assertIn('id="setting-smtp-tls-toggle"', body)
        self.assertNotIn('id="saveEmailSettingsBtn"', body)
        self.assertNotIn("saveEmailSettingsBtn", body)
        self.assertNotIn("hide-shared-footer", body)
        self.assertIn(".smtp-actions", css)
        self.assertIn(".tgl.action-pill-control", css)
        self.assertNotIn(".settings-main.hide-shared-footer .settings-footer", css)

    def test_theme_auto_option_is_available(self):
        body = self._index_template()

        self.assertIn('id="setThemeAuto"', body)
        self.assertIn("data-theme-pref", body)
        self.assertIn("prefers-color-scheme: dark", body)
        self.assertIn("applyTheme('auto')", body)

    def test_trends_chart_uses_handoff_svg_not_chartjs(self):
        body = self._index_template()

        self.assertNotIn("chart.umd.min.js", body)
        self.assertNotIn("new Chart(", body)
        self.assertNotIn('<canvas id="trendsChart"', body)
        self.assertIn('id="trendsChartSvg"', body)
        self.assertIn('stroke-dasharray="2 3"', body)

    def test_template_versions_are_platform_200(self):
        body = self._index_template()
        report_template_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "report_template.html"
        )
        with open(report_template_path, encoding="utf-8") as fh:
            report_template = fh.read()

        self.assertIn("Cashel v2.0.0", body)
        self.assertIn("Generated by Cashel v2.0.0", report_template)
        self.assertNotIn("1.5.1", body)
        self.assertNotIn("1.5.1", report_template)

    def test_bulk_mode_has_own_section_without_single_header_overlap(self):
        body = self._index_template()
        single_start = body.index('<div id="audit-mode-single">')
        bulk_start = body.index('<div id="audit-mode-bulk"')

        self.assertGreater(body.index("01 &mdash; New audit"), single_start)
        self.assertLess(body.index("01 &mdash; New audit"), bulk_start)
        self.assertGreater(body.index("01 &mdash; Bulk audit"), bulk_start)

    def test_live_ssh_sections_are_in_requested_order(self):
        body = self._index_template()
        connect = body[
            body.index('<form id="connectForm">') : body.index(
                '<button type="submit" class="btn-primary" id="connectBtn">'
            )
        ]
        labels = [
            '<div class="label">Device tag</div>',
            '<div class="label">Connection</div>',
            '<div class="label">Scope</div>',
            '<div class="label">Authentication</div>',
            '<div class="label">Credentials</div>',
        ]
        positions = [connect.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('<div class="label">Endpoint</div>', connect)

    def test_uptime_formatter_thresholds_are_encoded(self):
        body = self._index_template()

        self.assertIn("if (days > 0) return `${days}d ${hours}h`;", body)
        self.assertIn("if (hours > 0) return `${hours}h ${minutes}m`;", body)
        self.assertIn("if (minutes > 0) return `${minutes}m ${seconds}s`;", body)
        self.assertIn("return `${seconds}s`;", body)

    def test_tab_lists_do_not_render_transient_loading_text(self):
        body = self._index_template()
        self.assertNotIn(
            'id="schedulesList" class="schedules-list">\n          <p class="text-muted">Loading',
            body,
        )
        self.assertNotIn(
            'id="historyList" class="history-list" style="margin-top:24px">\n          <p class="text-muted">Loading',
            body,
        )
