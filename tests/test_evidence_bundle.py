"""Tests for the compliance evidence bundle endpoint.

Asserts that POST /reports/<report_id>/evidence-bundle returns a valid ZIP
containing exactly the 5 expected files, and that the route is auth-gated.

Run with:  python -m pytest tests/test_evidence_bundle.py -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

SAMPLE_FINDINGS = [
    {
        "id": "CASHEL-ASA-EXPOSURE-001",
        "vendor": "asa",
        "title": "Overly permissive any-any ACL rule",
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] Permit any any rule found — remove or restrict.",
        "evidence": "access-list OUTSIDE_IN permit ip any any",
        "affected_object": "OUTSIDE_IN",
        "rule_name": "OUTSIDE_IN",
        "confidence": "high",
        "verification": "Confirm the ACL no longer permits any-any.",
        "rollback": "Restore the prior ACL line from backup.",
        "remediation": "no access-list OUTSIDE_IN permit ip any any",
    },
    {
        "severity": "HIGH",
        "category": "protocol",
        "message": "[HIGH] Telnet enabled on management interface.",
        "remediation": "no telnet 0.0.0.0 0.0.0.0 mgmt",
    },
    {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] No remote syslog server configured.",
        "remediation": "logging host inside 10.0.0.1",
    },
]

SAMPLE_SUMMARY = {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0,
    "total": 3,
    "score": 74,
}

EXPECTED_FILES = {
    "audit_report.pdf",
    "findings.csv",
    "findings.json",
    "findings.sarif",
    "cover.pdf",
}


def _make_client():
    import cashel.web as web_mod

    app = web_mod.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    return app.test_client()


def _ensure_user_exists():
    from cashel import user_store as us
    from cashel.user_store import UserValidationError

    try:
        us.create_user("testadmin", "TestPass123!", "admin")
    except UserValidationError:
        pass


class TestEvidenceBundle(unittest.TestCase):
    def setUp(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        # Isolated temp DB
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self._tmp_db_path = f.name
        self._orig_db_path = db_mod.DB_PATH
        self._orig_db_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = self._tmp_db_path
        db_mod._local.conn = None
        db_mod.init_db()

        # Isolated temp settings (auth disabled)
        self.tmp_dir = tempfile.mkdtemp()
        self._tmp_settings = os.path.join(self.tmp_dir, "settings.json")
        self._orig_settings_file = settings_mod.SETTINGS_FILE
        settings_mod.SETTINGS_FILE = self._tmp_settings

        # Point REPORTS_FOLDER to temp dir
        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.reports as r_mod

        r_mod.REPORTS_FOLDER = self.tmp_dir

        self.client = _make_client()
        _ensure_user_exists()

        # Save a sample archive entry and record its ID
        self._entry_id = self._save_entry()

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
        import cashel.blueprints.reports as r_mod

        r_mod.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def _save_entry(self) -> str:
        resp = self.client.post(
            "/archive/save",
            json={
                "filename": "asa-lab.cfg",
                "vendor": "asa",
                "findings": SAMPLE_FINDINGS,
                "summary": SAMPLE_SUMMARY,
                "tag": "lab-device",
            },
        )
        self.assertEqual(resp.status_code, 200, f"Archive save failed: {resp.data}")
        return resp.get_json()["id"]

    def _get_bundle(self, entry_id=None, qs=""):
        eid = entry_id or self._entry_id
        return self.client.post(f"/reports/{eid}/evidence-bundle{qs}")

    # ── Tests ─────────────────────────────────────────────────────────────────

    def test_bundle_contains_all_five_files(self):
        """ZIP must contain exactly the 5 expected artifact files."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200, resp.data[:200])
        self.assertEqual(resp.content_type, "application/zip")

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        names = set(zf.namelist())
        self.assertEqual(names, EXPECTED_FILES, f"Missing: {EXPECTED_FILES - names}")

    def test_bundle_content_disposition(self):
        """Content-Disposition must be attachment with filename matching pattern."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200)
        cd = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", cd)
        self.assertIn(f"cashel_evidence_{self._entry_id}", cd)
        self.assertIn(".zip", cd)

    def test_bundle_findings_json_valid(self):
        """findings.json must be valid Cashel JSON with expected structure."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200)

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        data = json.loads(zf.read("findings.json"))
        self.assertEqual(data["tool"], "Cashel")
        self.assertEqual(data["vendor"], "asa")
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["findings"][0]["id"], "CASHEL-ASA-EXPOSURE-001")
        self.assertEqual(
            data["findings"][0]["evidence"],
            "access-list OUTSIDE_IN permit ip any any",
        )

    def test_bundle_findings_csv_has_header(self):
        """findings.csv must start with the standard 4-column header."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200)

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        csv_text = zf.read("findings.csv").decode("utf-8")
        first_line = csv_text.splitlines()[0]
        for col in (
            "id",
            "vendor",
            "severity",
            "category",
            "title",
            "message",
            "remediation",
            "evidence",
            "affected_object",
            "rule_name",
            "confidence",
        ):
            self.assertIn(col, first_line)

    def test_bundle_sarif_is_valid(self):
        """findings.sarif must be valid SARIF 2.1.0."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200)

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        sarif = json.loads(zf.read("findings.sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "Cashel")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "CASHEL-ASA-EXPOSURE-001")
        self.assertEqual(result["properties"]["vendor"], "asa")
        self.assertEqual(
            result["properties"]["evidence"],
            "access-list OUTSIDE_IN permit ip any any",
        )

    def test_bundle_pdfs_are_nonempty_and_valid(self):
        """audit_report.pdf and cover.pdf must be non-empty valid PDF bytes."""
        resp = self._get_bundle()
        self.assertEqual(resp.status_code, 200)

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        for pdf_name in ("audit_report.pdf", "cover.pdf"):
            data = zf.read(pdf_name)
            self.assertGreater(len(data), 100, f"{pdf_name} suspiciously small")
            self.assertEqual(data[:4], b"%PDF", f"{pdf_name} missing PDF magic bytes")

    def test_bundle_not_found(self):
        """Non-existent report_id must return 404."""
        resp = self._get_bundle("nonexistentid000")
        self.assertEqual(resp.status_code, 404)

    def test_bundle_compliance_param_accepted(self):
        """?compliance=pci,cis query param must be accepted and produce a valid ZIP."""
        resp = self._get_bundle(qs="?compliance=pci,cis")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "application/zip")

        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        self.assertEqual(set(zf.namelist()), EXPECTED_FILES)


if __name__ == "__main__":
    unittest.main()
