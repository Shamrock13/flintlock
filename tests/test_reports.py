"""Route tests for /remediation-plan and /demo/sample-report.pdf."""
import os
import sys
import tempfile
import unittest

# Point the DB at a writable temp location before importing the app
_TEST_DB_DIR = tempfile.mkdtemp()
os.environ.setdefault("CASHEL_DB", os.path.join(_TEST_DB_DIR, "test_cashel.db"))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.web as web_mod


def _make_client():
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
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] permit ip any any",
            "remediation": "Replace with specific rules.",
        }
    ],
    "vendor": "asa",
    "filename": "test.txt",
}


class TestRemediationPdfInline(unittest.TestCase):
    def setUp(self):
        import cashel.settings as settings_mod

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

        _ensure_user_exists()
        self.client = _make_client()

    def tearDown(self):
        import cashel.settings as settings_mod
        settings_mod.SETTINGS_FILE = self._orig_settings_file

        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder

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
