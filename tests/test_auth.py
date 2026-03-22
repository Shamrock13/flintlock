"""Tests for API key authentication (Phase 2).

Covers:
  - _hash_api_key / _verify_api_key helpers
  - before_request guard: pass-through when auth disabled
  - before_request guard: redirect when auth enabled and unauthenticated
  - before_request guard: 401 JSON for API callers when auth enabled
  - before_request guard: pass-through with valid X-API-Key
  - before_request guard: pass-through with valid session
  - /login GET renders login page when auth enabled
  - /login POST with wrong key returns error
  - /login POST with correct key creates session
  - /logout clears session
  - /settings/generate-api-key creates a key and stores hash
  - /settings/revoke-api-key clears the hash
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Prevent the scheduler and syslog configuration from running during tests.
os.environ.setdefault("SETTINGS_FILE", "/tmp/test_flintlock_auth_settings.json")

try:
    from flintlock.web import app, _hash_api_key, _verify_api_key
    from flintlock import settings as _settings_module
except ImportError as _import_err:
    print(f"SKIP test_auth.py — missing dependency: {_import_err}")
    sys.exit(0)


# ── Helper to reset settings between tests ────────────────────────────────────

def _reset_settings(**overrides):
    """Write a fresh settings file with optional overrides."""
    data = dict(_settings_module.DEFAULTS)
    data.update(overrides)
    os.makedirs(os.path.dirname(_settings_module.SETTINGS_FILE), exist_ok=True)
    import json
    with open(_settings_module.SETTINGS_FILE, "w") as f:
        json.dump(data, f)


# ── Key helper tests ──────────────────────────────────────────────────────────

class TestHashVerify(unittest.TestCase):
    def test_hash_and_verify_roundtrip(self):
        raw = "supersecretkey123"
        h = _hash_api_key(raw)
        self.assertTrue(_verify_api_key(raw, h))

    def test_wrong_key_does_not_verify(self):
        h = _hash_api_key("correct-key")
        self.assertFalse(_verify_api_key("wrong-key", h))

    def test_empty_hash_returns_false(self):
        self.assertFalse(_verify_api_key("any-key", ""))

    def test_malformed_hash_returns_false(self):
        self.assertFalse(_verify_api_key("any-key", "nodollar"))

    def test_different_hashes_for_same_key(self):
        raw = "same-key"
        h1 = _hash_api_key(raw)
        h2 = _hash_api_key(raw)
        # Each call uses a fresh salt
        self.assertNotEqual(h1, h2)
        self.assertTrue(_verify_api_key(raw, h1))
        self.assertTrue(_verify_api_key(raw, h2))


# ── before_request guard tests ────────────────────────────────────────────────

class TestAuthGuard(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_no_auth_passthrough(self):
        """When auth_enabled=False any request should succeed."""
        _reset_settings(auth_enabled=False)
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 200)

    def test_auth_redirect_browser(self):
        """Browser requests without session should be redirected to /login."""
        _reset_settings(auth_enabled=True, api_key_hash="")
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    def test_auth_401_for_json_client(self):
        """JSON API requests without credentials get 401, not a redirect."""
        _reset_settings(auth_enabled=True, api_key_hash="")
        res = self.client.get("/settings", headers={"Accept": "application/json"})
        self.assertEqual(res.status_code, 401)

    def test_valid_api_key_header_passes(self):
        """A valid X-API-Key header should grant access."""
        raw_key = "valid-test-key-abc123"
        _reset_settings(auth_enabled=True, api_key_hash=_hash_api_key(raw_key))
        res = self.client.get(
            "/settings",
            headers={"X-API-Key": raw_key, "Accept": "application/json"},
        )
        self.assertEqual(res.status_code, 200)

    def test_invalid_api_key_header_blocked(self):
        """An incorrect X-API-Key header should get 401."""
        _reset_settings(auth_enabled=True, api_key_hash=_hash_api_key("correct-key"))
        res = self.client.get(
            "/settings",
            headers={"X-API-Key": "wrong-key", "Accept": "application/json"},
        )
        self.assertEqual(res.status_code, 401)

    def test_login_page_with_session(self):
        """An authenticated session should bypass the guard."""
        raw_key = "session-test-key"
        _reset_settings(auth_enabled=True, api_key_hash=_hash_api_key(raw_key))
        with self.client.session_transaction() as sess:
            sess["authenticated"] = True
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 200)

    def test_login_exempt_from_auth(self):
        """/login itself must be accessible without a session."""
        _reset_settings(auth_enabled=True, api_key_hash="")
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)


# ── Login route tests ─────────────────────────────────────────────────────────

class TestLoginRoute(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_login_redirects_when_auth_disabled(self):
        _reset_settings(auth_enabled=False)
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 302)

    def test_login_get_renders_form(self):
        _reset_settings(auth_enabled=True, api_key_hash="")
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Sign in", res.data)

    def test_login_post_wrong_key(self):
        _reset_settings(auth_enabled=True, api_key_hash=_hash_api_key("correct"))
        res = self.client.post("/login", data={"api_key": "wrong"})
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Invalid", res.data)

    def test_login_post_correct_key_creates_session(self):
        raw = "my-secret-key"
        _reset_settings(auth_enabled=True, api_key_hash=_hash_api_key(raw))
        res = self.client.post("/login", data={"api_key": raw})
        self.assertEqual(res.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("authenticated"))


# ── Logout route tests ────────────────────────────────────────────────────────

class TestLogoutRoute(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_logout_clears_session(self):
        with self.client.session_transaction() as sess:
            sess["authenticated"] = True
        res = self.client.post("/logout")
        self.assertEqual(res.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get("authenticated"))


# ── Key generation / revocation API tests ─────────────────────────────────────

class TestApiKeyManagement(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_generate_key_returns_raw_key(self):
        _reset_settings(auth_enabled=False)
        res = self.client.post("/settings/generate-api-key")
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertIn("api_key", body)
        self.assertTrue(len(body["api_key"]) > 20)

    def test_generate_key_stores_hash(self):
        _reset_settings(auth_enabled=False)
        res = self.client.post("/settings/generate-api-key")
        raw = res.get_json()["api_key"]
        cfg = _settings_module.get_settings()
        self.assertTrue(_verify_api_key(raw, cfg["api_key_hash"]))

    def test_revoke_key_clears_hash(self):
        _reset_settings(auth_enabled=False, api_key_hash=_hash_api_key("some-key"))
        self.client.post("/settings/revoke-api-key")
        cfg = _settings_module.get_settings()
        self.assertEqual(cfg["api_key_hash"], "")

    def test_settings_save_preserves_hash(self):
        """Saving settings via the settings form must NOT wipe the api_key_hash."""
        raw = "preserve-this-key"
        _reset_settings(auth_enabled=False, api_key_hash=_hash_api_key(raw))
        # Simulate the settings form POST (no api_key_hash field)
        import json
        data = dict(_settings_module.get_settings())
        data.pop("api_key_hash", None)
        self.client.post(
            "/settings",
            data=json.dumps(data),
            content_type="application/json",
        )
        cfg = _settings_module.get_settings()
        self.assertTrue(_verify_api_key(raw, cfg["api_key_hash"]))


if __name__ == "__main__":
    unittest.main()
