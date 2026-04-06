"""Tests for multi-user auth — user_store.py and web integration.

Run with:  python -m pytest tests/test_auth.py -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.db as db_mod
from cashel import user_store as us
from cashel.user_store import UserValidationError


# ── Isolated temp DB decorator ────────────────────────────────────────────────


def _tmp_db(fn):
    def wrapper(*args, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        orig_path = db_mod.DB_PATH
        orig_conn = getattr(db_mod._local, "conn", None)
        try:
            db_mod.DB_PATH = tmp
            db_mod._local.conn = None
            db_mod.init_db()
            # Also reset the lockout dict between tests
            import cashel.blueprints.auth as auth_bp_mod
            auth_bp_mod._lockout.clear()
            return fn(*args, **kwargs)
        finally:
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


# ── user_store unit tests ─────────────────────────────────────────────────────


class TestUserStore(unittest.TestCase):

    @_tmp_db
    def test_has_users_false_when_empty(self):
        self.assertFalse(us.has_users())

    @_tmp_db
    def test_create_user_success(self):
        user = us.create_user("alice", "supersecretpass1", "admin")
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "admin")
        self.assertIn("id", user)
        self.assertNotIn("password_hash", user)
        self.assertNotIn("api_key_enc", user)
        self.assertFalse(user["has_api_key"])

    @_tmp_db
    def test_create_user_duplicate_username_raises(self):
        us.create_user("bob", "supersecretpass1", "viewer")
        with self.assertRaises(UserValidationError):
            us.create_user("bob", "anotherlongpassword", "viewer")

    @_tmp_db
    def test_create_user_short_password_raises(self):
        with self.assertRaises(UserValidationError):
            us.create_user("carol", "short", "viewer")

    @_tmp_db
    def test_create_user_short_username_raises(self):
        with self.assertRaises(UserValidationError):
            us.create_user("ab", "supersecretpass1", "viewer")

    @_tmp_db
    def test_create_user_invalid_role_raises(self):
        with self.assertRaises(UserValidationError):
            us.create_user("dave", "supersecretpass1", "superuser")

    @_tmp_db
    def test_check_password_correct(self):
        us.create_user("eve", "correcthorsebattery", "auditor")
        result = us.check_password("eve", "correcthorsebattery")
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "eve")

    @_tmp_db
    def test_check_password_wrong_password(self):
        us.create_user("frank", "correcthorsebattery", "viewer")
        result = us.check_password("frank", "wrongpassword123")
        self.assertIsNone(result)

    @_tmp_db
    def test_check_password_wrong_username(self):
        result = us.check_password("nobody", "correcthorsebattery")
        self.assertIsNone(result)

    @_tmp_db
    def test_list_users_excludes_hashes(self):
        us.create_user("grace", "supersecretpass1", "viewer")
        us.create_user("heidi", "supersecretpass1", "auditor")
        users = us.list_users()
        self.assertEqual(len(users), 2)
        for u in users:
            self.assertNotIn("password_hash", u)
            self.assertNotIn("api_key_enc", u)
            self.assertIn("has_api_key", u)

    @_tmp_db
    def test_delete_user_success(self):
        us.create_user("ivan", "supersecretpass1", "viewer")
        us.create_user("admin1", "supersecretpass1", "admin")
        users = us.list_users()
        ivan = next(u for u in users if u["username"] == "ivan")
        result = us.delete_user(ivan["id"])
        self.assertTrue(result)
        self.assertEqual(len(us.list_users()), 1)

    @_tmp_db
    def test_delete_last_admin_raises(self):
        us.create_user("judy", "supersecretpass1", "admin")
        users = us.list_users()
        judy = users[0]
        with self.assertRaises(UserValidationError):
            us.delete_user(judy["id"])

    @_tmp_db
    def test_change_password_success(self):
        us.create_user("ken", "supersecretpass1", "viewer")
        user = us.list_users()[0]
        us.change_password(user["id"], "brandnewpassword!")
        result = us.check_password("ken", "brandnewpassword!")
        self.assertIsNotNone(result)
        # Old password must no longer work
        self.assertIsNone(us.check_password("ken", "supersecretpass1"))

    @_tmp_db
    def test_change_password_too_short_raises(self):
        us.create_user("laura", "supersecretpass1", "viewer")
        user = us.list_users()[0]
        with self.assertRaises(UserValidationError):
            us.change_password(user["id"], "short")

    @_tmp_db
    def test_generate_api_key_returns_plaintext(self):
        us.create_user("mallory", "supersecretpass1", "viewer")
        user = us.list_users()[0]
        key = us.generate_api_key(user["id"])
        self.assertTrue(key.startswith("csh_"))
        self.assertGreater(len(key), 10)
        # User should now have_api_key = True
        updated = us.get_user_by_id(user["id"])
        self.assertTrue(updated["has_api_key"])

    @_tmp_db
    def test_get_user_by_api_key_correct(self):
        us.create_user("niaj", "supersecretpass1", "auditor")
        user = us.list_users()[0]
        key = us.generate_api_key(user["id"])
        found = us.get_user_by_api_key(key)
        self.assertIsNotNone(found)
        self.assertEqual(found["username"], "niaj")

    @_tmp_db
    def test_get_user_by_api_key_wrong_key(self):
        us.create_user("oscar", "supersecretpass1", "viewer")
        user = us.list_users()[0]
        us.generate_api_key(user["id"])
        found = us.get_user_by_api_key("csh_wrongkey")
        self.assertIsNone(found)

    @_tmp_db
    def test_revoke_api_key_clears_key(self):
        us.create_user("peggy", "supersecretpass1", "viewer")
        user = us.list_users()[0]
        key = us.generate_api_key(user["id"])
        us.revoke_api_key(user["id"])
        found = us.get_user_by_api_key(key)
        self.assertIsNone(found)
        updated = us.get_user_by_id(user["id"])
        self.assertFalse(updated["has_api_key"])


# ── Web integration tests ─────────────────────────────────────────────────────


def _make_client():
    """Create a Flask test client with CSRF disabled and auth enabled."""
    # Must be imported after sys.path adjustment
    import cashel.web as web_mod
    app = web_mod.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    return app.test_client()


class TestWebAuth(unittest.TestCase):

    def _setup(self):
        """Return (client, tmp_path) with an isolated DB."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        orig_path = db_mod.DB_PATH
        orig_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = tmp
        db_mod._local.conn = None
        db_mod.init_db()

        import cashel.blueprints.auth as auth_bp_mod
        auth_bp_mod._lockout.clear()

        client = _make_client()
        return client, tmp, orig_path, orig_conn

    def _teardown(self, tmp, orig_path, orig_conn):
        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = orig_path
        db_mod._local.conn = orig_conn
        try:
            os.unlink(tmp)
        except OSError:
            pass

    def test_setup_get_200_when_no_users(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            resp = client.get("/setup")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Setup", resp.data)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_setup_post_creates_admin_and_enables_auth(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            resp = client.post("/setup", data={
                "username": "adminuser",
                "password": "strongpassword1",
                "confirm_password": "strongpassword1",
            }, follow_redirects=False)
            # Should redirect to index after setup
            self.assertIn(resp.status_code, (302, 200))
            users = us.list_users()
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]["role"], "admin")
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_setup_redirects_to_login_when_users_exist(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("existing", "supersecretpass1", "admin")
            resp = client.get("/setup", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_login_success_sets_session(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("testuser", "supersecretpass1", "admin")
            # Enable auth via settings
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post("/login", data={
                "username": "testuser",
                "password": "supersecretpass1",
            }, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            with client.session_transaction() as sess:
                self.assertTrue(sess.get("authenticated"))
                self.assertIsNotNone(sess.get("user_id"))
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_login_wrong_password_401(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("testuser2", "supersecretpass1", "viewer")
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post("/login", data={
                "username": "testuser2",
                "password": "wrongpassword!!",
            })
            self.assertEqual(resp.status_code, 401)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_login_generic_error_message(self):
        """Error message must not reveal whether user exists or password is wrong."""
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("testuser3", "supersecretpass1", "viewer")
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post("/login", data={
                "username": "testuser3",
                "password": "badpassword1234",
            })
            body = resp.data.decode()
            self.assertIn("Invalid username or password", body)
            self.assertNotIn("wrong password", body.lower())
            self.assertNotIn("wrong user", body.lower())
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_login_lockout_after_five_failures(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("lockme", "supersecretpass1", "viewer")
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            for _ in range(5):
                client.post("/login", data={"username": "lockme", "password": "bad"})
            resp = client.post("/login", data={"username": "lockme", "password": "bad"})
            self.assertEqual(resp.status_code, 429)
            self.assertIn(b"locked", resp.data.lower())
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_api_key_auth_grants_access(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("apiuser", "supersecretpass1", "auditor")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.get("/schedules", headers={"X-API-Key": api_key})
            # Should not redirect to login
            self.assertNotEqual(resp.status_code, 302)
            self.assertIn(resp.status_code, (200, 404))
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_viewer_cannot_run_audit(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("viewonly", "supersecretpass1", "viewer")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post("/audit", headers={"X-API-Key": api_key},
                               data={"vendor": "asa"})
            self.assertEqual(resp.status_code, 403)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_auditor_can_run_audit(self):
        """Auditor role gets past _require_role (file missing → 400, not 403)."""
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("audituser", "supersecretpass1", "auditor")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post("/audit", headers={"X-API-Key": api_key},
                               data={"vendor": "asa"})
            # 400 means it passed role check but failed file validation — correct
            self.assertNotEqual(resp.status_code, 403)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_admin_can_manage_users(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("adminonly", "supersecretpass1", "admin")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.get("/auth/users", headers={"X-API-Key": api_key})
            self.assertEqual(resp.status_code, 200)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_viewer_cannot_manage_users(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("viewer2", "supersecretpass1", "viewer")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.get("/auth/users", headers={"X-API-Key": api_key})
            self.assertEqual(resp.status_code, 403)
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_change_password_success(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("chpwuser", "supersecretpass1", "viewer")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            import json
            resp = client.post(
                "/auth/change-password",
                headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                data=json.dumps({"new_password": "brandnewpassword!"}),
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["ok"])
        finally:
            self._teardown(tmp, orig, orig_conn)

    def test_generate_api_key_returns_key(self):
        client, tmp, orig, orig_conn = self._setup()
        try:
            us.create_user("keygen", "supersecretpass1", "auditor")
            users = us.list_users()
            api_key = us.generate_api_key(users[0]["id"])
            from cashel.settings import save_settings, get_settings
            save_settings({**get_settings(), "auth_enabled": True})

            resp = client.post(
                "/auth/generate-api-key",
                headers={"X-API-Key": api_key},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["ok"])
            self.assertTrue(data["api_key"].startswith("csh_"))
        finally:
            self._teardown(tmp, orig, orig_conn)


if __name__ == "__main__":
    unittest.main()
