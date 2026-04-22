"""Tests for the generic webhook event system.

Run with:  python -m pytest tests/test_webhooks.py -v
"""

import hashlib
import hmac as _hmac
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _setup_db():
    import cashel.db as db_mod

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    db_mod.DB_PATH = path
    db_mod._local.conn = None
    db_mod.init_db()
    return path


def _teardown_db(path):
    import cashel.db as db_mod

    if getattr(db_mod._local, "conn", None):
        db_mod._local.conn.close()
        db_mod._local.conn = None
    try:
        os.unlink(path)
    except OSError:
        pass


class TestWebhookCRUD(unittest.TestCase):
    def setUp(self):
        self._db_path = _setup_db()
        from cashel import webhooks

        self.wh = webhooks

    def tearDown(self):
        _teardown_db(self._db_path)

    def test_list_empty(self):
        self.assertEqual(self.wh.list_webhooks(), [])

    @patch("socket.getaddrinfo")
    def test_add_and_list(self, mock_dns):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        row = self.wh.add_webhook(
            "My Hook", "https://example.com/hook", ["audit.complete"]
        )
        self.assertEqual(row["name"], "My Hook")
        self.assertEqual(row["url"], "https://example.com/hook")
        self.assertIn("audit.complete", row["events"])
        self.assertTrue(row["enabled"])
        self.assertEqual(len(self.wh.list_webhooks()), 1)

    @patch("socket.getaddrinfo")
    def test_add_encrypts_url(self, mock_dns):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        from cashel.db import get_conn

        self.wh.add_webhook("Enc", "https://example.com/secret", ["audit.complete"])
        raw = get_conn().execute("SELECT url_enc FROM webhooks").fetchone()[0]
        self.assertNotIn("https://", raw)

    def test_add_rejects_http(self):
        with self.assertRaises(ValueError):
            self.wh.add_webhook("Bad", "http://example.com/hook", ["audit.complete"])

    def test_add_rejects_private_ip(self):
        with self.assertRaises(ValueError):
            self.wh.add_webhook("LAN", "https://192.168.1.1/hook", ["audit.complete"])

    def test_add_rejects_empty_events(self):
        with self.assertRaises(ValueError):
            self.wh.add_webhook("X", "https://example.com/", ["bogus.event"])

    @patch("socket.getaddrinfo")
    def test_update_webhook(self, mock_dns):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        row = self.wh.add_webhook("Hook", "https://example.com/a", ["audit.complete"])
        updated = self.wh.update_webhook(row["id"], name="Renamed", enabled=False)
        self.assertEqual(updated["name"], "Renamed")
        self.assertFalse(updated["enabled"])

    @patch("socket.getaddrinfo")
    def test_delete_webhook(self, mock_dns):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        row = self.wh.add_webhook("Del", "https://example.com/del", ["audit.complete"])
        self.wh.delete_webhook(row["id"])
        self.assertIsNone(self.wh.get_webhook(row["id"]))


class TestWebhookDelivery(unittest.TestCase):
    def setUp(self):
        self._db_path = _setup_db()
        from cashel import webhooks

        self.wh = webhooks

    def tearDown(self):
        _teardown_db(self._db_path)

    @patch("socket.getaddrinfo")
    def _add(self, events, mock_dns, secret=None):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        return self.wh.add_webhook("H", "https://example.com/hook", events, secret)

    @patch("cashel.webhooks._post")
    def test_dispatch_audit_complete(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        self._add(["audit.complete"])
        self.wh.dispatch_event("audit.complete", {"audit_id": "abc", "score": 95})
        mock_post.assert_called_once()
        _url, body_bytes, _secret = mock_post.call_args[0]
        payload = json.loads(body_bytes)
        self.assertEqual(payload["event"], "audit.complete")
        self.assertEqual(payload["data"]["audit_id"], "abc")

    @patch("cashel.webhooks._post")
    def test_dispatch_threshold_breach(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        self._add(["alert.threshold_breach"])
        self.wh.dispatch_event(
            "alert.threshold_breach", {"schedule_id": "s1", "metric": "high"}
        )
        mock_post.assert_called_once()
        payload = json.loads(mock_post.call_args[0][1])
        self.assertEqual(payload["event"], "alert.threshold_breach")

    @patch("cashel.webhooks._post")
    def test_dispatch_threshold_clear(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        self._add(["alert.threshold_clear"])
        self.wh.dispatch_event(
            "alert.threshold_clear", {"schedule_id": "s1", "metric": "high"}
        )
        mock_post.assert_called_once()

    @patch("cashel.webhooks._post")
    def test_dispatch_skips_wrong_event(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        self._add(["alert.threshold_breach"])
        self.wh.dispatch_event("audit.complete", {"audit_id": "x"})
        mock_post.assert_not_called()

    @patch("cashel.webhooks._post")
    def test_dispatch_skips_disabled(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        row = self._add(["audit.complete"])
        self.wh.update_webhook(row["id"], enabled=False)
        self.wh.dispatch_event("audit.complete", {"audit_id": "x"})
        mock_post.assert_not_called()

    @patch("cashel.webhooks._post")
    def test_dispatch_never_raises_on_error(self, mock_post):
        mock_post.side_effect = RuntimeError("network down")
        self._add(["audit.complete"])
        self.wh.dispatch_event("audit.complete", {"audit_id": "x"})  # must not raise

    def test_hmac_signature(self):
        body = b'{"event":"test"}'
        secret = "mysecret"
        sig = self.wh._sign(body, secret)
        expected = (
            "sha256=" + _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        )
        self.assertEqual(sig, expected)

    @patch("cashel.webhooks._post")
    def test_payload_includes_cashel_version(self, mock_post):
        mock_post.return_value = (True, "HTTP 200")
        self._add(["audit.complete"])
        self.wh.dispatch_event("audit.complete", {"audit_id": "z"})
        payload = json.loads(mock_post.call_args[0][1])
        self.assertIn("cashel_version", payload)
        self.assertIn("timestamp", payload)


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
