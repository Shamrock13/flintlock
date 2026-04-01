"""Tests for notify.py — Slack and email alert formatting.

Run with:  python3 tests/test_notify.py
"""

import json
import os
import sys
import smtplib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.notify import (
    _audit_subject,
    _audit_body_text,
    _top_high_findings,
    send_slack,
    send_email,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

SCHEDULE = {
    "id": "abc123",
    "vendor": "asa",
    "host": "192.168.1.1",
    "tag": "ASA-EDGE",
    "notify_on_finding": True,
    "notify_on_error": True,
    "notify_slack_webhook": "https://hooks.slack.com/services/TEST",
    "notify_email": "ops@example.com",
}

SUMMARY = {"high": 2, "medium": 1, "low": 0, "total": 3}

FINDINGS = [
    {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] Permit any any found.",
        "remediation": "Remove the rule.",
    },
    {
        "severity": "HIGH",
        "category": "management",
        "message": "[HIGH] Telnet enabled.",
        "remediation": "Disable telnet.",
    },
    {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] No syslog configured.",
        "remediation": "Add a syslog server.",
    },
]

PLAIN_FINDINGS = [
    "[HIGH] Permit any any found.",
    "[HIGH] Telnet enabled.",
    "[MEDIUM] No syslog configured.",
]


# ══════════════════════════════════════ _top_high_findings ══


def test_top_high_enriched():
    highs = _top_high_findings(FINDINGS)
    assert len(highs) == 2
    assert all("[HIGH]" in h for h in highs)


def test_top_high_plain():
    highs = _top_high_findings(PLAIN_FINDINGS)
    assert len(highs) == 2


def test_top_high_limit():
    many = [
        {"severity": "HIGH", "message": f"[HIGH] finding {i}", "category": "x"}
        for i in range(10)
    ]
    highs = _top_high_findings(many, limit=3)
    assert len(highs) == 3


def test_top_high_no_highs():
    low_only = [
        {"severity": "MEDIUM", "message": "[MEDIUM] something", "category": "x"}
    ]
    assert _top_high_findings(low_only) == []


# ══════════════════════════════════════════ _audit_subject ══


def test_subject_high_findings():
    subj = _audit_subject(SCHEDULE, SUMMARY, error=None)
    assert "[Cashel]" in subj
    assert "HIGH" in subj
    assert "ASA" in subj


def test_subject_error():
    subj = _audit_subject(SCHEDULE, {}, error="Connection refused")
    assert "error" in subj.lower()
    assert "ASA" in subj


def test_subject_no_findings():
    subj = _audit_subject(SCHEDULE, {"high": 0, "total": 0}, error=None)
    assert "no HIGH" in subj.lower() or "✅" in subj


# ══════════════════════════════════════════ _audit_body_text ══


def test_body_contains_label():
    body = _audit_body_text(SCHEDULE, SUMMARY, FINDINGS, error=None)
    assert "ASA" in body
    assert "192.168.1.1" in body
    assert "ASA-EDGE" in body


def test_body_summary_line():
    body = _audit_body_text(SCHEDULE, SUMMARY, FINDINGS, error=None)
    assert "3 finding" in body
    assert "2 HIGH" in body


def test_body_lists_high_findings():
    body = _audit_body_text(SCHEDULE, SUMMARY, FINDINGS, error=None)
    assert "Permit any any" in body


def test_body_error_message():
    body = _audit_body_text(SCHEDULE, {}, [], error="SSH timeout")
    assert "SSH timeout" in body


def test_body_clean_audit():
    body = _audit_body_text(
        SCHEDULE, {"high": 0, "medium": 0, "low": 0, "total": 0}, [], error=None
    )
    assert "No issues found" in body


# ════════════════════════════════════════════════ send_slack ══


class _MockHTTPResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _RaisingHTTPHandler:
    """Simulate a network failure."""

    import urllib.error

    def __enter__(self):
        raise ConnectionRefusedError("mock failure")

    def __exit__(self, *a):
        pass


def test_send_slack_empty_webhook_no_crash():
    """send_slack with empty URL must return silently without error."""
    send_slack("", SCHEDULE, SUMMARY, FINDINGS)  # must not raise


def test_send_slack_url_error_no_crash(monkeypatch):
    """send_slack must swallow network errors silently."""
    import urllib.request
    import urllib.error

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(
            urllib.error.URLError("simulated failure")
        ),
    )
    send_slack("https://hooks.slack.com/services/FAKE", SCHEDULE, SUMMARY, FINDINGS)


def test_send_slack_payload_structure():
    """Verify the JSON payload posted to Slack has the expected shape."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["data"] = json.loads(req.data.decode("utf-8"))
        return _MockHTTPResponse()

    import urllib.request as ureq

    orig = ureq.urlopen
    ureq.urlopen = fake_urlopen
    try:
        send_slack("https://hooks.slack.com/services/FAKE", SCHEDULE, SUMMARY, FINDINGS)
        assert "text" in captured["data"]
        assert "Cashel" in captured["data"]["text"]
        assert "ASA" in captured["data"]["text"]
    finally:
        ureq.urlopen = orig


# ════════════════════════════════════════════════ send_email ══


def test_send_email_empty_address_no_crash():
    """send_email with no address must return silently."""
    send_email("", SCHEDULE, SUMMARY, FINDINGS, {})


def test_send_email_missing_smtp_host_no_crash():
    """send_email without smtp_host configured must warn and return silently."""
    send_email("ops@example.com", SCHEDULE, SUMMARY, FINDINGS, {"smtp_host": ""})


def test_send_email_smtp_exception_no_crash():
    """send_email must swallow SMTPException without propagating."""
    smtp_cfg = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "u",
        "smtp_password": "p",
        "smtp_from": "from@example.com",
        "smtp_tls": True,
    }

    original_smtp = smtplib.SMTP

    class FakeSMTP:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            raise smtplib.SMTPException("connection refused")

        def __exit__(self, *a):
            pass

    smtplib.SMTP = FakeSMTP
    try:
        send_email("ops@example.com", SCHEDULE, SUMMARY, FINDINGS, smtp_cfg)
    finally:
        smtplib.SMTP = original_smtp


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_top_high_enriched,
        test_top_high_plain,
        test_top_high_limit,
        test_top_high_no_highs,
        test_subject_high_findings,
        test_subject_error,
        test_subject_no_findings,
        test_body_contains_label,
        test_body_summary_line,
        test_body_lists_high_findings,
        test_body_error_message,
        test_body_clean_audit,
        test_send_slack_empty_webhook_no_crash,
        test_send_slack_url_error_no_crash,
        test_send_slack_payload_structure,
        test_send_email_empty_address_no_crash,
        test_send_email_missing_smtp_host_no_crash,
        test_send_email_smtp_exception_no_crash,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests.")
    sys.exit(0 if failed == 0 else 1)
