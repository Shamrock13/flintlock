"""Settings blueprint — /settings/*, /license/*."""

import smtplib
import ssl
from email.mime.text import MIMEText

from flask import Blueprint, g, jsonify, request

from cashel._helpers import _require_role
from cashel.auth_audit import (
    AUTH_LICENSE_CHANGED,
    AUTH_SETTINGS_CHANGED,
    log_auth_event,
)
from cashel.license import (
    check_license,
    activate_license,
    deactivate_license,
    DEMO_MODE,
)
from cashel.settings import get_settings, save_settings
from cashel.syslog_handler import configure_syslog

settings_bp = Blueprint("settings_bp", __name__)


@settings_bp.route("/license/activate", methods=["POST"])
@_require_role("admin")
def license_activate():
    key = request.form.get("key", "").strip()
    success, message = activate_license(key)
    actor = (getattr(g, "current_user", None) or {}).get("username", "")
    log_auth_event(
        AUTH_LICENSE_CHANGED,
        actor=actor,
        success=success,
        details={"action": "activated", "message": message},
    )
    return jsonify({"success": success, "message": message})


@settings_bp.route("/license/deactivate", methods=["POST"])
@_require_role("admin")
def license_deactivate():
    success, message = deactivate_license()
    actor = (getattr(g, "current_user", None) or {}).get("username", "")
    log_auth_event(
        AUTH_LICENSE_CHANGED,
        actor=actor,
        success=success,
        details={"action": "deactivated", "message": message},
    )
    return jsonify({"success": success, "message": message})


@settings_bp.route("/license/status")
def license_status():
    licensed, info = check_license()
    return jsonify({"licensed": licensed, "info": info})


@settings_bp.route("/settings", methods=["GET"])
@_require_role("admin")
def settings_get():
    s = get_settings()
    return jsonify(s)


@settings_bp.route("/settings", methods=["POST"])
@_require_role("admin")
def settings_save():
    if DEMO_MODE:
        return jsonify({"error": "Settings cannot be saved in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    saved = save_settings(data)
    # Reconfigure syslog immediately when settings are changed.
    configure_syslog(saved)
    actor = (getattr(g, "current_user", None) or {}).get("username", "")
    log_auth_event(
        AUTH_SETTINGS_CHANGED, actor=actor, details={"keys_updated": list(data.keys())}
    )
    return jsonify(saved)


@settings_bp.route("/settings/test-smtp", methods=["POST"])
@_require_role("admin")
def settings_test_smtp():
    """Attempt a live SMTP connection and send a test email.

    Accepts the same SMTP fields as /settings POST so the user can test
    before saving.  Returns {ok: bool, message: str}.
    """
    if DEMO_MODE:
        return jsonify({"ok": False, "message": "SMTP is disabled in demo mode."}), 403

    data = request.get_json(silent=True) or {}
    smtp_host = (data.get("smtp_host") or "").strip()
    smtp_port = int(data.get("smtp_port") or 587)
    smtp_user = (data.get("smtp_user") or "").strip()
    smtp_password = data.get("smtp_password") or ""
    smtp_from = (data.get("smtp_from") or smtp_user or "").strip()
    smtp_tls = bool(data.get("smtp_tls", True))
    to_address = (data.get("to_address") or smtp_from or smtp_user or "").strip()

    if not smtp_host:
        return jsonify({"ok": False, "message": "SMTP host is required."}), 400
    if not to_address:
        return jsonify(
            {
                "ok": False,
                "message": "Could not determine a recipient address — set smtp_from or smtp_user.",
            }
        ), 400

    msg = MIMEText(
        "This is a test message from Cashel.\n\n"
        "If you received this, your SMTP settings are configured correctly.",
        "plain",
        "utf-8",
    )
    msg["Subject"] = "[Cashel] SMTP test"
    msg["From"] = smtp_from or to_address
    msg["To"] = to_address

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if smtp_tls:
                server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from or to_address, [to_address], msg.as_string())
        return jsonify(
            {"ok": True, "message": f"Test email sent successfully to {to_address}."}
        )
    except smtplib.SMTPAuthenticationError:
        return jsonify(
            {
                "ok": False,
                "message": "Authentication failed — check username and password.",
            }
        )
    except smtplib.SMTPConnectError as exc:
        return jsonify(
            {
                "ok": False,
                "message": f"Could not connect to {smtp_host}:{smtp_port} — {exc}",
            }
        )
    except smtplib.SMTPException as exc:
        return jsonify({"ok": False, "message": f"SMTP error: {exc}"})
    except OSError as exc:
        return jsonify({"ok": False, "message": f"Connection error: {exc}"})


# ── Alert Thresholds ──────────────────────────────────────────────────────────

from cashel.alert_engine import (  # noqa: E402
    list_thresholds,
    save_threshold as _save_threshold,
    delete_threshold as _delete_threshold,
    get_alert_channels,
    save_alert_channels as _save_alert_channels,
    VALID_METRICS,
    VALID_OPERATORS,
)


@settings_bp.route("/settings/alert-thresholds", methods=["GET"])
@_require_role("admin")
def alert_thresholds_get():
    return jsonify(list_thresholds())


@settings_bp.route("/settings/alert-thresholds", methods=["POST"])
@_require_role("admin")
def alert_thresholds_save():
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    metric = data.get("metric", "")
    operator = data.get("operator", "")
    if metric not in VALID_METRICS:
        return jsonify({"error": f"Invalid metric: {metric}"}), 400
    if operator not in VALID_OPERATORS:
        return jsonify({"error": f"Invalid operator: {operator}"}), 400
    try:
        threshold_value = float(data["threshold_value"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "threshold_value must be a number"}), 400
    saved = _save_threshold(
        {
            "id": data.get("id"),
            "schedule_id": data.get("schedule_id") or None,
            "metric": metric,
            "operator": operator,
            "threshold_value": threshold_value,
            "enabled": bool(data.get("enabled", True)),
        }
    )
    return jsonify(saved), 201


@settings_bp.route("/settings/alert-thresholds/<threshold_id>", methods=["DELETE"])
@_require_role("admin")
def alert_thresholds_delete(threshold_id):
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    deleted = _delete_threshold(threshold_id)
    if not deleted:
        return jsonify({"error": "Threshold not found"}), 404
    return jsonify({"ok": True})


@settings_bp.route("/settings/alert-channels", methods=["GET"])
@_require_role("admin")
def alert_channels_get():
    channels = get_alert_channels()
    # Mask webhook URLs — return only whether they are set
    return jsonify(
        {
            "alert_slack_webhook_set": bool(channels.get("alert_slack_webhook")),
            "alert_teams_webhook_set": bool(channels.get("alert_teams_webhook")),
            "alert_email_recipients": channels.get("alert_email_recipients", ""),
        }
    )


@settings_bp.route("/settings/alert-channels", methods=["POST"])
@_require_role("admin")
def alert_channels_save():
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    _save_alert_channels(
        {
            "alert_slack_webhook": data.get("alert_slack_webhook", ""),
            "alert_teams_webhook": data.get("alert_teams_webhook", ""),
            "alert_email_recipients": data.get("alert_email_recipients", ""),
        }
    )
    return jsonify({"ok": True})


# ── Webhooks ───────────────────────────────────────────────────────────────────

from cashel import webhooks as _webhooks  # noqa: E402


@settings_bp.route("/settings/webhooks", methods=["GET"])
@_require_role("admin")
def webhooks_list():
    rows = _webhooks.list_webhooks()
    # Mask secrets in list response — return only whether they are set
    for row in rows:
        row["secret_set"] = bool(row.pop("secret", ""))
    return jsonify(rows)


@settings_bp.route("/settings/webhooks", methods=["POST"])
@_require_role("admin")
def webhooks_add():
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    events = data.get("events") or []
    secret = (data.get("secret") or "").strip() or None
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not url:
        return jsonify({"error": "url is required"}), 400
    try:
        saved = _webhooks.add_webhook(name, url, events, secret)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    saved["secret_set"] = bool(saved.pop("secret", ""))
    return jsonify(saved), 201


@settings_bp.route("/settings/webhooks/<webhook_id>", methods=["PUT"])
@_require_role("admin")
def webhooks_update(webhook_id):
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    kwargs = {}
    for field in ("name", "url", "events", "secret", "enabled"):
        if field in data:
            kwargs[field] = data[field]
    try:
        saved = _webhooks.update_webhook(webhook_id, **kwargs)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    saved["secret_set"] = bool(saved.pop("secret", ""))
    return jsonify(saved)


@settings_bp.route("/settings/webhooks/<webhook_id>", methods=["DELETE"])
@_require_role("admin")
def webhooks_delete(webhook_id):
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    existing = _webhooks.get_webhook(webhook_id)
    if existing is None:
        return jsonify({"error": "Webhook not found"}), 404
    _webhooks.delete_webhook(webhook_id)
    return jsonify({"ok": True})


@settings_bp.route("/settings/webhooks/<webhook_id>/test", methods=["POST"])
@_require_role("admin")
def webhooks_test(webhook_id):
    """Dispatch a synthetic audit.complete event to one webhook for delivery verification."""
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    wh = _webhooks.get_webhook(webhook_id)
    if wh is None:
        return jsonify({"error": "Webhook not found"}), 404

    from datetime import datetime, timezone

    body = _webhooks._build_payload(
        "audit.complete",
        {
            "audit_id": "test000000",
            "filename": "test-config.conf",
            "vendor": "test",
            "score": 100,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
            "tag": None,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    secret = wh.get("secret") or None
    success, detail = _webhooks._post(wh["url"], body, secret)
    if success:
        return jsonify({"ok": True, "detail": detail})
    return jsonify({"ok": False, "error": detail}), 502
