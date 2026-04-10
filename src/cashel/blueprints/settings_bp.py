"""Settings blueprint — /settings/*, /license/*."""

import smtplib
import ssl
from email.mime.text import MIMEText

from flask import Blueprint, g, jsonify, request

from cashel._helpers import _require_role
from cashel.auth_audit import (
    AUTH_LICENSE_CHANGED, AUTH_SETTINGS_CHANGED, log_auth_event,
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
    log_auth_event(AUTH_LICENSE_CHANGED, actor=actor, success=success,
                   details={"action": "activated", "message": message})
    return jsonify({"success": success, "message": message})


@settings_bp.route("/license/deactivate", methods=["POST"])
@_require_role("admin")
def license_deactivate():
    success, message = deactivate_license()
    actor = (getattr(g, "current_user", None) or {}).get("username", "")
    log_auth_event(AUTH_LICENSE_CHANGED, actor=actor, success=success,
                   details={"action": "deactivated", "message": message})
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
    log_auth_event(AUTH_SETTINGS_CHANGED, actor=actor,
                   details={"keys_updated": list(data.keys())})
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
