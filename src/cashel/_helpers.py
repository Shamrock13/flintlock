"""Shared non-route utility helpers for Cashel.

Includes _require_auth_impl() so web.py stays lean while keeping
_require_auth registered as app.before_request (per task spec).
"""

import logging as _logging
import os
import tempfile
import time
import uuid
from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from .settings import get_settings

_logger = _logging.getLogger(__name__)

_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per-file limit enforced in routes

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/cashel_uploads")


def _make_temp_path(suffix: str) -> str:
    """Return a writable temp path, preferring UPLOAD_FOLDER with system-temp fallback."""
    candidate = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}{suffix}")
    try:
        fd = os.open(candidate, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        os.unlink(candidate)
        return candidate
    except OSError:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path


_AUTH_EXEMPT_ENDPOINTS = {
    "auth.login",
    "auth.login_post",
    "auth.logout",
    "auth.setup",
    "auth.setup_post",
    "health",
    "static",
    "audit.demo_sample_report",
}

# Path prefixes that bypass auth (Swagger UI and spec JSON — public API docs)
# Path prefixes exempt from auth — Swagger UI + spec JSON are always public
_AUTH_EXEMPT_PATH_PREFIXES = ("/api/docs", "/flasgger_static/", "/apispec")


def _require_auth_impl(demo_mode: bool):
    """Core auth gate — called by web.py's app.before_request hook."""
    if demo_mode:
        g.auth_method = "demo"
        g.current_user = None
        return

    settings = get_settings()

    # First-run: no users exist → redirect to /setup
    if request.endpoint not in _AUTH_EXEMPT_ENDPOINTS:
        from .user_store import has_users

        if not has_users():
            return redirect(url_for("auth.setup"))

    if not settings.get("auth_enabled"):
        g.current_user = None
        return

    if request.endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return

    if request.path.startswith(_AUTH_EXEMPT_PATH_PREFIXES):
        return

    # API key auth (X-API-Key header or ?api_key= param) — CI/CLI
    api_key_header = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key_header:
        from .user_store import get_user_by_api_key

        user = get_user_by_api_key(api_key_header)
        if user:
            g.auth_method = "api_key"
            g.current_user = user
            return
        from .auth_audit import log_auth_event, AUTH_INVALID_API_KEY

        log_auth_event(
            AUTH_INVALID_API_KEY, success=False, details={"endpoint": request.path}
        )
        if request.path.startswith("/api/"):
            return jsonify(
                {"ok": False, "data": None, "error": "Invalid API key."}
            ), 401
        return jsonify({"error": "Invalid API key."}), 401

    # Session auth (browser)
    if session.get("authenticated") and session.get("user_id"):
        lifetime = settings.get("session_lifetime_minutes", 480)
        if time.time() - session.get("last_seen", 0) < lifetime * 60:
            session["last_seen"] = time.time()
            g.auth_method = "session"
            from .user_store import get_user_by_id

            g.current_user = get_user_by_id(session["user_id"])
            return
        session.clear()

    # Not authenticated
    if request.path.startswith("/api/"):
        return jsonify(
            {"ok": False, "data": None, "error": "Authentication required."}
        ), 401
    next_url = request.url if request.method == "GET" else None
    return redirect(url_for("auth.login", next=next_url))


def _require_role(*allowed_roles):
    """Decorator: abort 403 if g.current_user's role is not in allowed_roles."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user and user.get("role") not in allowed_roles:
                if request.path.startswith("/api/"):
                    return jsonify(
                        {"ok": False, "error": "Insufficient permissions."}
                    ), 403
                return jsonify({"error": "Insufficient permissions."}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _err(exc: Exception, generic_msg: str = "An internal error occurred.") -> str:
    """Return an error message string respecting the error_detail setting.

    In 'full' mode (development) the raw exception is surfaced.
    In 'sanitized' mode (production default) only *generic_msg* is returned and
    the full exception is written to the application log.
    """
    _logger.exception("Internal error: %s", exc)
    if get_settings().get("error_detail") == "full":
        return str(exc)
    return generic_msg
