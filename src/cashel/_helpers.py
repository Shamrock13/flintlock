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

MAX_FILE_MB = 25
_MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
MAX_FILE_LIMIT_MESSAGE = f"File exceeds the {MAX_FILE_MB} MB per-file limit."

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

_TRUTHY_ENV_VALUES = {"1", "true", "yes", "on"}
_FALSEY_ENV_VALUES = {"0", "false", "no", "off"}

# Swagger UI static assets can stay public; the docs UI/spec routes are gated below.
_AUTH_EXEMPT_PATH_PREFIXES = ("/flasgger_static/",)
_API_DOCS_PATH_PREFIXES = ("/api/docs", "/apispec")


def api_docs_public_enabled() -> bool:
    """Return whether API docs/spec routes should remain public."""
    return os.environ.get("CASHEL_PUBLIC_API_DOCS", "false").strip().lower() in (
        _TRUTHY_ENV_VALUES
    )


def query_api_key_allowed() -> bool:
    """Return whether deprecated ?api_key= authentication is still accepted."""
    return (
        os.environ.get("CASHEL_ALLOW_QUERY_API_KEY", "true").strip().lower()
        not in _FALSEY_ENV_VALUES
    )


def _is_api_docs_path() -> bool:
    return request.path.startswith(_API_DOCS_PATH_PREFIXES)


def _require_auth_impl(demo_mode: bool):
    """Core auth gate — called by web.py's app.before_request hook."""
    if demo_mode:
        g.auth_method = "demo"
        g.current_user = None
        return

    if _is_api_docs_path() and api_docs_public_enabled():
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

    # API key auth (X-API-Key header preferred; ?api_key= is deprecated).
    api_key_header = request.headers.get("X-API-Key")
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

    query_api_key = request.args.get("api_key")
    if query_api_key:
        from .auth_audit import (
            AUTH_INVALID_API_KEY,
            AUTH_QUERY_API_KEY_DISABLED,
            AUTH_QUERY_API_KEY_USED,
            log_auth_event,
        )

        if not query_api_key_allowed():
            _logger.warning(
                "Rejected deprecated query-string API key auth for path %s",
                request.path,
            )
            log_auth_event(
                AUTH_QUERY_API_KEY_DISABLED,
                success=False,
                details={"endpoint": request.path, "auth_source": "query"},
            )
            if request.path.startswith("/api/"):
                return jsonify(
                    {
                        "ok": False,
                        "data": None,
                        "error": (
                            "Query-string API keys are disabled. "
                            "Use the X-API-Key header."
                        ),
                    }
                ), 401
        else:
            _logger.warning(
                "Deprecated query-string API key auth used for path %s",
                request.path,
            )
            from .user_store import get_user_by_api_key

            user = get_user_by_api_key(query_api_key)
            if user:
                log_auth_event(
                    AUTH_QUERY_API_KEY_USED,
                    success=True,
                    details={"endpoint": request.path, "auth_source": "query"},
                )
                g.auth_method = "api_key"
                g.current_user = user
                return
            log_auth_event(
                AUTH_QUERY_API_KEY_USED,
                success=False,
                details={"endpoint": request.path, "auth_source": "query"},
            )
            log_auth_event(
                AUTH_INVALID_API_KEY,
                success=False,
                details={"endpoint": request.path},
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
