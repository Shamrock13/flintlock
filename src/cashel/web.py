import atexit
import importlib.metadata
import os
import secrets
import time

from flask import Flask, g, jsonify, render_template, request
from flasgger import Swagger

from .extensions import csrf, limiter
from .license import check_license, mask_key, DEMO_MODE
from .archive import list_archive
from .settings import get_settings
from .scheduler_runner import start_scheduler, stop_scheduler, scheduler_available
from .syslog_handler import configure_syslog
from ._helpers import UPLOAD_FOLDER, _require_auth_impl

REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")
ARCHIVE_FOLDER = os.environ.get("ARCHIVE_FOLDER", "/tmp/cashel_archive")
ACTIVITY_FOLDER = os.environ.get("ACTIVITY_FOLDER", "/tmp/cashel_activity")

for _d in (UPLOAD_FOLDER, REPORTS_FOLDER, ARCHIVE_FOLDER, ACTIVITY_FOLDER):
    try:
        os.makedirs(_d, exist_ok=True)
    except OSError:
        pass  # Writability is checked at use-time via _make_temp_path

# Settings folder is created lazily by settings.py on first save.

app = Flask(__name__, template_folder="templates", static_folder="static")
_secret = os.environ.get("CASHEL_SECRET", "")
if not _secret:
    import warnings

    warnings.warn(
        "CASHEL_SECRET is not set — using a random ephemeral key. "
        "Sessions will not survive restarts. Set CASHEL_SECRET in production.",
        stacklevel=1,
    )
    _secret = secrets.token_hex(32)
app.config["SECRET_KEY"] = _secret
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB total request cap
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("CASHEL_SECURE_COOKIES", "false").lower() == "true"
)

csrf.init_app(app)
limiter.init_app(app)

_swagger = Swagger(
    app,
    config={
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/apispec.json",
                "rule_filter": lambda rule: rule.rule.startswith("/api/v1"),
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs",
    },
    template={
        "info": {
            "title": "Cashel API",
            "description": (
                "Cashel firewall auditing REST API. "
                "Authenticate with an `X-API-Key` header or `?api_key=` query parameter."
            ),
            "version": "1",
        },
        "securityDefinitions": {
            "ApiKeyHeader": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            }
        },
        "security": [{"ApiKeyHeader": []}],
        "tags": [
            {"name": "Audit", "description": "Run and retrieve audits"},
            {"name": "History", "description": "Browse audit history"},
            {"name": "Diff", "description": "Compare two configs"},
        ],
    },
)

_start_time = time.time()


@app.before_request
def _assign_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


# HSTS omitted — enable at the reverse-proxy layer when deploying with TLS.
@app.after_request
def _add_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    # Swagger UI (flasgger) serves its own bundled JS from the same origin and
    # uses inline scripts for initialisation — relax script-src for those paths only.
    _is_docs = request.path.startswith(("/api/docs", "/flasgger_static/", "/apispec"))
    if _is_docs:
        script_src = "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
    else:
        script_src = f"'nonce-{nonce}' https://cdn.jsdelivr.net"
    response.headers.setdefault(
        "Content-Security-Policy",
        f"default-src 'self'; "
        f"script-src {script_src}; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"frame-ancestors 'none';",
    )
    return response


@app.errorhandler(413)
def request_too_large(_e):
    return jsonify(
        {"error": "Upload too large. Maximum file size is 5 MB per file."}
    ), 413


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify(
        {
            "error": "Rate limit exceeded. Please slow down.",
            "retry_after": str(getattr(e, "retry_after", "")),
        }
    ), 429


@app.before_request
def _require_auth():
    """Registered as app.before_request; delegates to _helpers._require_auth_impl."""
    return _require_auth_impl(DEMO_MODE)


@app.route("/health")
def health():
    """Container health/readiness probe — always public."""
    try:
        _version = importlib.metadata.version("cashel")
    except importlib.metadata.PackageNotFoundError:
        _version = "dev"
    entries = list_archive()
    last_audit = entries[0]["timestamp"] if entries else None
    return jsonify(
        {
            "ok": True,
            "version": _version,
            "uptime_seconds": round(time.time() - _start_time),
            "scheduler_running": scheduler_available(),
            "last_audit_at": last_audit,
        }
    )


@app.route("/")
def index():
    from .blueprints.audit import get_demo_index_data

    licensed, license_info = check_license()
    if licensed:
        license_info = mask_key(license_info)
    # Pre-serialize sample lists so the template renders cards server-side,
    # avoiding the async fetch that caused "Loading samples…" to get stuck.
    demo_configs, demo_comparisons = get_demo_index_data() if DEMO_MODE else ([], [])
    return render_template(
        "index.html",
        licensed=licensed,
        license_info=license_info,
        demo_mode=DEMO_MODE,
        demo_configs=demo_configs,
        demo_comparisons=demo_comparisons,
        current_user=getattr(g, "current_user", None),
    )


# ── Blueprint registration ────────────────────────────────────────────────────

from .blueprints.auth import auth_bp  # noqa: E402
from .blueprints.audit import audit_bp  # noqa: E402
from .blueprints.history import history_bp  # noqa: E402
from .blueprints.schedules import schedules_bp  # noqa: E402
from .blueprints.settings_bp import settings_bp  # noqa: E402
from .blueprints.reports import reports_bp  # noqa: E402
from .blueprints.api_v1 import api_bp  # noqa: E402

app.register_blueprint(auth_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(history_bp)
app.register_blueprint(schedules_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(api_bp)

from .db import init_db  # noqa: E402

init_db()


# ── Startup ───────────────────────────────────────────────────────────────────
# When running under gunicorn with multiple workers, only the first worker
# starts the scheduler (the others have CASHEL_SKIP_SCHEDULER=1 set by
# gunicorn.conf.py).

if os.environ.get("CASHEL_SKIP_SCHEDULER") != "1":
    start_scheduler()
    atexit.register(stop_scheduler)
if not DEMO_MODE:
    configure_syslog(get_settings())


def main():
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
