import atexit
import importlib.metadata
import json
import logging as _logging
import os
import re
import secrets
import time
import uuid
from defusedxml import ElementTree as ET
from pathlib import Path
from flask import (
    Flask,
    Blueprint,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    redirect,
    url_for,
    g,
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .license import (
    check_license,
    activate_license,
    deactivate_license,
    mask_key,
    DEMO_MODE,
)
from .ftd import is_ftd_config
from .reporter import generate_report
from .audit_engine import (
    _findings_to_strings,
    _wrap_compliance,
    _sort_findings,
    _build_summary,
    run_vendor_audit,
    run_compliance_checks,
)
from .diff import diff_configs
from .archive import save_audit, list_archive, get_entry, delete_entry, compare_entries
from .export import to_json, to_csv, to_sarif
from .activity_log import (
    log_activity,
    list_activity,
    delete_activity_entry,
    clear_activity,
    ACTION_FILE_AUDIT,
    ACTION_SSH_CONNECT,
    ACTION_CONFIG_DIFF,
)
from .settings import get_settings, save_settings, save_api_key
from .schedule_store import (
    list_schedules,
    get_schedule,
    create_schedule,
    update_schedule,
    delete_schedule,
    ScheduleValidationError,
)
from .scheduler_runner import (
    start_scheduler,
    stop_scheduler,
    reload_job,
    run_now as scheduler_run_now,
    scheduler_available,
)
from .syslog_handler import configure_syslog
from .remediation import generate_plan, plan_to_markdown, plan_to_pdf

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/cashel_uploads")
REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")
ARCHIVE_FOLDER = os.environ.get("ARCHIVE_FOLDER", "/tmp/cashel_archive")
ACTIVITY_FOLDER = os.environ.get("ACTIVITY_FOLDER", "/tmp/cashel_activity")

for _d in (UPLOAD_FOLDER, REPORTS_FOLDER, ARCHIVE_FOLDER, ACTIVITY_FOLDER):
    try:
        os.makedirs(_d, exist_ok=True)
    except OSError:
        pass  # Writability is checked at use-time via _make_temp_path


def _make_temp_path(suffix: str) -> str:
    """Return a writable temp path, preferring UPLOAD_FOLDER with system-temp fallback."""
    import tempfile

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


# Settings folder is created lazily by settings.py on first save

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

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)

_start_time = time.time()
_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per-file limit enforced in routes

# ── REST API blueprint (CSRF-exempt; auth via X-API-Key) ──────────────────────
api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
csrf.exempt(api_bp)


# ── CSP nonce ─────────────────────────────────────────────────────────────────


@app.before_request
def _assign_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


# ── HTTP security headers ─────────────────────────────────────────────────────
# HSTS is intentionally omitted — enable at the reverse-proxy layer when
# deploying with TLS.


@app.after_request
def _add_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        f"default-src 'self'; "
        f"script-src 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"frame-ancestors 'none';",
    )
    return response


# ── Error handlers ────────────────────────────────────────────────────────────


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


# ── Authentication middleware ─────────────────────────────────────────────────

_AUTH_EXEMPT_ENDPOINTS = {"login", "login_post", "logout", "health", "static"}


@app.before_request
def _require_auth():
    # Demo mode: no authentication required at all.
    if DEMO_MODE:
        g.auth_method = "demo"
        return

    settings = get_settings()
    if not settings.get("auth_enabled"):
        return

    if request.endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return

    # API key auth (header or query param) — used by CLI/CI clients
    api_key_header = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key_header:
        stored = settings.get("api_key", "")
        if stored and secrets.compare_digest(api_key_header, stored):
            g.auth_method = "api_key"
            return
        if request.path.startswith("/api/"):
            return jsonify(
                {"ok": False, "data": None, "error": "Invalid API key."}
            ), 401
        return jsonify({"error": "Invalid API key."}), 401

    # Session auth (browser)
    if session.get("authenticated"):
        lifetime = settings.get("session_lifetime_minutes", 480)
        if time.time() - session.get("last_seen", 0) < lifetime * 60:
            session["last_seen"] = time.time()
            g.auth_method = "session"
            return
        session.clear()

    # Not authenticated
    if request.path.startswith("/api/"):
        return jsonify(
            {"ok": False, "data": None, "error": "Authentication required."}
        ), 401
    next_url = request.url if request.method == "GET" else None
    return redirect(url_for("login", next=next_url))


# ── Error response helper ─────────────────────────────────────────────────────

_logger = _logging.getLogger(__name__)


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


VENDOR_DISPLAY = {
    "asa": "Cisco",
    "ftd": "Cisco",
    "cisco": "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense": "pfSense",
    "aws": "AWS Security Group",
    "azure": "Azure NSG",
    "gcp": "GCP VPC Firewall",
    "iptables": "iptables",
    "juniper": "Juniper SRX",
    "nftables": "nftables",
}

ALL_VENDORS = set(VENDOR_DISPLAY)


# ── Vendor auto-detection ─────────────────────────────────────────────────────


def detect_vendor(content: str, filename: str) -> str | None:
    """Infer firewall vendor from file content and filename."""
    filename_lower = filename.lower()
    content_lower = content.lower()
    stripped = content.strip()

    # JSON-based: AWS, Azure, or GCP
    if (
        stripped.startswith("{")
        or stripped.startswith("[")
        or filename_lower.endswith(".json")
    ):
        try:
            data = json.loads(content[:8192])  # partial parse for detection
            if isinstance(data, dict):
                if (
                    "SecurityGroups" in data
                    or "GroupId" in data
                    or "IpPermissions" in data
                ):
                    return "aws"
                if "securityRules" in data or "defaultSecurityRules" in data:
                    return "azure"
                if isinstance(data.get("value"), list):
                    # Could be az network nsg list output
                    if data["value"] and "securityRules" in data["value"][0]:
                        return "azure"
                if (
                    "items" in data
                    and isinstance(data["items"], list)
                    and data["items"]
                ):
                    first = data["items"][0]
                    if (
                        "direction" in first
                        and "IPProtocol" not in first
                        and ("allowed" in first or "denied" in first)
                    ):
                        return "gcp"
                if "direction" in data and ("allowed" in data or "denied" in data):
                    return "gcp"
            elif isinstance(data, list) and data:
                first = data[0]
                if "GroupId" in first or "IpPermissions" in first:
                    return "aws"
                if "securityRules" in first or "defaultSecurityRules" in first:
                    return "azure"
                if "direction" in first and ("allowed" in first or "denied" in first):
                    return "gcp"
        except Exception:
            pass

    # XML-based: pfSense or Palo Alto
    if stripped.startswith("<") or filename_lower.endswith(".xml"):
        if "<pfsense>" in content_lower or (
            "<filter>" in content_lower and "<rule>" in content_lower
        ):
            return "pfsense"
        if any(
            k in content_lower
            for k in ("<devices>", "<vsys>", "<security>", "<rulebase>")
        ):
            return "paloalto"

    # Text-based: Fortinet
    if "config firewall policy" in content_lower or (
        "set srcintf" in content_lower and "set dstintf" in content_lower
    ):
        return "fortinet"

    # Text-based: Cisco FTD (check before ASA — FTD has ASA-style ACLs too)
    if any(
        k in content_lower
        for k in (
            "access-control-policy",
            "firepower threat defense",
            "firepower-module",
            "intrusion-policy",
        )
    ):
        return "ftd"

    # Text-based: Juniper SRX ("set" style or hierarchical brace style)
    if re.search(r"set security policies from-zone", content) or (
        "from-zone" in content_lower
        and "to-zone" in content_lower
        and ("security {" in content or "security{" in content)
    ):
        return "juniper"

    # Text-based: nftables ("nft list ruleset" output)
    if re.search(r"\btable\s+\w+\s+\w+\s*\{|\bchain\s+\w+\s*\{", content):
        return "nftables"

    # JSON nftables ("nft -j list ruleset")
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(content[:8192])
            nft_entries = data if isinstance(data, list) else data.get("nftables", [])
            if isinstance(nft_entries, list) and any(
                "chain" in e or "rule" in e for e in nft_entries
            ):
                return "nftables"
        except Exception:
            pass

    # Text-based: iptables-save
    if re.search(r"^\*\w+$|^-A\s+\w+", content, re.MULTILINE):
        return "iptables"

    # Text-based: Cisco ASA
    if "access-list" in content_lower and any(
        k in content_lower for k in ("permit", "deny")
    ):
        return "asa"

    return None


def validate_vendor_format(
    content: str, filename: str, vendor: str
) -> tuple[bool, str]:
    """Return (is_valid, error_message). Ensures the file actually matches the vendor format."""
    content_lower = content.lower()
    is_xml = content.strip().startswith("<") or filename.lower().endswith(".xml")
    is_json = content.strip().startswith(("{", "[")) or filename.lower().endswith(
        ".json"
    )

    if vendor == "ftd":
        if is_xml or is_json:
            return (
                False,
                "Cisco FTD LINA configs are text-based, but this file appears to be XML or JSON.",
            )
        # FTD configs may or may not have access-list; require at least some Cisco CLI content
        if not any(
            k in content_lower
            for k in (
                "access-list",
                "access-control-policy",
                "threat-detection",
                "intrusion-policy",
                "interface",
                "firepower",
            )
        ):
            return (
                False,
                "No recognizable Cisco FTD configuration markers found. Check vendor selection.",
            )

    elif vendor == "asa":
        if is_xml or is_json:
            return (
                False,
                "Cisco configs are text-based, but this file appears to be XML or JSON.",
            )
        # If the file actually looks like FTD, upgrade silently
        if is_ftd_config(content):
            return True, ""  # will be re-routed to ftd in run_audit
        if "access-list" not in content_lower:
            return (
                False,
                "No Cisco access-list statements found. Check vendor selection.",
            )

    elif vendor == "paloalto":
        if not is_xml:
            return False, "Palo Alto configs are XML-based, but this file is not XML."
        if not any(
            m in content_lower
            for m in ("<devices>", "<vsys>", "<security>", "<rulebase>")
        ):
            return (
                False,
                "This XML does not contain Palo Alto Networks configuration markers.",
            )

    elif vendor == "fortinet":
        if is_xml or is_json:
            return (
                False,
                "Fortinet configs are text-based, but this file appears to be XML or JSON.",
            )
        if not any(
            m in content_lower
            for m in ("config firewall policy", "set srcintf", "set dstintf")
        ):
            return (
                False,
                "No Fortinet firewall policy statements found. Check vendor selection.",
            )

    elif vendor == "pfsense":
        if not is_xml:
            return False, "pfSense configs are XML-based, but this file is not XML."
        if "<pfsense>" not in content_lower:
            return False, "pfSense root element <pfsense> not found in this XML file."

    elif vendor == "aws":
        if not is_json:
            return (
                False,
                "AWS Security Group exports are JSON. Please upload a .json file.",
            )

    elif vendor == "azure":
        if not is_json:
            return False, "Azure NSG exports are JSON. Please upload a .json file."

    elif vendor == "juniper":
        if is_xml or is_json:
            return (
                False,
                "Juniper SRX configs are text-based, but this file appears to be XML or JSON.",
            )
        if not any(
            m in content_lower
            for m in (
                "set security",
                "from-zone",
                "to-zone",
                "security-zone",
                "security {",
            )
        ):
            return (
                False,
                "No Juniper SRX security configuration markers found. Check vendor selection.",
            )

    elif vendor == "gcp":
        if not is_json:
            return (
                False,
                "GCP VPC firewall exports are JSON. Please upload a .json file.",
            )
        try:
            parsed = json.loads(content[:8192])
            items = (
                parsed if isinstance(parsed, list) else parsed.get("items", [parsed])
            )
            if not items or not isinstance(items[0], dict):
                raise ValueError("empty")
            first = items[0]
            if "direction" not in first or (
                "allowed" not in first and "denied" not in first
            ):
                return False, (
                    "This JSON does not contain GCP VPC firewall rule markers "
                    "('direction', 'allowed'/'denied'). Check vendor selection."
                )
        except Exception:
            return False, "Could not parse this file as a GCP VPC firewall JSON export."

    elif vendor == "iptables":
        if is_xml:
            return False, "iptables-save files are text-based, not XML."
        if not re.search(r"^\*\w+$|^-A\s+\w+", content, re.MULTILINE):
            return False, (
                "No iptables-save markers found (expected '*filter' or '-A INPUT ...'). "
                "Export with 'iptables-save > rules.txt'."
            )

    elif vendor == "nftables":
        # Accept either nft text or JSON
        is_nft_text = bool(
            re.search(r"\btable\s+\w+\s+\w+\s*\{|\bchain\s+\w+\s*\{", content)
        )
        is_nft_json = False
        if is_json:
            try:
                data = json.loads(content[:8192])
                nft_entries = (
                    data if isinstance(data, list) else data.get("nftables", [])
                )
                is_nft_json = isinstance(nft_entries, list) and any(
                    "chain" in e or "rule" in e for e in nft_entries
                )
            except Exception:
                pass
        if not is_nft_text and not is_nft_json:
            return False, (
                "No nftables markers found. "
                "Export with 'nft list ruleset' or 'nft -j list ruleset'."
            )

    else:
        return False, f"Unknown vendor: {vendor}"

    return True, ""


# ── Hostname extraction ───────────────────────────────────────────────────────


def extract_hostname(vendor: str, content: str) -> str | None:
    """Try to extract the device hostname from a config file."""
    try:
        if vendor in ("asa", "ftd"):
            m = re.search(r"^hostname\s+(\S+)", content, re.MULTILINE)
            return m.group(1) if m else None

        if vendor == "paloalto":
            root = ET.fromstring(content)
            el = root.find(".//devices/entry/deviceconfig/system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "fortinet":
            block = re.search(r"config system global(.*?)end", content, re.DOTALL)
            if block:
                m = re.search(r'set hostname\s+"?([^"\n]+)"?', block.group(1))
                return m.group(1).strip().strip('"') if m else None
            return None

        if vendor == "pfsense":
            root = ET.fromstring(content)
            el = root.find("system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "aws":
            data = json.loads(content)
            groups = (
                data if isinstance(data, list) else data.get("SecurityGroups", [data])
            )
            if groups:
                for t in groups[0].get("Tags", []):
                    if t.get("Key") == "Name":
                        return t["Value"]
                return groups[0].get("GroupName")

        if vendor == "azure":
            data = json.loads(content)
            items = data.get("value", [data]) if isinstance(data, dict) else data
            if items:
                return items[0].get("name")

    except Exception:
        pass
    return None


# ── Routes ────────────────────────────────────────────────────────────────────


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


@app.route("/login", methods=["GET"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    key = request.form.get("api_key", "")
    settings = get_settings()
    stored = settings.get("api_key", "")
    if stored and secrets.compare_digest(key, stored):
        session.clear()
        session["authenticated"] = True
        session["last_seen"] = time.time()
        next_url = request.args.get("next", "")
        # Guard against open-redirect: only accept relative paths
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("index"))
    return render_template(
        "login.html", error="Invalid API key. Please try again."
    ), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    licensed, license_info = check_license()
    if licensed:
        license_info = mask_key(license_info)
    # Pre-serialize sample lists so the template renders cards server-side,
    # avoiding the async fetch that caused "Loading samples…" to get stuck.
    demo_configs = (
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
            }
            for k, v in _DEMO_CONFIGS.items()
        ]
        if DEMO_MODE
        else []
    )
    demo_comparisons = (
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
                "label_a": v["label_a"],
                "label_b": v["label_b"],
            }
            for k, v in _DEMO_COMPARISON_PAIRS.items()
        ]
        if DEMO_MODE
        else []
    )
    return render_template(
        "index.html",
        licensed=licensed,
        license_info=license_info,
        demo_mode=DEMO_MODE,
        demo_configs=demo_configs,
        demo_comparisons=demo_comparisons,
    )


# ── Demo mode: serve bundled sample configs ───────────────────────────────────
_DEMO_SAMPLES_DIR = Path(__file__).parent / "demo_samples"

_DEMO_CONFIGS = {
    "cisco_asa": {
        "label": "Cisco ASA — Enterprise Edge",
        "filename": "cisco_asa.txt",
        "vendor": "asa",
        "description": "ASA 5525-X with ACL misconfigurations, SNMPv2, Telnet, and duplicate rules.",
    },
    "palo_alto": {
        "label": "Palo Alto PA-3220 — PAN-OS 11.1",
        "filename": "palo_alto.xml",
        "vendor": "paloalto",
        "description": "Any/any permit policy, missing log-end settings, and shadowed rules.",
    },
    "fortinet": {
        "label": "Fortinet FortiGate — Edge Firewall",
        "filename": "fortinet_fortigate.txt",
        "vendor": "fortinet",
        "description": "Unrestricted any/any policy with logging disabled and a duplicate rule.",
    },
    "aws": {
        "label": "AWS Security Groups — VPC Production",
        "filename": "aws_security_groups.json",
        "vendor": "aws",
        "description": "SSH/RDP open to 0.0.0.0/0 and a wildcard TCP 0-65535 rule.",
    },
}


@app.route("/demo/configs")
def demo_configs():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
            }
            for k, v in _DEMO_CONFIGS.items()
        ]
    )


@app.route("/demo/load/<config_id>")
def demo_load(config_id):
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    if config_id not in _DEMO_CONFIGS:
        return jsonify({"error": "Unknown demo config."}), 404
    cfg = _DEMO_CONFIGS[config_id]
    file_path = _DEMO_SAMPLES_DIR / cfg["filename"]
    if not file_path.exists():
        return jsonify({"error": "Sample config file not found."}), 500
    return send_file(
        file_path,
        as_attachment=True,
        download_name=cfg["filename"],
        mimetype="text/plain",
    )


_DEMO_COMPARISON_PAIRS = {
    "asa_weekly": {
        "label": "Cisco ASA — Week 1 vs Week 2",
        "vendor": "asa",
        "description": "Baseline with Telnet, any/any, and open HTTP management vs. hardened current config.",
        "file_a": "cisco_asa_baseline.txt",
        "file_b": "cisco_asa_current.txt",
        "label_a": "Week 1 — Baseline",
        "label_b": "Week 2 — Current",
    },
    "fortinet_patch": {
        "label": "Fortinet FortiGate — Pre-patch vs Post-patch",
        "vendor": "fortinet",
        "description": "Broad any/any policies and logging disabled vs. tightened rules with full logging.",
        "file_a": "fortinet_baseline.txt",
        "file_b": "fortinet_current.txt",
        "label_a": "Pre-patch — Baseline",
        "label_b": "Post-patch — Current",
    },
}


@app.route("/demo/comparisons")
def demo_comparisons():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
                "label_a": v["label_a"],
                "label_b": v["label_b"],
            }
            for k, v in _DEMO_COMPARISON_PAIRS.items()
        ]
    )


@app.route("/demo/compare/<pair_id>")
def demo_compare(pair_id):
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    if pair_id not in _DEMO_COMPARISON_PAIRS:
        return jsonify({"error": "Unknown demo comparison."}), 404
    pair = _DEMO_COMPARISON_PAIRS[pair_id]
    path_a = str(_DEMO_SAMPLES_DIR / pair["file_a"])
    path_b = str(_DEMO_SAMPLES_DIR / pair["file_b"])
    if not Path(path_a).exists() or not Path(path_b).exists():
        return jsonify({"error": "Sample config files not found."}), 500
    try:
        result = diff_configs(pair["vendor"], path_a, path_b)
        result["vendor"] = pair["vendor"]
        result["filename_a"] = pair["label_a"]
        result["filename_b"] = pair["label_b"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Comparison failed: {e}"}), 500


# Pre-canned demo SSH audit result (Cisco ASA scenario).
# Must use "message" key (not "title") and include severity prefix so
# findingClass() and buildFindingHTML() in index.html render correctly.
_DEMO_SSH_FINDINGS = [
    {
        "severity": "critical",
        "category": "exposure",
        "message": "[CRITICAL] Telnet enabled on inside interface — transmits credentials in plaintext",
        "remediation": "Disable Telnet with 'no telnet' and enforce SSH for all remote management access.",
    },
    {
        "severity": "high",
        "category": "protocol",
        "message": "[HIGH] SNMPv2 community string 'public' configured — no per-user auth, plaintext on wire",
        "remediation": "Migrate to SNMPv3 with authPriv. Remove all SNMPv2 community strings.",
    },
    {
        "severity": "high",
        "category": "exposure",
        "message": "[HIGH] ACL OUTSIDE_IN contains 'permit ip any any' — unrestricted inbound traffic",
        "remediation": "Replace with explicit permit rules scoped to required sources, destinations, and services. Ensure a deny-all terminator exists.",
    },
    {
        "severity": "high",
        "category": "exposure",
        "message": "[HIGH] ASDM HTTP server accessible from 0.0.0.0/0 on outside interface",
        "remediation": "Restrict HTTP server to management subnets only: 'http <mgmt-subnet> <mask> inside'. Remove the 0.0.0.0/0 outside entry.",
    },
    {
        "severity": "medium",
        "category": "hygiene",
        "message": "[MEDIUM] Duplicate ACL rule — 'permit tcp any host 172.16.0.10 eq 80' appears twice in OUTSIDE_IN",
        "remediation": "Remove the duplicate entry. Use 'show access-list' hit counts to identify and consolidate redundant rules.",
    },
    {
        "severity": "medium",
        "category": "hygiene",
        "message": "[MEDIUM] NTP not configured — log timestamps will be unreliable",
        "remediation": "Configure at least two NTP servers: 'ntp server <ip> prefer'. Ensure NTP traffic is permitted by the management ACL.",
    },
    {
        "severity": "low",
        "category": "compliance",
        "message": "[LOW] No login banner configured — required by CIS and STIG for legal notice",
        "remediation": "Add 'banner login' or 'banner motd' with an authorised-use warning.",
    },
]

_DEMO_SSH_SUMMARY = {
    "score": 34,
    "total": 7,
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@app.route("/demo/ssh-audit", methods=["POST"])
def demo_ssh_audit():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        {
            "findings": [f["message"] for f in _DEMO_SSH_FINDINGS],
            "enriched_findings": _DEMO_SSH_FINDINGS,
            "summary": _DEMO_SSH_SUMMARY,
            "detected_vendor": "asa",
            "host": "203.0.113.50",
            "archive_id": None,
        }
    )


@app.route("/demo/bulk-audit", methods=["POST"])
def demo_bulk_audit():
    """Run all demo sample configs through the audit engine and return bulk results."""
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404

    results = []
    for _cfg_id, cfg in _DEMO_CONFIGS.items():
        src_path = str(_DEMO_SAMPLES_DIR / cfg["filename"])
        vendor = cfg["vendor"]
        result_entry: dict = {
            "filename": cfg["label"],
            "status": "error",
            "findings": [],
            "enriched_findings": [],
            "summary": {},
            "vendor": vendor,
            "archive_id": None,
            "error": None,
        }
        try:
            findings, _parse, _extra = run_vendor_audit(vendor, src_path)
            findings = _sort_findings(findings)
            summary = _build_summary(findings)
            result_entry.update(
                {
                    "status": "ok",
                    "findings": _findings_to_strings(findings),
                    "enriched_findings": findings,
                    "summary": summary,
                }
            )
        except Exception as exc:  # noqa: BLE001
            result_entry["error"] = str(exc)
        results.append(result_entry)

    return jsonify(results)


# Demo schedules — shown read-only when DEMO_MODE is active
_DEMO_SCHEDULES = [
    {
        "id": "demo-sched-1",
        "name": "ASA01 — Daily Security Audit",
        "vendor": "asa",
        "host": "203.0.113.50",
        "port": 22,
        "username": "auditor",
        "tag": "ASA01-EDGE",
        "compliance": "cis",
        "frequency": "daily",
        "hour": 2,
        "minute": 0,
        "day_of_week": "mon",
        "enabled": True,
        "last_run": "2026-03-27T02:00:12Z",
        "last_status": "ok",
        "last_error": None,
        "notify_on_finding": True,
        "notify_on_error": True,
        "notify_slack_webhook": "",
        "notify_teams_webhook": "",
        "notify_email": "security@corp.example.com",
    },
    {
        "id": "demo-sched-2",
        "name": "FortiGate-HQ — Weekly Review",
        "vendor": "fortinet",
        "host": "10.20.0.254",
        "port": 22,
        "username": "admin",
        "tag": "FGT-EDGE-01",
        "compliance": "",
        "frequency": "weekly",
        "hour": 3,
        "minute": 30,
        "day_of_week": "sun",
        "enabled": True,
        "last_run": "2026-03-23T03:30:08Z",
        "last_status": "ok",
        "last_error": None,
        "notify_on_finding": False,
        "notify_on_error": True,
        "notify_slack_webhook": "https://hooks.slack.com/services/demo/webhook",
        "notify_teams_webhook": "",
        "notify_email": "",
    },
    {
        "id": "demo-sched-3",
        "name": "PA-3220-DMZ — Daily Audit",
        "vendor": "paloalto",
        "host": "172.16.0.254",
        "port": 22,
        "username": "audituser",
        "tag": "PA-DMZ",
        "compliance": "pci",
        "frequency": "daily",
        "hour": 1,
        "minute": 15,
        "day_of_week": "mon",
        "enabled": False,
        "last_run": "2026-03-20T01:15:44Z",
        "last_status": "error",
        "last_error": "Connection timed out",
        "notify_on_finding": True,
        "notify_on_error": True,
        "notify_slack_webhook": "",
        "notify_teams_webhook": "",
        "notify_email": "security@corp.example.com",
    },
]


@app.route("/audit", methods=["POST"])
@limiter.limit("30/minute")
def run_audit():
    if "config" not in request.files or request.files["config"].filename == "":
        return jsonify({"error": "No config file uploaded"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    generate_pdf = request.form.get("report") == "1"
    archive_it = request.form.get("archive") == "1"
    tag = request.form.get("tag", "").strip() or None

    # Early vendor allowlist check — reject unknown values before touching disk.
    if vendor not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor}'."}), 400

    # Early compliance allowlist check.
    from .schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return jsonify({"error": f"Unknown compliance framework '{compliance}'."}), 400

    upload = request.files["config"]
    upload.seek(0, 2)
    if upload.tell() > _MAX_FILE_BYTES:
        return jsonify({"error": "File exceeds the 5 MB per-file limit."}), 413
    upload.seek(0)
    suffix = Path(upload.filename).suffix or ".txt"
    temp_path = _make_temp_path(suffix)
    upload.save(temp_path)

    try:
        with open(temp_path, "r", errors="ignore") as f:
            sample = f.read(16384)
    except Exception:
        sample = ""

    if vendor == "auto":
        vendor = detect_vendor(sample, upload.filename) or ""

    if vendor not in ALL_VENDORS:
        os.remove(temp_path)
        return jsonify(
            {"error": "Could not determine vendor. Please select one manually."}
        ), 400

    # Resolve "cisco" (user-facing) or re-route "asa" to "ftd" if file is FTD
    if vendor in ("cisco", "asa"):
        vendor = "ftd" if is_ftd_config(sample) else "asa"

    detected_hostname = extract_hostname(vendor, sample)

    is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
    if not is_valid:
        os.remove(temp_path)
        return jsonify(
            {
                "error": f"Wrong vendor selected ({VENDOR_DISPLAY.get(vendor, vendor)}): {validation_msg}"
            }
        ), 400

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        # Compliance checks (license-gated; not applicable for AWS/Azure)
        license_warning = None
        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if not licensed:
                license_warning = (
                    "Compliance checks require a valid license. "
                    'Purchase one at <a href="https://shamrock13.gumroad.com/l/cashel" '
                    'target="_blank" rel="noopener">shamrock13.gumroad.com/l/cashel</a>. '
                    "Once purchased, enter your key using the Licensed/Unlicensed badge in the top-right corner."
                )
            else:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        report_filename = None
        if generate_pdf:
            report_name = f"cashel_report_{uuid.uuid4().hex[:8]}.pdf"
            report_path = os.path.join(REPORTS_FOLDER, report_name)
            generate_report(
                _findings_to_strings(findings),
                upload.filename,
                vendor,
                compliance,
                output_path=report_path,
                summary=summary,
            )
            report_filename = report_name

        # Optional archive save — skipped in demo mode
        archive_id = None
        if archive_it and not DEMO_MODE:
            archive_id, _ = save_audit(
                upload.filename,
                vendor,
                _findings_to_strings(findings),
                summary,
                config_path=temp_path,
                tag=tag,
            )

        # Activity log — skipped in demo mode
        if not DEMO_MODE:
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor,
                success=True,
                details={
                    "total": summary.get("total", 0),
                    "high": summary.get("high", 0),
                    "archived": archive_id is not None,
                },
            )

        return jsonify(
            {
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "summary": summary,
                "report": report_filename,
                "license_warning": license_warning,
                "detected_vendor": vendor,
                "detected_hostname": detected_hostname,
                "archive_id": archive_id,
            }
        )

    except Exception as e:
        if not DEMO_MODE:
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor or "unknown",
                success=False,
                error=str(e),
            )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ── Config diff ───────────────────────────────────────────────────────────────


@app.route("/diff", methods=["POST"])
@limiter.limit("30/minute")
def run_diff():
    if "config_a" not in request.files or "config_b" not in request.files:
        return jsonify(
            {"error": "Two config files required (config_a and config_b)"}
        ), 400
    if (
        request.files["config_a"].filename == ""
        or request.files["config_b"].filename == ""
    ):
        return jsonify({"error": "Both config files must be selected"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()

    # Early vendor allowlist check before touching disk.
    if vendor not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor}'."}), 400

    upload_a = request.files["config_a"]
    upload_b = request.files["config_b"]
    suffix_a = Path(upload_a.filename).suffix or ".txt"
    suffix_b = Path(upload_b.filename).suffix or ".txt"
    path_a = _make_temp_path(suffix_a)
    path_b = _make_temp_path(suffix_b)
    upload_a.save(path_a)
    upload_b.save(path_b)

    try:
        # Auto-detect or resolve cisco from the first file if needed
        if vendor in ("auto", "cisco", "asa"):
            with open(path_a, "r", errors="ignore") as f:
                sample = f.read(16384)
            if vendor == "auto":
                vendor = detect_vendor(sample, upload_a.filename) or ""
            else:
                vendor = "ftd" if is_ftd_config(sample) else "asa"

        if vendor not in ALL_VENDORS:
            return jsonify(
                {"error": "Could not determine vendor. Please select one manually."}
            ), 400

        result = diff_configs(vendor, path_a, path_b)
        result["vendor"] = vendor
        result["filename_a"] = upload_a.filename
        result["filename_b"] = upload_b.filename

        log_activity(
            ACTION_CONFIG_DIFF,
            f"{upload_a.filename} → {upload_b.filename}",
            vendor=vendor,
            success=True,
            details={
                "added": len(result.get("added", [])),
                "removed": len(result.get("removed", [])),
                "unchanged": len(result.get("unchanged", [])),
            },
        )
        return jsonify(result)

    except Exception as e:
        log_activity(
            ACTION_CONFIG_DIFF,
            f"{upload_a.filename} → {upload_b.filename}",
            vendor=vendor or "unknown",
            success=False,
            error=str(e),
        )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        for p in (path_a, path_b):
            if os.path.exists(p):
                os.remove(p)


# ── Live SSH connect ──────────────────────────────────────────────────────────


@app.route("/connect", methods=["POST"])
@limiter.limit("10/minute")
def live_connect():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "22").strip() or "22"
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    vendor = request.form.get("vendor", "").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    tag = request.form.get("tag", "").strip() or None

    if not host or not username or not vendor:
        return jsonify({"error": "host, username, and vendor are required"}), 400
    if vendor not in ("asa", "ftd", "cisco", "fortinet", "paloalto"):
        return jsonify(
            {
                "error": f"Live SSH not supported for vendor '{vendor}'. Supported: Cisco, Fortinet, Palo Alto Networks"
            }
        ), 400
    if vendor == "cisco":
        vendor = "asa"

    # PEM key-based auth (optional)
    pem_key_path = None
    pem_passphrase = request.form.get("pem_passphrase", "") or None
    pem_upload = request.files.get("pem_key")
    if pem_upload and pem_upload.filename:
        pem_path = _make_temp_path(".pem")
        pem_upload.save(pem_path)
        try:
            os.chmod(pem_path, 0o600)
        except OSError:
            pass
        pem_key_path = pem_path

    label = f"{vendor.upper()}@{host}"

    try:
        from .ssh_connector import connect_and_pull

        _settings = get_settings()
        temp_path, _ = connect_and_pull(
            vendor,
            host,
            port,
            username,
            password,
            timeout=30,
            upload_folder=UPLOAD_FOLDER,
            host_key_policy=_settings.get("ssh_host_key_policy", "warn"),
            pem_key_path=pem_key_path,
            pem_passphrase=pem_passphrase,
        )
    except Exception as e:
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "port": port},
        )
        return jsonify({"error": f"Connection failed: {e}"}), 500
    finally:
        if pem_key_path and os.path.exists(pem_key_path):
            os.remove(pem_key_path)

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        # Save successful SSH audits to Audit History (store plain strings)
        archive_id, _ = save_audit(
            label,
            vendor,
            _findings_to_strings(findings),
            summary,
            config_path=temp_path,
            tag=tag,
        )

        # Log successful activity
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=True,
            details={
                "host": host,
                "port": port,
                "total": summary.get("total", 0),
                "high": summary.get("high", 0),
            },
        )

        return jsonify(
            {
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "summary": summary,
                "detected_vendor": vendor,
                "host": host,
                "archive_id": archive_id,
            }
        )

    except Exception as e:
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "port": port},
        )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        if "temp_path" in dir() and os.path.exists(temp_path):
            os.remove(temp_path)


# ── Archive API ───────────────────────────────────────────────────────────────


@app.route("/archive", methods=["GET"])
def archive_list():
    return jsonify(list_archive())


@app.route("/archive/save", methods=["POST"])
def archive_save():
    """Manually save the most recent audit result to the archive."""
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "unknown")
    vendor = data.get("vendor", "unknown")
    findings = data.get("findings", [])
    summary = data.get("summary", {})
    tag = data.get("tag")
    if not findings and not summary:
        return jsonify({"error": "No audit data to save"}), 400
    entry_id, entry = save_audit(filename, vendor, findings, summary, tag=tag)
    return jsonify({"id": entry_id, "entry": entry})


@app.route("/archive/<entry_id>", methods=["GET"])
def archive_get(entry_id):
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@app.route("/archive/<entry_id>", methods=["DELETE"])
def archive_delete(entry_id):
    deleted = delete_entry(entry_id)
    return jsonify({"deleted": deleted})


@app.route("/archive/<entry_id>/export", methods=["GET"])
def archive_export(entry_id):
    """Export an archived audit as JSON, CSV, or SARIF.

    Query param: fmt = json | csv | sarif  (default: json)
    """
    from flask import Response

    fmt = request.args.get("fmt", "json").lower()
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404

    base = (entry.get("filename") or "audit").rsplit(".", 1)[0]

    if fmt == "json":
        content, mime, ext = to_json(entry), "application/json", "json"
    elif fmt == "csv":
        content, mime, ext = to_csv(entry), "text/csv", "csv"
    elif fmt == "sarif":
        content, mime, ext = to_sarif(entry), "application/json", "sarif"
    else:
        return jsonify(
            {"error": f"Unknown format '{fmt}'. Use json, csv, or sarif."}
        ), 400

    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f'attachment; filename="{base}_cashel.{ext}"'},
    )


@app.route("/archive/trends", methods=["GET"])
def archive_trends():
    """Return time-series data for score/finding trends grouped by filename.

    Accepts an optional ``limit`` query param (default 200) to cap the number
    of entries returned and avoid scanning unbounded archive directories.
    """
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    entries = list_archive()  # already sorted newest-first
    if limit > 0:
        entries = entries[:limit]
    series = []
    for e in entries:
        s = e.get("summary", {})
        series.append(
            {
                "id": e["id"],
                "filename": e["filename"],
                "vendor": e.get("vendor", ""),
                "timestamp": e.get("timestamp", ""),
                "score": s.get("score"),
                "high": s.get("high", 0),
                "medium": s.get("medium", 0),
                "total": s.get("total", 0),
                "tag": e.get("tag"),
                "version": e.get("version", 1),
            }
        )
    series.sort(key=lambda x: x["timestamp"])
    return jsonify(series)


@app.route("/archive/compare", methods=["POST"])
def archive_compare():
    data = request.get_json(silent=True) or {}
    id_a = data.get("id_a", "")
    id_b = data.get("id_b", "")
    if not id_a or not id_b:
        return jsonify({"error": "id_a and id_b are required"}), 400
    result, error = compare_entries(id_a, id_b)
    if error:
        return jsonify({"error": error}), 404
    return jsonify(result)


# ── Remediation Plan ─────────────────────────────────────────────────────────


@app.route("/remediation-plan", methods=["POST"])
@limiter.limit("30/minute")
def remediation_plan_inline():
    """Generate a remediation plan from inline audit data (POST JSON).

    Expected body: {findings, vendor, filename?, compliance?, summary?}
    Query param: fmt = json | markdown | pdf  (default: json)
    """
    data = request.get_json(silent=True) or {}
    findings = data.get("findings") or data.get("enriched_findings") or []
    vendor = data.get("vendor", "unknown")
    filename = data.get("filename", "")
    compliance = data.get("compliance")
    summary = data.get("summary")

    if not findings:
        return jsonify({"error": "No findings provided."}), 400

    plan = generate_plan(findings, vendor, filename, compliance, summary)
    fmt = request.args.get("fmt", "json").lower()

    if fmt == "json":
        return jsonify(plan)
    elif fmt == "markdown":
        md = plan_to_markdown(plan)
        base = (filename or "audit").rsplit(".", 1)[0]
        return app.response_class(
            md,
            mimetype="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{base}_remediation.md"'
            },
        )
    elif fmt == "pdf":
        report_name = f"remediation_{uuid.uuid4().hex[:8]}.pdf"
        report_path = os.path.join(REPORTS_FOLDER, report_name)
        plan_to_pdf(plan, report_path)
        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{(filename or 'audit').rsplit('.', 1)[0]}_remediation.pdf",
        )
    else:
        return jsonify(
            {"error": f"Unknown format '{fmt}'. Use json, markdown, or pdf."}
        ), 400


@app.route("/archive/<entry_id>/remediation-plan", methods=["GET"])
def archive_remediation_plan(entry_id):
    """Generate a remediation plan from an archived audit.

    Query param: fmt = json | markdown | pdf  (default: json)
    """
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404

    # Archived findings may be strings or enriched dicts
    findings = entry.get("findings", [])
    vendor = entry.get("vendor", "unknown")
    filename = entry.get("filename", "")
    summary = entry.get("summary")

    plan = generate_plan(findings, vendor, filename, summary=summary)
    fmt = request.args.get("fmt", "json").lower()

    if fmt == "json":
        return jsonify(plan)
    elif fmt == "markdown":
        md = plan_to_markdown(plan)
        base = (filename or "audit").rsplit(".", 1)[0]
        return app.response_class(
            md,
            mimetype="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{base}_remediation.md"'
            },
        )
    elif fmt == "pdf":
        report_name = f"remediation_{uuid.uuid4().hex[:8]}.pdf"
        report_path = os.path.join(REPORTS_FOLDER, report_name)
        plan_to_pdf(plan, report_path)
        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{(filename or 'audit').rsplit('.', 1)[0]}_remediation.pdf",
        )
    else:
        return jsonify(
            {"error": f"Unknown format '{fmt}'. Use json, markdown, or pdf."}
        ), 400


# ── Activity Log API ──────────────────────────────────────────────────────────


@app.route("/activity", methods=["GET"])
def activity_list():
    limit = int(request.args.get("limit", 200))
    return jsonify(list_activity(limit=limit))


@app.route("/activity/<event_id>", methods=["DELETE"])
def activity_delete(event_id):
    deleted = delete_activity_entry(event_id)
    return jsonify({"deleted": deleted})


@app.route("/activity/clear", methods=["POST"])
def activity_clear():
    count = clear_activity()
    return jsonify({"cleared": count})


# ── Bulk audit ────────────────────────────────────────────────────────────────


@app.route("/bulk_audit", methods=["POST"])
@limiter.limit("10/minute")
def bulk_audit():
    """Audit multiple config files in one request.

    Accepts: multipart/form-data with repeated field ``configs[]``.
    Optional shared fields: vendor (default auto), compliance, archive (1/0), tag.
    Returns: JSON list of per-file result objects.
    """
    uploads = request.files.getlist("configs[]")
    if not uploads or all(u.filename == "" for u in uploads):
        return jsonify({"error": "No config files uploaded"}), 400

    vendor_override = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    archive_it = request.form.get("archive") == "1"
    tag_prefix = request.form.get("tag", "").strip() or None

    # Early allowlist checks before processing any files.
    if vendor_override not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor_override}'."}), 400
    from .schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return jsonify({"error": f"Unknown compliance framework '{compliance}'."}), 400

    results = []

    for upload in uploads:
        if upload.filename == "":
            continue

        suffix = Path(upload.filename).suffix or ".txt"
        temp_path = _make_temp_path(suffix)
        upload.save(temp_path)

        result_entry = {
            "filename": upload.filename,
            "status": "error",
            "findings": [],
            "summary": {},
            "vendor": None,
            "archive_id": None,
            "error": None,
        }

        try:
            with open(temp_path, "r", errors="ignore") as f:
                sample = f.read(16384)

            vendor = vendor_override
            if vendor == "auto":
                vendor = detect_vendor(sample, upload.filename) or ""

            if vendor not in ALL_VENDORS:
                result_entry["error"] = "Could not determine vendor"
                results.append(result_entry)
                continue

            if vendor == "asa" and is_ftd_config(sample):
                vendor = "ftd"

            is_valid, validation_msg = validate_vendor_format(
                sample, upload.filename, vendor
            )
            if not is_valid:
                result_entry["error"] = validation_msg
                results.append(result_entry)
                continue

            findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

            if compliance and vendor not in (
                "aws",
                "azure",
                "gcp",
                "iptables",
                "nftables",
            ):
                licensed, _ = check_license()
                if licensed:
                    raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                    findings += [_wrap_compliance(c) for c in raw]

            findings = _sort_findings(findings)
            summary = _build_summary(findings)

            archive_id = None
            if archive_it:
                tag = (
                    f"{tag_prefix}/{upload.filename}" if tag_prefix else upload.filename
                )
                archive_id, _ = save_audit(
                    upload.filename,
                    vendor,
                    _findings_to_strings(findings),
                    summary,
                    config_path=temp_path,
                    tag=tag,
                )

            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor,
                success=True,
                details={
                    "bulk": True,
                    "total": summary.get("total", 0),
                    "high": summary.get("high", 0),
                    "archived": archive_id is not None,
                },
            )

            result_entry.update(
                {
                    "status": "ok",
                    "vendor": vendor,
                    "findings": _findings_to_strings(findings),
                    "enriched_findings": findings,
                    "summary": summary,
                    "archive_id": archive_id,
                }
            )

        except Exception as e:
            result_entry["error"] = str(e)
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor_override,
                success=False,
                error=str(e),
                details={"bulk": True},
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        results.append(result_entry)

    return jsonify(results)


# ── Scheduled audits API ───────────────────────────────────────────────────────


@app.route("/schedules", methods=["GET"])
def schedules_list():
    if DEMO_MODE:
        return jsonify(_DEMO_SCHEDULES)
    return jsonify(list_schedules())


@app.route("/schedules", methods=["POST"])
def schedules_create():
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    if not data.get("host") or not data.get("username"):
        return jsonify({"error": "host and username are required"}), 400
    try:
        schedule = create_schedule(data)
    except ScheduleValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    reload_job(schedule["id"], get_schedule(schedule["id"], include_password=True))
    return jsonify(schedule), 201


@app.route("/schedules/<schedule_id>", methods=["GET"])
def schedules_get(schedule_id):
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    return jsonify(schedule)


@app.route("/schedules/<schedule_id>", methods=["PUT"])
def schedules_update(schedule_id):
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    try:
        schedule = update_schedule(schedule_id, data)
    except ScheduleValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    reload_job(schedule_id, get_schedule(schedule_id, include_password=True))
    return jsonify(schedule)


@app.route("/schedules/<schedule_id>", methods=["DELETE"])
def schedules_delete(schedule_id):
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    deleted = delete_schedule(schedule_id)
    if deleted:
        reload_job(schedule_id, None)  # removes the job from the scheduler
    return jsonify({"deleted": deleted})


@app.route("/schedules/<schedule_id>/run", methods=["POST"])
def schedules_run_now(schedule_id):
    """Trigger an immediate on-demand run of a scheduled audit."""
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    scheduler_run_now(schedule_id)
    return jsonify({"queued": True, "id": schedule_id})


@app.route("/schedules/status", methods=["GET"])
def schedules_status():
    return jsonify({"scheduler_available": scheduler_available()})


# ── Reports / License ─────────────────────────────────────────────────────────


@app.route("/reports", methods=["GET"])
def reports_list():
    """List all saved PDF reports."""
    reports = []
    for fname in sorted(os.listdir(REPORTS_FOLDER), reverse=True):
        if fname.endswith(".pdf"):
            path = os.path.join(REPORTS_FOLDER, fname)
            reports.append(
                {
                    "filename": fname,
                    "size": os.path.getsize(path),
                    "mtime": os.path.getmtime(path),
                }
            )
    return jsonify(reports)


def _safe_report_path(filename):
    """Resolve a report filename and verify it stays inside REPORTS_FOLDER."""
    path = os.path.realpath(os.path.join(REPORTS_FOLDER, filename))
    if not path.startswith(os.path.realpath(REPORTS_FOLDER) + os.sep):
        return None
    if not os.path.exists(path):
        return None
    return path


@app.route("/reports/<filename>")
def download_report(filename):
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/reports/<filename>/view")
def view_report(filename):
    """Serve PDF inline for in-browser viewing."""
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=False, mimetype="application/pdf")


@app.route("/license/activate", methods=["POST"])
def license_activate():
    key = request.form.get("key", "").strip()
    success, message = activate_license(key)
    return jsonify({"success": success, "message": message})


@app.route("/license/deactivate", methods=["POST"])
def license_deactivate():
    success, message = deactivate_license()
    return jsonify({"success": success, "message": message})


@app.route("/license/status")
def license_status():
    licensed, info = check_license()
    return jsonify({"licensed": licensed, "info": info})


# ── Settings API ──────────────────────────────────────────────────────────────


@app.route("/settings", methods=["GET"])
def settings_get():
    s = get_settings()
    # Never expose the plaintext API key over the wire — return masked hint only
    raw_key = s.pop("api_key", "")
    s["api_key_set"] = bool(raw_key)
    s["api_key_hint"] = (
        ("csh_…" + raw_key[-4:]) if len(raw_key) >= 4 else ("set" if raw_key else "")
    )
    return jsonify(s)


@app.route("/settings", methods=["POST"])
def settings_save():
    if DEMO_MODE:
        return jsonify({"error": "Settings cannot be saved in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    saved = save_settings(data)
    # Reconfigure syslog immediately when settings are changed.
    configure_syslog(saved)
    saved.pop("api_key", None)
    return jsonify(saved)


@app.route("/settings/generate-api-key", methods=["POST"])
def settings_generate_api_key():
    """Generate a new random API key, store it encrypted, and return it once in plaintext.
    The caller must copy and store the key immediately — it cannot be retrieved again.
    """
    new_key = "csh_" + secrets.token_urlsafe(32)
    save_api_key(new_key)
    hint = ("csh_…" + new_key[-4:]) if len(new_key) >= 4 else ""
    return jsonify({"ok": True, "api_key": new_key, "api_key_hint": hint})


@app.route("/settings/test-smtp", methods=["POST"])
def settings_test_smtp():
    """Attempt a live SMTP connection and send a test email.

    Accepts the same SMTP fields as /settings POST so the user can test
    before saving.  Returns {ok: bool, message: str}.
    """
    if DEMO_MODE:
        return jsonify({"ok": False, "message": "SMTP is disabled in demo mode."}), 403
    import smtplib
    import ssl
    from email.mime.text import MIMEText

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


# ── REST API v1 (CI/CD integration) ───────────────────────────────────────────
# Blueprint registered above; CSRF exempt — authenticated via X-API-Key header.
# All responses use the envelope: {"ok": bool, "data": ..., "error": str|null}


def _api_ok(data):
    return jsonify({"ok": True, "data": data, "error": None})


def _api_err(message, status=400):
    return jsonify({"ok": False, "data": None, "error": message}), status


@api_bp.route("/audit", methods=["POST"])
@limiter.limit("30/minute")
def api_audit():
    """POST /api/v1/audit — audit a config file, returns findings + summary."""
    if "config" not in request.files or not request.files["config"].filename:
        return _api_err("config file is required")

    vendor = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    archive_it = request.form.get("archive", "1") == "1"
    tag = request.form.get("tag", "").strip() or None

    if vendor not in ("auto", *ALL_VENDORS):
        return _api_err(f"Unknown vendor '{vendor}'.")

    from .schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return _api_err(f"Unknown compliance framework '{compliance}'.")

    upload = request.files["config"]
    upload.seek(0, 2)
    if upload.tell() > _MAX_FILE_BYTES:
        return _api_err("File exceeds the 5 MB per-file limit.", 413)
    upload.seek(0)

    suffix = Path(upload.filename).suffix or ".txt"
    temp_path = _make_temp_path(suffix)
    upload.save(temp_path)

    try:
        sample = open(temp_path, encoding="utf-8", errors="ignore").read(4096)

        if vendor in ("auto", "cisco"):
            detected = detect_vendor(sample, upload.filename)
            if vendor == "auto":
                if not detected:
                    return _api_err(
                        "Could not auto-detect vendor. Specify vendor explicitly."
                    )
                vendor = detected
            elif vendor == "cisco":
                vendor = "ftd" if is_ftd_config(sample) else "asa"
        elif vendor == "asa" and is_ftd_config(sample):
            vendor = "ftd"

        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)
        archive_id = None
        if archive_it:
            archive_id, _ = save_audit(
                upload.filename,
                vendor,
                _findings_to_strings(findings),
                summary,
                config_path=temp_path,
                tag=tag,
            )

        return _api_ok(
            {
                "archive_id": archive_id,
                "vendor": vendor,
                "summary": summary,
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "detected_hostname": extract_hostname(vendor, sample),
            }
        )
    except Exception as e:
        return _api_err(_err(e, "Audit failed."), 500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@api_bp.route("/audit/<entry_id>", methods=["GET"])
def api_audit_get(entry_id):
    """GET /api/v1/audit/<id> — retrieve a specific archived audit result."""
    entry = get_entry(entry_id)
    if not entry:
        return _api_err("Audit not found.", 404)
    return _api_ok(entry)


@api_bp.route("/audit/<entry_id>/remediation-plan", methods=["GET"])
def api_remediation_plan(entry_id):
    """GET /api/v1/audit/<id>/remediation-plan — generate remediation plan.

    Query param: fmt = json | markdown  (default: json)
    """
    entry = get_entry(entry_id)
    if not entry:
        return _api_err("Audit not found.", 404)

    findings = entry.get("findings", [])
    vendor = entry.get("vendor", "unknown")
    filename = entry.get("filename", "")
    summary = entry.get("summary")

    plan = generate_plan(findings, vendor, filename, summary=summary)
    fmt = request.args.get("fmt", "json").lower()

    if fmt == "json":
        return _api_ok(plan)
    elif fmt == "markdown":
        return _api_ok({"markdown": plan_to_markdown(plan)})
    else:
        return _api_err(f"Unknown format '{fmt}'. Use json or markdown.", 400)


@api_bp.route("/history", methods=["GET"])
def api_history():
    """GET /api/v1/history — list audit history (metadata only, no findings)."""
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except (ValueError, TypeError):
        limit = 50
    vendor_filter = request.args.get("vendor", "").strip().lower() or None
    tag_filter = request.args.get("tag", "").strip() or None

    entries = list_archive()
    if vendor_filter:
        entries = [e for e in entries if e.get("vendor") == vendor_filter]
    if tag_filter:
        entries = [e for e in entries if e.get("tag") == tag_filter]
    entries = entries[:limit]

    # Strip bulky findings list from history response
    slim = [{k: v for k, v in e.items() if k != "findings"} for e in entries]
    return _api_ok(slim)


@api_bp.route("/diff", methods=["POST"])
@limiter.limit("30/minute")
def api_diff():
    """POST /api/v1/diff — compare two config files."""
    if "config_a" not in request.files or "config_b" not in request.files:
        return _api_err("config_a and config_b files are required.")

    vendor = request.form.get("vendor", "auto").strip().lower()
    if vendor not in ("auto", *ALL_VENDORS):
        return _api_err(f"Unknown vendor '{vendor}'.")

    paths = []
    try:
        for field in ("config_a", "config_b"):
            f = request.files[field]
            suffix = Path(f.filename).suffix or ".txt"
            p = _make_temp_path(suffix)
            f.save(p)
            paths.append(p)

        path_a, path_b = paths
        sample_a = open(path_a, encoding="utf-8", errors="ignore").read(4096)

        if vendor in ("auto", "cisco"):
            detected = detect_vendor(sample_a, request.files["config_a"].filename)
            vendor = (
                detected
                if vendor == "auto" and detected
                else (
                    ("ftd" if is_ftd_config(sample_a) else "asa")
                    if vendor == "cisco"
                    else (detected or "asa")
                )
            )
        elif vendor == "asa" and is_ftd_config(sample_a):
            vendor = "ftd"

        result = diff_configs(vendor, path_a, path_b)
        return _api_ok(result)
    except Exception as e:
        return _api_err(_err(e, "Diff failed."), 500)
    finally:
        for p in paths:
            if os.path.exists(p):
                os.remove(p)


app.register_blueprint(api_bp)


# Start scheduler on import — covers both WSGI servers (gunicorn/uwsgi)
# and direct `cashel-web` invocation. When running under gunicorn with
# multiple workers, only the first worker starts the scheduler (the others
# have CASHEL_SKIP_SCHEDULER=1 set by gunicorn.conf.py).
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
