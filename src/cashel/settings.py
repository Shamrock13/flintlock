"""Global application settings — persisted as JSON.

SMTP passwords are encrypted at rest using Fernet (see crypto.py).
Legacy plaintext passwords are transparently migrated on next save.

SECURITY ROADMAP NOTES
━━━━━━━━━━━━━━━━━━━━━━
Phase 2 — API Key Authentication (pending):
  Keys to add: ``auth_enabled`` (bool), ``api_key_hash`` (bcrypt/scrypt hash of
  the admin key), ``session_lifetime_minutes`` (int).
"""
import json
import os

from .crypto import encrypt, decrypt

SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "/tmp/cashel_settings/settings.json")

# Valid values for enumerated security settings.
VALID_SSH_KEY_POLICIES  = ("warn", "strict", "auto_add")
VALID_ERROR_DETAIL      = ("sanitized", "full")
VALID_SYSLOG_PROTOCOLS  = ("udp", "tcp")
VALID_SYSLOG_FACILITIES = (
    "kernel", "user", "daemon",
    "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
)

DEFAULTS: dict = {
    # ── General ───────────────────────────────────────────────────────────────
    "auto_pdf":           False,
    "auto_archive":       False,
    "default_compliance": "",

    # ── SMTP (scheduled-audit email alerts) ───────────────────────────────────
    "smtp_host":     "",
    "smtp_port":     587,
    "smtp_user":     "",
    "smtp_password": "",
    "smtp_from":     "",
    "smtp_tls":      True,

    # ── Security — SSH ────────────────────────────────────────────────────────
    # Controls how unknown SSH host keys are handled for Live Connect audits.
    # "warn"     → log a warning and proceed (default; balances usability + visibility)
    # "strict"   → reject connections to hosts not in known_hosts (most secure)
    # "auto_add" → silently accept any host key (insecure; lab use only)
    "ssh_host_key_policy": "warn",

    # ── Security — Webhooks ───────────────────────────────────────────────────
    # Comma-separated list of extra hostname suffixes allowed as webhook targets,
    # in addition to the built-in allowlist (hooks.slack.com, webhook.office.com,
    # discord.com).  Example: "webhooks.mycorp.com, hooks.internal.net"
    "webhook_allowlist": "",

    # ── Security — Error detail ───────────────────────────────────────────────
    # "sanitized" → return generic messages to the browser (production default)
    # "full"      → return raw exception text (development only)
    "error_detail": "sanitized",

    # ── Syslog ────────────────────────────────────────────────────────────────
    # Forward application events to a remote syslog server for SIEM integration.
    # Protocol: "udp" (RFC 3164, default) or "tcp" (reliable delivery).
    # Facility: LOCAL0–LOCAL7, DAEMON, USER.
    "syslog_enabled":  False,
    "syslog_host":     "localhost",
    "syslog_port":     514,
    "syslog_protocol": "udp",
    "syslog_facility": "local0",
}


def get_settings() -> dict:
    """Return current settings merged with defaults (so new keys always present)."""
    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
        merged = {**DEFAULTS, **{k: data[k] for k in DEFAULTS if k in data}}
        # Decrypt smtp_password — stored encrypted, exposed in-process as plaintext
        if data.get("smtp_password_enc"):
            merged["smtp_password"] = decrypt(data["smtp_password_enc"])
        return merged
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULTS)


def save_settings(data: dict) -> dict:
    """Persist settings. Unknown keys are ignored. Returns the saved dict."""
    merged = {}
    for k, default in DEFAULTS.items():
        merged[k] = data.get(k, default)

    # Validate enumerated fields before persisting.
    if merged["ssh_host_key_policy"] not in VALID_SSH_KEY_POLICIES:
        merged["ssh_host_key_policy"] = "warn"
    if merged["error_detail"] not in VALID_ERROR_DETAIL:
        merged["error_detail"] = "sanitized"
    if merged["syslog_protocol"] not in VALID_SYSLOG_PROTOCOLS:
        merged["syslog_protocol"] = "udp"
    if merged["syslog_facility"] not in VALID_SYSLOG_FACILITIES:
        merged["syslog_facility"] = "local0"
    try:
        merged["syslog_port"] = int(merged["syslog_port"])
        if not 1 <= merged["syslog_port"] <= 65535:
            merged["syslog_port"] = 514
    except (TypeError, ValueError):
        merged["syslog_port"] = 514

    # Encrypt smtp_password before persisting; store under smtp_password_enc
    smtp_pw = merged.pop("smtp_password", "")
    if smtp_pw:
        merged["smtp_password_enc"] = encrypt(smtp_pw)
    elif "smtp_password_enc" not in merged:
        merged["smtp_password_enc"] = ""
    # Don't store plaintext password key in the file
    merged.pop("smtp_password", None)

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(merged, f, indent=2)

    # Return with decrypted password so callers get the expected key
    merged["smtp_password"] = smtp_pw
    return merged
