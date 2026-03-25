"""Global application settings — persisted as JSON.

SMTP passwords and API keys are encrypted at rest using Fernet (see crypto.py).
Legacy plaintext passwords are transparently migrated on next save.
"""

import json
import os

from .crypto import encrypt, decrypt

_DEFAULT_SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".config", "cashel")
_DEFAULT_SETTINGS_FILE = os.path.join(_DEFAULT_SETTINGS_DIR, "settings.json")
SETTINGS_FILE = os.environ.get("SETTINGS_FILE", _DEFAULT_SETTINGS_FILE)

# Valid values for enumerated security settings.
VALID_SSH_KEY_POLICIES = ("warn", "strict", "auto_add")
VALID_ERROR_DETAIL = ("sanitized", "full")
VALID_SYSLOG_PROTOCOLS = ("udp", "tcp")
VALID_SYSLOG_FACILITIES = (
    "kernel",
    "user",
    "daemon",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)

DEFAULTS: dict = {
    # ── General ───────────────────────────────────────────────────────────────
    "auto_pdf": False,
    "auto_archive": False,
    "default_compliance": "",
    # ── SMTP (scheduled-audit email alerts) ───────────────────────────────────
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_tls": True,
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
    # ── Authentication ────────────────────────────────────────────────────────
    # When auth_enabled is True, all web UI and API routes require the API key.
    # The key is stored encrypted (api_key_enc) and never shown after first
    # generation — treat it like a password.  Session lifetime controls how long
    # a browser login is valid (sliding window).
    "auth_enabled": False,
    "session_lifetime_minutes": 480,  # 8 hours default
    # ── Syslog ────────────────────────────────────────────────────────────────
    # Forward application events to a remote syslog server for SIEM integration.
    # Protocol: "udp" (RFC 3164, default) or "tcp" (reliable delivery).
    # Facility: LOCAL0–LOCAL7, DAEMON, USER.
    "syslog_enabled": False,
    "syslog_host": "localhost",
    "syslog_port": 514,
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
        # Decrypt api_key — stored encrypted, never exposed to the template directly
        merged["api_key"] = (
            decrypt(data["api_key_enc"]) if data.get("api_key_enc") else ""
        )
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
    merged.pop("smtp_password", None)

    # api_key is managed separately via /settings/generate-api-key; never passed
    # through save_settings (it would be overwritten to empty on every settings save).
    # Remove it from the dict — the encrypted api_key_enc is preserved from disk.
    merged.pop("api_key", None)

    # Preserve existing api_key_enc from disk if not being explicitly updated
    try:
        with open(SETTINGS_FILE) as _f:
            _existing = json.load(_f)
        if _existing.get("api_key_enc") and "api_key_enc" not in merged:
            merged["api_key_enc"] = _existing["api_key_enc"]
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(merged, f, indent=2)

    # Return with decrypted values so callers get the expected keys
    merged["smtp_password"] = smtp_pw
    return merged


def save_api_key(plaintext_key: str) -> None:
    """Encrypt and persist the API key. Separate from save_settings so it is
    never accidentally overwritten by a settings form submission."""
    from .crypto import encrypt as _enc

    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data["api_key_enc"] = _enc(plaintext_key)
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)
