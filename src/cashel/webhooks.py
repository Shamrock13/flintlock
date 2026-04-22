"""Generic outbound webhook event system.

Supports CRUD management of webhook endpoints and fire-and-forget
delivery of structured event payloads.  Delivery errors are logged to
the activity table and never raised to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import crypto
from .db import get_conn

logger = logging.getLogger(__name__)

VALID_EVENTS = {"audit.complete", "alert.threshold_breach", "alert.threshold_clear"}

# Private / reserved network ranges — same list as notify.py.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# ── URL validation ─────────────────────────────────────────────────────────────


def _validate_url(url: str) -> tuple[bool, str]:
    """Validate a webhook URL to prevent SSRF.

    Rules:
    1. Scheme must be ``https``.
    2. If the hostname resolves to a private/reserved IP it is rejected.

    Unlike notify.py (which has a per-service allowlist), outbound webhooks
    are general-purpose and only enforce the HTTPS + private-IP rules.

    Returns ``(is_valid, error_message)``.
    """
    if not url:
        return False, "Webhook URL is empty."

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Webhook URL could not be parsed."

    if parsed.scheme != "https":
        return False, "Webhook URL must use HTTPS."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False, "Webhook URL has no hostname."

    try:
        infos = socket.getaddrinfo(hostname, None)
        for _fam, _type, _proto, _canon, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if any(ip in net for net in _PRIVATE_NETS):
                return False, (
                    f"Webhook URL resolves to a private/reserved address ({ip}) "
                    "and cannot be used."
                )
    except socket.gaierror:
        # DNS failure — let the actual HTTP request fail.
        pass

    return True, ""


# ── CRUD ───────────────────────────────────────────────────────────────────────


def _row_to_dict(row) -> dict:
    """Convert a DB row to a webhook dict with decrypted URL/secret."""
    d = dict(row)
    d["url"] = crypto.decrypt(d.pop("url_enc", "") or "")
    raw_secret = d.pop("secret_enc", "") or ""
    d["secret"] = crypto.decrypt(raw_secret) if raw_secret else ""
    d["events"] = json.loads(d["events"]) if d.get("events") else []
    d["enabled"] = bool(d["enabled"])
    return d


def list_webhooks() -> list[dict]:
    """Return all webhook rows with URLs and secrets decrypted."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
    return [_row_to_dict(row) for row in rows]


def get_webhook(webhook_id: str) -> dict | None:
    """Return a single webhook by id, or None."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone()
    return _row_to_dict(row) if row else None


def add_webhook(
    name: str,
    url: str,
    events: list[str],
    secret: str | None = None,
) -> dict:
    """Validate, encrypt, and insert a new webhook.  Returns the saved row."""
    valid, reason = _validate_url(url)
    if not valid:
        raise ValueError(reason)

    # Normalise events list
    events = [e for e in events if e in VALID_EVENTS]
    if not events:
        raise ValueError(f"events must include at least one of {sorted(VALID_EVENTS)}")

    webhook_id = secrets.token_hex(8)
    url_enc = crypto.encrypt(url)
    secret_enc = crypto.encrypt(secret) if secret else ""
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO webhooks (id, name, url_enc, events, secret_enc, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (webhook_id, name, url_enc, json.dumps(events), secret_enc, created_at),
    )
    conn.commit()
    result = get_webhook(webhook_id)
    assert result is not None
    return result


def update_webhook(webhook_id: str, **kwargs) -> dict:
    """Partial update of a webhook.  Returns the updated row."""
    existing = get_webhook(webhook_id)
    if existing is None:
        raise KeyError(f"Webhook {webhook_id!r} not found.")

    updates: dict[str, object] = {}

    if "name" in kwargs:
        updates["name"] = kwargs["name"]

    if "url" in kwargs:
        valid, reason = _validate_url(kwargs["url"])
        if not valid:
            raise ValueError(reason)
        updates["url_enc"] = crypto.encrypt(kwargs["url"])

    if "events" in kwargs:
        events = [e for e in kwargs["events"] if e in VALID_EVENTS]
        if not events:
            raise ValueError(
                f"events must include at least one of {sorted(VALID_EVENTS)}"
            )
        updates["events"] = json.dumps(events)

    if "secret" in kwargs:
        updates["secret_enc"] = (
            crypto.encrypt(kwargs["secret"]) if kwargs["secret"] else ""
        )

    if "enabled" in kwargs:
        updates["enabled"] = 1 if kwargs["enabled"] else 0

    if not updates:
        return existing

    set_clause = ", ".join(f"{col} = ?" for col in updates)
    conn = get_conn()
    conn.execute(
        f"UPDATE webhooks SET {set_clause} WHERE id = ?",
        [*updates.values(), webhook_id],
    )
    conn.commit()
    result = get_webhook(webhook_id)
    assert result is not None
    return result


def delete_webhook(webhook_id: str) -> None:
    """Delete a webhook by id."""
    conn = get_conn()
    conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    conn.commit()


# ── Delivery ───────────────────────────────────────────────────────────────────


def _build_payload(event_type: str, data: dict) -> bytes:
    from .export import TOOL_VERSION

    envelope = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cashel_version": TOOL_VERSION,
        "data": data,
    }
    return json.dumps(envelope).encode("utf-8")


def _sign(body: bytes, secret: str) -> str:
    """Return ``sha256=<hex>`` HMAC-SHA256 signature."""
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _post(url: str, body: bytes, secret: str | None) -> tuple[bool, str]:
    """POST *body* to *url*.  Returns (success, detail)."""
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if secret:
        headers["X-Cashel-Signature"] = _sign(body, secret)

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
        return True, f"HTTP {status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} {exc.reason}"
    except urllib.error.URLError as exc:
        return False, f"URLError: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def dispatch_event(event_type: str, data: dict) -> None:
    """Fire-and-forget delivery of *event_type* to all matching enabled webhooks.

    Results (success/failure) are logged to the ``activity`` table.
    This function never raises.
    """
    from .activity_log import log_activity

    try:
        conn = get_conn()
        rows = conn.execute("SELECT * FROM webhooks WHERE enabled = 1").fetchall()
    except Exception as exc:  # noqa: BLE001
        logger.error("dispatch_event: failed to load webhooks: %s", exc)
        return

    body = _build_payload(event_type, data)

    for row in rows:
        try:
            wh = _row_to_dict(row)
        except Exception as exc:  # noqa: BLE001
            logger.warning("dispatch_event: failed to decode webhook row: %s", exc)
            continue

        if event_type not in wh.get("events", []):
            continue

        url = wh.get("url", "")
        secret = wh.get("secret") or None
        webhook_id = wh.get("id", "")

        try:
            success, detail = _post(url, body, secret)
        except Exception as exc:  # noqa: BLE001
            success, detail = False, str(exc)

        try:
            log_activity(
                "webhook_dispatch",
                label=url,
                vendor="",
                success=success,
                error="" if success else detail,
                details={
                    "webhook_id": webhook_id,
                    "event_type": event_type,
                    "detail": detail,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("dispatch_event: failed to log activity: %s", exc)

        if success:
            logger.info(
                "Webhook %s dispatched event %r: %s", webhook_id, event_type, detail
            )
        else:
            logger.warning(
                "Webhook %s failed for event %r: %s", webhook_id, event_type, detail
            )
