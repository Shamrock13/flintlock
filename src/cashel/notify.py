"""Alert notifications for scheduled audits.

Supports two channels — Slack (incoming webhook) and email (SMTP).
Both functions are fire-and-forget: they log errors but never raise, so a
misconfigured webhook or SMTP server cannot crash the background scheduler.
"""

import ipaddress
import json
import logging
import smtplib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ── Webhook SSRF protection ───────────────────────────────────────────────────

# Built-in safe webhook hostname suffixes. Additional domains may be added via
# the webhook_allowlist setting (comma-separated).
_DEFAULT_WEBHOOK_DOMAINS: tuple[str, ...] = (
    "hooks.slack.com",
    "webhook.office.com",  # Microsoft Teams
    "discord.com",
    "discordapp.com",
)

# Private / reserved network ranges that must never be webhook targets.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS IMDS
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # ULA IPv6
    ipaddress.ip_network("fe80::/10"),  # link-local IPv6
]


def _host_matches(host: str, pattern: str) -> bool:
    """Return True if *host* equals *pattern* or is a subdomain of it."""
    host = host.lower()
    pattern = pattern.lower().lstrip("*.")
    return host == pattern or host.endswith("." + pattern)


def validate_webhook_url(
    url: str, extra_domains: list[str] | None = None
) -> tuple[bool, str]:
    """Validate a webhook URL to prevent SSRF.

    Rules enforced:
    1. Scheme must be ``https``.
    2. Hostname must match an entry in the built-in or settings-supplied allowlist.
    3. If the hostname resolves to a private/reserved IP it is rejected.

    Returns ``(is_valid, error_message)``.  ``error_message`` is empty on success.
    """
    if not url:
        return False, "Webhook URL is empty."

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Webhook URL could not be parsed."

    if parsed.scheme != "https":
        return False, "Webhook URL must use HTTPS (not HTTP or other schemes)."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False, "Webhook URL has no hostname."

    allowed = list(_DEFAULT_WEBHOOK_DOMAINS) + [
        d.strip() for d in (extra_domains or []) if d.strip()
    ]
    if not any(_host_matches(hostname, d) for d in allowed):
        return (
            False,
            f"Webhook host '{hostname}' is not in the allowed domains list. "
            f"Add it to Settings → Security → Allowed Webhook Domains.",
        )

    # Resolve hostname and block private/reserved IPs (best-effort; DNS
    # rebinding is mitigated by the allowlist check above).
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
        # DNS failure — let the actual HTTP request fail; don't block valid URLs
        # just because DNS is temporarily unavailable.
        pass

    return True, ""


# Maximum number of individual HIGH findings shown in an alert message.
_MAX_FINDINGS_IN_ALERT = 5


# ── Message helpers ───────────────────────────────────────────────────────────


def _top_high_findings(
    findings: list, limit: int = _MAX_FINDINGS_IN_ALERT
) -> list[str]:
    """Return up to *limit* plain-string HIGH findings."""
    highs = [
        (f.get("message") or f) if isinstance(f, dict) else f
        for f in findings
        if "[HIGH]" in (f.get("message", "") if isinstance(f, dict) else f)
    ]
    return [str(h) for h in highs[:limit]]


def _audit_subject(schedule: dict, summary: dict, error: str | None) -> str:
    vendor = (schedule.get("vendor") or "device").upper()
    host = schedule.get("host") or "unknown"
    label = f"{vendor}@{host}"
    if error:
        return f"[Cashel] ❌ Audit error on {label}"
    high = summary.get("high", 0)
    if high:
        return f"[Cashel] 🔥 {high} HIGH finding(s) on {label}"
    return f"[Cashel] ✅ Audit complete — {label} (no HIGH findings)"


def _audit_body_text(
    schedule: dict, summary: dict, findings: list, error: str | None
) -> str:
    """Return a plain-text body suitable for email or Slack fallback."""
    vendor = (schedule.get("vendor") or "device").upper()
    host = schedule.get("host") or "unknown"
    tag = schedule.get("tag") or ""
    label = f"{vendor}@{host}" + (f" [{tag}]" if tag else "")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"Cashel Scheduled Audit — {label}",
        f"Completed: {now}",
        "",
    ]

    if error:
        lines += [f"ERROR: {error}", ""]
    else:
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = summary.get("total", 0)
        lines += [
            f"Summary: {total} finding(s) — {high} HIGH · {med} MEDIUM · {low} LOW",
            "",
        ]
        highs = _top_high_findings(findings)
        if highs:
            lines.append("Top HIGH findings:")
            for h in highs:
                lines.append(f"  • {h}")
            extra = summary.get("high", 0) - len(highs)
            if extra > 0:
                lines.append(f"  … and {extra} more HIGH finding(s)")
            lines.append("")
        elif total == 0:
            lines.append("✅ No issues found.")
            lines.append("")

    lines.append("— Cashel Firewall Auditor")
    return "\n".join(lines)


# ── Slack ─────────────────────────────────────────────────────────────────────


def send_slack(
    webhook_url: str,
    schedule: dict,
    summary: dict,
    findings: list,
    error: str | None = None,
    extra_webhook_domains: list[str] | None = None,
) -> None:
    """POST an audit alert to a Slack incoming webhook.

    Uses urllib so there is no external dependency.  Fails silently on error.
    The *extra_webhook_domains* list is taken from Settings → Security and
    allows organisations to use self-hosted webhook receivers.
    """
    if not webhook_url:
        return

    valid, reason = validate_webhook_url(webhook_url, extra_webhook_domains)
    if not valid:
        logger.warning(
            "Slack alert blocked for schedule %s — invalid webhook URL: %s",
            schedule.get("id"),
            reason,
        )
        return

    vendor = (schedule.get("vendor") or "device").upper()
    host = schedule.get("host") or "unknown"
    tag = schedule.get("tag") or ""
    label = f"{vendor}@{host}" + (f" [{tag}]" if tag else "")

    if error:
        text = f":x: *Cashel audit error* — {label}\n```{error}```"
    else:
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = summary.get("total", 0)
        icon = ":fire:" if high else ":white_check_mark:"
        text = (
            f"{icon} *Cashel audit complete* — {label}\n"
            f"*{total} finding(s): {high} HIGH · {med} MEDIUM · {low} LOW*"
        )
        highs = _top_high_findings(findings)
        if highs:
            text += "\n\n*Top HIGH findings:*\n" + "\n".join(f"• {h}" for h in highs)
            extra = summary.get("high", 0) - len(highs)
            if extra > 0:
                text += f"\n_…and {extra} more_"

    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
        logger.info("Slack alert sent for schedule %s", schedule.get("id"))
    except urllib.error.URLError as exc:
        logger.warning(
            "Slack alert failed for schedule %s: %s", schedule.get("id"), exc
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Slack alert unexpected error for schedule %s: %s", schedule.get("id"), exc
        )


# ── Email ─────────────────────────────────────────────────────────────────────


def send_email(
    to_address: str,
    schedule: dict,
    summary: dict,
    findings: list,
    smtp_cfg: dict,
    error: str | None = None,
) -> None:
    """Send an audit alert email via SMTP.

    *smtp_cfg* keys: smtp_host, smtp_port (int), smtp_user, smtp_password,
    smtp_from, smtp_tls (bool).  Fails silently on any error.
    """
    if not to_address:
        return

    smtp_host = (smtp_cfg.get("smtp_host") or "").strip()
    if not smtp_host:
        logger.warning("Email alert skipped: smtp_host not configured.")
        return

    smtp_port = int(smtp_cfg.get("smtp_port") or 587)
    smtp_user = (smtp_cfg.get("smtp_user") or "").strip()
    smtp_password = smtp_cfg.get("smtp_password") or ""
    smtp_from = (smtp_cfg.get("smtp_from") or smtp_user or "cashel@localhost").strip()
    use_tls = bool(smtp_cfg.get("smtp_tls", True))

    subject = _audit_subject(schedule, summary, error)
    body = _audit_body_text(schedule, summary, findings, error)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_address

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_address], msg.as_string())
        logger.info(
            "Email alert sent to %s for schedule %s", to_address, schedule.get("id")
        )
    except smtplib.SMTPException as exc:
        logger.warning(
            "Email alert SMTP error for schedule %s: %s", schedule.get("id"), exc
        )
    except OSError as exc:
        logger.warning(
            "Email alert connection error for schedule %s: %s", schedule.get("id"), exc
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Email alert unexpected error for schedule %s: %s", schedule.get("id"), exc
        )


# ── Microsoft Teams ───────────────────────────────────────────────────────────


def send_teams(
    webhook_url: str,
    schedule: dict,
    summary: dict,
    findings: list,
    error: str | None = None,
    extra_webhook_domains: list[str] | None = None,
) -> None:
    """POST an audit alert to a Microsoft Teams incoming webhook.

    Uses the legacy Office 365 Connector MessageCard format which is broadly
    supported by all Teams tenants.  The webhook URL must resolve to
    ``webhook.office.com`` (already in the built-in allowlist).

    Fails silently — a misconfigured webhook will never crash the scheduler.
    """
    if not webhook_url:
        return

    valid, reason = validate_webhook_url(webhook_url, extra_webhook_domains)
    if not valid:
        logger.warning(
            "Teams alert blocked for schedule %s — invalid webhook URL: %s",
            schedule.get("id"),
            reason,
        )
        return

    vendor = (schedule.get("vendor") or "device").upper()
    host = schedule.get("host") or "unknown"
    tag = schedule.get("tag") or ""
    label = f"{vendor}@{host}" + (f" [{tag}]" if tag else "")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if error:
        theme_color = "CC2200"
        title = f"\u274c Cashel Audit Error — {label}"
        facts = [{"name": "Error", "value": error}]
        text = ""
    else:
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = summary.get("total", 0)
        theme_color = "CC2200" if high else "1A8055"
        title = (
            f"\U0001f525 {high} HIGH finding(s) — {label}"
            if high
            else f"\u2705 Audit complete — {label}"
        )
        facts = [
            {"name": "Completed", "value": now},
            {"name": "Total", "value": str(total)},
            {"name": "HIGH", "value": str(high)},
            {"name": "MEDIUM", "value": str(med)},
            {"name": "LOW", "value": str(low)},
        ]
        highs = _top_high_findings(findings)
        text = ""
        if highs:
            bullet_list = "\n\n".join(f"- {h}" for h in highs)
            extra = summary.get("high", 0) - len(highs)
            if extra > 0:
                bullet_list += f"\n\n_\u2026and {extra} more HIGH finding(s)_"
            text = f"**Top HIGH findings:**\n\n{bullet_list}"

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": title,
        "sections": [
            {
                "activityTitle": "**Cashel Firewall Auditor**",
                "activitySubtitle": title,
                "facts": facts,
                **({"text": text} if text else {}),
            }
        ],
    }

    payload = json.dumps(card).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
        logger.info("Teams alert sent for schedule %s", schedule.get("id"))
    except urllib.error.URLError as exc:
        logger.warning(
            "Teams alert failed for schedule %s: %s", schedule.get("id"), exc
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Teams alert unexpected error for schedule %s: %s", schedule.get("id"), exc
        )
