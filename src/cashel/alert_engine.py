"""Threshold-based alerting engine.

Evaluates audit summaries against configured thresholds, manages dedup/re-arm
state, and fires consolidated breach notifications via notify.py.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from .db import get_conn

logger = logging.getLogger(__name__)

# Valid metric keys and their source paths in the audit summary dict.
# Severity counts are top-level keys; compliance metrics live under summary["compliance"][fw]["score"].
_SEVERITY_METRICS = {"critical", "high", "medium", "low", "total"}
_COMPLIANCE_METRICS = {"pci", "cis", "nist", "hipaa", "soc2", "stig"}
VALID_METRICS = _SEVERITY_METRICS | _COMPLIANCE_METRICS | {"score"}
VALID_OPERATORS = {"lt", "gte"}

# Sentinel for manual/API-triggered audits (not from a schedule).
_MANUAL_SENTINEL = "__manual__"


@dataclass
class AlertResult:
    breached: bool = False
    suppressed: bool = False  # True when already in_breach with no new metrics
    breached_metrics: list[dict] = field(default_factory=list)
    cleared: bool = False  # True when was in_breach and condition is now clean


# ── Threshold CRUD ─────────────────────────────────────────────────────────────


def save_threshold(threshold: dict) -> dict:
    """Insert or update a threshold rule. Returns the saved threshold with id."""
    metric = threshold.get("metric")
    operator = threshold.get("operator")
    if metric not in VALID_METRICS:
        raise ValueError(
            f"Invalid metric: {metric!r}. Must be one of {sorted(VALID_METRICS)}"
        )
    if operator not in VALID_OPERATORS:
        raise ValueError(
            f"Invalid operator: {operator!r}. Must be one of {sorted(VALID_OPERATORS)}"
        )
    tid = threshold.get("id") or uuid.uuid4().hex[:12]
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO alert_thresholds (id, schedule_id, metric, operator, threshold_value, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            schedule_id     = excluded.schedule_id,
            metric          = excluded.metric,
            operator        = excluded.operator,
            threshold_value = excluded.threshold_value,
            enabled         = excluded.enabled
        """,
        (
            tid,
            threshold.get("schedule_id"),
            threshold["metric"],
            threshold["operator"],
            float(threshold["threshold_value"]),
            1 if threshold.get("enabled", True) else 0,
            now,
        ),
    )
    conn.commit()
    return {**threshold, "id": tid, "created_at": now}


def delete_threshold(threshold_id: str) -> bool:
    """Delete a threshold by id. Returns True if deleted."""
    conn = get_conn()
    # Fetch the threshold first so we can clear its schedule's alert state
    row = conn.execute(
        "SELECT schedule_id FROM alert_thresholds WHERE id = ?", (threshold_id,)
    ).fetchone()
    cur = conn.execute("DELETE FROM alert_thresholds WHERE id = ?", (threshold_id,))
    conn.commit()
    if cur.rowcount > 0 and row:
        # Clear alert state for the affected schedule so stale breach state
        # doesn't suppress alerts after threshold reconfiguration
        state_key = row["schedule_id"] or _MANUAL_SENTINEL
        _clear_state(state_key)
    return cur.rowcount > 0


def list_thresholds() -> list[dict]:
    """Return all threshold rules (global and per-schedule)."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alert_thresholds ORDER BY created_at ASC"
    ).fetchall()
    return [_threshold_row(r) for r in rows]


def get_effective_thresholds(schedule_id: str | None = None) -> list[dict]:
    """Return effective thresholds for a schedule.

    Per-schedule overrides take precedence over global defaults on a per-metric
    basis. A schedule override fully replaces the global for that metric.
    """
    conn = get_conn()
    # Load globals (schedule_id IS NULL)
    globals_ = {
        r["metric"]: _threshold_row(r)
        for r in conn.execute(
            "SELECT * FROM alert_thresholds WHERE schedule_id IS NULL AND enabled = 1"
        ).fetchall()
    }
    if schedule_id:
        # Load per-schedule overrides and merge over globals
        overrides = {
            r["metric"]: _threshold_row(r)
            for r in conn.execute(
                "SELECT * FROM alert_thresholds WHERE schedule_id = ? AND enabled = 1",
                (schedule_id,),
            ).fetchall()
        }
        merged = {**globals_, **overrides}
    else:
        merged = globals_
    return list(merged.values())


# ── Alert channel config ───────────────────────────────────────────────────────


def get_alert_channels() -> dict:
    """Return alert channel config from settings (decrypted)."""
    from .settings import get_settings
    from .crypto import decrypt

    s = get_settings()
    slack = ""
    teams = ""
    if s.get("alert_slack_webhook_enc"):
        try:
            slack = decrypt(s["alert_slack_webhook_enc"])
        except Exception:
            pass
    if s.get("alert_teams_webhook_enc"):
        try:
            teams = decrypt(s["alert_teams_webhook_enc"])
        except Exception:
            pass
    return {
        "alert_slack_webhook": slack,
        "alert_teams_webhook": teams,
        "alert_email_recipients": s.get("alert_email_recipients", ""),
    }


def save_alert_channels(channels: dict) -> None:
    """Persist alert channel config to settings.json.

    Reads and writes settings.json directly (bypassing get_settings/save_settings)
    to avoid hydrating smtp_password into memory. Only the three alert-specific
    keys are written. TOCTOU risk is acceptable: this is a single-process app
    and settings writes are low-frequency admin operations.
    """
    from .crypto import encrypt
    from .settings import SETTINGS_FILE
    import json as _json
    import os

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    try:
        with open(SETTINGS_FILE) as f:
            existing = _json.load(f)
    except (FileNotFoundError, _json.JSONDecodeError):
        existing = {}

    if channels.get("alert_slack_webhook"):
        existing["alert_slack_webhook_enc"] = encrypt(channels["alert_slack_webhook"])
    if channels.get("alert_teams_webhook"):
        existing["alert_teams_webhook_enc"] = encrypt(channels["alert_teams_webhook"])
    if "alert_email_recipients" in channels:
        existing["alert_email_recipients"] = channels["alert_email_recipients"]

    with open(SETTINGS_FILE, "w") as f:
        _json.dump(existing, f, indent=2)


# ── Core evaluation ────────────────────────────────────────────────────────────


def check_thresholds(
    audit_summary: dict,
    schedule_id: str | None = None,
    audit_id: str | None = None,
    hostname: str | None = None,
) -> AlertResult:
    """Evaluate audit_summary against thresholds.  Fire alert if new breach.

    Never raises — all errors are caught and logged.
    """
    try:
        return _check_thresholds_impl(audit_summary, schedule_id, audit_id, hostname)
    except Exception as exc:  # noqa: BLE001
        logger.error("check_thresholds failed unexpectedly: %s", exc)
        return AlertResult()


def _check_thresholds_impl(
    audit_summary: dict,
    schedule_id: str | None,
    audit_id: str | None,
    hostname: str | None,
) -> AlertResult:
    state_key = schedule_id or _MANUAL_SENTINEL
    thresholds = get_effective_thresholds(schedule_id)

    if not thresholds:
        return AlertResult()

    # Evaluate each threshold
    newly_breached: list[dict] = []
    for t in thresholds:
        value = _extract_metric(audit_summary, t["metric"])
        if value is None:
            logger.debug("Metric %s not found in summary — skipping", t["metric"])
            continue
        if _operator_matches(value, t["operator"], t["threshold_value"]):
            newly_breached.append(
                {
                    "metric": t["metric"],
                    "operator": t["operator"],
                    "threshold_value": t["threshold_value"],
                    "actual_value": value,
                }
            )

    # Load current state
    state = _get_state(state_key)
    in_breach = bool(state.get("in_breach"))
    prev_metrics = set(state.get("breached_metrics_list", []))
    current_metrics = {m["metric"] for m in newly_breached}

    result = AlertResult()

    if not newly_breached:
        if in_breach:
            # Condition cleared — re-arm
            _clear_state(state_key)
            result.cleared = True
            logger.info("Alert cleared for schedule=%s", state_key)
            # Outbound webhook — threshold clear
            from cashel import webhooks as _wh

            _wh.dispatch_event(
                "alert.threshold_clear",
                {
                    "schedule_id": schedule_id,
                    "metric": ", ".join(sorted(prev_metrics)),
                },
            )
        return result

    # There are breached thresholds
    new_only = [m for m in newly_breached if m["metric"] not in prev_metrics]

    if in_breach and not new_only:
        # Already notified, no new metrics
        result.suppressed = True
        return result

    # Fire alert — either first breach or new metrics added
    result.breached = True
    result.breached_metrics = new_only if in_breach else newly_breached

    _set_state(state_key, audit_id, current_metrics | prev_metrics)

    # Dispatch existing channels
    _dispatch_alert(result.breached_metrics, audit_summary, audit_id, hostname)

    # Outbound webhook events — one dispatch per breached metric
    from cashel import webhooks as _wh

    for m in result.breached_metrics:
        _wh.dispatch_event(
            "alert.threshold_breach",
            {
                "schedule_id": schedule_id,
                "metric": m["metric"],
                "operator": m["operator"],
                "threshold_value": m["threshold_value"],
                "actual_value": m["actual_value"],
                "audit_id": audit_id or "",
            },
        )

    return result


def _extract_metric(summary: dict, metric: str) -> float | None:
    """Extract a numeric value from the audit summary for the given metric key."""
    if metric == "score":
        v = summary.get("score")
        return float(v) if v is not None else None
    if metric in _SEVERITY_METRICS:
        v = summary.get(metric)
        return float(v) if v is not None else None
    if metric in _COMPLIANCE_METRICS:
        compliance = summary.get("compliance") or {}
        fw_data = compliance.get(metric) or {}
        v = fw_data.get("score")
        return float(v) if v is not None else None
    return None


def _operator_matches(value: float, operator: str, threshold: float) -> bool:
    if operator == "lt":
        return value < threshold
    if operator == "gte":
        return value >= threshold
    return False


# ── State management ───────────────────────────────────────────────────────────


def _get_state(state_key: str) -> dict:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM alert_state WHERE schedule_id = ?", (state_key,)
    ).fetchone()
    if not row:
        return {"in_breach": 0, "breached_metrics_list": []}
    d = dict(row)
    d["breached_metrics_list"] = json.loads(d.get("breached_metrics") or "[]")
    return d


def _set_state(state_key: str, audit_id: str | None, all_metrics: set[str]) -> None:
    conn = get_conn()
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        """
        INSERT INTO alert_state (schedule_id, in_breach, breach_started_at, breach_audit_id, breached_metrics)
        VALUES (?, 1, ?, ?, ?)
        ON CONFLICT(schedule_id) DO UPDATE SET
            in_breach         = 1,
            breach_audit_id   = excluded.breach_audit_id,
            breached_metrics  = excluded.breached_metrics
        """,
        (state_key, now, audit_id or "", json.dumps(sorted(all_metrics))),
    )
    conn.commit()


def _clear_state(state_key: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE alert_state SET in_breach = 0, breached_metrics = '[]' WHERE schedule_id = ?",
        (state_key,),
    )
    conn.commit()


# ── Dispatch ───────────────────────────────────────────────────────────────────


def _dispatch_alert(
    breached_metrics: list[dict],
    summary: dict,
    audit_id: str | None,
    hostname: str | None,
) -> None:
    """Send consolidated breach alert to all configured channels."""
    from .activity_log import log_activity
    from .settings import get_settings

    channels = get_alert_channels()
    settings = get_settings()
    extra_domains = [
        d.strip() for d in settings.get("webhook_allowlist", "").split(",") if d.strip()
    ]

    subject = _build_subject(hostname, summary)
    body = _build_body(breached_metrics, summary, audit_id, hostname)

    if channels.get("alert_slack_webhook"):
        _send_alert_slack(
            channels["alert_slack_webhook"],
            breached_metrics,
            summary,
            hostname,
            extra_domains,
        )

    if channels.get("alert_teams_webhook"):
        _send_alert_teams(
            channels["alert_teams_webhook"],
            breached_metrics,
            summary,
            hostname,
            extra_domains,
        )

    for recipient in _parse_recipients(channels.get("alert_email_recipients", "")):
        _send_alert_email(recipient, subject, body, settings)

    log_activity(
        "threshold_breach",
        hostname or "unknown",
        success=True,
        details={
            "breached_metrics": [m["metric"] for m in breached_metrics],
            "audit_id": audit_id or "",
        },
    )


def _build_subject(hostname: str | None, summary: dict) -> str:
    host = hostname or "unknown"
    score = summary.get("score", "?")
    return f"[Cashel Alert] Audit threshold breach — {host} (score: {score})"


def _build_body(
    breached_metrics: list[dict],
    summary: dict,
    audit_id: str | None,
    hostname: str | None,
) -> str:
    import os

    host = hostname or "unknown"
    score = summary.get("score", "?")
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"Audit threshold breach detected for: {host}",
        f"Audit ID: {audit_id or 'n/a'} | Score: {score}/100 | {ts}",
        "",
        "Breached thresholds:",
    ]
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        lines.append(
            f"  \u2717 {m['metric'].upper()}: {m['actual_value']} "
            f"(threshold: {op_str} {m['threshold_value']})"
        )
    base_url = os.environ.get("CASHEL_BASE_URL", "").rstrip("/")
    if base_url and audit_id:
        lines += ["", f"View full audit: {base_url}/history"]
    lines += ["", "\u2014 Cashel Firewall Auditor"]
    return "\n".join(lines)


def _parse_recipients(recipients_str: str) -> list[str]:
    return [r.strip() for r in recipients_str.split(",") if r.strip()]


def _send_alert_slack(
    webhook_url: str,
    breached_metrics: list[dict],
    summary: dict,
    hostname: str | None,
    extra_domains: list[str],
) -> None:
    import json as _json
    import urllib.request
    from .notify import validate_webhook_url

    valid, reason = validate_webhook_url(webhook_url, extra_domains)
    if not valid:
        logger.warning("Alert Slack webhook blocked: %s", reason)
        return

    host = hostname or "unknown"
    score = summary.get("score", "?")
    lines = [f":warning: *Cashel threshold breach* — {host} (score: {score}/100)", ""]
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        lines.append(
            f"• *{m['metric'].upper()}*: {m['actual_value']} "
            f"(threshold: {op_str} {m['threshold_value']})"
        )
    payload = _json.dumps({"text": "\n".join(lines)}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert Slack dispatch failed: %s", exc)


def _send_alert_teams(
    webhook_url: str,
    breached_metrics: list[dict],
    summary: dict,
    hostname: str | None,
    extra_domains: list[str],
) -> None:
    import json as _json
    import urllib.request
    from .notify import validate_webhook_url

    valid, reason = validate_webhook_url(webhook_url, extra_domains)
    if not valid:
        logger.warning("Alert Teams webhook blocked: %s", reason)
        return

    host = hostname or "unknown"
    score = summary.get("score", "?")
    facts = []
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        facts.append(
            {
                "name": m["metric"].upper(),
                "value": f"{m['actual_value']} (threshold: {op_str} {m['threshold_value']})",
            }
        )
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "CC2200",
        "summary": f"Cashel threshold breach — {host}",
        "sections": [
            {
                "activityTitle": "**Cashel Firewall Auditor — Threshold Breach**",
                "activitySubtitle": f"{host} | Score: {score}/100",
                "facts": facts,
            }
        ],
    }
    payload = _json.dumps(card).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert Teams dispatch failed: %s", exc)


def _send_alert_email(
    recipient: str,
    subject: str,
    body: str,
    smtp_cfg: dict,
) -> None:
    import smtplib
    import ssl
    from email.mime.text import MIMEText

    smtp_host = (smtp_cfg.get("smtp_host") or "").strip()
    if not smtp_host:
        logger.warning("Alert email skipped: smtp_host not configured.")
        return

    smtp_port = int(smtp_cfg.get("smtp_port") or 587)
    smtp_user = (smtp_cfg.get("smtp_user") or "").strip()
    smtp_password = smtp_cfg.get("smtp_password") or ""
    smtp_from = (smtp_cfg.get("smtp_from") or smtp_user or "cashel@localhost").strip()
    use_tls = bool(smtp_cfg.get("smtp_tls", True))

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = recipient

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [recipient], msg.as_string())
        logger.info("Alert email sent to %s", recipient)
    except smtplib.SMTPException as exc:
        logger.warning("Alert email SMTP error to %s: %s", recipient, exc)
    except OSError as exc:
        logger.warning("Alert email connection error to %s: %s", recipient, exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert email unexpected error to %s: %s", recipient, exc)


# ── Internal helpers ───────────────────────────────────────────────────────────


def _threshold_row(row) -> dict:
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    d["threshold_value"] = float(d["threshold_value"])
    return d
