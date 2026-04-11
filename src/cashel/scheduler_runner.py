"""Background scheduler for automated SSH audits."""

import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

APSCHEDULER_AVAILABLE = True

_scheduler = None


# ── Job execution ──────────────────────────────────────────────────────────────


def _run_scheduled_audit(schedule_id: str):
    """Execute one scheduled SSH audit and persist results."""
    from .schedule_store import get_schedule, get_password, record_run
    from .ssh_connector import connect_and_pull
    from .archive import save_audit
    from .license import check_license
    from .activity_log import log_activity, ACTION_SSH_CONNECT
    from .audit_engine import (
        run_vendor_audit,
        run_compliance_checks,
        _sort_findings,
        _build_summary,
        _findings_to_strings,
        _wrap_compliance,
    )
    from .notify import send_slack, send_teams, send_email
    from .settings import get_settings
    from .alert_engine import check_thresholds

    schedule = get_schedule(schedule_id, include_password=True)
    if not schedule or not schedule.get("enabled"):
        return

    vendor = schedule["vendor"]
    host = schedule["host"]
    port = schedule["port"]
    username = schedule["username"]
    password = get_password(schedule_id)
    tag = schedule.get("tag") or f"{vendor.upper()}@{host}"
    compliance = schedule.get("compliance") or None
    label = f"{vendor.upper()}@{host}"

    upload_folder = os.environ.get("UPLOAD_FOLDER", "/tmp/cashel_uploads")
    os.makedirs(upload_folder, exist_ok=True)

    settings = get_settings()
    _extra_domains = [
        d.strip() for d in settings.get("webhook_allowlist", "").split(",") if d.strip()
    ]

    # ── SSH pull ──────────────────────────────────────────────────────────────
    temp_path = None
    try:
        temp_path, _ = connect_and_pull(
            vendor,
            host,
            port,
            username,
            password,
            timeout=30,
            upload_folder=upload_folder,
            host_key_policy=settings.get("ssh_host_key_policy", "warn"),
        )
    except Exception as e:
        record_run(schedule_id, "error", str(e))
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "scheduled": True},
        )
        if schedule.get("notify_on_error"):
            send_slack(
                schedule.get("notify_slack_webhook", ""),
                schedule,
                {},
                [],
                error=str(e),
                extra_webhook_domains=_extra_domains,
            )
            send_teams(
                schedule.get("notify_teams_webhook", ""),
                schedule,
                {},
                [],
                error=str(e),
                extra_webhook_domains=_extra_domains,
            )
            send_email(
                schedule.get("notify_email", ""),
                schedule,
                {},
                [],
                settings,
                error=str(e),
            )
        return

    # ── Audit + compliance ────────────────────────────────────────────────────
    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance:
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(
                    vendor, compliance, parse, extra_data, temp_path
                )
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        save_audit(
            label,
            vendor,
            _findings_to_strings(findings),
            summary,
            config_path=temp_path,
            tag=tag,
        )
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=True,
            details={
                "host": host,
                "scheduled": True,
                "total": summary.get("total", 0),
                "high": summary.get("high", 0),
            },
        )
        record_run(schedule_id, "ok")

        try:
            check_thresholds(
                summary,
                schedule_id=schedule_id,
                audit_id=None,
                hostname=host,
            )
        except Exception as _ae:  # noqa: BLE001
            logger.warning("check_thresholds failed for schedule %s: %s", schedule_id, _ae)

        if schedule.get("notify_on_finding") and summary.get("high", 0) > 0:
            send_slack(
                schedule.get("notify_slack_webhook", ""),
                schedule,
                summary,
                findings,
                extra_webhook_domains=_extra_domains,
            )
            send_teams(
                schedule.get("notify_teams_webhook", ""),
                schedule,
                summary,
                findings,
                extra_webhook_domains=_extra_domains,
            )
            send_email(
                schedule.get("notify_email", ""), schedule, summary, findings, settings
            )

    except Exception as e:
        record_run(schedule_id, "error", str(e))
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "scheduled": True},
        )
        if schedule.get("notify_on_error"):
            send_slack(
                schedule.get("notify_slack_webhook", ""),
                schedule,
                {},
                [],
                error=str(e),
                extra_webhook_domains=_extra_domains,
            )
            send_teams(
                schedule.get("notify_teams_webhook", ""),
                schedule,
                {},
                [],
                error=str(e),
                extra_webhook_domains=_extra_domains,
            )
            send_email(
                schedule.get("notify_email", ""),
                schedule,
                {},
                [],
                settings,
                error=str(e),
            )
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ── Trigger factory ────────────────────────────────────────────────────────────


def _build_trigger(schedule: dict):
    freq = schedule.get("frequency", "daily")
    hour = schedule.get("hour", 2)
    minute = schedule.get("minute", 0)
    dow = schedule.get("day_of_week", "mon")

    if freq == "hourly":
        return CronTrigger(minute=minute)
    if freq == "weekly":
        return CronTrigger(day_of_week=dow, hour=hour, minute=minute)
    return CronTrigger(hour=hour, minute=minute)


# ── Lifecycle ──────────────────────────────────────────────────────────────────


def start_scheduler():
    """Start the APScheduler background scheduler and load all enabled jobs."""
    global _scheduler
    if not APSCHEDULER_AVAILABLE:
        return
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")

    from .schedule_store import list_schedules

    for sched in list_schedules(include_password=True):
        if sched.get("enabled"):
            try:
                _scheduler.add_job(
                    _run_scheduled_audit,
                    trigger=_build_trigger(sched),
                    args=[sched["id"]],
                    id=sched["id"],
                    replace_existing=True,
                )
            except Exception as exc:
                logger.warning("Could not schedule job %s: %s", sched.get("id"), exc)

    _scheduler.start()
    logger.info("Cashel scheduler started with %d job(s)", len(_scheduler.get_jobs()))


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


def reload_job(schedule_id: str, schedule: dict | None = None):
    """Add, update, or remove a scheduler job for the given schedule ID."""
    if not APSCHEDULER_AVAILABLE or not _scheduler:
        return
    # Always remove first
    try:
        _scheduler.remove_job(schedule_id)
    except Exception:
        pass
    # Re-add if enabled
    if schedule and schedule.get("enabled"):
        try:
            _scheduler.add_job(
                _run_scheduled_audit,
                trigger=_build_trigger(schedule),
                args=[schedule_id],
                id=schedule_id,
                replace_existing=True,
            )
        except Exception as exc:
            logger.warning("Could not reload job %s: %s", schedule_id, exc)


def run_now(schedule_id: str):
    """Fire the scheduled audit immediately in a daemon thread."""
    import threading

    t = threading.Thread(target=_run_scheduled_audit, args=(schedule_id,), daemon=True)
    t.start()


def scheduler_available() -> bool:
    return APSCHEDULER_AVAILABLE
