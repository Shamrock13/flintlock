"""Schedules blueprint — /schedules/*."""

from flask import Blueprint, jsonify, request

from cashel._helpers import _require_role
from cashel.license import DEMO_MODE
from cashel.schedule_store import (
    list_schedules,
    get_schedule,
    create_schedule,
    update_schedule,
    delete_schedule,
    ScheduleValidationError,
)
from cashel.scheduler_runner import (
    reload_job,
    run_now as scheduler_run_now,
    scheduler_available,
)

schedules_bp = Blueprint("schedules", __name__)

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


@schedules_bp.route("/schedules", methods=["GET"])
def schedules_list():
    if DEMO_MODE:
        return jsonify(_DEMO_SCHEDULES)
    return jsonify(list_schedules())


@schedules_bp.route("/schedules", methods=["POST"])
@_require_role("admin", "auditor")
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


@schedules_bp.route("/schedules/<schedule_id>", methods=["GET"])
def schedules_get(schedule_id):
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    return jsonify(schedule)


@schedules_bp.route("/schedules/<schedule_id>", methods=["PUT"])
@_require_role("admin", "auditor")
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


@schedules_bp.route("/schedules/<schedule_id>", methods=["DELETE"])
@_require_role("admin", "auditor")
def schedules_delete(schedule_id):
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    deleted = delete_schedule(schedule_id)
    if deleted:
        reload_job(schedule_id, None)  # removes the job from the scheduler
    return jsonify({"deleted": deleted})


@schedules_bp.route("/schedules/<schedule_id>/run", methods=["POST"])
@_require_role("admin", "auditor")
def schedules_run_now(schedule_id):
    """Trigger an immediate on-demand run of a scheduled audit."""
    if DEMO_MODE:
        return jsonify({"error": "Schedules are read-only in demo mode."}), 403
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    scheduler_run_now(schedule_id)
    return jsonify({"queued": True, "id": schedule_id})


@schedules_bp.route("/schedules/status", methods=["GET"])
def schedules_status():
    return jsonify({"scheduler_available": scheduler_available()})
