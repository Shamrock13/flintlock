"""History blueprint — /archive/* and /activity/*."""

import os
import uuid

from flask import Blueprint, Response, jsonify, request, send_file

from cashel._helpers import _require_role
from cashel.web import limiter  # noqa: F401
from cashel.archive import (
    save_audit,
    list_archive,
    get_entry,
    delete_entry,
    compare_entries,
)
from cashel.export import to_json, to_csv, to_sarif
from cashel.activity_log import (
    list_activity,
    delete_activity_entry,
    clear_activity,
)
from cashel.remediation import generate_plan, plan_to_markdown, plan_to_pdf

REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")

history_bp = Blueprint("history", __name__)


@history_bp.route("/archive", methods=["GET"])
def archive_list():
    return jsonify(list_archive())


@history_bp.route("/archive/save", methods=["POST"])
@_require_role("admin", "auditor")
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


@history_bp.route("/archive/<entry_id>", methods=["GET"])
def archive_get(entry_id):
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@history_bp.route("/archive/<entry_id>", methods=["DELETE"])
@_require_role("admin")
def archive_delete(entry_id):
    deleted = delete_entry(entry_id)
    return jsonify({"deleted": deleted})


@history_bp.route("/archive/<entry_id>/export", methods=["GET"])
def archive_export(entry_id):
    """Export an archived audit as JSON, CSV, or SARIF.

    Query param: fmt = json | csv | sarif  (default: json)
    """
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


@history_bp.route("/archive/trends", methods=["GET"])
def archive_trends():
    """Return time-series data for score/finding trends grouped by filename."""
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    entries = list_archive()
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


@history_bp.route("/archive/compare", methods=["POST"])
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


@history_bp.route("/archive/<entry_id>/remediation-plan", methods=["GET"])
def archive_remediation_plan(entry_id):
    """Generate a remediation plan from an archived audit.

    Query param: fmt = json | markdown | pdf  (default: json)
    """
    from flask import current_app

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
        return current_app.response_class(
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


@history_bp.route("/activity", methods=["GET"])
@_require_role("admin")
def activity_list():
    limit = int(request.args.get("limit", 200))
    return jsonify(list_activity(limit=limit))


@history_bp.route("/activity/<event_id>", methods=["DELETE"])
@_require_role("admin")
def activity_delete(event_id):
    deleted = delete_activity_entry(event_id)
    return jsonify({"deleted": deleted})


@history_bp.route("/activity/clear", methods=["POST"])
@_require_role("admin")
def activity_clear():
    count = clear_activity()
    return jsonify({"cleared": count})
