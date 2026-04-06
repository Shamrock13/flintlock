"""Reports blueprint — /reports/* and /remediation-plan."""

import os
import uuid

from flask import Blueprint, jsonify, request, send_file

from cashel.web import limiter, csrf  # noqa: F401 (csrf imported for completeness)
from cashel.remediation import generate_plan, plan_to_markdown, plan_to_pdf

REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")

reports_bp = Blueprint("reports", __name__)


def _safe_report_path(filename):
    """Resolve a report filename and verify it stays inside REPORTS_FOLDER."""
    path = os.path.realpath(os.path.join(REPORTS_FOLDER, filename))
    if not path.startswith(os.path.realpath(REPORTS_FOLDER) + os.sep):
        return None
    if not os.path.exists(path):
        return None
    return path


@reports_bp.route("/reports", methods=["GET"])
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


@reports_bp.route("/reports/<filename>")
def download_report(filename):
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@reports_bp.route("/reports/<filename>/view")
def view_report(filename):
    """Serve PDF inline for in-browser viewing."""
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=False, mimetype="application/pdf")


@reports_bp.route("/remediation-plan", methods=["POST"])
@limiter.limit("30/minute")
def remediation_plan_inline():
    """Generate a remediation plan from inline audit data (POST JSON).

    Expected body: {findings, vendor, filename?, compliance?, summary?}
    Query param: fmt = json | markdown | pdf  (default: json)
    """
    from flask import current_app

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
