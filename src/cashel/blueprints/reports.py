"""Reports blueprint — /reports/* and /remediation-plan."""

import io
import json
import logging
import os
import uuid
import zipfile
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, send_file

from cashel._helpers import _require_role
from cashel.archive import get_entry
from cashel.export import to_csv, to_json, to_sarif
from cashel.extensions import limiter
from cashel.remediation import generate_plan, plan_to_markdown, plan_to_pdf
from cashel.reporter import (
    VENDOR_DISPLAY,
    finding_rows,
    generate_cover_pdf,
    generate_report,
    report_sidecar_path,
)

logger = logging.getLogger(__name__)

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


def _load_report_metadata(path):
    sidecar = report_sidecar_path(path)
    if not os.path.exists(sidecar):
        return None
    try:
        with open(sidecar, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not load report sidecar: %s", sidecar)
        return None


def _fmt_generated(value, fallback_ts):
    if value:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            dt = None
        if dt:
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc)
            return (
                dt.strftime("%B %d, %Y").replace(" 0", " "),
                dt.strftime("%H:%M:%S UTC"),
            )
    dt = datetime.fromtimestamp(fallback_ts, timezone.utc)
    return dt.strftime("%B %d, %Y").replace(" 0", " "), dt.strftime("%H:%M:%S UTC")


def _compliance_label(value):
    if not value:
        return "Basic hygiene"
    labels = {
        "cis": "CIS Benchmark",
        "stig": "DISA STIG",
        "hipaa": "HIPAA Security Rule",
        "nist": "NIST SP 800-41",
        "pci": "PCI-DSS",
        "soc2": "SOC2",
    }
    return labels.get(str(value).lower(), str(value))


def _viewer_context(path, filename):
    metadata = _load_report_metadata(path) or {}
    fallback = not bool(metadata)
    summary = metadata.get("summary") or {}
    findings = metadata.get("findings") or []
    rows = finding_rows(findings)
    total = summary.get("total", len(rows))
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    score = summary.get("score")
    generated_date, generated_time = _fmt_generated(
        metadata.get("generated_at"), os.path.getmtime(path)
    )
    vendor = metadata.get("vendor") or "unknown"
    compliance = _compliance_label(metadata.get("compliance"))
    return {
        "fallback": fallback,
        "pdf_filename": filename,
        "report_id": metadata.get("report_id") or os.path.splitext(filename)[0],
        "audit_filename": metadata.get("filename") or filename,
        "vendor": vendor,
        "vendor_label": VENDOR_DISPLAY.get(vendor, vendor.upper()),
        "compliance": compliance,
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": total,
            "score": score,
        },
        "generated_date": generated_date,
        "generated_time": generated_time,
        "findings": rows,
    }


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
    """Render a polished HTML report viewer for a generated PDF report."""
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return render_template("report_view.html", report=_viewer_context(path, filename))


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
        inline = request.args.get("inline") == "1"
        report_name = f"remediation_{uuid.uuid4().hex[:8]}.pdf"
        report_path = os.path.join(REPORTS_FOLDER, report_name)
        os.makedirs(REPORTS_FOLDER, exist_ok=True)
        plan_to_pdf(plan, report_path)
        download_name = f"{(filename or 'audit').rsplit('.', 1)[0]}_remediation.pdf"
        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=not inline,
            download_name=download_name,
        )
    else:
        return jsonify(
            {"error": f"Unknown format '{fmt}'. Use json, markdown, or pdf."}
        ), 400


@reports_bp.route("/reports/<report_id>/evidence-bundle", methods=["POST"])
@_require_role("admin", "auditor")
def evidence_bundle(report_id):
    """Generate and download a compliance evidence bundle ZIP for an archived audit.

    Optional query param: ?compliance=pci,cis — filter/label compliance frameworks.
    Returns a ZIP with: audit_report.pdf, findings.csv, findings.json,
    findings.sarif, and cover.pdf (one-page summary).
    """
    entry = get_entry(report_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404

    compliance_param = request.args.get("compliance")

    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]

    # ── Generate audit_report.pdf ──────────────────────────────────────────────
    audit_pdf_path = os.path.join(REPORTS_FOLDER, f"bundle_audit_{run_id}.pdf")
    generate_report(
        findings=entry.get("findings", []),
        filename=entry.get("filename", ""),
        vendor=entry.get("vendor", "unknown"),
        compliance=compliance_param,
        output_path=audit_pdf_path,
        summary=entry.get("summary"),
    )

    # ── Generate cover.pdf ─────────────────────────────────────────────────────
    cover_pdf_path = os.path.join(REPORTS_FOLDER, f"bundle_cover_{run_id}.pdf")
    generate_cover_pdf(entry, cover_pdf_path, compliance=compliance_param)

    # ── Assemble ZIP in memory ─────────────────────────────────────────────────
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("findings.json", to_json(entry))
        zf.writestr("findings.csv", to_csv(entry))
        zf.writestr("findings.sarif", to_sarif(entry))
        with open(audit_pdf_path, "rb") as fh:
            zf.writestr("audit_report.pdf", fh.read())
        with open(cover_pdf_path, "rb") as fh:
            zf.writestr("cover.pdf", fh.read())
    zip_buf.seek(0)

    # ── Clean up temp PDFs ─────────────────────────────────────────────────────
    for path in (audit_pdf_path, cover_pdf_path):
        try:
            os.remove(path)
        except OSError:
            logger.warning("Could not remove temp file: %s", path)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    download_name = f"cashel_evidence_{report_id}_{timestamp}.zip"

    return send_file(
        zip_buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=download_name,
    )
