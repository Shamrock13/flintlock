"""REST API v1 blueprint — /api/v1/*.

CSRF-exempt; authenticated via X-API-Key header.
All responses use the envelope: {"ok": bool, "data": ..., "error": str|null}
"""

import os
from pathlib import Path

from flask import Blueprint, jsonify, request

from cashel.web import limiter, csrf
from cashel._vendor_helpers import ALL_VENDORS, detect_vendor, extract_hostname
from cashel._helpers import _err, _make_temp_path, _MAX_FILE_BYTES
from cashel.ftd import is_ftd_config
from cashel.archive import save_audit, get_entry, list_archive
from cashel.audit_engine import (
    _findings_to_strings,
    _wrap_compliance,
    _sort_findings,
    _build_summary,
    run_vendor_audit,
    run_compliance_checks,
)
from cashel.diff import diff_configs
from cashel.license import check_license
from cashel.remediation import generate_plan, plan_to_markdown

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
csrf.exempt(api_bp)


def _api_ok(data):
    return jsonify({"ok": True, "data": data, "error": None})


def _api_err(message, status=400):
    return jsonify({"ok": False, "data": None, "error": message}), status


@api_bp.route("/audit", methods=["POST"])
@limiter.limit("30/minute")
def api_audit():
    """POST /api/v1/audit — audit a config file, returns findings + summary."""
    if "config" not in request.files or not request.files["config"].filename:
        return _api_err("config file is required")

    vendor = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    archive_it = request.form.get("archive", "1") == "1"
    tag = request.form.get("tag", "").strip() or None

    if vendor not in ("auto", *ALL_VENDORS):
        return _api_err(f"Unknown vendor '{vendor}'.")

    from cashel.schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return _api_err(f"Unknown compliance framework '{compliance}'.")

    upload = request.files["config"]
    upload.seek(0, 2)
    if upload.tell() > _MAX_FILE_BYTES:
        return _api_err("File exceeds the 5 MB per-file limit.", 413)
    upload.seek(0)

    suffix = Path(upload.filename).suffix or ".txt"
    temp_path = _make_temp_path(suffix)
    upload.save(temp_path)

    try:
        sample = open(temp_path, encoding="utf-8", errors="ignore").read(4096)

        if vendor in ("auto", "cisco"):
            detected = detect_vendor(sample, upload.filename)
            if vendor == "auto":
                if not detected:
                    return _api_err(
                        "Could not auto-detect vendor. Specify vendor explicitly."
                    )
                vendor = detected
            elif vendor == "cisco":
                vendor = "ftd" if is_ftd_config(sample) else "asa"
        elif vendor == "asa" and is_ftd_config(sample):
            vendor = "ftd"

        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)
        archive_id = None
        if archive_it:
            archive_id, _ = save_audit(
                upload.filename,
                vendor,
                _findings_to_strings(findings),
                summary,
                config_path=temp_path,
                tag=tag,
            )

        return _api_ok(
            {
                "archive_id": archive_id,
                "vendor": vendor,
                "summary": summary,
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "detected_hostname": extract_hostname(vendor, sample),
            }
        )
    except Exception as e:
        return _api_err(_err(e, "Audit failed."), 500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@api_bp.route("/audit/<entry_id>", methods=["GET"])
def api_audit_get(entry_id):
    """GET /api/v1/audit/<id> — retrieve a specific archived audit result."""
    entry = get_entry(entry_id)
    if not entry:
        return _api_err("Audit not found.", 404)
    return _api_ok(entry)


@api_bp.route("/audit/<entry_id>/remediation-plan", methods=["GET"])
def api_remediation_plan(entry_id):
    """GET /api/v1/audit/<id>/remediation-plan — generate remediation plan.

    Query param: fmt = json | markdown  (default: json)
    """
    entry = get_entry(entry_id)
    if not entry:
        return _api_err("Audit not found.", 404)

    findings = entry.get("findings", [])
    vendor = entry.get("vendor", "unknown")
    filename = entry.get("filename", "")
    summary = entry.get("summary")

    plan = generate_plan(findings, vendor, filename, summary=summary)
    fmt = request.args.get("fmt", "json").lower()

    if fmt == "json":
        return _api_ok(plan)
    elif fmt == "markdown":
        return _api_ok({"markdown": plan_to_markdown(plan)})
    else:
        return _api_err(f"Unknown format '{fmt}'. Use json or markdown.", 400)


@api_bp.route("/history", methods=["GET"])
def api_history():
    """GET /api/v1/history — list audit history (metadata only, no findings)."""
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except (ValueError, TypeError):
        limit = 50
    vendor_filter = request.args.get("vendor", "").strip().lower() or None
    tag_filter = request.args.get("tag", "").strip() or None

    entries = list_archive()
    if vendor_filter:
        entries = [e for e in entries if e.get("vendor") == vendor_filter]
    if tag_filter:
        entries = [e for e in entries if e.get("tag") == tag_filter]
    entries = entries[:limit]

    # Strip bulky findings list from history response
    slim = [{k: v for k, v in e.items() if k != "findings"} for e in entries]
    return _api_ok(slim)


@api_bp.route("/diff", methods=["POST"])
@limiter.limit("30/minute")
def api_diff():
    """POST /api/v1/diff — compare two config files."""
    if "config_a" not in request.files or "config_b" not in request.files:
        return _api_err("config_a and config_b files are required.")

    vendor = request.form.get("vendor", "auto").strip().lower()
    if vendor not in ("auto", *ALL_VENDORS):
        return _api_err(f"Unknown vendor '{vendor}'.")

    paths = []
    try:
        for field in ("config_a", "config_b"):
            f = request.files[field]
            suffix = Path(f.filename).suffix or ".txt"
            p = _make_temp_path(suffix)
            f.save(p)
            paths.append(p)

        path_a, path_b = paths
        sample_a = open(path_a, encoding="utf-8", errors="ignore").read(4096)

        if vendor in ("auto", "cisco"):
            detected = detect_vendor(sample_a, request.files["config_a"].filename)
            vendor = (
                detected
                if vendor == "auto" and detected
                else (
                    ("ftd" if is_ftd_config(sample_a) else "asa")
                    if vendor == "cisco"
                    else (detected or "asa")
                )
            )
        elif vendor == "asa" and is_ftd_config(sample_a):
            vendor = "ftd"

        result = diff_configs(vendor, path_a, path_b)
        return _api_ok(result)
    except Exception as e:
        return _api_err(_err(e, "Diff failed."), 500)
    finally:
        for p in paths:
            if os.path.exists(p):
                os.remove(p)
