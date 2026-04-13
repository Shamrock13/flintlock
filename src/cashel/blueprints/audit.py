"""Audit blueprint — /audit, /bulk_audit, /diff, /connect, /demo/*."""

import os
import uuid
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from cashel.extensions import limiter
from cashel._vendor_helpers import (
    ALL_VENDORS,
    VENDOR_DISPLAY,
    detect_vendor,
    validate_vendor_format,
    extract_hostname,
)
from cashel._helpers import (
    _err,
    _make_temp_path,
    _MAX_FILE_BYTES,
    _require_role,
    UPLOAD_FOLDER,
)
from cashel.ftd import is_ftd_config
from cashel.audit_engine import (
    _findings_to_strings,
    _wrap_compliance,
    _sort_findings,
    _build_summary,
    run_vendor_audit,
    run_compliance_checks,
)
from cashel.diff import diff_configs
from cashel.archive import save_audit
from cashel.activity_log import (
    log_activity,
    ACTION_FILE_AUDIT,
    ACTION_SSH_CONNECT,
    ACTION_CONFIG_DIFF,
)
from cashel.license import check_license, DEMO_MODE
from cashel.reporter import generate_report
from cashel.settings import get_settings

REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")

audit_bp = Blueprint("audit", __name__)

# ── Demo mode: sample configs ─────────────────────────────────────────────────
_DEMO_SAMPLES_DIR = Path(__file__).parent.parent / "demo_samples"

_DEMO_CONFIGS = {
    "cisco_asa": {
        "label": "Cisco ASA — Enterprise Edge",
        "filename": "cisco_asa.txt",
        "vendor": "asa",
        "description": "ASA 5525-X with ACL misconfigurations, SNMPv2, Telnet, and duplicate rules.",
    },
    "palo_alto": {
        "label": "Palo Alto PA-3220 — PAN-OS 11.1",
        "filename": "palo_alto.xml",
        "vendor": "paloalto",
        "description": "Any/any permit policy, missing log-end settings, and shadowed rules.",
    },
    "fortinet": {
        "label": "Fortinet FortiGate — Edge Firewall",
        "filename": "fortinet_fortigate.txt",
        "vendor": "fortinet",
        "description": "Unrestricted any/any policy with logging disabled and a duplicate rule.",
    },
    "aws": {
        "label": "AWS Security Groups — VPC Production",
        "filename": "aws_security_groups.json",
        "vendor": "aws",
        "description": "SSH/RDP open to 0.0.0.0/0 and a wildcard TCP 0-65535 rule.",
    },
}

_DEMO_COMPARISON_PAIRS = {
    "asa_weekly": {
        "label": "Cisco ASA — Week 1 vs Week 2",
        "vendor": "asa",
        "description": "Baseline with Telnet, any/any, and open HTTP management vs. hardened current config.",
        "file_a": "cisco_asa_baseline.txt",
        "file_b": "cisco_asa_current.txt",
        "label_a": "Week 1 — Baseline",
        "label_b": "Week 2 — Current",
    },
    "fortinet_patch": {
        "label": "Fortinet FortiGate — Pre-patch vs Post-patch",
        "vendor": "fortinet",
        "description": "Broad any/any policies and logging disabled vs. tightened rules with full logging.",
        "file_a": "fortinet_baseline.txt",
        "file_b": "fortinet_current.txt",
        "label_a": "Pre-patch — Baseline",
        "label_b": "Post-patch — Current",
    },
}

# Pre-canned demo SSH audit result (Cisco ASA scenario).
_DEMO_SSH_FINDINGS = [
    {
        "severity": "CRITICAL",
        "category": "exposure",
        "message": "[CRITICAL] Telnet enabled on inside interface — transmits credentials in plaintext",
        "remediation": "Disable Telnet with 'no telnet' and enforce SSH for all remote management access.",
    },
    {
        "severity": "HIGH",
        "category": "protocol",
        "message": "[HIGH] SNMPv2 community string 'public' configured — no per-user auth, plaintext on wire",
        "remediation": "Migrate to SNMPv3 with authPriv. Remove all SNMPv2 community strings.",
    },
    {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] ACL OUTSIDE_IN contains 'permit ip any any' — unrestricted inbound traffic",
        "remediation": "Replace with explicit permit rules scoped to required sources, destinations, and services. Ensure a deny-all terminator exists.",
    },
    {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] ASDM HTTP server accessible from 0.0.0.0/0 on outside interface",
        "remediation": "Restrict HTTP server to management subnets only: 'http <mgmt-subnet> <mask> inside'. Remove the 0.0.0.0/0 outside entry.",
    },
    {
        "severity": "MEDIUM",
        "category": "hygiene",
        "message": "[MEDIUM] Duplicate ACL rule — 'permit tcp any host 172.16.0.10 eq 80' appears twice in OUTSIDE_IN",
        "remediation": "Remove the duplicate entry. Use 'show access-list' hit counts to identify and consolidate redundant rules.",
    },
    {
        "severity": "MEDIUM",
        "category": "hygiene",
        "message": "[MEDIUM] NTP not configured — log timestamps will be unreliable",
        "remediation": "Configure at least two NTP servers: 'ntp server <ip> prefer'. Ensure NTP traffic is permitted by the management ACL.",
    },
    {
        "severity": "LOW",
        "category": "compliance",
        "message": "[LOW] No login banner configured — required by CIS and STIG for legal notice",
        "remediation": "Add 'banner login' or 'banner motd' with an authorised-use warning.",
    },
]

_DEMO_SSH_SUMMARY = {
    "score": 34,
    "total": 7,
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def get_demo_index_data() -> tuple[list, list]:
    """Return (demo_configs, demo_comparisons) card lists for the index template."""
    configs = [
        {
            "id": k,
            "label": v["label"],
            "vendor": v["vendor"],
            "description": v["description"],
        }
        for k, v in _DEMO_CONFIGS.items()
    ]
    comparisons = [
        {
            "id": k,
            "label": v["label"],
            "vendor": v["vendor"],
            "description": v["description"],
            "label_a": v["label_a"],
            "label_b": v["label_b"],
        }
        for k, v in _DEMO_COMPARISON_PAIRS.items()
    ]
    return configs, comparisons


@audit_bp.route("/demo/configs")
def demo_configs():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
            }
            for k, v in _DEMO_CONFIGS.items()
        ]
    )


@audit_bp.route("/demo/load/<config_id>")
def demo_load(config_id):
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    if config_id not in _DEMO_CONFIGS:
        return jsonify({"error": "Unknown demo config."}), 404
    cfg = _DEMO_CONFIGS[config_id]
    file_path = _DEMO_SAMPLES_DIR / cfg["filename"]
    if not file_path.exists():
        return jsonify({"error": "Sample config file not found."}), 500
    return send_file(
        file_path,
        as_attachment=True,
        download_name=cfg["filename"],
        mimetype="text/plain",
    )


@audit_bp.route("/demo/comparisons")
def demo_comparisons():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        [
            {
                "id": k,
                "label": v["label"],
                "vendor": v["vendor"],
                "description": v["description"],
                "label_a": v["label_a"],
                "label_b": v["label_b"],
            }
            for k, v in _DEMO_COMPARISON_PAIRS.items()
        ]
    )


@audit_bp.route("/demo/compare/<pair_id>")
def demo_compare(pair_id):
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    if pair_id not in _DEMO_COMPARISON_PAIRS:
        return jsonify({"error": "Unknown demo comparison."}), 404
    pair = _DEMO_COMPARISON_PAIRS[pair_id]
    path_a = str(_DEMO_SAMPLES_DIR / pair["file_a"])
    path_b = str(_DEMO_SAMPLES_DIR / pair["file_b"])
    if not Path(path_a).exists() or not Path(path_b).exists():
        return jsonify({"error": "Sample config files not found."}), 500
    try:
        result = diff_configs(pair["vendor"], path_a, path_b)
        result["vendor"] = pair["vendor"]
        result["filename_a"] = pair["label_a"]
        result["filename_b"] = pair["label_b"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Comparison failed: {e}"}), 500


@audit_bp.route("/demo/ssh-audit", methods=["POST"])
def demo_ssh_audit():
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404
    return jsonify(
        {
            "findings": [f["message"] for f in _DEMO_SSH_FINDINGS],
            "enriched_findings": _DEMO_SSH_FINDINGS,
            "summary": _DEMO_SSH_SUMMARY,
            "detected_vendor": "asa",
            "host": "203.0.113.50",
            "archive_id": None,
        }
    )


@audit_bp.route("/demo/bulk-audit", methods=["POST"])
def demo_bulk_audit():
    """Run all demo sample configs through the audit engine and return bulk results."""
    if not DEMO_MODE:
        return jsonify({"error": "Not available outside demo mode."}), 404

    results = []
    for _cfg_id, cfg in _DEMO_CONFIGS.items():
        src_path = str(_DEMO_SAMPLES_DIR / cfg["filename"])
        vendor = cfg["vendor"]
        result_entry: dict = {
            "filename": cfg["label"],
            "status": "error",
            "findings": [],
            "enriched_findings": [],
            "summary": {},
            "vendor": vendor,
            "archive_id": None,
            "error": None,
        }
        try:
            findings, _parse, _extra = run_vendor_audit(vendor, src_path)
            findings = _sort_findings(findings)
            summary = _build_summary(findings)
            result_entry.update(
                {
                    "status": "ok",
                    "findings": _findings_to_strings(findings),
                    "enriched_findings": findings,
                    "summary": summary,
                }
            )
        except Exception as exc:  # noqa: BLE001
            result_entry["error"] = str(exc)
        results.append(result_entry)

    return jsonify(results)


@audit_bp.route("/audit", methods=["POST"])
@limiter.limit("30/minute")
@_require_role("admin", "auditor")
def run_audit():
    if "config" not in request.files or request.files["config"].filename == "":
        return jsonify({"error": "No config file uploaded"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    generate_pdf = request.form.get("report") == "1"
    archive_it = request.form.get("archive") == "1"
    tag = request.form.get("tag", "").strip() or None

    # Early vendor allowlist check — reject unknown values before touching disk.
    if vendor not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor}'."}), 400

    # Early compliance allowlist check.
    from cashel.schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return jsonify({"error": f"Unknown compliance framework '{compliance}'."}), 400

    upload = request.files["config"]
    upload.seek(0, 2)
    if upload.tell() > _MAX_FILE_BYTES:
        return jsonify({"error": "File exceeds the 5 MB per-file limit."}), 413
    upload.seek(0)
    suffix = Path(upload.filename).suffix or ".txt"
    temp_path = _make_temp_path(suffix)
    upload.save(temp_path)

    try:
        with open(temp_path, "r", errors="ignore") as f:
            sample = f.read(16384)
    except Exception:
        sample = ""

    if vendor == "auto":
        vendor = detect_vendor(sample, upload.filename) or ""

    if vendor not in ALL_VENDORS:
        os.remove(temp_path)
        return jsonify(
            {"error": "Could not determine vendor. Please select one manually."}
        ), 400

    # Resolve "cisco" (user-facing) or re-route "asa" to "ftd" if file is FTD
    if vendor in ("cisco", "asa"):
        vendor = "ftd" if is_ftd_config(sample) else "asa"

    detected_hostname = extract_hostname(vendor, sample)

    is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
    if not is_valid:
        os.remove(temp_path)
        return jsonify(
            {
                "error": f"Wrong vendor selected ({VENDOR_DISPLAY.get(vendor, vendor)}): {validation_msg}"
            }
        ), 400

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        # Compliance checks (license-gated; not applicable for AWS/Azure)
        license_warning = None
        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if not licensed:
                license_warning = (
                    "Compliance checks require a valid license. "
                    'Purchase one at <a href="https://shamrock13.gumroad.com/l/cashel" '
                    'target="_blank" rel="noopener">shamrock13.gumroad.com/l/cashel</a>. '
                    "Once purchased, enter your key using the Licensed/Unlicensed badge in the top-right corner."
                )
            else:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        report_filename = None
        if generate_pdf:
            report_name = f"cashel_report_{uuid.uuid4().hex[:8]}.pdf"
            report_path = os.path.join(REPORTS_FOLDER, report_name)
            generate_report(
                _findings_to_strings(findings),
                upload.filename,
                vendor,
                compliance,
                output_path=report_path,
                summary=summary,
            )
            report_filename = report_name

        # Optional archive save — skipped in demo mode
        archive_id = None
        if archive_it and not DEMO_MODE:
            archive_id, _ = save_audit(
                upload.filename,
                vendor,
                _findings_to_strings(findings),
                summary,
                config_path=temp_path,
                tag=tag,
            )

        # Activity log — skipped in demo mode
        if not DEMO_MODE:
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor,
                success=True,
                details={
                    "total": summary.get("total", 0),
                    "high": summary.get("high", 0),
                    "archived": archive_id is not None,
                },
            )

        return jsonify(
            {
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "summary": summary,
                "report": report_filename,
                "license_warning": license_warning,
                "detected_vendor": vendor,
                "detected_hostname": detected_hostname,
                "archive_id": archive_id,
            }
        )

    except Exception as e:
        if not DEMO_MODE:
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor or "unknown",
                success=False,
                error=str(e),
            )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@audit_bp.route("/diff", methods=["POST"])
@limiter.limit("30/minute")
def run_diff():
    if "config_a" not in request.files or "config_b" not in request.files:
        return jsonify(
            {"error": "Two config files required (config_a and config_b)"}
        ), 400
    if (
        request.files["config_a"].filename == ""
        or request.files["config_b"].filename == ""
    ):
        return jsonify({"error": "Both config files must be selected"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()

    # Early vendor allowlist check before touching disk.
    if vendor not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor}'."}), 400

    upload_a = request.files["config_a"]
    upload_b = request.files["config_b"]
    suffix_a = Path(upload_a.filename).suffix or ".txt"
    suffix_b = Path(upload_b.filename).suffix or ".txt"
    path_a = _make_temp_path(suffix_a)
    path_b = _make_temp_path(suffix_b)
    upload_a.save(path_a)
    upload_b.save(path_b)

    try:
        # Auto-detect or resolve cisco from the first file if needed
        if vendor in ("auto", "cisco", "asa"):
            with open(path_a, "r", errors="ignore") as f:
                sample = f.read(16384)
            if vendor == "auto":
                vendor = detect_vendor(sample, upload_a.filename) or ""
            else:
                vendor = "ftd" if is_ftd_config(sample) else "asa"

        if vendor not in ALL_VENDORS:
            return jsonify(
                {"error": "Could not determine vendor. Please select one manually."}
            ), 400

        result = diff_configs(vendor, path_a, path_b)
        result["vendor"] = vendor
        result["filename_a"] = upload_a.filename
        result["filename_b"] = upload_b.filename

        log_activity(
            ACTION_CONFIG_DIFF,
            f"{upload_a.filename} → {upload_b.filename}",
            vendor=vendor,
            success=True,
            details={
                "added": len(result.get("added", [])),
                "removed": len(result.get("removed", [])),
                "unchanged": len(result.get("unchanged", [])),
            },
        )
        return jsonify(result)

    except Exception as e:
        log_activity(
            ACTION_CONFIG_DIFF,
            f"{upload_a.filename} → {upload_b.filename}",
            vendor=vendor or "unknown",
            success=False,
            error=str(e),
        )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        for p in (path_a, path_b):
            if os.path.exists(p):
                os.remove(p)


@audit_bp.route("/connect", methods=["POST"])
@limiter.limit("10/minute")
@_require_role("admin", "auditor")
def live_connect():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "22").strip() or "22"
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    vendor = request.form.get("vendor", "").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    tag = request.form.get("tag", "").strip() or None

    if not host or not username or not vendor:
        return jsonify({"error": "host, username, and vendor are required"}), 400
    if vendor not in ("asa", "ftd", "cisco", "fortinet", "paloalto"):
        return jsonify(
            {
                "error": f"Live SSH not supported for vendor '{vendor}'. Supported: Cisco, Fortinet, Palo Alto Networks"
            }
        ), 400
    if vendor == "cisco":
        vendor = "asa"

    # PEM key-based auth (optional)
    pem_key_path = None
    pem_passphrase = request.form.get("pem_passphrase", "") or None
    pem_upload = request.files.get("pem_key")
    if pem_upload and pem_upload.filename:
        pem_path = _make_temp_path(".pem")
        pem_upload.save(pem_path)
        try:
            os.chmod(pem_path, 0o600)
        except OSError:
            pass
        pem_key_path = pem_path

    label = f"{vendor.upper()}@{host}"

    try:
        from cashel.ssh_connector import connect_and_pull

        _settings = get_settings()
        temp_path, _ = connect_and_pull(
            vendor,
            host,
            port,
            username,
            password,
            timeout=30,
            upload_folder=UPLOAD_FOLDER,
            host_key_policy=_settings.get("ssh_host_key_policy", "warn"),
            pem_key_path=pem_key_path,
            pem_passphrase=pem_passphrase,
        )
    except Exception as e:
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "port": port},
        )
        return jsonify({"error": f"Connection failed: {e}"}), 500
    finally:
        if pem_key_path and os.path.exists(pem_key_path):
            os.remove(pem_key_path)

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance and vendor not in ("aws", "azure", "gcp", "iptables", "nftables"):
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        # Save successful SSH audits to Audit History (store plain strings)
        archive_id, _ = save_audit(
            label,
            vendor,
            _findings_to_strings(findings),
            summary,
            config_path=temp_path,
            tag=tag,
        )

        # Log successful activity
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=True,
            details={
                "host": host,
                "port": port,
                "total": summary.get("total", 0),
                "high": summary.get("high", 0),
            },
        )

        return jsonify(
            {
                "findings": _findings_to_strings(findings),
                "enriched_findings": findings,
                "summary": summary,
                "detected_vendor": vendor,
                "host": host,
                "archive_id": archive_id,
            }
        )

    except Exception as e:
        log_activity(
            ACTION_SSH_CONNECT,
            label,
            vendor=vendor,
            success=False,
            error=str(e),
            details={"host": host, "port": port},
        )
        return jsonify(
            {
                "error": _err(
                    e,
                    "Audit failed. Check your configuration file and vendor selection.",
                )
            }
        ), 500
    finally:
        if "temp_path" in dir() and os.path.exists(temp_path):
            os.remove(temp_path)


@audit_bp.route("/bulk_audit", methods=["POST"])
@limiter.limit("10/minute")
@_require_role("admin", "auditor")
def bulk_audit():
    """Audit multiple config files in one request.

    Accepts: multipart/form-data with repeated field ``configs[]``.
    Optional shared fields: vendor (default auto), compliance, archive (1/0), tag.
    Returns: JSON list of per-file result objects.
    """
    uploads = request.files.getlist("configs[]")
    if not uploads or all(u.filename == "" for u in uploads):
        return jsonify({"error": "No config files uploaded"}), 400

    vendor_override = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    archive_it = request.form.get("archive") == "1"
    tag_prefix = request.form.get("tag", "").strip() or None

    # Early allowlist checks before processing any files.
    if vendor_override not in ("auto", *ALL_VENDORS):
        return jsonify({"error": f"Unknown vendor '{vendor_override}'."}), 400
    from cashel.schedule_store import VALID_FRAMEWORKS

    if compliance and compliance not in VALID_FRAMEWORKS:
        return jsonify({"error": f"Unknown compliance framework '{compliance}'."}), 400

    results = []

    for upload in uploads:
        if upload.filename == "":
            continue

        suffix = Path(upload.filename).suffix or ".txt"
        temp_path = _make_temp_path(suffix)
        upload.save(temp_path)

        result_entry = {
            "filename": upload.filename,
            "status": "error",
            "findings": [],
            "summary": {},
            "vendor": None,
            "archive_id": None,
            "error": None,
        }

        try:
            with open(temp_path, "r", errors="ignore") as f:
                sample = f.read(16384)

            vendor = vendor_override
            if vendor == "auto":
                vendor = detect_vendor(sample, upload.filename) or ""

            if vendor not in ALL_VENDORS:
                result_entry["error"] = "Could not determine vendor"
                results.append(result_entry)
                continue

            if vendor == "asa" and is_ftd_config(sample):
                vendor = "ftd"

            is_valid, validation_msg = validate_vendor_format(
                sample, upload.filename, vendor
            )
            if not is_valid:
                result_entry["error"] = validation_msg
                results.append(result_entry)
                continue

            findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

            if compliance and vendor not in (
                "aws",
                "azure",
                "gcp",
                "iptables",
                "nftables",
            ):
                licensed, _ = check_license()
                if licensed:
                    raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                    findings += [_wrap_compliance(c) for c in raw]

            findings = _sort_findings(findings)
            summary = _build_summary(findings)

            archive_id = None
            if archive_it:
                tag = (
                    f"{tag_prefix}/{upload.filename}" if tag_prefix else upload.filename
                )
                archive_id, _ = save_audit(
                    upload.filename,
                    vendor,
                    _findings_to_strings(findings),
                    summary,
                    config_path=temp_path,
                    tag=tag,
                )

            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor,
                success=True,
                details={
                    "bulk": True,
                    "total": summary.get("total", 0),
                    "high": summary.get("high", 0),
                    "archived": archive_id is not None,
                },
            )

            result_entry.update(
                {
                    "status": "ok",
                    "vendor": vendor,
                    "findings": _findings_to_strings(findings),
                    "enriched_findings": findings,
                    "summary": summary,
                    "archive_id": archive_id,
                }
            )

        except Exception as e:
            result_entry["error"] = str(e)
            log_activity(
                ACTION_FILE_AUDIT,
                upload.filename,
                vendor=vendor_override,
                success=False,
                error=str(e),
                details={"bulk": True},
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        results.append(result_entry)

    return jsonify(results)
