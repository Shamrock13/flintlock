import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from ciscoconfparse import CiscoConfParse

from .license import check_license, activate_license, deactivate_license
from .compliance import (
    check_cis_compliance, check_pci_compliance, check_nist_compliance,
    check_cis_compliance_pa, check_pci_compliance_pa, check_nist_compliance_pa,
    check_cis_compliance_forti, check_pci_compliance_forti, check_nist_compliance_forti,
    check_cis_compliance_pf, check_pci_compliance_pf, check_nist_compliance_pf,
)
from .paloalto import audit_paloalto, parse_paloalto
from .fortinet import audit_fortinet
from .pfsense import audit_pfsense
from .aws import audit_aws_sg
from .azure import audit_azure_nsg
from .reporter import generate_report
from .diff import diff_configs
from .archive import save_audit, list_archive, get_entry, delete_entry, compare_entries
from .activity_log import (
    log_activity, list_activity, delete_activity_entry, clear_activity,
    ACTION_FILE_AUDIT, ACTION_SSH_CONNECT, ACTION_CONFIG_DIFF, ACTION_COMPARISON,
)

UPLOAD_FOLDER    = os.environ.get("UPLOAD_FOLDER",    "/tmp/flintlock_uploads")
REPORTS_FOLDER   = os.environ.get("REPORTS_FOLDER",   "/tmp/flintlock_reports")
ARCHIVE_FOLDER   = os.environ.get("ARCHIVE_FOLDER",   "/tmp/flintlock_archive")
ACTIVITY_FOLDER  = os.environ.get("ACTIVITY_FOLDER",  "/tmp/flintlock_activity")

for _d in (UPLOAD_FOLDER, REPORTS_FOLDER, ARCHIVE_FOLDER, ACTIVITY_FOLDER):
    os.makedirs(_d, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


VENDOR_DISPLAY = {
    "asa":      "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense":  "pfSense",
    "aws":      "AWS Security Group",
    "azure":    "Azure NSG",
}

ALL_VENDORS = set(VENDOR_DISPLAY)


# ── Vendor auto-detection ─────────────────────────────────────────────────────

def detect_vendor(content: str, filename: str) -> str | None:
    """Infer firewall vendor from file content and filename."""
    filename_lower = filename.lower()
    content_lower  = content.lower()
    stripped       = content.strip()

    # JSON-based: AWS or Azure
    if stripped.startswith("{") or stripped.startswith("[") or filename_lower.endswith(".json"):
        try:
            import json
            data = json.loads(content[:8192])  # partial parse for detection
            if isinstance(data, dict):
                if "SecurityGroups" in data or "GroupId" in data or "IpPermissions" in data:
                    return "aws"
                if "securityRules" in data or "defaultSecurityRules" in data:
                    return "azure"
                if isinstance(data.get("value"), list):
                    # Could be az network nsg list output
                    if data["value"] and "securityRules" in data["value"][0]:
                        return "azure"
            elif isinstance(data, list) and data:
                first = data[0]
                if "GroupId" in first or "IpPermissions" in first:
                    return "aws"
                if "securityRules" in first or "defaultSecurityRules" in first:
                    return "azure"
        except Exception:
            pass

    # XML-based: pfSense or Palo Alto
    if stripped.startswith("<") or filename_lower.endswith(".xml"):
        if "<pfsense>" in content_lower or ("<filter>" in content_lower and "<rule>" in content_lower):
            return "pfsense"
        if any(k in content_lower for k in ("<devices>", "<vsys>", "<security>", "<rulebase>")):
            return "paloalto"

    # Text-based: Fortinet
    if "config firewall policy" in content_lower or (
        "set srcintf" in content_lower and "set dstintf" in content_lower
    ):
        return "fortinet"

    # Text-based: Cisco ASA
    if "access-list" in content_lower and any(k in content_lower for k in ("permit", "deny")):
        return "asa"

    return None


def validate_vendor_format(content: str, filename: str, vendor: str) -> tuple[bool, str]:
    """Return (is_valid, error_message). Ensures the file actually matches the vendor format."""
    content_lower = content.lower()
    is_xml  = content.strip().startswith("<") or filename.lower().endswith(".xml")
    is_json = content.strip().startswith(("{", "[")) or filename.lower().endswith(".json")

    if vendor == "asa":
        if is_xml or is_json:
            return False, "Cisco configs are text-based, but this file appears to be XML or JSON."
        if "access-list" not in content_lower:
            return False, "No Cisco access-list statements found. Check vendor selection."

    elif vendor == "paloalto":
        if not is_xml:
            return False, "Palo Alto configs are XML-based, but this file is not XML."
        if not any(m in content_lower for m in ("<devices>", "<vsys>", "<security>", "<rulebase>")):
            return False, "This XML does not contain Palo Alto Networks configuration markers."

    elif vendor == "fortinet":
        if is_xml or is_json:
            return False, "Fortinet configs are text-based, but this file appears to be XML or JSON."
        if not any(m in content_lower for m in ("config firewall policy", "set srcintf", "set dstintf")):
            return False, "No Fortinet firewall policy statements found. Check vendor selection."

    elif vendor == "pfsense":
        if not is_xml:
            return False, "pfSense configs are XML-based, but this file is not XML."
        if "<pfsense>" not in content_lower:
            return False, "pfSense root element <pfsense> not found in this XML file."

    elif vendor == "aws":
        if not is_json:
            return False, "AWS Security Group exports are JSON. Please upload a .json file."

    elif vendor == "azure":
        if not is_json:
            return False, "Azure NSG exports are JSON. Please upload a .json file."

    else:
        return False, f"Unknown vendor: {vendor}"

    return True, ""


def _sort_findings(findings: list) -> list:
    def priority(f):
        is_comp = any(x in f for x in ("PCI-", "CIS-", "NIST-"))
        if "[HIGH]"   in f and not is_comp: return 0
        if "[MEDIUM]" in f and not is_comp: return 1
        if "HIGH"     in f and is_comp:     return 2
        if "MEDIUM"   in f and is_comp:     return 3
        return 4
    return sorted(findings, key=priority)


# ── ASA audit helpers ─────────────────────────────────────────────────────────

def _check_any_any(parse):
    return [f"[HIGH] Overly permissive rule found: {r.text}"
            for r in parse.find_objects(r"access-list.*permit.*any any")]


def _check_missing_logging(parse):
    return [f"[MEDIUM] Permit rule missing logging: {r.text}"
            for r in parse.find_objects(r"access-list.*permit") if "log" not in r.text]


def _check_deny_all(parse):
    return [] if parse.find_objects(r"access-list.*deny ip any any") else [
        "[HIGH] No explicit deny-all rule found at end of ACL"
    ]


def _check_redundant_rules(parse):
    findings, seen = [], []
    for rule in parse.find_objects(r"access-list.*permit"):
        text_clean = rule.text.strip().lower().replace(" log", "").strip()
        if text_clean in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: {rule.text}")
        else:
            seen.append(text_clean)
    return findings


def _audit_asa(filepath):
    parse = CiscoConfParse(filepath, ignore_blank_lines=False)
    findings = (
        _check_any_any(parse)
        + _check_missing_logging(parse)
        + _check_deny_all(parse)
        + _check_redundant_rules(parse)
    )
    return findings, parse


def _build_summary(findings):
    def _count(tag):
        return len([f for f in findings if tag in f])
    high   = [f for f in findings if "[HIGH]"   in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
    medium = [f for f in findings if "[MEDIUM]" in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
    return {
        "high":        len(high),
        "medium":      len(medium),
        "pci_high":    _count("PCI-HIGH"),
        "pci_medium":  _count("PCI-MEDIUM"),
        "cis_high":    _count("CIS-HIGH"),
        "cis_medium":  _count("CIS-MEDIUM"),
        "nist_high":   _count("NIST-HIGH"),
        "nist_medium": _count("NIST-MEDIUM"),
        "total":       len(findings),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    licensed, license_info = check_license()
    return render_template("index.html", licensed=licensed, license_info=license_info)


@app.route("/audit", methods=["POST"])
def run_audit():
    if "config" not in request.files or request.files["config"].filename == "":
        return jsonify({"error": "No config file uploaded"}), 400

    vendor       = request.form.get("vendor", "auto").strip().lower()
    compliance   = request.form.get("compliance", "").strip().lower() or None
    generate_pdf = request.form.get("report") == "1"
    archive_it   = request.form.get("archive") == "1"

    upload = request.files["config"]
    suffix = Path(upload.filename).suffix or ".txt"
    temp_name = f"{uuid.uuid4()}{suffix}"
    temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
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
        return jsonify({"error": "Could not determine vendor. Please select one manually."}), 400

    is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
    if not is_valid:
        os.remove(temp_path)
        return jsonify({"error": f"Wrong vendor selected ({VENDOR_DISPLAY.get(vendor, vendor)}): {validation_msg}"}), 400

    try:
        findings    = []
        extra_data  = None
        parse       = None

        if vendor == "asa":
            findings, parse = _audit_asa(temp_path)
        elif vendor == "paloalto":
            findings = audit_paloalto(temp_path)
        elif vendor == "fortinet":
            findings, extra_data = audit_fortinet(temp_path)
        elif vendor == "pfsense":
            findings, extra_data = audit_pfsense(temp_path)
        elif vendor == "aws":
            findings, extra_data = audit_aws_sg(temp_path)
        elif vendor == "azure":
            findings, extra_data = audit_azure_nsg(temp_path)

        # Compliance checks (license-gated; not applicable for AWS/Azure)
        license_warning = None
        if compliance and vendor not in ("aws", "azure"):
            licensed, _ = check_license()
            if not licensed:
                license_warning = (
                    "Compliance checks require a valid license. "
                    'Purchase one at <a href="https://shamrock13.gumroad.com/l/flintlock" '
                    'target="_blank" rel="noopener">shamrock13.gumroad.com/l/flintlock</a>. '
                    "Once purchased, enter your key using the Licensed/Unlicensed badge in the top-right corner."
                )
            else:
                fn_map = {}
                if vendor == "asa":
                    fn_map = {"cis": check_cis_compliance, "pci": check_pci_compliance, "nist": check_nist_compliance}
                    fn = fn_map.get(compliance)
                    if fn:
                        findings += fn(parse)
                elif vendor == "paloalto":
                    rules, _ = parse_paloalto(temp_path)
                    fn_map = {"cis": check_cis_compliance_pa, "pci": check_pci_compliance_pa, "nist": check_nist_compliance_pa}
                    fn = fn_map.get(compliance)
                    if fn:
                        findings += fn(rules)
                elif vendor == "fortinet":
                    fn_map = {"cis": check_cis_compliance_forti, "pci": check_pci_compliance_forti, "nist": check_nist_compliance_forti}
                    fn = fn_map.get(compliance)
                    if fn and extra_data is not None:
                        findings += fn(extra_data)
                elif vendor == "pfsense":
                    fn_map = {"cis": check_cis_compliance_pf, "pci": check_pci_compliance_pf, "nist": check_nist_compliance_pf}
                    fn = fn_map.get(compliance)
                    if fn and extra_data is not None:
                        findings += fn(extra_data)

        report_filename = None
        if generate_pdf:
            report_name = f"flintlock_report_{uuid.uuid4().hex[:8]}.pdf"
            report_path = os.path.join(REPORTS_FOLDER, report_name)
            generate_report(findings, upload.filename, vendor, compliance, output_path=report_path)
            report_filename = report_name

        findings = _sort_findings(findings)
        summary  = _build_summary(findings)

        # Optional archive save
        archive_id = None
        if archive_it:
            archive_id, _ = save_audit(upload.filename, vendor, findings, summary, config_path=temp_path)

        # Always log activity
        log_activity(
            ACTION_FILE_AUDIT, upload.filename, vendor=vendor, success=True,
            details={"total": summary.get("total", 0), "high": summary.get("high", 0),
                     "archived": archive_id is not None},
        )

        return jsonify({
            "findings":        findings,
            "summary":         summary,
            "report":          report_filename,
            "license_warning": license_warning,
            "detected_vendor": vendor,
            "archive_id":      archive_id,
        })

    except Exception as e:
        log_activity(ACTION_FILE_AUDIT, upload.filename, vendor=vendor or "unknown",
                     success=False, error=str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ── Config diff ───────────────────────────────────────────────────────────────

@app.route("/diff", methods=["POST"])
def run_diff():
    if "config_a" not in request.files or "config_b" not in request.files:
        return jsonify({"error": "Two config files required (config_a and config_b)"}), 400
    if request.files["config_a"].filename == "" or request.files["config_b"].filename == "":
        return jsonify({"error": "Both config files must be selected"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()

    upload_a = request.files["config_a"]
    upload_b = request.files["config_b"]
    suffix_a = Path(upload_a.filename).suffix or ".txt"
    suffix_b = Path(upload_b.filename).suffix or ".txt"
    path_a = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}{suffix_a}")
    path_b = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}{suffix_b}")
    upload_a.save(path_a)
    upload_b.save(path_b)

    try:
        # Auto-detect from the first file if needed
        if vendor == "auto":
            with open(path_a, "r", errors="ignore") as f:
                sample = f.read(16384)
            vendor = detect_vendor(sample, upload_a.filename) or ""

        if vendor not in ALL_VENDORS:
            return jsonify({"error": "Could not determine vendor. Please select one manually."}), 400

        if vendor in ("aws", "azure"):
            return jsonify({"error": "Config diff is not supported for cloud vendors (AWS/Azure). Use the audit tool separately."}), 400

        result = diff_configs(vendor, path_a, path_b)
        result["vendor"]     = vendor
        result["filename_a"] = upload_a.filename
        result["filename_b"] = upload_b.filename

        log_activity(ACTION_CONFIG_DIFF,
                     f"{upload_a.filename} → {upload_b.filename}",
                     vendor=vendor, success=True,
                     details={"added": len(result.get("added", [])),
                               "removed": len(result.get("removed", [])),
                               "unchanged": len(result.get("unchanged", []))})
        return jsonify(result)

    except Exception as e:
        log_activity(ACTION_CONFIG_DIFF,
                     f"{upload_a.filename} → {upload_b.filename}",
                     vendor=vendor or "unknown", success=False, error=str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        for p in (path_a, path_b):
            if os.path.exists(p):
                os.remove(p)


# ── Live SSH connect ──────────────────────────────────────────────────────────

@app.route("/connect", methods=["POST"])
def live_connect():
    host       = request.form.get("host", "").strip()
    port       = request.form.get("port", "22").strip() or "22"
    username   = request.form.get("username", "").strip()
    password   = request.form.get("password", "")
    vendor     = request.form.get("vendor", "").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None

    if not host or not username or not vendor:
        return jsonify({"error": "host, username, and vendor are required"}), 400
    if vendor not in ("asa", "fortinet", "paloalto"):
        return jsonify({"error": f"Live SSH not supported for vendor '{vendor}'. Supported: asa, fortinet, paloalto"}), 400

    label = f"{vendor.upper()}@{host}"

    try:
        from .ssh_connector import connect_and_pull
        temp_path, _ = connect_and_pull(
            vendor, host, port, username, password,
            timeout=30, upload_folder=UPLOAD_FOLDER
        )
    except Exception as e:
        # Log the failed attempt to activity log only — do NOT save to Audit History
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=False, error=str(e),
                     details={"host": host, "port": port})
        return jsonify({"error": f"Connection failed: {e}"}), 500

    try:
        findings   = []
        extra_data = None
        parse      = None

        if vendor == "asa":
            findings, parse = _audit_asa(temp_path)
        elif vendor == "paloalto":
            findings = audit_paloalto(temp_path)
        elif vendor == "fortinet":
            findings, extra_data = audit_fortinet(temp_path)

        if compliance and vendor not in ("aws", "azure"):
            licensed, _ = check_license()
            if licensed:
                if vendor == "asa":
                    fn_map = {"cis": check_cis_compliance, "pci": check_pci_compliance, "nist": check_nist_compliance}
                    fn = fn_map.get(compliance)
                    if fn:
                        findings += fn(parse)
                elif vendor == "paloalto":
                    rules, _ = parse_paloalto(temp_path)
                    fn_map = {"cis": check_cis_compliance_pa, "pci": check_pci_compliance_pa, "nist": check_nist_compliance_pa}
                    fn = fn_map.get(compliance)
                    if fn:
                        findings += fn(rules)
                elif vendor == "fortinet":
                    fn_map = {"cis": check_cis_compliance_forti, "pci": check_pci_compliance_forti, "nist": check_nist_compliance_forti}
                    fn = fn_map.get(compliance)
                    if fn and extra_data is not None:
                        findings += fn(extra_data)

        findings = _sort_findings(findings)
        summary  = _build_summary(findings)

        # Save successful SSH audits to Audit History
        archive_id, _ = save_audit(label, vendor, findings, summary, config_path=temp_path)

        # Log successful activity
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=True,
                     details={"host": host, "port": port,
                              "total": summary.get("total", 0), "high": summary.get("high", 0)})

        return jsonify({
            "findings":        findings,
            "summary":         summary,
            "detected_vendor": vendor,
            "host":            host,
            "archive_id":      archive_id,
        })

    except Exception as e:
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=False, error=str(e),
                     details={"host": host, "port": port})
        return jsonify({"error": str(e)}), 500
    finally:
        if "temp_path" in dir() and os.path.exists(temp_path):
            os.remove(temp_path)


# ── Archive API ───────────────────────────────────────────────────────────────

@app.route("/archive", methods=["GET"])
def archive_list():
    return jsonify(list_archive())


@app.route("/archive/save", methods=["POST"])
def archive_save():
    """Manually save the most recent audit result to the archive."""
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "unknown")
    vendor   = data.get("vendor", "unknown")
    findings = data.get("findings", [])
    summary  = data.get("summary", {})
    if not findings and not summary:
        return jsonify({"error": "No audit data to save"}), 400
    entry_id, entry = save_audit(filename, vendor, findings, summary)
    return jsonify({"id": entry_id, "entry": entry})


@app.route("/archive/<entry_id>", methods=["GET"])
def archive_get(entry_id):
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@app.route("/archive/<entry_id>", methods=["DELETE"])
def archive_delete(entry_id):
    deleted = delete_entry(entry_id)
    return jsonify({"deleted": deleted})


@app.route("/archive/compare", methods=["POST"])
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


# ── Activity Log API ──────────────────────────────────────────────────────────

@app.route("/activity", methods=["GET"])
def activity_list():
    limit = int(request.args.get("limit", 200))
    return jsonify(list_activity(limit=limit))


@app.route("/activity/<event_id>", methods=["DELETE"])
def activity_delete(event_id):
    deleted = delete_activity_entry(event_id)
    return jsonify({"deleted": deleted})


@app.route("/activity/clear", methods=["POST"])
def activity_clear():
    count = clear_activity()
    return jsonify({"cleared": count})


# ── Reports / License ─────────────────────────────────────────────────────────

@app.route("/reports/<filename>")
def download_report(filename):
    if ".." in filename or "/" in filename:
        return "Not found", 404
    path = os.path.join(REPORTS_FOLDER, filename)
    if not os.path.exists(path):
        return "Report not found", 404
    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/license/activate", methods=["POST"])
def license_activate():
    key = request.form.get("key", "").strip()
    success, message = activate_license(key)
    return jsonify({"success": success, "message": message})


@app.route("/license/deactivate", methods=["POST"])
def license_deactivate():
    success, message = deactivate_license()
    return jsonify({"success": success, "message": message})


@app.route("/license/status")
def license_status():
    licensed, info = check_license()
    return jsonify({"licensed": licensed, "info": info})


def main():
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
