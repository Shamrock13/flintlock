import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
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
from .reporter import generate_report

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/flintlock_uploads")
REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/flintlock_reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


VENDOR_DISPLAY = {
    "asa":       "Cisco",
    "paloalto":  "Palo Alto Networks",
    "fortinet":  "Fortinet",
    "pfsense":   "pfSense",
}


# --- Vendor auto-detection and validation ---

def detect_vendor(content: str, filename: str) -> str | None:
    """Infer firewall vendor from file content and filename."""
    filename_lower = filename.lower()
    content_lower = content.lower()
    stripped = content.strip()

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
    is_xml = content.strip().startswith("<") or filename.lower().endswith(".xml")

    if vendor == "asa":
        if is_xml:
            return False, "Cisco configs are text-based, but this file appears to be XML."
        if "access-list" not in content_lower:
            return False, "No Cisco access-list statements found. Check vendor selection."

    elif vendor == "paloalto":
        if not is_xml:
            return False, "Palo Alto Networks configs are XML-based, but this file is not XML."
        pa_markers = ("<devices>", "<vsys>", "<security>", "<rulebase>")
        if not any(m in content_lower for m in pa_markers):
            return False, "This XML does not contain Palo Alto Networks configuration markers."

    elif vendor == "fortinet":
        if is_xml:
            return False, "Fortinet configs are text-based, but this file appears to be XML."
        forti_markers = ("config firewall policy", "set srcintf", "set dstintf")
        if not any(m in content_lower for m in forti_markers):
            return False, "No Fortinet firewall policy statements found. Check vendor selection."

    elif vendor == "pfsense":
        if not is_xml:
            return False, "pfSense configs are XML-based, but this file is not XML."
        if "<pfsense>" not in content_lower:
            return False, "pfSense root element <pfsense> not found in this XML file."

    else:
        return False, f"Unknown vendor: {vendor}"

    return True, ""


def _sort_findings(findings: list) -> list:
    """Sort findings: base HIGH → base MEDIUM → compliance HIGH → compliance MEDIUM → other."""
    def priority(f):
        is_comp = any(x in f for x in ("PCI-", "CIS-", "NIST-"))
        if "[HIGH]"   in f and not is_comp: return 0
        if "[MEDIUM]" in f and not is_comp: return 1
        if "HIGH"     in f and is_comp:     return 2
        if "MEDIUM"   in f and is_comp:     return 3
        return 4
    return sorted(findings, key=priority)


# --- ASA audit helpers (mirrors main.py logic) ---

def _check_any_any(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit.*any any"):
        findings.append(f"[HIGH] Overly permissive rule found: {rule.text}")
    return findings


def _check_missing_logging(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[MEDIUM] Permit rule missing logging: {rule.text}")
    return findings


def _check_deny_all(parse):
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        return ["[HIGH] No explicit deny-all rule found at end of ACL"]
    return []


def _check_redundant_rules(parse):
    findings = []
    seen = []
    for rule in parse.find_objects(r"access-list.*permit"):
        text_clean = rule.text.strip().lower().replace(" log", "").strip()
        if text_clean in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: {rule.text}")
        else:
            seen.append(text_clean)
    return findings


def _audit_asa(filepath):
    parse = CiscoConfParse(filepath, ignore_blank_lines=False)
    findings = []
    findings += _check_any_any(parse)
    findings += _check_missing_logging(parse)
    findings += _check_deny_all(parse)
    findings += _check_redundant_rules(parse)
    return findings, parse


def _build_summary(findings):
    high = [f for f in findings if "[HIGH]" in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
    medium = [f for f in findings if "[MEDIUM]" in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
    pci_high = [f for f in findings if "PCI-HIGH" in f]
    pci_medium = [f for f in findings if "PCI-MEDIUM" in f]
    cis_high = [f for f in findings if "CIS-HIGH" in f]
    cis_medium = [f for f in findings if "CIS-MEDIUM" in f]
    nist_high = [f for f in findings if "NIST-HIGH" in f]
    nist_medium = [f for f in findings if "NIST-MEDIUM" in f]
    return {
        "high": len(high),
        "medium": len(medium),
        "pci_high": len(pci_high),
        "pci_medium": len(pci_medium),
        "cis_high": len(cis_high),
        "cis_medium": len(cis_medium),
        "nist_high": len(nist_high),
        "nist_medium": len(nist_medium),
        "total": len(findings),
    }


# --- Routes ---

@app.route("/")
def index():
    licensed, license_info = check_license()
    return render_template("index.html", licensed=licensed, license_info=license_info)


@app.route("/audit", methods=["POST"])
def run_audit():
    if "config" not in request.files or request.files["config"].filename == "":
        return jsonify({"error": "No config file uploaded"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    generate_pdf = request.form.get("report") == "1"

    # Save upload to temp file first (needed for detection/validation)
    upload = request.files["config"]
    suffix = Path(upload.filename).suffix or ".txt"
    temp_name = f"{uuid.uuid4()}{suffix}"
    temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
    upload.save(temp_path)

    # Read a sample for detection and validation (one read, used for both)
    try:
        with open(temp_path, "r", errors="ignore") as f:
            sample = f.read(16384)
    except Exception:
        sample = ""

    # Auto-detect vendor from file contents
    if vendor == "auto":
        vendor = detect_vendor(sample, upload.filename) or ""

    if vendor not in ("asa", "paloalto", "fortinet", "pfsense"):
        os.remove(temp_path)
        return jsonify({"error": "Could not determine vendor. Please select one manually."}), 400

    # Validate the file actually matches the chosen vendor's format
    is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
    if not is_valid:
        os.remove(temp_path)
        vendor_name = VENDOR_DISPLAY.get(vendor, vendor)
        return jsonify({"error": f"Wrong vendor selected ({vendor_name}): {validation_msg}"}), 400

    try:
        # Run audit
        findings = []
        extra_data = None  # for fortinet/pfsense policies/rules

        if vendor == "asa":
            findings, parse = _audit_asa(temp_path)
        elif vendor == "paloalto":
            findings = audit_paloalto(temp_path)
        elif vendor == "fortinet":
            findings, extra_data = audit_fortinet(temp_path)
        elif vendor == "pfsense":
            findings, extra_data = audit_pfsense(temp_path)

        # Run compliance checks (requires license)
        compliance_findings = []
        license_warning = None
        if compliance:
            licensed, lic_msg = check_license()
            if not licensed:
                license_warning = (
                    "Compliance checks require a valid license. "
                    'Purchase one at <a href="https://shamrock13.gumroad.com/l/flintlock" target="_blank" rel="noopener">shamrock13.gumroad.com/l/flintlock</a>. '
                    "Once purchased, enter your key using the Licensed/Unlicensed badge in the top-right corner of the app."
                )
            else:
                if vendor == "asa":
                    fn_map = {"cis": check_cis_compliance, "pci": check_pci_compliance, "nist": check_nist_compliance}
                    fn = fn_map.get(compliance)
                    if fn:
                        compliance_findings = fn(parse)
                elif vendor == "paloalto":
                    rules, _ = parse_paloalto(temp_path)
                    fn_map = {"cis": check_cis_compliance_pa, "pci": check_pci_compliance_pa, "nist": check_nist_compliance_pa}
                    fn = fn_map.get(compliance)
                    if fn:
                        compliance_findings = fn(rules)
                elif vendor == "fortinet":
                    fn_map = {"cis": check_cis_compliance_forti, "pci": check_pci_compliance_forti, "nist": check_nist_compliance_forti}
                    fn = fn_map.get(compliance)
                    if fn and extra_data is not None:
                        compliance_findings = fn(extra_data)
                elif vendor == "pfsense":
                    fn_map = {"cis": check_cis_compliance_pf, "pci": check_pci_compliance_pf, "nist": check_nist_compliance_pf}
                    fn = fn_map.get(compliance)
                    if fn and extra_data is not None:
                        compliance_findings = fn(extra_data)
                findings += compliance_findings

        # Generate PDF report if requested
        report_filename = None
        if generate_pdf:
            report_name = f"flintlock_report_{uuid.uuid4().hex[:8]}.pdf"
            report_path = os.path.join(REPORTS_FOLDER, report_name)
            generate_report(findings, upload.filename, vendor, compliance, output_path=report_path)
            report_filename = report_name

        findings = _sort_findings(findings)
        summary = _build_summary(findings)

        return jsonify({
            "findings": findings,
            "summary": summary,
            "report": report_filename,
            "license_warning": license_warning,
            "detected_vendor": vendor,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/reports/<filename>")
def download_report(filename):
    # Safety: only allow safe filenames with no path traversal
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
