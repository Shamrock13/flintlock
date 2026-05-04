from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from .export import TOOL_VERSION
from .html_pdf import render_template_to_pdf


VENDOR_DISPLAY = {
    "asa": "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense": "pfSense",
    "aws": "AWS Security Group",
    "azure": "Azure NSG",
}


def report_sidecar_path(output_path: str) -> str:
    """Return the JSON sidecar path for a generated PDF report."""
    root, _ext = os.path.splitext(output_path)
    return f"{root}.json"


def write_report_sidecar(
    output_path: str,
    *,
    findings,
    filename: str,
    vendor: str,
    compliance=None,
    summary=None,
    report_id: str | None = None,
    generated_at: str | None = None,
) -> str:
    """Persist metadata used by the HTML report viewer next to the PDF."""
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    payload = {
        "report_id": report_id or os.path.splitext(os.path.basename(output_path))[0],
        "pdf_filename": os.path.basename(output_path),
        "filename": filename,
        "vendor": vendor,
        "compliance": compliance,
        "summary": summary or {},
        "findings": findings or [],
        "generated_at": generated,
    }
    path = report_sidecar_path(output_path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def compliance_label(value) -> str:
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


def _finding_message(finding) -> str:
    return finding.get("message", "") if isinstance(finding, dict) else str(finding)


def _finding_severity(finding) -> str:
    if isinstance(finding, dict) and finding.get("severity"):
        return str(finding["severity"]).upper()
    msg = _finding_message(finding).upper()
    if "[CRITICAL]" in msg or "CRITICAL" in msg:
        return "CRITICAL"
    if "[HIGH]" in msg or "HIGH" in msg:
        return "HIGH"
    if "[MEDIUM]" in msg or "MEDIUM" in msg:
        return "MEDIUM"
    if "[LOW]" in msg or "LOW" in msg:
        return "LOW"
    return "INFO"


def _finding_title(message: str) -> str:
    text = str(message or "")
    for tag in ("[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]", "[INFO]"):
        text = text.replace(tag, "")
    return text.strip(" :-") or "Finding"


def _finding_commands(finding) -> str:
    if not isinstance(finding, dict):
        return ""
    commands = finding.get("suggested_commands")
    if isinstance(commands, list):
        return "\n".join(str(command) for command in commands if command)
    return str(commands or "")


def _finding_metadata(finding) -> str:
    if not isinstance(finding, dict) or not isinstance(finding.get("metadata"), dict):
        return ""
    metadata = {
        k: v for k, v in finding["metadata"].items() if not str(k).startswith("_")
    }
    return json.dumps(metadata, sort_keys=True) if metadata else ""


def finding_rows(findings) -> list[dict[str, Any]]:
    rows = []
    for idx, finding in enumerate(findings or [], start=1):
        msg = _finding_message(finding)
        sev = _finding_severity(finding)
        rows.append(
            {
                "index": idx,
                "severity": sev.title(),
                "severity_key": sev.lower(),
                "id": finding.get("id", "") if isinstance(finding, dict) else "",
                "vendor": finding.get("vendor", "")
                if isinstance(finding, dict)
                else "",
                "title": (
                    finding.get("title")
                    if isinstance(finding, dict) and finding.get("title")
                    else _finding_title(msg)
                ),
                "message": msg,
                "category": (
                    finding.get("category", "") if isinstance(finding, dict) else ""
                ),
                "remediation": (
                    finding.get("remediation", "") if isinstance(finding, dict) else ""
                ),
                "evidence": finding.get("evidence", "")
                if isinstance(finding, dict)
                else "",
                "affected_object": (
                    finding.get("affected_object", "")
                    if isinstance(finding, dict)
                    else ""
                ),
                "rule_name": (
                    finding.get("rule_name", "") if isinstance(finding, dict) else ""
                ),
                "confidence": (
                    finding.get("confidence", "") if isinstance(finding, dict) else ""
                ),
                "verification": (
                    finding.get("verification", "") if isinstance(finding, dict) else ""
                ),
                "rollback": (
                    finding.get("rollback", "") if isinstance(finding, dict) else ""
                ),
                "suggested_commands": _finding_commands(finding),
                "metadata": _finding_metadata(finding),
            }
        )
    return rows


def _summary_from_findings(findings, summary=None) -> dict[str, Any]:
    summary = summary or {}
    if summary:
        return {
            "critical": int(summary.get("critical", 0) or 0),
            "high": int(summary.get("high", 0) or 0),
            "medium": int(summary.get("medium", 0) or 0),
            "low": int(summary.get("low", 0) or 0),
            "total": int(summary.get("total", len(findings or [])) or 0),
            "score": summary.get("score"),
        }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings or []:
        sev = _finding_severity(finding)
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())
    score = max(
        0, 100 - counts["CRITICAL"] * 20 - counts["HIGH"] * 10 - counts["MEDIUM"] * 3
    )
    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total": total,
        "score": score,
    }


def _fmt_generated(value=None) -> tuple[str, str]:
    dt = None
    if value:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            dt = None
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%B %d, %Y").replace(" 0", " "), dt.strftime("%H:%M:%S UTC")


def build_audit_report_context(
    *,
    findings,
    filename: str,
    vendor: str,
    compliance=None,
    summary=None,
    pdf_filename: str | None = None,
    report_id: str | None = None,
    generated_at: str | None = None,
    fallback: bool = False,
) -> dict[str, Any]:
    rows = finding_rows(findings)
    generated_date, generated_time = _fmt_generated(generated_at)
    vendor_label = VENDOR_DISPLAY.get(vendor, vendor.upper() if vendor else "Unknown")
    return {
        "fallback": fallback,
        "pdf_filename": pdf_filename or "audit_report.pdf",
        "report_id": report_id or "generated-report",
        "audit_filename": filename or "Firewall audit",
        "vendor": vendor,
        "vendor_label": vendor_label,
        "compliance": compliance_label(compliance),
        "summary": _summary_from_findings(findings, summary),
        "generated_date": generated_date,
        "generated_time": generated_time,
        "findings": rows,
        "tool_version": TOOL_VERSION,
    }


def generate_report(
    findings, filename, vendor, compliance=None, output_path="report.pdf", summary=None
):
    """Generate a modern HTML-rendered audit report PDF."""
    context = build_audit_report_context(
        findings=findings,
        filename=filename,
        vendor=vendor,
        compliance=compliance,
        summary=summary,
        pdf_filename=os.path.basename(output_path),
        report_id=os.path.splitext(os.path.basename(output_path))[0],
    )
    return render_template_to_pdf("audit_report_pdf.html", output_path, report=context)


def generate_cover_pdf(
    entry: dict, output_path: str, compliance: str | None = None
) -> str:
    """Generate a modern HTML-rendered evidence bundle cover PDF."""
    filename = entry.get("filename", "")
    vendor = entry.get("vendor", "unknown")
    summary = _summary_from_findings(entry.get("findings", []), entry.get("summary"))
    generated_date, generated_time = _fmt_generated(entry.get("timestamp"))
    context = {
        "filename": filename or "Firewall audit",
        "vendor": vendor,
        "vendor_label": VENDOR_DISPLAY.get(vendor, vendor.upper()),
        "compliance": compliance_label(compliance or entry.get("compliance")),
        "summary": summary,
        "generated_date": generated_date,
        "generated_time": generated_time,
        "bundle_id": os.path.splitext(os.path.basename(output_path))[0],
        "tool_version": TOOL_VERSION,
        "items": [
            "audit_report.pdf - Full PDF audit report",
            "findings.csv - Findings in CSV format",
            "findings.json - Findings in Cashel JSON format",
            "findings.sarif - Findings in SARIF 2.1.0 format",
            "cover.pdf - This cover page",
        ],
    }
    return render_template_to_pdf("bundle_cover_pdf.html", output_path, cover=context)
