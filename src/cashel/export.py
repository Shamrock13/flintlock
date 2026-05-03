"""Serialize audit findings to JSON, CSV, and SARIF 2.1.0 formats.

Handles both enriched finding dicts (severity/category/message/remediation)
and plain-string findings stored in the archive (e.g. "[HIGH] No deny-all…").
"""

import csv
import io
import json

TOOL_NAME = "Cashel"
TOOL_VERSION = "2.0.0"
TOOL_INFO_URI = "https://github.com/Shamrock13/cashel"


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get((severity or "").upper(), "warning")


def _parse_plain(finding) -> tuple[str, str, str, str]:
    """Return (severity, category, message, remediation) for a finding."""
    if isinstance(finding, dict):
        return (
            finding.get("severity") or "",
            finding.get("category") or "",
            finding.get("message") or "",
            finding.get("remediation") or "",
        )
    msg = str(finding)
    sev = "HIGH" if "[HIGH]" in msg else ("MEDIUM" if "[MEDIUM]" in msg else "")
    return sev, "", msg, ""


def _field(finding, key: str) -> str:
    if isinstance(finding, dict):
        return str(finding.get(key) or "")
    return ""


# ── JSON ─────────────────────────────────────────────────────────────────────


def to_json(entry: dict) -> str:
    """Serialize an audit entry to Cashel JSON format."""
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "filename": entry.get("filename", ""),
        "vendor": entry.get("vendor", ""),
        "timestamp": entry.get("timestamp", ""),
        "tag": entry.get("tag", ""),
        "summary": entry.get("summary", {}),
        "findings": entry.get("findings", []),
    }
    return json.dumps(payload, indent=2)


# ── CSV ──────────────────────────────────────────────────────────────────────


def to_csv(entry: dict) -> str:
    """Serialize findings to CSV with backward-compatible core columns."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow(
        ["id", "title", "severity", "category", "message", "evidence", "remediation"]
    )
    for f in entry.get("findings", []):
        severity, category, message, remediation = _parse_plain(f)
        writer.writerow(
            [
                _field(f, "id"),
                _field(f, "title"),
                severity,
                category,
                message,
                _field(f, "evidence"),
                remediation,
            ]
        )
    return buf.getvalue()


# ── SARIF 2.1.0 ──────────────────────────────────────────────────────────────


def to_sarif(entry: dict) -> str:
    """Serialize findings to SARIF 2.1.0 format.

    Compatible with GitHub Advanced Security, VS Code SARIF Viewer, and Azure DevOps.
    Rule IDs prefer stable finding IDs and fall back to finding categories.
    Locations are empty arrays — config analysis tools have no source-code positions.
    """
    seen_rules: dict = {}
    results = []

    for f in entry.get("findings", []):
        severity, category, message, remediation = _parse_plain(f)
        category = category or "general"
        finding_id = _field(f, "id")
        rule_id = finding_id or f"FLK-{category.upper()}"
        rule_name = _field(f, "title") or category.replace("-", " ").title()

        if rule_id not in seen_rules:
            seen_rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "properties": {"category": category},
            }
            if isinstance(f, dict) and f.get("compliance_refs"):
                seen_rules[rule_id]["properties"]["compliance_refs"] = f[
                    "compliance_refs"
                ]

        result: dict = {
            "ruleId": rule_id,
            "level": _sarif_level(severity),
            "message": {"text": message},
            "locations": [],
        }
        if isinstance(f, dict):
            properties = {}
            for key in ("evidence", "affected_object", "confidence"):
                if f.get(key):
                    properties[key] = f[key]
            if properties:
                result["properties"] = properties
        if remediation:
            result["fixes"] = [{"description": {"text": remediation}}]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
