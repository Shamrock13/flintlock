"""Cross-vendor QA for normalized findings, remediation, reports, and exports."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections.abc import Callable

from cashel.audit_engine import _audit_asa
from cashel.export import to_csv, to_json, to_sarif
from cashel.fortinet import audit_fortinet
from cashel.juniper import audit_juniper
from cashel.models.findings import validate_finding_shape
from cashel.paloalto import audit_paloalto
from cashel.pfsense import audit_pfsense
from cashel.remediation import generate_plan
from cashel.reporter import build_audit_report_context

TESTS_DIR = os.path.dirname(__file__)

JUNIPER_RISKY = """\
set system host-name srx-bad
set system services telnet
set security policies from-zone trust to-zone untrust policy allow-all match source-address any
set security policies from-zone trust to-zone untrust policy allow-all match destination-address any
set security policies from-zone trust to-zone untrust policy allow-all match application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
"""


def _juniper_sample() -> tuple[list[dict], list[dict]]:
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(JUNIPER_RISKY)
        path = fh.name
    try:
        return audit_juniper(path)
    finally:
        os.unlink(path)


VENDOR_AUDITS: list[tuple[str, Callable[[], tuple[list[dict], object]]]] = [
    ("asa", lambda: _audit_asa(os.path.join(TESTS_DIR, "test_asa.txt"))),
    ("fortinet", lambda: audit_fortinet(os.path.join(TESTS_DIR, "test_forti.txt"))),
    ("paloalto", lambda: audit_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))),
    ("juniper", _juniper_sample),
    ("pfsense", lambda: audit_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))),
]


def _first_enriched(findings: list[dict], vendor: str) -> dict:
    for finding in findings:
        if (
            isinstance(finding, dict)
            and finding.get("id")
            and finding.get("vendor") == vendor
        ):
            return finding
    raise AssertionError(f"No enriched {vendor} finding found")


def _csv_rows(entry: dict) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(to_csv(entry))))


def _remediation_steps(finding: dict, vendor: str) -> list[dict]:
    plan = generate_plan([finding], vendor, filename=f"{vendor}.cfg")
    return [step for phase in plan["phases"] for step in phase["steps"]]


def test_cross_vendor_audits_emit_valid_enriched_findings():
    for vendor, audit in VENDOR_AUDITS:
        findings, parsed = audit()
        enriched = _first_enriched(findings, vendor)

        assert findings, vendor
        assert parsed is not None, vendor
        assert enriched["evidence"], vendor
        assert enriched["title"], vendor
        assert enriched["id"].startswith("CASHEL-"), vendor
        assert validate_finding_shape(enriched) == [], vendor


def test_cross_vendor_exports_preserve_enriched_fields():
    expected_csv_columns = {
        "id",
        "vendor",
        "severity",
        "category",
        "title",
        "message",
        "remediation",
        "evidence",
        "affected_object",
        "rule_name",
        "confidence",
    }

    for vendor, audit in VENDOR_AUDITS:
        findings, _parsed = audit()
        enriched = _first_enriched(findings, vendor)
        entry = {
            "filename": f"{vendor}.cfg",
            "vendor": vendor,
            "summary": {"total": len(findings)},
            "findings": [enriched],
        }

        json_out = json.loads(to_json(entry))
        assert json_out["findings"][0]["id"] == enriched["id"], vendor
        assert json_out["findings"][0]["evidence"] == enriched["evidence"], vendor

        csv_row = _csv_rows(entry)[0]
        assert set(csv_row) == expected_csv_columns
        assert csv_row["id"] == enriched["id"], vendor
        assert csv_row["vendor"] == vendor, vendor
        assert csv_row["evidence"] == enriched["evidence"], vendor

        sarif = json.loads(to_sarif(entry))
        result = sarif["runs"][0]["results"][0]
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert result["ruleId"] == enriched["id"], vendor
        assert rule["id"] == enriched["id"], vendor
        assert result["properties"]["vendor"] == vendor, vendor
        assert result["properties"]["category"] == enriched["category"], vendor
        assert result["properties"]["evidence"] == enriched["evidence"], vendor


def test_cross_vendor_remediation_uses_evidence_and_verification_when_present():
    for vendor, audit in VENDOR_AUDITS:
        findings, _parsed = audit()
        enriched = _first_enriched(findings, vendor)
        steps = _remediation_steps(enriched, vendor)

        assert steps, vendor
        step = steps[0]
        assert step["title"] == enriched["title"], vendor
        assert step["evidence"] == enriched["evidence"], vendor
        if enriched.get("verification"):
            assert step["verification"] == enriched["verification"], vendor
        if enriched.get("rollback"):
            assert step["rollback"] == enriched["rollback"], vendor
        if enriched.get("suggested_commands"):
            assert step["suggested_commands"], vendor


def test_report_context_preserves_enriched_and_legacy_findings():
    enriched = {
        "id": "CASHEL-QA-001",
        "vendor": "asa",
        "severity": "HIGH",
        "category": "exposure",
        "title": "Evidence-backed report finding",
        "message": "[HIGH] permit ip any any",
        "remediation": "Restrict the ACL.",
        "evidence": "access-list OUTSIDE_IN permit ip any any",
        "affected_object": "OUTSIDE_IN",
        "confidence": "high",
        "verification": "Re-run the audit.",
        "rollback": "Restore the previous ACL line.",
        "suggested_commands": ["no access-list <ACL_NAME> permit ip any any"],
        "metadata": {"acl": "OUTSIDE_IN"},
    }

    context = build_audit_report_context(
        findings=[enriched, "[LOW] Plain archive finding"],
        filename="qa.cfg",
        vendor="asa",
    )
    first, second = context["findings"]

    assert first["id"] == "CASHEL-QA-001"
    assert first["title"] == "Evidence-backed report finding"
    assert first["evidence"] == "access-list OUTSIDE_IN permit ip any any"
    assert first["verification"] == "Re-run the audit."
    assert first["rollback"] == "Restore the previous ACL line."
    assert first["suggested_commands"] == "no access-list <ACL_NAME> permit ip any any"
    assert first["metadata"] == '{"acl": "OUTSIDE_IN"}'
    assert second["message"] == "[LOW] Plain archive finding"
    assert second["evidence"] == ""
