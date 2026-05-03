"""Tests for normalized Fortinet audit findings."""

import json
import os

from cashel.export import to_csv, to_json, to_sarif
from cashel.fortinet import (
    _f,
    audit_fortinet,
    check_any_any_forti,
    parse_fortinet,
)
from cashel.remediation import generate_plan

TESTS_DIR = os.path.dirname(__file__)


def _policies():
    policies, error = parse_fortinet(os.path.join(TESTS_DIR, "test_forti.txt"))
    assert error is None
    return policies


def test_fortinet_legacy_helper_shape_still_works():
    finding = _f("LOW", "hygiene", "[LOW] Legacy Fortinet finding", "Fix it.")

    assert finding["severity"] == "LOW"
    assert finding["category"] == "hygiene"
    assert finding["message"] == "[LOW] Legacy Fortinet finding"
    assert finding["remediation"] == "Fix it."
    assert finding["vendor"] == "fortinet"


def test_fortinet_any_any_finding_has_normalized_fields():
    finding = check_any_any_forti(_policies())[0]

    assert finding["id"] == "CASHEL-FORTINET-EXPOSURE-001"
    assert finding["vendor"] == "fortinet"
    assert finding["title"] == "Fortinet policy allows all sources to all destinations"
    assert "policy_id=1" in finding["evidence"]
    assert "srcaddr=all" in finding["evidence"]
    assert finding["affected_object"] == "Allow-All"
    assert finding["rule_id"] == "1"
    assert finding["confidence"] == "high"
    assert finding["suggested_commands"]


def test_fortinet_audit_findings_include_ids_titles_and_evidence():
    findings, policies = audit_fortinet(os.path.join(TESTS_DIR, "test_forti.txt"))

    assert policies
    assert findings
    assert all(f["vendor"] == "fortinet" for f in findings)
    assert all("id" in f and f["id"].startswith("CASHEL-FORTINET-") for f in findings)
    assert all(f.get("title") for f in findings)
    assert all(f.get("evidence") for f in findings)


def test_fortinet_remediation_plan_consumes_commands_and_evidence():
    finding = check_any_any_forti(_policies())[0]
    plan = generate_plan([finding], "fortinet")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-FORTINET-EXPOSURE-001"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert "set srcaddr <SPECIFIC_ADDR_OBJ>" in step["suggested_commands"]


def test_fortinet_exports_preserve_enriched_fields():
    finding = check_any_any_forti(_policies())[0]
    entry = {
        "filename": "forti.cfg",
        "vendor": "fortinet",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-FORTINET-EXPOSURE-001"
    assert json_out["findings"][0]["evidence"] == finding["evidence"]

    csv_out = to_csv(entry)
    assert "CASHEL-FORTINET-EXPOSURE-001" in csv_out
    assert "policy_id=1" in csv_out

    sarif_out = json.loads(to_sarif(entry))
    result = sarif_out["runs"][0]["results"][0]
    rule = sarif_out["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "CASHEL-FORTINET-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert rule["id"] == "CASHEL-FORTINET-EXPOSURE-001"
