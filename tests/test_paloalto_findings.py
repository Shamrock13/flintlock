"""Tests for normalized Palo Alto audit findings."""

import json
import os

from cashel.export import to_csv, to_json, to_sarif
from cashel.paloalto import (
    _f,
    audit_paloalto,
    check_any_application_pa,
    check_any_any_pa,
    check_any_service_pa,
    check_missing_logging_pa,
    parse_paloalto,
)
from cashel.remediation import generate_plan

TESTS_DIR = os.path.dirname(__file__)


def _rules():
    rules, error = parse_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))
    assert error is None
    return rules


def test_paloalto_audit_returns_findings_and_rules():
    findings, rules = audit_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))

    assert findings
    assert rules
    assert all(isinstance(finding, dict) for finding in findings)


def test_paloalto_legacy_helper_shape_still_works():
    finding = _f("LOW", "hygiene", "[LOW] Legacy Palo Alto finding", "Fix it.")

    assert finding["severity"] == "LOW"
    assert finding["category"] == "hygiene"
    assert finding["message"] == "[LOW] Legacy Palo Alto finding"
    assert finding["remediation"] == "Fix it."
    assert finding["vendor"] == "paloalto"


def test_paloalto_findings_keep_legacy_keys_and_enriched_fields():
    findings, _rules_out = audit_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))

    for finding in findings:
        assert finding["severity"]
        assert finding["category"]
        assert finding["message"]
        assert "remediation" in finding
        assert finding["id"].startswith("CASHEL-PA-")
        assert finding["vendor"] == "paloalto"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["confidence"]
        assert isinstance(finding["metadata"], dict)


def test_paloalto_any_any_finding_includes_scope_metadata():
    finding = check_any_any_pa(_rules())[0]

    assert finding["id"] == "CASHEL-PA-EXPOSURE-001"
    assert finding["title"] == "Palo Alto rule allows any source to any destination"
    assert finding["rule_name"] == "Allow-Any-Any"
    assert finding["affected_object"] == "Allow-Any-Any"
    assert '<entry name="Allow-Any-Any">' in finding["evidence"]
    assert finding["metadata"]["source_zones"] == ["any"]
    assert finding["metadata"]["destination_zones"] == ["any"]
    assert finding["metadata"]["source_addresses"] == ["any"]
    assert finding["metadata"]["destination_addresses"] == ["any"]
    assert finding["metadata"]["applications"] == ["any"]
    assert finding["metadata"]["services"] == ["any"]
    assert finding["metadata"]["action"] == "allow"


def test_paloalto_missing_logging_includes_log_metadata():
    finding = check_missing_logging_pa(_rules())[0]

    assert finding["id"] == "CASHEL-PA-LOGGING-001"
    assert finding["metadata"]["log_start"] == ""
    assert finding["metadata"]["log_end"] == ""
    assert "log-end yes" in "\n".join(finding["suggested_commands"])
    assert finding["verification"]


def test_paloalto_application_any_includes_suggested_commands():
    finding = check_any_application_pa(_rules())[0]

    assert finding["id"] == "CASHEL-PA-EXPOSURE-002"
    assert finding["metadata"]["applications"] == ["any"]
    assert "application <APP_NAME>" in "\n".join(finding["suggested_commands"])


def test_paloalto_service_any_includes_suggested_commands():
    finding = check_any_service_pa(_rules())[0]

    assert finding["id"] == "CASHEL-PA-EXPOSURE-003"
    assert finding["metadata"]["services"] == ["any"]
    assert "service <SERVICE_NAME>" in "\n".join(finding["suggested_commands"])


def test_paloalto_remediation_plan_consumes_commands_and_evidence():
    finding = check_any_application_pa(_rules())[0]
    plan = generate_plan([finding], "paloalto")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-PA-EXPOSURE-002"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert step["verification"] == finding["verification"]
    assert step["rollback"] == finding["rollback"]
    assert "application <APP_NAME>" in step["suggested_commands"]


def test_paloalto_exports_preserve_enriched_fields():
    finding = check_any_any_pa(_rules())[0]
    entry = {
        "filename": "pa.xml",
        "vendor": "paloalto",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-PA-EXPOSURE-001"
    assert json_out["findings"][0]["evidence"] == finding["evidence"]

    csv_out = to_csv(entry)
    assert "CASHEL-PA-EXPOSURE-001" in csv_out
    assert "Allow-Any-Any" in csv_out

    sarif_out = json.loads(to_sarif(entry))
    result = sarif_out["runs"][0]["results"][0]
    rule = sarif_out["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "CASHEL-PA-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert rule["id"] == "CASHEL-PA-EXPOSURE-001"


def test_paloalto_old_and_plain_findings_remain_compatible():
    old_dict = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Rule 'AllowWeb' missing log-end setting",
        "remediation": "Enable log-end on the rule.",
    }
    plan = generate_plan([old_dict, "[LOW] Plain archive finding"], "paloalto")

    assert plan["total_steps"] == 1
    step = plan["phases"][0]["steps"][0]
    assert step["description"] == old_dict["message"]
    assert "log-end yes" in step["suggested_commands"]
