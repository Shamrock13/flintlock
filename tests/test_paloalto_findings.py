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
    check_redundant_rules_pa,
    expand_address,
    expand_addresses,
    expand_application,
    expand_applications,
    expand_service,
    expand_services,
    check_missing_logging_pa,
    parse_paloalto_config,
    parse_paloalto,
)
from cashel.remediation import generate_plan

TESTS_DIR = os.path.dirname(__file__)


def _rules():
    rules, error = parse_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))
    assert error is None
    return rules


def _object_config():
    config, error = parse_paloalto_config(
        os.path.join(TESTS_DIR, "test_pa_objects.xml")
    )
    assert error is None
    return config


def test_paloalto_audit_returns_findings_and_rules():
    findings, rules = audit_paloalto(os.path.join(TESTS_DIR, "test_pa.xml"))

    assert findings
    assert rules
    assert all(isinstance(finding, dict) for finding in findings)


def test_paloalto_parse_returns_rules_and_error_tuple():
    rules, error = parse_paloalto(os.path.join(TESTS_DIR, "test_pa_objects.xml"))

    assert error is None
    assert rules
    assert rules[0].get("name") == "Group-Any-Any"


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
    assert finding["metadata"]["raw_source_addresses"] == ["any"]
    assert finding["metadata"]["raw_destination_addresses"] == ["any"]
    assert finding["metadata"]["raw_applications"] == ["any"]
    assert finding["metadata"]["raw_services"] == ["any"]
    assert finding["metadata"]["expanded_source_addresses"] == ["any"]
    assert finding["metadata"]["expanded_destination_addresses"] == ["any"]
    assert finding["metadata"]["expanded_applications"] == ["any"]
    assert finding["metadata"]["expanded_services"] == ["any"]
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
    finding = check_any_any_pa(_object_config()["rules"])[0]
    entry = {
        "filename": "pa.xml",
        "vendor": "paloalto",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-PA-EXPOSURE-001"
    assert json_out["findings"][0]["evidence"] == finding["evidence"]
    assert json_out["findings"][0]["metadata"]["raw_source_addresses"] == [
        "BROAD-USERS"
    ]
    assert json_out["findings"][0]["metadata"]["expanded_source_addresses"] == ["any"]

    csv_out = to_csv(entry)
    assert "CASHEL-PA-EXPOSURE-001" in csv_out
    assert "Group-Any-Any" in csv_out

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


def test_paloalto_config_parser_extracts_address_objects():
    config = _object_config()
    objects = config["address_objects"]

    assert objects["HR-NET"]["ip-netmask"] == "10.20.10.0/24"
    assert objects["APP-FQDN"]["fqdn"] == "app.example.com"
    assert objects["RANGE-OBJ"]["ip-range"] == "10.40.1.10-10.40.1.20"


def test_paloalto_config_parser_extracts_address_groups():
    groups = _object_config()["address_groups"]

    assert groups["INTERNAL-USERS"]["members"] == ["HR-NET", "VPN-USERS"]
    assert groups["NESTED-USERS"]["members"] == ["INTERNAL-USERS", "WEB-SERVER"]


def test_paloalto_nested_address_group_expansion():
    config = _object_config()

    assert expand_address(
        "NESTED-USERS", config["address_objects"], config["address_groups"]
    ) == ["10.20.10.0/24", "10.30.20.50/32", "VPN-USERS"]


def test_paloalto_address_group_cycle_protection():
    config = _object_config()

    assert (
        expand_address(
            "ADDR-CYCLE-A", config["address_objects"], config["address_groups"]
        )
        == []
    )


def test_paloalto_config_parser_extracts_service_objects():
    services = _object_config()["service_objects"]

    assert services["TCP-8443"]["protocol"] == "tcp"
    assert services["TCP-8443"]["port"] == "8443"
    assert services["UDP-5353"]["protocol"] == "udp"
    assert services["UDP-5353"]["port"] == "5353"


def test_paloalto_config_parser_extracts_service_groups():
    groups = _object_config()["service_groups"]

    assert groups["APP-SERVICES"]["members"] == ["service-http", "TCP-8443"]
    assert groups["NESTED-SERVICES"]["members"] == ["APP-SERVICES", "UDP-5353"]


def test_paloalto_nested_service_group_expansion():
    config = _object_config()

    assert expand_service(
        "NESTED-SERVICES", config["service_objects"], config["service_groups"]
    ) == ["service-http", "tcp/8443", "udp/5353"]


def test_paloalto_service_group_cycle_protection():
    config = _object_config()

    assert (
        expand_service(
            "SVC-CYCLE-A", config["service_objects"], config["service_groups"]
        )
        == []
    )


def test_paloalto_config_parser_extracts_application_groups():
    groups = _object_config()["application_groups"]

    assert groups["RISKY-APPS"]["members"] == ["ssl", "web-browsing"]
    assert groups["NESTED-APPS"]["members"] == ["RISKY-APPS", "dns"]


def test_paloalto_nested_application_group_expansion():
    groups = _object_config()["application_groups"]

    assert expand_application("NESTED-APPS", groups) == [
        "dns",
        "ssl",
        "web-browsing",
    ]


def test_paloalto_application_group_cycle_protection():
    groups = _object_config()["application_groups"]

    assert expand_application("APP-CYCLE-A", groups) == []


def test_paloalto_unknown_objects_are_preserved():
    config = _object_config()

    assert expand_address(
        "UNKNOWN-ADDR", config["address_objects"], config["address_groups"]
    ) == ["UNKNOWN-ADDR"]
    assert expand_service(
        "UNKNOWN-SVC", config["service_objects"], config["service_groups"]
    ) == ["UNKNOWN-SVC"]
    assert expand_application("UNKNOWN-APP", config["application_groups"]) == [
        "UNKNOWN-APP"
    ]


def test_paloalto_any_all_star_normalization():
    config = _object_config()

    assert expand_addresses(
        ["all", "ALL", "*"], config["address_objects"], config["address_groups"]
    ) == ["any"]
    assert expand_services(
        ["all", "ALL", "*"], config["service_objects"], config["service_groups"]
    ) == ["any"]
    assert expand_applications(["all", "ALL", "*"], config["application_groups"]) == [
        "any"
    ]


def test_paloalto_findings_include_raw_and_expanded_object_scope_metadata():
    findings, _rules_out = audit_paloalto(
        os.path.join(TESTS_DIR, "test_pa_objects.xml")
    )
    finding = next(f for f in findings if f["rule_name"] == "Group-Any-Any")
    metadata = finding["metadata"]

    assert metadata["raw_source_addresses"] == ["BROAD-USERS"]
    assert metadata["raw_destination_addresses"] == ["any"]
    assert metadata["raw_applications"] == ["BROAD-APPS"]
    assert metadata["raw_services"] == ["BROAD-SERVICES"]
    assert metadata["expanded_source_addresses"] == ["any"]
    assert metadata["expanded_destination_addresses"] == ["any"]
    assert metadata["expanded_applications"] == ["any"]
    assert metadata["expanded_services"] == ["any"]


def test_paloalto_any_any_detection_uses_expanded_address_groups():
    findings = check_any_any_pa(_object_config()["rules"])

    assert any(f["rule_name"] == "Group-Any-Any" for f in findings)


def test_paloalto_application_any_detection_uses_expanded_application_groups():
    findings = check_any_application_pa(_object_config()["rules"])

    assert any(f["rule_name"] == "Group-Any-Any" for f in findings)


def test_paloalto_service_any_detection_uses_expanded_service_groups():
    findings = check_any_service_pa(_object_config()["rules"])

    assert any(f["rule_name"] == "Group-Any-Any" for f in findings)


def test_paloalto_duplicate_detection_uses_expanded_scope():
    findings = check_redundant_rules_pa(_object_config()["rules"])

    duplicate = next(f for f in findings if f["rule_name"] == "Duplicate-Expanded-B")
    assert duplicate["id"] == "CASHEL-PA-REDUNDANCY-002"
    assert duplicate["metadata"]["duplicate_of_rule"] == "Duplicate-Expanded-A"
