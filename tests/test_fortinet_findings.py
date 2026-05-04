"""Tests for normalized Fortinet audit findings."""

import json
import os
import tempfile

from cashel.export import to_csv, to_json, to_sarif
from cashel.fortinet import (
    _f,
    audit_fortinet,
    check_any_any_forti,
    check_any_service_forti,
    check_deny_all_forti,
    check_insecure_services_forti,
    check_missing_logging_forti,
    check_missing_utm_forti,
    check_redundant_rules_forti,
    expand_address,
    expand_addresses,
    expand_service,
    expand_services,
    parse_fortinet,
)
from cashel.remediation import generate_plan

TESTS_DIR = os.path.dirname(__file__)


def _policies():
    policies, error = parse_fortinet(os.path.join(TESTS_DIR, "test_forti.txt"))
    assert error is None
    return policies


def _policy(**overrides):
    policy = {
        "id": "100",
        "name": "Specific Web",
        "srcintf": ["lan"],
        "dstintf": ["dmz"],
        "srcaddr": ["TrustedUsers"],
        "dstaddr": ["WebServer"],
        "service": ["HTTPS"],
        "action": "accept",
        "logtraffic": "all",
        "status": "enable",
        "utm-status": "enable",
        "schedule": "always",
        "nat": "disable",
        "comments": "",
        "av-profile": "",
        "ips-sensor": "",
        "application-list": "",
        "webfilter-profile": "",
        "profile-protocol-options": "",
    }
    policy.update(overrides)
    return policy


def _ids(findings):
    return {finding["id"] for finding in findings}


def _parse_text(config_text):
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(config_text)
        path = fh.name
    try:
        policies, error = parse_fortinet(path)
    finally:
        os.unlink(path)
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


def test_specific_accept_policy_does_not_trigger_any_any_exposure():
    findings = check_any_any_forti([_policy()])

    assert "CASHEL-FORTINET-EXPOSURE-001" not in _ids(findings)


def test_disabled_any_any_policy_does_not_trigger_exposure():
    findings = check_any_any_forti(
        [
            _policy(
                name="Disabled Any",
                status="disable",
                srcaddr=["all"],
                dstaddr=["all"],
            )
        ]
    )

    assert "CASHEL-FORTINET-EXPOSURE-001" not in _ids(findings)


def test_accept_policy_with_logtraffic_all_does_not_trigger_missing_logging():
    findings = check_missing_logging_forti([_policy(logtraffic="all")])

    assert "CASHEL-FORTINET-LOGGING-001" not in _ids(findings)


def test_explicit_deny_all_suppresses_missing_deny_all():
    findings = check_deny_all_forti(
        [
            _policy(action="accept"),
            _policy(
                id="999",
                name="Explicit Deny",
                action="deny",
                srcaddr=["all"],
                dstaddr=["all"],
            ),
        ]
    )

    assert "CASHEL-FORTINET-HYGIENE-001" not in _ids(findings)


def test_internal_only_policy_does_not_trigger_missing_utm():
    findings = check_missing_utm_forti(
        [_policy(srcintf=["lan"], dstintf=["dmz"], **{"utm-status": ""})]
    )

    assert "CASHEL-FORTINET-HYGIENE-004" not in _ids(findings)


def test_named_source_destination_service_does_not_trigger_all_service():
    findings = check_any_service_forti(
        [
            _policy(
                srcaddr=["TrustedUsers"],
                dstaddr=["WebServer"],
                service=["HTTPS"],
            )
        ]
    )

    assert "CASHEL-FORTINET-PROTOCOL-001" not in _ids(findings)


def test_parser_captures_extended_policy_fields():
    policies = _parse_text(
        """
config firewall policy
    edit 42
        set name "Profiled Web"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "Trusted Users"
        set dstaddr "Web Server"
        set action accept
        set service "HTTPS"
        set schedule "business-hours"
        set nat enable
        set comments "Owner: app team"
        set logtraffic all
        set utm-status enable
        set av-profile "default"
        set ips-sensor "strict"
        set application-list "app-control"
        set webfilter-profile "web-default"
        set profile-protocol-options "protocol-default"
    next
end
"""
    )

    policy = policies[0]
    assert policy["schedule"] == "business-hours"
    assert policy["nat"] == "enable"
    assert policy["comments"] == "Owner: app team"
    assert policy["av-profile"] == "default"
    assert policy["ips-sensor"] == "strict"
    assert policy["application-list"] == "app-control"
    assert policy["webfilter-profile"] == "web-default"
    assert policy["profile-protocol-options"] == "protocol-default"
    assert policy["srcaddr"] == ["Trusted Users"]
    assert policy["dstaddr"] == ["Web Server"]


def test_address_object_and_group_parsing_and_expansion():
    policies = _parse_text(
        """
config firewall address
    edit "HR-NET"
        set subnet 10.20.10.0 255.255.255.0
    next
    edit "WEB-SERVER"
        set subnet 10.30.20.50 255.255.255.255
    next
end
config firewall addrgrp
    edit "INTERNAL-USERS"
        set member "HR-NET" "VPN-USERS"
    next
    edit "NESTED-USERS"
        set member "INTERNAL-USERS" "WEB-SERVER"
    next
end
config firewall policy
    edit 1
        set name "Object Policy"
        set srcintf "lan"
        set dstintf "dmz"
        set srcaddr "NESTED-USERS"
        set dstaddr "WEB-SERVER"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end
"""
    )
    policy = policies[0]
    objects = policy["_address_objects"]
    groups = policy["_address_groups"]

    assert objects["HR-NET"]["subnet"] == "10.20.10.0 255.255.255.0"
    assert objects["WEB-SERVER"]["subnet"] == "10.30.20.50 255.255.255.255"
    assert groups["INTERNAL-USERS"]["member"] == ["HR-NET", "VPN-USERS"]
    assert expand_address("HR-NET", objects, groups) == ["10.20.10.0 255.255.255.0"]
    assert expand_addresses(["NESTED-USERS"], objects, groups) == [
        "10.20.10.0 255.255.255.0",
        "VPN-USERS",
        "10.30.20.50 255.255.255.255",
    ]


def test_address_group_cycle_protection_and_unknown_preservation():
    objects = {"HR-NET": {"name": "HR-NET", "subnet": "10.20.10.0 255.255.255.0"}}
    groups = {
        "A": {"name": "A", "member": ["B", "UNKNOWN"]},
        "B": {"name": "B", "member": ["A", "HR-NET"]},
    }

    expanded = expand_addresses(["A"], objects, groups)

    assert "UNKNOWN" in expanded
    assert "10.20.10.0 255.255.255.0" in expanded
    assert len(expanded) < 6


def test_custom_service_and_group_parsing_and_expansion():
    policies = _parse_text(
        """
config firewall service custom
    edit "TCP-8443"
        set tcp-portrange 8443
    next
    edit "LEGACY-TELNET"
        set tcp-portrange 23
    next
    edit "UDP-5353"
        set udp-portrange 5353
    next
end
config firewall service group
    edit "APP-SERVICES"
        set member "HTTPS" "TCP-8443" "LEGACY-TELNET"
    next
    edit "NESTED-SERVICES"
        set member "APP-SERVICES" "UDP-5353"
    next
end
config firewall policy
    edit 1
        set name "Service Policy"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "TrustedUsers"
        set dstaddr "WebServer"
        set action accept
        set service "NESTED-SERVICES"
        set logtraffic all
    next
end
"""
    )
    policy = policies[0]
    services = policy["_service_objects"]
    service_groups = policy["_service_groups"]

    assert services["TCP-8443"]["tcp-portrange"] == "8443"
    assert services["LEGACY-TELNET"]["tcp-portrange"] == "23"
    assert services["UDP-5353"]["udp-portrange"] == "5353"
    assert service_groups["APP-SERVICES"]["member"] == [
        "HTTPS",
        "TCP-8443",
        "LEGACY-TELNET",
    ]
    assert expand_services(["NESTED-SERVICES"], services, service_groups) == [
        "HTTPS",
        "tcp/8443",
        "tcp/23",
        "udp/5353",
    ]


def test_service_group_cycle_protection_and_unknown_preservation():
    services = {"TCP-8443": {"name": "TCP-8443", "tcp-portrange": "8443"}}
    service_groups = {
        "A": {"name": "A", "member": ["B", "UNKNOWN-SVC"]},
        "B": {"name": "B", "member": ["A", "TCP-8443"]},
    }

    expanded = expand_services(["A"], services, service_groups)

    assert "UNKNOWN-SVC" in expanded
    assert "tcp/8443" in expanded
    assert len(expanded) < 6


def test_unknown_objects_are_preserved_and_broad_values_normalize():
    assert expand_address("MISSING-NET", {}, {}) == ["MISSING-NET"]
    assert expand_service("MISSING-SVC", {}, {}) == ["MISSING-SVC"]
    assert expand_addresses(["all", "any", "*", "ALL"], {}, {}) == ["ALL"]
    assert expand_services(["all", "any", "*", "ALL"], {}, {}) == ["ALL"]


def test_evidence_and_metadata_include_extended_policy_fields():
    policy = _policy(
        schedule="business-hours",
        nat="enable",
        comments="Owner: app team",
        **{
            "av-profile": "default",
            "ips-sensor": "strict",
            "application-list": "app-control",
            "webfilter-profile": "web-default",
            "profile-protocol-options": "protocol-default",
        },
    )

    finding = check_any_any_forti([policy | {"srcaddr": ["all"], "dstaddr": ["all"]}])[
        0
    ]

    assert "schedule=business-hours" in finding["evidence"]
    assert "nat=enable" in finding["evidence"]
    assert "comments=Owner: app team" in finding["evidence"]
    assert "av-profile=default" in finding["evidence"]
    assert finding["metadata"]["schedule"] == "business-hours"
    assert finding["metadata"]["nat"] == "enable"
    assert finding["metadata"]["comments"] == "Owner: app team"
    assert finding["metadata"]["av_profile"] == "default"
    assert finding["metadata"]["profile_protocol_options"] == "protocol-default"


def test_fortinet_findings_include_raw_and_expanded_scope_metadata():
    policies = _parse_text(
        """
config firewall address
    edit "HR-NET"
        set subnet 10.20.10.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "BROAD-USERS"
        set member "all"
    next
end
config firewall service custom
    edit "LEGACY-TELNET"
        set tcp-portrange 23
    next
end
config firewall service group
    edit "BAD-SERVICES"
        set member "LEGACY-TELNET"
    next
end
config firewall policy
    edit 10
        set name "Expanded Any"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "BROAD-USERS"
        set dstaddr "all"
        set action accept
        set service "BAD-SERVICES"
        set logtraffic disable
    next
end
"""
    )

    exposure = check_any_any_forti(policies)[0]
    insecure = check_insecure_services_forti(policies)[0]

    assert exposure["metadata"]["raw_srcaddr"] == ["BROAD-USERS"]
    assert exposure["metadata"]["raw_dstaddr"] == ["all"]
    assert exposure["metadata"]["expanded_srcaddr"] == ["ALL"]
    assert exposure["metadata"]["expanded_dstaddr"] == ["ALL"]
    assert exposure["metadata"]["expanded_service"] == ["tcp/23"]
    assert "expanded_srcaddr=ALL" in exposure["evidence"]
    assert "expanded_service=tcp/23" in exposure["evidence"]
    assert insecure["metadata"]["insecure_services"] == ["TELNET"]


def test_duplicate_detection_includes_interfaces_schedule_and_nat():
    base = _policy(
        id="1",
        name="Base Policy",
        srcintf=["lan"],
        dstintf=["wan1"],
        schedule="always",
        nat="enable",
    )
    same = _policy(
        id="2",
        name="Duplicate Policy",
        srcintf=["lan"],
        dstintf=["wan1"],
        schedule="always",
        nat="enable",
    )
    different_srcintf = _policy(
        id="3",
        name="Different Interface",
        srcintf=["dmz"],
        dstintf=["wan1"],
        schedule="always",
        nat="enable",
    )
    different_schedule = _policy(
        id="4",
        name="Different Schedule",
        srcintf=["lan"],
        dstintf=["wan1"],
        schedule="business-hours",
        nat="enable",
    )
    different_nat = _policy(
        id="5",
        name="Different NAT",
        srcintf=["lan"],
        dstintf=["wan1"],
        schedule="always",
        nat="disable",
    )

    duplicate_findings = check_redundant_rules_forti([base, same])
    assert len(duplicate_findings) == 1
    assert duplicate_findings[0]["id"] == "CASHEL-FORTINET-REDUNDANCY-002"

    distinct_findings = check_redundant_rules_forti(
        [base, different_srcintf, different_schedule, different_nat]
    )
    assert distinct_findings == []


def test_duplicate_detection_uses_expanded_effective_scope():
    policies = _parse_text(
        """
config firewall address
    edit "HR-NET"
        set subnet 10.20.10.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "HR-GROUP"
        set member "HR-NET"
    next
end
config firewall service custom
    edit "TCP-8443"
        set tcp-portrange 8443
    next
end
config firewall service group
    edit "APP-GROUP"
        set member "TCP-8443"
    next
end
config firewall policy
    edit 1
        set name "Object Policy"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "HR-GROUP"
        set dstaddr "Unknown-Web"
        set action accept
        set service "APP-GROUP"
        set schedule "always"
        set nat enable
    next
    edit 2
        set name "Expanded Duplicate"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "HR-NET"
        set dstaddr "Unknown-Web"
        set action accept
        set service "TCP-8443"
        set schedule "always"
        set nat enable
    next
end
"""
    )

    findings = check_redundant_rules_forti(policies)

    assert len(findings) == 1
    assert findings[0]["id"] == "CASHEL-FORTINET-REDUNDANCY-002"
    assert findings[0]["metadata"]["expanded_srcaddr"] == ["10.20.10.0 255.255.255.0"]
    assert findings[0]["metadata"]["expanded_service"] == ["tcp/8443"]
