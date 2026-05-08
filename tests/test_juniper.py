"""Tests for Juniper SRX parser, auditor, and shadow detection.

Run with:  python3 tests/test_juniper.py
"""

import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.export import to_csv, to_json, to_sarif
from cashel.juniper import (
    _f,
    _parse_set_style,
    _parse_hierarchical,
    audit_juniper,
    check_any_any_juniper,
    check_deny_all_juniper,
    check_insecure_apps_juniper,
    check_missing_log_juniper,
    check_system_juniper,
    expand_address,
    expand_addresses,
    expand_application,
    expand_applications,
    parse_juniper,
    parse_juniper_config,
)
from cashel.remediation import generate_plan
from cashel.rule_quality import check_shadow_rules_juniper

# ── Sample configs ────────────────────────────────────────────────────────────

SET_STYLE_CLEAN = """\
set system host-name srx-edge
set system services ssh
set system ntp server 10.0.0.1
set system syslog host 10.0.0.2 any any
set security policies from-zone trust to-zone untrust policy allow-web match source-address corp-subnet
set security policies from-zone trust to-zone untrust policy allow-web match destination-address any
set security policies from-zone trust to-zone untrust policy allow-web match application junos-http
set security policies from-zone trust to-zone untrust policy allow-web then permit log
set security policies from-zone trust to-zone untrust policy deny-all match source-address any
set security policies from-zone trust to-zone untrust policy deny-all match destination-address any
set security policies from-zone trust to-zone untrust policy deny-all match application any
set security policies from-zone trust to-zone untrust policy deny-all then deny
"""

SET_STYLE_RISKY = """\
set system host-name srx-bad
set system services telnet
set snmp community public authorization read-only
set security policies from-zone trust to-zone untrust policy allow-all match source-address any
set security policies from-zone trust to-zone untrust policy allow-all match destination-address any
set security policies from-zone trust to-zone untrust policy allow-all match application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
set security policies from-zone trust to-zone untrust policy allow-telnet match source-address any
set security policies from-zone trust to-zone untrust policy allow-telnet match destination-address any
set security policies from-zone trust to-zone untrust policy allow-telnet match application junos-telnet
set security policies from-zone trust to-zone untrust policy allow-telnet then permit
"""

HIERARCHICAL_CLEAN = """\
security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address corp-subnet;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit {
                        log {
                            session-close;
                        }
                    }
                }
            }
            policy deny-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}
"""

HIERARCHICAL_INACTIVE = """\
security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy disabled-rule {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
            policy deny-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}
"""

SET_STYLE_OBJECTS = """\
set system host-name srx-objects
set system services telnet
set security address-book global address HR-NET 10.20.10.0/24
set security address-book global address WEB-SERVER 10.30.20.50/32
set security address-book global address APP-FQDN dns-name app.example.com
set security address-book global address RANGE-OBJ range-address 10.40.1.10 to 10.40.1.20
set security address-book global address ANY-OBJ any
set security address-book global address-set INTERNAL-USERS address HR-NET
set security address-book global address-set INTERNAL-USERS address VPN-USERS
set security address-book global address-set NESTED-USERS address-set INTERNAL-USERS
set security address-book global address-set NESTED-USERS address WEB-SERVER
set security address-book global address-set BROAD-USERS address ANY-OBJ
set security address-book global address-set CYCLE-A address-set CYCLE-B
set security address-book global address-set CYCLE-B address-set CYCLE-A
set security zones security-zone trust address-book address TRUST-HOST 10.10.10.10/32
set security zones security-zone trust address-book address-set TRUST-USERS address HR-NET
set applications application TCP-8443 protocol tcp
set applications application TCP-8443 destination-port 8443
set applications application UDP-5353 protocol udp
set applications application UDP-5353 destination-port 5353
set applications application SRC-RANGE protocol tcp
set applications application SRC-RANGE source-port 1024-65535
set applications application SRC-RANGE destination-port 9443
set applications application LEGACY-TELNET protocol tcp
set applications application LEGACY-TELNET destination-port 23
set applications application-set APP-SERVICES application junos-https
set applications application-set APP-SERVICES application TCP-8443
set applications application-set APP-SERVICES application LEGACY-TELNET
set applications application-set NESTED-SERVICES application-set APP-SERVICES
set applications application-set BROAD-APPS application junos-any
set applications application-set APP-CYCLE-A application-set APP-CYCLE-B
set applications application-set APP-CYCLE-B application-set APP-CYCLE-A
set security policies from-zone trust to-zone untrust policy broad-object-rule match source-address BROAD-USERS
set security policies from-zone trust to-zone untrust policy broad-object-rule match destination-address any
set security policies from-zone trust to-zone untrust policy broad-object-rule match application BROAD-APPS
set security policies from-zone trust to-zone untrust policy broad-object-rule then permit
set security policies from-zone trust to-zone untrust policy app-set-telnet match source-address TRUST-USERS
set security policies from-zone trust to-zone untrust policy app-set-telnet match destination-address WEB-SERVER
set security policies from-zone trust to-zone untrust policy app-set-telnet match application APP-SERVICES
set security policies from-zone trust to-zone untrust policy app-set-telnet then permit log
set security policies from-zone trust to-zone untrust policy expanded-deny match source-address BROAD-USERS
set security policies from-zone trust to-zone untrust policy expanded-deny match destination-address any
set security policies from-zone trust to-zone untrust policy expanded-deny match application BROAD-APPS
set security policies from-zone trust to-zone untrust policy expanded-deny then deny
"""


# ══════════════════════════════════════════════ SET-STYLE PARSER ══


def test_set_parse_basic():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert len(policies) == 2
    names = {p["name"] for p in policies}
    assert "allow-web" in names
    assert "deny-all" in names


def test_set_parse_zone_fields():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    web = next(p for p in policies if p["name"] == "allow-web")
    assert web["from_zone"] == "trust"
    assert web["to_zone"] == "untrust"


def test_set_parse_action_permit():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    web = next(p for p in policies if p["name"] == "allow-web")
    assert web["action"] == "permit"
    assert web["log"] is True


def test_set_parse_action_deny():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    deny = next(p for p in policies if p["name"] == "deny-all")
    assert deny["action"] == "deny"


def test_set_parse_src_dst_app():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    web = next(p for p in policies if p["name"] == "allow-web")
    assert "corp-subnet" in web["src"]
    assert "any" in web["dst"]
    assert "junos-http" in web["app"]


def test_set_parse_deactivated():
    config = (
        SET_STYLE_CLEAN
        + "\ndeactivate security policies from-zone trust to-zone untrust policy allow-web\n"
    )
    policies = _parse_set_style(config)
    web = next(p for p in policies if p["name"] == "allow-web")
    assert web["disabled"] is True


# ══════════════════════════════════════════ HIERARCHICAL PARSER ══


def test_hier_parse_basic():
    policies = _parse_hierarchical(HIERARCHICAL_CLEAN)
    assert any(p["name"] == "allow-web" for p in policies)
    assert any(p["name"] == "deny-all" for p in policies)


def test_hier_parse_log():
    policies = _parse_hierarchical(HIERARCHICAL_CLEAN)
    web = next(p for p in policies if p["name"] == "allow-web")
    assert web["log"] is True


def test_hier_parse_inactive():
    policies = _parse_hierarchical(HIERARCHICAL_INACTIVE)
    disabled = next(p for p in policies if p["name"] == "disabled-rule")
    assert disabled["disabled"] is True


def test_hier_parse_deny_action():
    policies = _parse_hierarchical(HIERARCHICAL_CLEAN)
    deny = next(p for p in policies if p["name"] == "deny-all")
    assert deny["action"] == "deny"


# ══════════════════════════════════════════════ POLICY CHECKS ══


def test_juniper_legacy_helper_shape_still_works():
    finding = _f("LOW", "hygiene", "[LOW] Legacy Juniper finding", "Fix it.")

    assert finding["severity"] == "LOW"
    assert finding["category"] == "hygiene"
    assert finding["message"] == "[LOW] Legacy Juniper finding"
    assert finding["remediation"] == "Fix it."
    assert finding["vendor"] == "juniper"


def test_any_any_detects_violation():
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_any_any_juniper(policies)
    assert len(findings) >= 1
    assert all(f["severity"] == "CRITICAL" for f in findings)


def test_any_any_finding_has_enriched_policy_metadata():
    policies = _parse_set_style(SET_STYLE_RISKY)
    finding = check_any_any_juniper(policies)[0]

    assert finding["id"] == "CASHEL-JUNIPER-EXPOSURE-001"
    assert finding["vendor"] == "juniper"
    assert finding["title"]
    assert "allow-all" in finding["evidence"]
    assert finding["affected_object"] == "allow-all"
    assert finding["rule_name"] == "allow-all"
    assert finding["confidence"] == "high"
    assert finding["metadata"]["policy_name"] == "allow-all"
    assert finding["metadata"]["from_zone"] == "trust"
    assert finding["metadata"]["to_zone"] == "untrust"
    assert finding["metadata"]["source_address"] == ["any"]
    assert finding["metadata"]["destination_address"] == ["any"]
    assert finding["metadata"]["application"] == ["any"]
    assert finding["metadata"]["action"] == "permit"
    assert finding["suggested_commands"]


def test_any_any_clean_config():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert check_any_any_juniper(policies) == []


def test_missing_log_detects():
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_missing_log_juniper(policies)
    # allow-all and allow-telnet both missing log
    assert len(findings) >= 1
    assert all(f["severity"] == "MEDIUM" for f in findings)


def test_missing_log_finding_has_log_metadata():
    policies = _parse_set_style(SET_STYLE_RISKY)
    finding = check_missing_log_juniper(policies)[0]

    assert finding["id"] == "CASHEL-JUNIPER-LOGGING-001"
    assert finding["metadata"]["log"] is False
    assert finding["metadata"]["session_init"] is False
    assert finding["metadata"]["session_close"] is False
    assert "session-init session-close" in "\n".join(finding["suggested_commands"])


def test_missing_log_clean():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    # allow-web has log; deny-all is not a permit rule
    assert check_missing_log_juniper(policies) == []


def test_insecure_apps_detects_telnet():
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_insecure_apps_juniper(policies)
    assert any("junos-telnet" in f["message"] for f in findings)
    assert all(f["severity"] == "CRITICAL" for f in findings)


def test_insecure_apps_clean():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert check_insecure_apps_juniper(policies) == []


def test_deny_all_missing():
    # Risky config has no deny-all at end — allow-telnet is last and is permit
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_deny_all_juniper(policies)
    assert len(findings) >= 1
    assert all(f["severity"] == "HIGH" for f in findings)


def test_deny_all_present():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert check_deny_all_juniper(policies) == []


# ══════════════════════════════════════════════ SYSTEM CHECKS ══


def test_system_detects_telnet():
    findings = check_system_juniper(SET_STYLE_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("Telnet" in m for m in msgs)
    telnet_findings = [f for f in findings if "Telnet" in f["message"]]
    assert all(f["severity"] == "CRITICAL" for f in telnet_findings)


def test_system_telnet_finding_has_raw_config_evidence():
    finding = next(
        f for f in check_system_juniper(SET_STYLE_RISKY) if "Telnet" in f["message"]
    )

    assert finding["id"] == "CASHEL-JUNIPER-MANAGEMENT-001"
    assert finding["vendor"] == "juniper"
    assert finding["evidence"] == "set system services telnet"
    assert finding["affected_object"] == "system services telnet"
    assert finding["metadata"]["subsystem"] == "system services"
    assert finding["metadata"]["service_name"] == "telnet"
    assert finding["suggested_commands"] == ["delete system services telnet"]


def test_system_detects_snmp_community():
    findings = check_system_juniper(SET_STYLE_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("public" in m for m in msgs)


def test_system_no_ntp():
    findings = check_system_juniper(SET_STYLE_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("NTP" in m for m in msgs)


def test_system_no_syslog():
    findings = check_system_juniper(SET_STYLE_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("syslog" in m.lower() for m in msgs)


def test_system_clean_config():
    findings = check_system_juniper(SET_STYLE_CLEAN)
    # Clean config has SSH, NTP, syslog — no HIGH system findings expected
    high_system = [
        f for f in findings if f["severity"] == "HIGH" and f["category"] == "management"
    ]
    assert len(high_system) == 0


# ══════════════════════════════════════════ SHADOW DETECTION ══


def test_shadow_rules_detected():
    # allow-all shadows allow-telnet in the risky config
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_shadow_rules_juniper(policies)
    assert len(findings) >= 1
    assert all(f["severity"] == "HIGH" for f in findings)
    assert any("allow-all" in f["message"] for f in findings)


def test_shadow_rules_clean():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert check_shadow_rules_juniper(policies) == []


# ══════════════════════════════════════════════ audit_juniper ══


def _write_tmp(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _object_config():
    path = _write_tmp(SET_STYLE_OBJECTS)
    try:
        config, error = parse_juniper_config(path)
    finally:
        os.unlink(path)
    assert error is None
    return config


def test_parse_juniper_success_returns_policies_and_no_error():
    path = _write_tmp(SET_STYLE_CLEAN)
    try:
        policies, error = parse_juniper(path)
    finally:
        os.unlink(path)

    assert error is None
    assert policies
    assert all(isinstance(policy, dict) for policy in policies)


def test_parse_juniper_missing_file_returns_error_tuple():
    policies, error = parse_juniper("/nonexistent/path.conf")

    assert policies == []
    assert error
    assert "Failed to read Juniper config" in error


def test_parse_juniper_config_returns_content_and_objects():
    config = _object_config()

    assert config["policies"]
    assert "set applications application TCP-8443 protocol tcp" in config["content"]
    assert (
        config["global_address_book"]["addresses"]["HR-NET"]["value"] == "10.20.10.0/24"
    )
    assert config["address_books"]["global"] is config["global_address_book"]
    assert config["applications"]["TCP-8443"]["protocol"] == "tcp"
    assert config["application_sets"]["APP-SERVICES"]["applications"] == [
        "junos-https",
        "TCP-8443",
        "LEGACY-TELNET",
    ]


def test_rule_quality_accepts_parse_juniper_policy_list():
    path = _write_tmp(SET_STYLE_RISKY)
    try:
        policies, error = parse_juniper(path)
    finally:
        os.unlink(path)

    assert error is None
    findings = check_shadow_rules_juniper(policies)
    assert findings


def test_audit_juniper_uses_policy_and_raw_system_checks():
    path = _write_tmp(SET_STYLE_OBJECTS)
    try:
        findings, policies = audit_juniper(path)
    finally:
        os.unlink(path)

    assert policies
    assert any(f["id"] == "CASHEL-JUNIPER-EXPOSURE-001" for f in findings)
    assert any(f["id"] == "CASHEL-JUNIPER-MANAGEMENT-001" for f in findings)


def test_juniper_global_and_zone_address_parsing():
    config = _object_config()
    global_book = config["address_books"]["global"]
    zone_book = config["address_books"]["zones"]["trust"]

    assert global_book["addresses"]["HR-NET"]["type"] == "ip-prefix"
    assert global_book["addresses"]["APP-FQDN"]["type"] == "dns-name"
    assert global_book["addresses"]["APP-FQDN"]["value"] == "app.example.com"
    assert global_book["addresses"]["RANGE-OBJ"]["type"] == "range-address"
    assert global_book["addresses"]["RANGE-OBJ"]["value"] == "10.40.1.10 to 10.40.1.20"
    assert zone_book["addresses"]["TRUST-HOST"]["value"] == "10.10.10.10/32"


def test_juniper_address_set_parsing_and_nested_expansion():
    config = _object_config()
    address_books = config["address_books"]

    assert address_books["global"]["address_sets"]["INTERNAL-USERS"]["addresses"] == [
        "HR-NET",
        "VPN-USERS",
    ]
    assert expand_address("NESTED-USERS", address_books) == [
        "10.20.10.0/24",
        "10.30.20.50/32",
        "VPN-USERS",
    ]
    assert expand_address("TRUST-USERS", address_books, zone="trust") == [
        "10.20.10.0/24"
    ]


def test_juniper_address_cycle_unknown_and_broad_normalization():
    address_books = _object_config()["address_books"]

    assert expand_address("CYCLE-A", address_books) == []
    assert expand_address("UNKNOWN-ADDR", address_books) == ["UNKNOWN-ADDR"]
    assert expand_addresses(["all", "*", "any-ipv4"], address_books) == ["any"]


def test_juniper_application_parsing_and_expansion():
    config = _object_config()
    applications = config["applications"]
    application_sets = config["application_sets"]

    assert applications["TCP-8443"]["protocol"] == "tcp"
    assert applications["TCP-8443"]["destination-port"] == "8443"
    assert applications["UDP-5353"]["protocol"] == "udp"
    assert applications["UDP-5353"]["destination-port"] == "5353"
    assert applications["SRC-RANGE"]["source-port"] == "1024-65535"
    assert expand_application("NESTED-SERVICES", applications, application_sets) == [
        "junos-https",
        "tcp/23",
        "tcp/8443",
    ]


def test_juniper_application_cycle_unknown_and_broad_normalization():
    config = _object_config()

    assert (
        expand_application(
            "APP-CYCLE-A", config["applications"], config["application_sets"]
        )
        == []
    )
    assert expand_application(
        "UNKNOWN-APP", config["applications"], config["application_sets"]
    ) == ["UNKNOWN-APP"]
    assert expand_applications(
        ["all", "*", "junos-any"], config["applications"], config["application_sets"]
    ) == ["any"]


def test_juniper_findings_include_raw_and_expanded_scope_metadata():
    finding = check_any_any_juniper(_object_config()["policies"])[0]
    metadata = finding["metadata"]

    assert metadata["raw_source_address"] == ["BROAD-USERS"]
    assert metadata["raw_destination_address"] == ["any"]
    assert metadata["raw_application"] == ["BROAD-APPS"]
    assert metadata["expanded_source_address"] == ["any"]
    assert metadata["expanded_destination_address"] == ["any"]
    assert metadata["expanded_application"] == ["any"]


def test_any_any_detection_uses_expanded_address_and_application_sets():
    findings = check_any_any_juniper(_object_config()["policies"])

    assert any(f["rule_name"] == "broad-object-rule" for f in findings)


def test_insecure_application_detection_uses_expanded_application_sets():
    findings = check_insecure_apps_juniper(_object_config()["policies"])
    finding = next(f for f in findings if f["rule_name"] == "app-set-telnet")

    assert finding["id"] == "CASHEL-JUNIPER-PROTOCOL-001"
    assert "tcp/23" in finding["metadata"]["insecure_applications"]


def test_deny_all_detection_recognizes_expanded_any_policy():
    findings = check_deny_all_juniper(_object_config()["policies"])

    assert findings == []


def test_audit_juniper_risky():
    path = _write_tmp(SET_STYLE_RISKY)
    try:
        findings, policies = audit_juniper(path)
        assert len(findings) > 0
        assert len(policies) > 0
        severities = {f["severity"] for f in findings}
        assert "HIGH" in severities
    finally:
        os.unlink(path)


def test_audit_juniper_findings_are_backward_compatible_dicts():
    path = _write_tmp(SET_STYLE_RISKY)
    try:
        findings, policies = audit_juniper(path)
    finally:
        os.unlink(path)

    assert policies
    assert findings
    for finding in findings:
        assert isinstance(finding, dict)
        assert finding["severity"]
        assert finding["category"]
        assert finding["message"]
        assert "remediation" in finding
        assert finding["id"].startswith("CASHEL-JUNIPER-")
        assert finding["vendor"] == "juniper"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["confidence"]
        assert isinstance(finding["metadata"], dict)


def test_juniper_remediation_plan_consumes_commands_and_evidence():
    finding = check_missing_log_juniper(_parse_set_style(SET_STYLE_RISKY))[0]
    plan = generate_plan([finding], "juniper")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-JUNIPER-LOGGING-001"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert "session-init session-close" in step["suggested_commands"]


def test_juniper_exports_preserve_enriched_fields():
    finding = check_any_any_juniper(_parse_set_style(SET_STYLE_RISKY))[0]
    entry = {
        "filename": "srx.conf",
        "vendor": "juniper",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-JUNIPER-EXPOSURE-001"
    assert json_out["findings"][0]["metadata"]["from_zone"] == "trust"

    csv_out = to_csv(entry)
    assert "CASHEL-JUNIPER-EXPOSURE-001" in csv_out
    assert "allow-all" in csv_out

    sarif_out = json.loads(to_sarif(entry))
    result = sarif_out["runs"][0]["results"][0]
    rule = sarif_out["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "CASHEL-JUNIPER-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert rule["id"] == "CASHEL-JUNIPER-EXPOSURE-001"


def test_juniper_old_and_plain_findings_remain_compatible():
    old_dict = {
        "severity": "HIGH",
        "category": "management",
        "message": "[HIGH] Telnet service enabled.",
        "remediation": "Disable telnet.",
    }
    plan = generate_plan([old_dict, "[LOW] Plain archive finding"], "juniper")

    assert plan["total_steps"] == 1
    step = plan["phases"][0]["steps"][0]
    assert step["description"] == old_dict["message"]
    assert "delete system services telnet" in step["suggested_commands"]


def test_audit_juniper_hierarchical():
    path = _write_tmp(HIERARCHICAL_CLEAN)
    try:
        findings, policies = audit_juniper(path)
        assert isinstance(findings, list)
        assert isinstance(policies, list)
    finally:
        os.unlink(path)


def test_audit_juniper_missing_file():
    findings, policies = audit_juniper("/nonexistent/path.conf")
    assert len(findings) == 1
    assert "Parse error" in findings[0]["message"]
    assert policies == []


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_set_parse_basic,
        test_set_parse_zone_fields,
        test_set_parse_action_permit,
        test_set_parse_action_deny,
        test_set_parse_src_dst_app,
        test_set_parse_deactivated,
        test_hier_parse_basic,
        test_hier_parse_log,
        test_hier_parse_inactive,
        test_hier_parse_deny_action,
        test_any_any_detects_violation,
        test_any_any_clean_config,
        test_missing_log_detects,
        test_missing_log_clean,
        test_insecure_apps_detects_telnet,
        test_insecure_apps_clean,
        test_deny_all_missing,
        test_deny_all_present,
        test_system_detects_telnet,
        test_system_detects_snmp_community,
        test_system_no_ntp,
        test_system_no_syslog,
        test_system_clean_config,
        test_shadow_rules_detected,
        test_shadow_rules_clean,
        test_audit_juniper_risky,
        test_audit_juniper_hierarchical,
        test_audit_juniper_missing_file,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests.")
    sys.exit(0 if failed == 0 else 1)
