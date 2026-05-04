"""Tests for pfSense parser and normalized audit findings."""

import json
import os
import tempfile

from cashel.export import to_csv, to_json, to_sarif
from cashel.pfsense import (
    _f,
    audit_pfsense,
    check_any_any_pf,
    check_missing_logging_pf,
    check_redundant_rules_pf,
    check_wan_any_source_pf,
    expand_address,
    expand_addresses,
    expand_port,
    expand_ports,
    parse_pfsense_config,
    parse_pfsense,
)
from cashel.remediation import generate_plan
from cashel.rule_quality import check_shadow_rules_pfsense

TESTS_DIR = os.path.dirname(__file__)

PFSENSE_RICH = """\
<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <tracker>1001</tracker>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <descr>Allow All</descr>
    </rule>
    <rule>
      <tracker>1002</tracker>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination>
        <address>10.0.0.1</address>
        <port>443</port>
      </destination>
      <protocol>tcp</protocol>
      <log/>
      <descr>Allow Web</descr>
    </rule>
    <rule>
      <tracker>1003</tracker>
      <type>block</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <log/>
      <descr>Block All</descr>
    </rule>
  </filter>
</pfsense>
"""

PFSENSE_ALIASES = """\
<?xml version="1.0"?>
<pfsense>
  <aliases>
    <alias>
      <name>LAN_NETS</name>
      <type>network</type>
      <address>10.10.0.0/16 10.20.0.0/16</address>
      <descr>Internal LAN networks</descr>
    </alias>
    <alias>
      <name>WEB_SERVERS</name>
      <type>host</type>
      <address>10.30.20.10 10.30.20.11</address>
    </alias>
    <alias>
      <name>ANY_SOURCES</name>
      <type>network</type>
      <address>any</address>
    </alias>
    <alias>
      <name>MGMT_PORTS</name>
      <type>port</type>
      <address>22 443 8443</address>
    </alias>
    <alias>
      <name>REMOTE_SOURCES</name>
      <type>urltable</type>
      <url>https://example.com/sources.txt</url>
      <descr>Remote source table</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <tracker>2001</tracker>
      <type>pass</type>
      <interface>wan</interface>
      <source><address>ANY_SOURCES</address></source>
      <destination>
        <any/>
        <port>MGMT_PORTS</port>
      </destination>
      <protocol>tcp</protocol>
      <descr>Alias Any Pass</descr>
    </rule>
    <rule>
      <tracker>2002</tracker>
      <type>pass</type>
      <interface>lan</interface>
      <source><address>LAN_NETS</address></source>
      <destination>
        <address>WEB_SERVERS</address>
        <port>MGMT_PORTS</port>
      </destination>
      <protocol>tcp</protocol>
      <descr>Alias Web A</descr>
    </rule>
    <rule>
      <tracker>2003</tracker>
      <type>pass</type>
      <interface>lan</interface>
      <source><address>LAN_NETS</address></source>
      <destination>
        <address>WEB_SERVERS</address>
        <port>MGMT_PORTS</port>
      </destination>
      <protocol>tcp</protocol>
      <descr>Alias Web B</descr>
    </rule>
    <rule>
      <tracker>2004</tracker>
      <type>block</type>
      <interface>wan</interface>
      <source><address>ANY_SOURCES</address></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <descr>Alias Block All</descr>
    </rule>
  </filter>
</pfsense>
"""


def _write_tmp(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _rules():
    rules, error = parse_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))
    assert error is None
    return rules


def _alias_config():
    path = _write_tmp(PFSENSE_ALIASES)
    try:
        config, error = parse_pfsense_config(path)
    finally:
        os.unlink(path)
    assert error is None
    return config


def test_parse_pfsense_returns_rules_and_error_tuple():
    rules, error = parse_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    assert error is None
    assert rules
    assert rules[0]["descr"] == "Allow All"


def test_parse_pfsense_config_returns_rules_and_alias_dictionaries():
    config = _alias_config()

    assert config["rules"]
    assert "LAN_NETS" in config["aliases"]
    assert "LAN_NETS" in config["address_aliases"]
    assert "MGMT_PORTS" in config["port_aliases"]
    assert "REMOTE_SOURCES" in config["url_aliases"]


def test_parse_pfsense_captures_rule_evidence_and_metadata_fields():
    path = _write_tmp(PFSENSE_RICH)
    try:
        rules, error = parse_pfsense(path)
    finally:
        os.unlink(path)

    assert error is None
    first = rules[0]
    web = rules[1]
    assert first["tracker"] == "1001"
    assert first["disabled"] is False
    assert "<tracker>1001</tracker>" in first["_raw"]
    assert web["destination_port"] == "443"


def test_audit_pfsense_returns_existing_public_shape():
    findings, rules = audit_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    assert findings
    assert rules
    assert all(isinstance(finding, dict) for finding in findings)


def test_rule_quality_still_accepts_parse_pfsense_rule_list():
    rules, error = parse_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    assert error is None
    findings = check_shadow_rules_pfsense(rules)
    assert findings


def test_pfsense_legacy_helper_shape_still_works():
    finding = _f("LOW", "hygiene", "[LOW] Legacy pfSense finding", "Fix it.")

    assert finding["severity"] == "LOW"
    assert finding["category"] == "hygiene"
    assert finding["message"] == "[LOW] Legacy pfSense finding"
    assert finding["remediation"] == "Fix it."
    assert finding["vendor"] == "pfsense"


def test_pfsense_findings_keep_legacy_keys_and_enriched_fields():
    findings, _rules_out = audit_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    for finding in findings:
        assert finding["severity"]
        assert finding["category"]
        assert finding["message"]
        assert "remediation" in finding
        assert finding["id"].startswith("CASHEL-PFSENSE-")
        assert finding["vendor"] == "pfsense"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["confidence"]
        assert isinstance(finding["metadata"], dict)


def test_pfsense_any_any_finding_includes_rule_metadata():
    finding = check_any_any_pf(_rules())[0]
    metadata = finding["metadata"]

    assert finding["id"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert finding["rule_name"] == "Allow All"
    assert finding["affected_object"] == "Allow All"
    assert "<descr>Allow All</descr>" in finding["evidence"]
    assert metadata["interface"] == "wan"
    assert metadata["source"] == "1"
    assert metadata["destination"] == "1"
    assert metadata["protocol"] == "any"
    assert metadata["type"] == "pass"
    assert metadata["action"] == "pass"
    assert metadata["log"] is False
    assert metadata["raw_source"] == "1"
    assert metadata["raw_destination"] == "1"
    assert metadata["expanded_source"] == ["any"]
    assert metadata["expanded_destination"] == ["any"]


def test_pfsense_missing_logging_finding_includes_logging_metadata():
    finding = check_missing_logging_pf(_rules())[0]

    assert finding["id"] == "CASHEL-PFSENSE-LOGGING-001"
    assert finding["metadata"]["log"] is False
    assert "Enable Log packets" in "\n".join(finding["suggested_commands"])


def test_pfsense_wan_exposure_uses_ui_style_guidance():
    finding = check_wan_any_source_pf(_rules())[0]
    commands = "\n".join(finding["suggested_commands"])

    assert finding["id"] == "CASHEL-PFSENSE-EXPOSURE-002"
    assert "pfSense UI: Firewall > Rules > WAN" in commands
    assert "pfctl" not in commands.lower()


def test_pfsense_remediation_plan_consumes_commands_and_evidence():
    finding = check_missing_logging_pf(_rules())[0]
    plan = generate_plan([finding], "pfsense")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-PFSENSE-LOGGING-001"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert "Enable Log packets" in step["suggested_commands"]


def test_pfsense_exports_preserve_enriched_fields():
    finding = check_any_any_pf(_rules())[0]
    entry = {
        "filename": "config.xml",
        "vendor": "pfsense",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert json_out["findings"][0]["metadata"]["interface"] == "wan"

    csv_out = to_csv(entry)
    assert "CASHEL-PFSENSE-EXPOSURE-001" in csv_out
    assert "Allow All" in csv_out

    sarif_out = json.loads(to_sarif(entry))
    result = sarif_out["runs"][0]["results"][0]
    rule = sarif_out["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert rule["id"] == "CASHEL-PFSENSE-EXPOSURE-001"


def test_pfsense_old_and_plain_findings_remain_compatible():
    old_dict = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] pfSense rule missing logging.",
        "remediation": "Enable logging in the pfSense UI.",
    }
    plan = generate_plan([old_dict, "[LOW] Plain archive finding"], "pfsense")

    assert plan["total_steps"] == 1
    step = plan["phases"][0]["steps"][0]
    assert step["description"] == old_dict["message"]
    assert "suggested_commands" not in step


def test_pfsense_alias_parser_captures_addresses_ports_urls_and_descriptions():
    config = _alias_config()

    assert config["address_aliases"]["LAN_NETS"]["address"] == [
        "10.10.0.0/16",
        "10.20.0.0/16",
    ]
    assert config["address_aliases"]["WEB_SERVERS"]["type"] == "host"
    assert config["port_aliases"]["MGMT_PORTS"]["address"] == ["22", "443", "8443"]
    assert config["url_aliases"]["REMOTE_SOURCES"]["url"] == (
        "https://example.com/sources.txt"
    )
    assert config["url_aliases"]["REMOTE_SOURCES"]["descr"] == "Remote source table"


def test_pfsense_alias_expansion_preserves_unknowns_and_normalizes_broad_values():
    config = _alias_config()

    assert expand_address("LAN_NETS", config["address_aliases"]) == [
        "10.10.0.0/16",
        "10.20.0.0/16",
    ]
    assert expand_address("REMOTE_SOURCES", config["address_aliases"]) == [
        "https://example.com/sources.txt"
    ]
    assert expand_address("UNKNOWN_ALIAS", config["address_aliases"]) == [
        "UNKNOWN_ALIAS"
    ]
    assert expand_addresses(["1", "*", "any"], config["address_aliases"]) == ["any"]
    assert expand_port("MGMT_PORTS", config["port_aliases"]) == ["22", "443", "8443"]
    assert expand_port("UNKNOWN_PORT", config["port_aliases"]) == ["UNKNOWN_PORT"]
    assert expand_ports(["", "*", "1"], config["port_aliases"]) == ["any"]


def test_pfsense_any_any_detection_uses_alias_expansion():
    finding = check_any_any_pf(_alias_config()["rules"])[0]

    assert finding["rule_name"] == "Alias Any Pass"
    assert finding["metadata"]["raw_source"] == "ANY_SOURCES"
    assert finding["metadata"]["expanded_source"] == ["any"]
    assert "Replace source alias ANY_SOURCES" in "\n".join(
        finding["suggested_commands"]
    )


def test_pfsense_wan_any_source_detection_uses_alias_expansion():
    finding = check_wan_any_source_pf(_alias_config()["rules"])[0]

    assert finding["rule_name"] == "Alias Any Pass"
    assert finding["metadata"]["expanded_source"] == ["any"]


def test_pfsense_redundant_detection_uses_expanded_alias_scope():
    findings = check_redundant_rules_pf(_alias_config()["rules"])
    duplicate = next(f for f in findings if f["rule_name"] == "Alias Web B")

    assert duplicate["id"] == "CASHEL-PFSENSE-REDUNDANCY-002"
    assert duplicate["metadata"]["expanded_source"] == [
        "10.10.0.0/16",
        "10.20.0.0/16",
    ]
    assert duplicate["metadata"]["expanded_destination_port"] == ["22", "443", "8443"]


def test_pfsense_alias_exports_preserve_expanded_fields():
    finding = check_any_any_pf(_alias_config()["rules"])[0]
    entry = {
        "filename": "config.xml",
        "vendor": "pfsense",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["metadata"]["raw_source"] == "ANY_SOURCES"
    assert json_out["findings"][0]["metadata"]["expanded_source"] == ["any"]

    sarif_out = json.loads(to_sarif(entry))
    assert sarif_out["runs"][0]["results"][0]["ruleId"] == (
        "CASHEL-PFSENSE-EXPOSURE-001"
    )
