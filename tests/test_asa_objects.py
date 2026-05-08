"""Tests for Cisco ASA object/object-group expansion and enriched findings."""

import csv
import io
import json
import os
import sys
import tempfile
from os import unlink as _os_unlink

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ciscoconfparse import CiscoConfParse

from cashel.audit_engine import (
    _audit_asa,
    _check_any_any,
    _check_redundant_rules,
    _check_telnet_asa,
    expand_asa_address,
    expand_asa_service,
    parse_asa_network_object_groups,
    parse_asa_network_objects,
    parse_asa_service_object_groups,
    parse_asa_service_objects,
)
from cashel.export import to_csv, to_json, to_sarif
from cashel.models.findings import validate_finding_shape
from cashel.remediation import generate_plan


def _parse(cfg_text: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as fh:
        fh.write(cfg_text)
        path = fh.name
    parse = CiscoConfParse(path, ignore_blank_lines=False)
    _os_unlink(path)
    return parse


ASA_OBJECT_CFG = """
object network WEB-SERVER
 host 10.30.20.50
object network HR-NET
 subnet 10.20.10.0 255.255.255.0
object network RANGE-OBJ
 range 10.40.1.10 10.40.1.20
object-group network VPN-USERS
 network-object host 10.10.10.10
object-group network INTERNAL-USERS
 network-object object HR-NET
 network-object object VPN-USERS
 network-object host 10.10.10.11
 network-object 10.20.0.0 255.255.0.0
 group-object NESTED-USERS
object-group network NESTED-USERS
 network-object object RANGE-OBJ
object-group network BROAD-USERS
 network-object any 255.255.255.255
object-group network CYCLE-A
 group-object CYCLE-B
object-group network CYCLE-B
 group-object CYCLE-A
object service TCP-8443
 service tcp destination eq 8443
object service LEGACY-TELNET
 service tcp destination eq 23
object-group service LEGACY-SERVICES tcp
 service-object object LEGACY-TELNET
object-group service APP-SERVICES tcp
 port-object eq 443
 port-object eq 8443
 service-object tcp destination eq 23
 group-object LEGACY-SERVICES
object-group service CYCLE-SVC-A tcp
 group-object CYCLE-SVC-B
object-group service CYCLE-SVC-B tcp
 group-object CYCLE-SVC-A
"""


def test_asa_network_object_parsing_host_subnet_and_range():
    objects = parse_asa_network_objects(_parse(ASA_OBJECT_CFG))

    assert objects["WEB-SERVER"]["type"] == "host"
    assert objects["WEB-SERVER"]["value"] == "10.30.20.50"
    assert objects["HR-NET"]["type"] == "subnet"
    assert objects["HR-NET"]["value"] == "10.20.10.0 255.255.255.0"
    assert objects["RANGE-OBJ"]["type"] == "range"
    assert objects["RANGE-OBJ"]["value"] == "10.40.1.10-10.40.1.20"
    assert "host 10.30.20.50" in objects["WEB-SERVER"]["raw_lines"]


def test_asa_network_object_group_parsing_and_expansion():
    parse = _parse(ASA_OBJECT_CFG)
    objects = parse_asa_network_objects(parse)
    groups = parse_asa_network_object_groups(parse)

    group = groups["INTERNAL-USERS"]
    assert group["members"][0] == {"kind": "object", "value": "HR-NET"}
    assert "NESTED-USERS" in group["group_members"]
    assert expand_asa_address("INTERNAL-USERS", objects, groups) == [
        "10.20.10.0 255.255.255.0",
        "10.10.10.10",
        "10.10.10.11",
        "10.20.0.0 255.255.0.0",
        "10.40.1.10-10.40.1.20",
    ]


def test_asa_network_expansion_cycle_unknown_and_broad_values():
    parse = _parse(ASA_OBJECT_CFG)
    objects = parse_asa_network_objects(parse)
    groups = parse_asa_network_object_groups(parse)

    assert expand_asa_address("CYCLE-A", objects, groups) == []
    assert expand_asa_address("UNKNOWN-OBJ", objects, groups) == ["UNKNOWN-OBJ"]
    assert expand_asa_address("any4", objects, groups) == ["any"]
    assert expand_asa_address("*", objects, groups) == ["any"]
    assert expand_asa_address("BROAD-USERS", objects, groups) == ["any"]


def test_asa_service_object_and_group_parsing_and_expansion():
    parse = _parse(ASA_OBJECT_CFG)
    services = parse_asa_service_objects(parse)
    groups = parse_asa_service_object_groups(parse)

    assert services["TCP-8443"]["protocol"] == "tcp"
    assert services["TCP-8443"]["destination_operator"] == "eq"
    assert services["TCP-8443"]["destination_port"] == "8443"
    assert groups["APP-SERVICES"]["protocol"] == "tcp"
    assert groups["APP-SERVICES"]["port_objects"][0] == {
        "operator": "eq",
        "port": "443",
    }
    assert expand_asa_service("APP-SERVICES", services, groups) == [
        "tcp/443",
        "tcp/8443",
        "tcp/23",
    ]


def test_asa_service_expansion_cycle_unknown_and_broad_values():
    parse = _parse(ASA_OBJECT_CFG)
    services = parse_asa_service_objects(parse)
    groups = parse_asa_service_object_groups(parse)

    assert expand_asa_service("CYCLE-SVC-A", services, groups) == []
    assert expand_asa_service("UNKNOWN-SERVICE", services, groups) == [
        "UNKNOWN-SERVICE"
    ]
    assert expand_asa_service("any6", services, groups) == ["any"]


def test_asa_any_any_detection_uses_expanded_object_group_scope():
    parse = _parse(
        ASA_OBJECT_CFG
        + "access-list OUTSIDE_IN extended permit ip object-group BROAD-USERS any\n"
    )
    findings = _check_any_any(parse)

    assert len(findings) == 1
    finding = findings[0]
    assert validate_finding_shape(finding) == []
    assert finding["id"] == "CASHEL-ASA-EXPOSURE-001"
    assert finding["evidence"] == (
        "access-list OUTSIDE_IN extended permit ip object-group BROAD-USERS any"
    )
    assert finding["metadata"]["raw_source"] == "object-group BROAD-USERS"
    assert finding["metadata"]["raw_destination"] == "any"
    assert finding["metadata"]["expanded_source"] == ["any"]
    assert finding["metadata"]["expanded_destination"] == ["any"]
    assert finding["metadata"]["acl_name"] == "OUTSIDE_IN"


def test_asa_findings_include_raw_and_expanded_destination_and_service_metadata():
    parse = _parse(
        ASA_OBJECT_CFG
        + "access-list OUTSIDE_IN extended permit tcp any object WEB-SERVER object-group APP-SERVICES\n"
    )
    finding = _check_telnet_asa(parse)[0]

    assert finding["id"] == "CASHEL-ASA-PROTOCOL-002"
    assert finding["affected_object"] == "OUTSIDE_IN"
    assert finding["metadata"]["raw_destination"] == "object WEB-SERVER"
    assert finding["metadata"]["expanded_destination"] == ["10.30.20.50"]
    assert finding["metadata"]["raw_service"] == "object-group APP-SERVICES"
    assert "tcp/23" in finding["metadata"]["expanded_service"]


def test_asa_redundant_detection_uses_expanded_effective_scope():
    parse = _parse(
        ASA_OBJECT_CFG
        + "\n".join(
            [
                "access-list OUTSIDE_IN extended permit tcp any object WEB-SERVER eq 8443",
                "access-list OUTSIDE_IN extended permit tcp any host 10.30.20.50 object TCP-8443",
            ]
        )
        + "\n"
    )
    findings = _check_redundant_rules(parse)

    assert len(findings) == 1
    assert findings[0]["id"] == "CASHEL-ASA-REDUNDANCY-001"
    assert findings[0]["metadata"]["expanded_destination"] == ["10.30.20.50"]
    assert "tcp/8443" in findings[0]["metadata"]["expanded_service"]


def test_asa_remediation_and_exports_preserve_enriched_fields():
    path = _write_cfg(
        ASA_OBJECT_CFG
        + "access-list OUTSIDE_IN extended permit ip object-group BROAD-USERS any\n"
    )
    try:
        findings, _parse_out = _audit_asa(path)
    finally:
        _os_unlink(path)
    finding = next(f for f in findings if f["id"] == "CASHEL-ASA-EXPOSURE-001")

    plan = generate_plan([finding], "asa")
    step = plan["phases"][0]["steps"][0]
    assert step["evidence"] == finding["evidence"]
    assert step["suggested_commands"]

    entry = {"filename": "asa.cfg", "vendor": "asa", "findings": [finding]}
    assert json.loads(to_json(entry))["findings"][0]["metadata"]["expanded_source"] == [
        "any"
    ]
    rows = list(csv.DictReader(io.StringIO(to_csv(entry))))
    assert rows[0]["id"] == "CASHEL-ASA-EXPOSURE-001"
    sarif = json.loads(to_sarif(entry))
    assert (
        sarif["runs"][0]["results"][0]["properties"]["evidence"] == finding["evidence"]
    )


def test_asa_old_and_plain_findings_remain_compatible():
    legacy = {
        "severity": "LOW",
        "category": "hygiene",
        "message": "[LOW] Legacy ASA finding",
        "remediation": "Fix it.",
    }

    assert validate_finding_shape(legacy) == []
    assert validate_finding_shape("[LOW] Plain ASA archive finding") == []


def _write_cfg(cfg_text: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as fh:
        fh.write(cfg_text)
        return fh.name
