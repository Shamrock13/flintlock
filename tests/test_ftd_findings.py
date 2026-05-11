"""Tests for enriched Cisco FTD audit findings."""

import csv
import io
import json
import os
import sys
import tempfile
from os import unlink as _os_unlink

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ciscoconfparse import CiscoConfParse

from cashel.audit_engine import _findings_to_strings
from cashel.export import to_csv, to_json, to_sarif
from cashel.ftd import (
    _check_any_any,
    _check_deny_all,
    _check_icmp_any,
    _check_missing_logging,
    _check_redundant_rules,
    _check_telnet,
)
from cashel.models.findings import validate_finding_shape
from cashel.remediation import generate_plan


def _parse(cfg_text: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as fh:
        fh.write(cfg_text)
        path = fh.name
    parse = CiscoConfParse(path, ignore_blank_lines=False)
    _os_unlink(path)
    return parse


def test_ftd_prioritized_acl_findings_are_enriched_and_legacy_compatible():
    parse = _parse(
        "\n".join(
            [
                "access-list OUTSIDE_IN extended permit ip any any",
                "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443",
                "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443",
                "access-list OUTSIDE_IN extended permit icmp any any",
                "telnet 0.0.0.0 0.0.0.0 management",
            ]
        )
        + "\n"
    )

    findings = (
        _check_any_any(parse)
        + _check_missing_logging(parse)
        + _check_deny_all(parse)
        + _check_redundant_rules(parse)
        + _check_telnet(parse)
        + _check_icmp_any(parse)
    )

    assert len(_check_any_any(parse)) == 1
    assert len(_check_missing_logging(parse)) == 4
    assert len(_check_deny_all(parse)) == 1
    assert len(_check_redundant_rules(parse)) == 1
    assert len(_check_telnet(parse)) == 1
    assert len(_check_icmp_any(parse)) == 1
    assert {finding["id"] for finding in findings} >= {
        "CASHEL-FTD-EXPOSURE-001",
        "CASHEL-FTD-LOGGING-001",
        "CASHEL-FTD-HYGIENE-001",
        "CASHEL-FTD-REDUNDANCY-001",
        "CASHEL-FTD-PROTOCOL-001",
        "CASHEL-FTD-EXPOSURE-002",
    }
    assert all(validate_finding_shape(finding) == [] for finding in findings)
    assert any(finding["severity"] == "CRITICAL" for finding in findings)
    assert any(finding.get("evidence") for finding in findings)
    assert any("[CRITICAL]" in message for message in _findings_to_strings(findings))


def test_ftd_rule_backed_findings_include_acl_evidence_and_metadata():
    parse = _parse(
        "\n".join(
            [
                "access-list OUTSIDE_IN extended permit ip any any",
                "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 23",
                "access-list OUTSIDE_IN extended permit icmp any any",
            ]
        )
        + "\n"
    )

    any_any = _check_any_any(parse)[0]
    telnet_acl = _check_telnet(parse)[0]
    icmp = _check_icmp_any(parse)[0]

    for finding in (any_any, telnet_acl, icmp):
        assert finding["vendor"] == "ftd"
        assert finding["evidence"].startswith("access-list OUTSIDE_IN")
        assert finding["affected_object"] == "OUTSIDE_IN"
        assert finding["rule_name"] == "OUTSIDE_IN"
        assert finding["confidence"] == "high"
        assert finding["verification"]
        assert finding["rollback"]
        assert finding["metadata"]["acl_name"] == "OUTSIDE_IN"
        assert finding["metadata"]["syntax_family"] == "asa-compatible"
        assert finding["metadata"]["acl_line"] == finding["evidence"]


def test_ftd_redundant_finding_tracks_duplicate_rule_context():
    parse = _parse(
        "\n".join(
            [
                "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443",
                "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443",
            ]
        )
        + "\n"
    )

    finding = _check_redundant_rules(parse)[0]

    assert finding["id"] == "CASHEL-FTD-REDUNDANCY-001"
    assert finding["evidence"] == (
        "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443"
    )
    assert finding["metadata"]["duplicate_of"] == finding["evidence"]
    assert "tcp/443" in finding["metadata"]["expanded_service"]


def test_ftd_enriched_findings_feed_remediation_and_exports():
    parse = _parse("access-list OUTSIDE_IN extended permit ip any any\n")
    finding = _check_any_any(parse)[0]

    plan = generate_plan([finding], "ftd")
    step = plan["phases"][0]["steps"][0]
    assert step["id"] == "CASHEL-FTD-EXPOSURE-001"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert step["suggested_commands"]

    entry = {"filename": "ftd.cfg", "vendor": "ftd", "findings": [finding]}
    assert json.loads(to_json(entry))["findings"][0]["id"] == finding["id"]

    rows = list(csv.DictReader(io.StringIO(to_csv(entry))))
    assert rows[0]["id"] == "CASHEL-FTD-EXPOSURE-001"
    assert rows[0]["evidence"] == finding["evidence"]

    sarif = json.loads(to_sarif(entry))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CASHEL-FTD-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]


def test_ftd_safe_acl_sample_has_no_prioritized_acl_findings():
    parse = _parse(
        "\n".join(
            [
                "access-list OUTSIDE_IN extended permit tcp host 10.0.0.10 host 10.0.0.20 eq 443 log",
                "access-list OUTSIDE_IN extended deny ip any any log",
                "ssh version 2",
            ]
        )
        + "\n"
    )

    assert _check_any_any(parse) == []
    assert _check_missing_logging(parse) == []
    assert _check_deny_all(parse) == []
    assert _check_redundant_rules(parse) == []
    assert _check_telnet(parse) == []
    assert _check_icmp_any(parse) == []
