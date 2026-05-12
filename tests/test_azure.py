from __future__ import annotations

import csv
import io
import json
import os
import tempfile

from cashel.azure import audit_azure_nsg
from cashel.export import to_csv, to_json, to_sarif
from cashel.models.findings import validate_finding_shape
from cashel.remediation import generate_plan


AZURE_RISKY = {
    "name": "edge-nsg",
    "securityRules": [
        {
            "name": "AllowAnyHigh",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 100,
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
            },
        },
        {
            "name": "AllowSSH",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 200,
                "protocol": "Tcp",
                "sourceAddressPrefix": "Internet",
                "destinationAddressPrefix": "10.0.0.4",
                "sourcePortRange": "*",
                "destinationPortRange": "22",
            },
        },
        {
            "name": "AllowWeb",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 300,
                "protocol": "Tcp",
                "sourceAddressPrefix": "Any",
                "destinationAddressPrefix": "10.0.0.5",
                "sourcePortRange": "*",
                "destinationPortRange": "443",
            },
        },
        {
            "name": "AllowAppRange",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 400,
                "protocol": "Tcp",
                "sourceAddressPrefix": "10.0.0.0/8",
                "destinationAddressPrefix": "10.0.0.6",
                "sourcePortRange": "*",
                "destinationPortRange": "1000-1205",
            },
        },
    ],
    "defaultSecurityRules": [],
}


AZURE_SAFE = {
    "name": "private-nsg",
    "flowLogs": {"enabled": True},
    "securityRules": [
        {
            "name": "AllowPartnerHttps",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "priority": 1000,
                "protocol": "Tcp",
                "sourceAddressPrefix": "203.0.113.0/24",
                "destinationAddressPrefix": "10.0.1.4",
                "sourcePortRange": "*",
                "destinationPortRange": "443",
            },
        },
        {
            "name": "DenyInternet",
            "properties": {
                "direction": "Inbound",
                "access": "Deny",
                "priority": 2000,
                "protocol": "*",
                "sourceAddressPrefix": "Internet",
                "destinationAddressPrefix": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
            },
        },
    ],
    "defaultSecurityRules": [],
}


def _audit_sample(sample: dict) -> tuple[list[dict], list[dict]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(sample, fh)
        path = fh.name
    try:
        return audit_azure_nsg(path)
    finally:
        os.unlink(path)


def _entry(findings: list[dict]) -> dict:
    return {
        "filename": "azure-nsg.json",
        "vendor": "azure",
        "summary": {"total": len(findings)},
        "findings": findings,
    }


def test_azure_findings_preserve_count_and_severity_expectations():
    findings, nsgs = _audit_sample(AZURE_RISKY)

    assert len(nsgs) == 1
    assert len(findings) == 6
    assert [f["severity"] for f in findings].count("HIGH") == 3
    assert [f["severity"] for f in findings].count("MEDIUM") == 3
    assert any(
        "ALL inbound traffic from Any source allowed" in f["message"] for f in findings
    )
    assert any("SSH port 22 open to Any source" in f["message"] for f in findings)
    assert any("Port 443 open to Any source" in f["message"] for f in findings)
    assert any("Flow log status unknown" in f["message"] for f in findings)
    assert any("High-priority allow-all inbound rule" in f["message"] for f in findings)
    assert any("Wide inbound port range 1000-1205" in f["message"] for f in findings)


def test_azure_findings_are_enriched_with_stable_ids_and_rule_evidence():
    findings, _nsgs = _audit_sample(AZURE_RISKY)

    for finding in findings:
        assert finding["id"].startswith("CASHEL-AZURE-")
        assert finding["vendor"] == "azure"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["affected_object"]
        assert finding["confidence"]
        assert finding["verification"]
        assert finding["metadata"]["nsg_name"] == "edge-nsg"
        assert "flow_log_state" in finding["metadata"]
        assert validate_finding_shape(finding) == []

    assert [f["id"] for f in _audit_sample(AZURE_RISKY)[0]] == [
        f["id"] for f in findings
    ]

    rule_backed = [
        f for f in findings if f["metadata"].get("raw_rule_context") is not None
    ]
    assert rule_backed
    for finding in rule_backed:
        metadata = finding["metadata"]
        assert metadata["rule_name"]
        assert metadata["direction"] == "Inbound"
        assert metadata["priority"]
        assert metadata["protocol"]
        assert metadata["source_address_prefixes"]
        assert metadata["destination_address_prefixes"]
        assert metadata["source_port_ranges"]
        assert metadata["destination_port_ranges"]
        assert metadata["action"] == "Allow"
        assert "priority=" in finding["evidence"]


def test_azure_exports_preserve_enriched_fields():
    findings, _nsgs = _audit_sample(AZURE_RISKY)
    finding = findings[0]
    entry = _entry([finding])

    json_out = json.loads(to_json(entry))
    exported = json_out["findings"][0]
    assert exported["id"] == finding["id"]
    assert exported["metadata"]["nsg_name"] == "edge-nsg"
    assert exported["metadata"]["rule_name"] == "AllowAnyHigh"
    assert exported["evidence"] == finding["evidence"]

    csv_row = next(csv.DictReader(io.StringIO(to_csv(entry))))
    assert csv_row["id"] == finding["id"]
    assert csv_row["vendor"] == "azure"
    assert csv_row["evidence"] == finding["evidence"]
    assert csv_row["affected_object"] == finding["affected_object"]
    assert csv_row["rule_name"] == finding["rule_name"]

    sarif = json.loads(to_sarif(entry))
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == finding["id"]
    assert rule["id"] == finding["id"]
    assert result["properties"]["vendor"] == "azure"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert result["properties"]["rule_name"] == finding["rule_name"]


def test_azure_remediation_consumes_enriched_fields():
    findings, _nsgs = _audit_sample(AZURE_RISKY)
    finding = findings[0]

    plan = generate_plan([finding], "azure", filename="azure-nsg.json")
    step = plan["phases"][0]["steps"][0]

    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert step["verification"] == finding["verification"]
    assert step["rollback"] == finding["rollback"]
    assert step["affected_object"] == finding["affected_object"]
    assert "suggested_commands" not in step


def test_azure_safe_sample_has_no_prioritized_false_positives():
    findings, nsgs = _audit_sample(AZURE_SAFE)

    assert len(nsgs) == 1
    assert findings == []
