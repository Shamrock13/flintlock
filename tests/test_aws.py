from __future__ import annotations

import csv
import io
import json
import os
import tempfile

from cashel.aws import audit_aws_sg
from cashel.export import to_csv, to_json, to_sarif
from cashel.models.findings import validate_finding_shape
from cashel.remediation import generate_plan


AWS_RISKY = {
    "SecurityGroups": [
        {
            "GroupId": "sg-0123456789abcdef0",
            "GroupName": "web-tier",
            "Description": "",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": "public https",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 1000,
                    "ToPort": 1205,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/8",
                            "Description": "internal app range",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
        },
        {
            "GroupId": "sg-0default",
            "GroupName": "default",
            "Description": "default",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [{"GroupId": "sg-peer"}],
                }
            ],
            "IpPermissionsEgress": [],
        },
    ]
}


AWS_SAFE = {
    "SecurityGroups": [
        {
            "GroupId": "sg-safe",
            "GroupName": "private-api",
            "Description": "Private API security group owned by platform.",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "203.0.113.0/24",
                            "Description": "partner office egress range",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/8",
                            "Description": "private service endpoints",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
        }
    ]
}


def _audit_sample(sample: dict) -> tuple[list[dict], list[dict]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(sample, fh)
        path = fh.name
    try:
        return audit_aws_sg(path)
    finally:
        os.unlink(path)


def _entry(findings: list[dict]) -> dict:
    return {
        "filename": "aws-security-groups.json",
        "vendor": "aws",
        "summary": {"total": len(findings)},
        "findings": findings,
    }


def test_aws_findings_preserve_count_and_severity_expectations():
    findings, groups = _audit_sample(AWS_RISKY)

    assert len(groups) == 2
    assert len(findings) == 8
    assert [f["severity"] for f in findings].count("HIGH") == 1
    assert [f["severity"] for f in findings].count("MEDIUM") == 7
    assert any("SSH (port 22) open to 0.0.0.0/0" in f["message"] for f in findings)
    assert any("Unrestricted outbound traffic" in f["message"] for f in findings)
    assert any("Missing or generic group description" in f["message"] for f in findings)
    assert any("Default security group" in f["message"] for f in findings)
    assert any("Wide port range 1000-1205" in f["message"] for f in findings)


def test_aws_findings_are_enriched_with_stable_ids_and_rule_evidence():
    findings, _groups = _audit_sample(AWS_RISKY)

    for finding in findings:
        assert finding["id"].startswith("CASHEL-AWS-")
        assert finding["vendor"] == "aws"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["affected_object"]
        assert finding["confidence"]
        assert finding["verification"]
        assert finding["metadata"]["security_group_id"]
        assert validate_finding_shape(finding) == []

    first_run_ids = [f["id"] for f in findings]
    second_run_ids = [f["id"] for f in _audit_sample(AWS_RISKY)[0]]
    assert second_run_ids == first_run_ids

    rule_backed = [
        f
        for f in findings
        if f["metadata"].get("raw_permission_context")
        and isinstance(f["metadata"]["raw_permission_context"], dict)
    ]
    assert rule_backed
    for finding in rule_backed:
        metadata = finding["metadata"]
        assert metadata["rule_direction"] in {"ingress", "egress"}
        assert metadata["protocol"]
        assert "from_port" in metadata
        assert "to_port" in metadata
        assert "cidr" in metadata
        assert "description" in metadata
        assert "raw_permission_context" in metadata
        assert "direction=" in finding["evidence"]


def test_aws_exports_preserve_enriched_fields():
    findings, _groups = _audit_sample(AWS_RISKY)
    finding = findings[0]
    entry = _entry([finding])

    json_out = json.loads(to_json(entry))
    exported = json_out["findings"][0]
    assert exported["id"] == finding["id"]
    assert exported["metadata"]["security_group_id"] == "sg-0123456789abcdef0"
    assert exported["evidence"] == finding["evidence"]

    csv_row = next(csv.DictReader(io.StringIO(to_csv(entry))))
    assert csv_row["id"] == finding["id"]
    assert csv_row["vendor"] == "aws"
    assert csv_row["evidence"] == finding["evidence"]
    assert csv_row["affected_object"] == finding["affected_object"]
    assert csv_row["confidence"] == finding["confidence"]

    sarif = json.loads(to_sarif(entry))
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == finding["id"]
    assert rule["id"] == finding["id"]
    assert result["properties"]["vendor"] == "aws"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert result["properties"]["affected_object"] == finding["affected_object"]


def test_aws_remediation_consumes_enriched_fields():
    findings, _groups = _audit_sample(AWS_RISKY)
    finding = findings[0]

    plan = generate_plan([finding], "aws", filename="aws-security-groups.json")
    step = plan["phases"][0]["steps"][0]

    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert step["verification"] == finding["verification"]
    assert step["rollback"] == finding["rollback"]
    assert "suggested_commands" not in step


def test_aws_safe_sample_has_no_prioritized_false_positives():
    findings, groups = _audit_sample(AWS_SAFE)

    assert len(groups) == 1
    assert findings == []
