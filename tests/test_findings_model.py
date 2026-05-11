"""Tests for normalized finding helpers."""

from cashel.models.findings import (
    finding_to_dict,
    make_finding,
    normalize_finding,
    validate_finding_shape,
    NormalizedFinding,
)


def test_make_finding_returns_backward_compatible_dict():
    finding = make_finding(
        "HIGH",
        "exposure",
        "[HIGH] Test finding",
        "Fix it.",
        id="CASHEL-TEST-001",
        title="Test finding",
        evidence="access-list OUTSIDE_IN permit ip any any",
    )

    assert isinstance(finding, dict)
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "exposure"
    assert finding["message"] == "[HIGH] Test finding"
    assert finding["remediation"] == "Fix it."
    assert finding["id"] == "CASHEL-TEST-001"
    assert finding["title"] == "Test finding"
    assert finding["evidence"] == "access-list OUTSIDE_IN permit ip any any"


def test_finding_to_dict_preserves_preferred_and_optional_fields():
    finding = NormalizedFinding(
        id="CASHEL-ASA-EXPOSURE-001",
        vendor="asa",
        severity="HIGH",
        category="exposure",
        title="ASA ACL permits any source to any destination",
        message="[HIGH] ACL rule permits ip any any",
        remediation="Replace the broad ACL with scoped objects.",
        evidence="access-list OUTSIDE_IN permit ip any any",
        affected_object="OUTSIDE_IN",
        rule_id="OUTSIDE_IN:10",
        rule_name="OUTSIDE_IN",
        confidence="high",
        impact="Internet exposure",
        verification="Re-run the audit.",
        rollback="Restore the previous ACL line.",
        compliance_refs=["PCI-DSS 1.2"],
        suggested_commands=["no access-list OUTSIDE_IN permit ip any any"],
        metadata={"acl": "OUTSIDE_IN", "line": 10},
    )

    data = finding_to_dict(finding)

    assert data["id"] == "CASHEL-ASA-EXPOSURE-001"
    assert data["title"] == "ASA ACL permits any source to any destination"
    assert data["evidence"] == "access-list OUTSIDE_IN permit ip any any"
    assert data["affected_object"] == "OUTSIDE_IN"
    assert data["rule_id"] == "OUTSIDE_IN:10"
    assert data["rule_name"] == "OUTSIDE_IN"
    assert data["confidence"] == "high"
    assert data["verification"] == "Re-run the audit."
    assert data["rollback"] == "Restore the previous ACL line."
    assert data["compliance_refs"] == ["PCI-DSS 1.2"]
    assert data["suggested_commands"] == ["no access-list OUTSIDE_IN permit ip any any"]
    assert data["metadata"] == {"acl": "OUTSIDE_IN", "line": 10}


def test_normalize_finding_handles_old_style_dict():
    finding = normalize_finding(
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "[MEDIUM] Missing logging",
            "remediation": "Enable logging.",
        },
        vendor="asa",
    )

    assert finding["vendor"] == "asa"
    assert finding["severity"] == "MEDIUM"
    assert finding["category"] == "logging"
    assert finding["message"] == "[MEDIUM] Missing logging"
    assert finding["remediation"] == "Enable logging."
    assert finding["confidence"] == "medium"
    assert finding["metadata"] == {}


def test_normalize_finding_preserves_enriched_dict_fields():
    finding = normalize_finding(
        {
            "id": "CASHEL-PA-LOGGING-001",
            "vendor": "paloalto",
            "severity": "MEDIUM",
            "category": "logging",
            "title": "Palo Alto rule missing log-end",
            "message": "[MEDIUM] Rule missing log-end",
            "remediation": "Enable log-end.",
            "evidence": "rule=Allow-Web log-end=no",
            "affected_object": "Allow-Web",
            "confidence": "high",
        }
    )

    assert finding["id"] == "CASHEL-PA-LOGGING-001"
    assert finding["title"] == "Palo Alto rule missing log-end"
    assert finding["evidence"] == "rule=Allow-Web log-end=no"
    assert finding["affected_object"] == "Allow-Web"
    assert finding["confidence"] == "high"


def test_normalize_finding_handles_plain_string():
    finding = normalize_finding("[HIGH] Plain archive finding")

    assert finding["severity"] == "HIGH"
    assert finding["category"] == ""
    assert finding["message"] == "[HIGH] Plain archive finding"
    assert finding["remediation"] == ""


def test_validate_finding_shape_reports_normalized_shape_issues():
    finding = make_finding(
        "HIGH",
        "exposure",
        "[HIGH] Test finding",
        "Fix it.",
        id="CASHEL-TEST-001",
        vendor="ASA",
        title="Test finding",
        evidence="permit ip any any",
        affected_object="OUTSIDE_IN",
        suggested_commands=["access-list <ACL_NAME> deny ip any any log"],
        metadata={"acl": "OUTSIDE_IN"},
    )

    problems = validate_finding_shape(finding)

    assert "vendor must be lowercase: ASA" in problems


def test_validate_finding_shape_accepts_legacy_and_plain_findings():
    legacy = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Missing logging",
        "remediation": "Enable logging.",
    }

    assert validate_finding_shape(legacy) == []
    assert validate_finding_shape("[HIGH] Plain archive finding") == []
