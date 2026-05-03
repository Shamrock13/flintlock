"""Tests for normalized finding helpers."""

from cashel.models.findings import make_finding, normalize_finding


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


def test_normalize_finding_handles_plain_string():
    finding = normalize_finding("[HIGH] Plain archive finding")

    assert finding["severity"] == "HIGH"
    assert finding["category"] == ""
    assert finding["message"] == "[HIGH] Plain archive finding"
    assert finding["remediation"] == ""
