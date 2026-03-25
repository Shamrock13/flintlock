"""Tests for gcp.py — GCP VPC Firewall parser and auditor.

Run with:  python3 tests/test_gcp.py
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.gcp import (
    parse_gcp_firewall,
    check_internet_ingress_gcp,
    check_unrestricted_egress_gcp,
    check_default_network_rules_gcp,
    check_missing_description_gcp,
    check_disabled_rules_gcp,
    check_no_target_restriction_gcp,
    check_icmp_unrestricted_gcp,
    audit_gcp_firewall,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

RULES_CLEAN = [
    {
        "name": "allow-internal",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "description": "Allow internal traffic between app servers",
        "sourceRanges": ["10.0.0.0/8"],
        "targetTags": ["app-server"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["8080", "8443"]}],
    },
    {
        "name": "deny-all-egress",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
        "direction": "EGRESS",
        "priority": 65534,
        "disabled": False,
        "description": "Explicit deny-all egress",
        "destinationRanges": ["0.0.0.0/0"],
        "denied": [{"IPProtocol": "all"}],
    },
]

RULES_RISKY = [
    {
        "name": "default-allow-ssh",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "INGRESS",
        "priority": 65534,
        "disabled": False,
        "description": "",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    },
    {
        "name": "default-allow-rdp",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "INGRESS",
        "priority": 65534,
        "disabled": False,
        "description": "",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
    },
    {
        "name": "allow-all-traffic",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "description": "",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "all"}],
    },
    {
        "name": "allow-all-egress",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "EGRESS",
        "priority": 65534,
        "disabled": False,
        "description": "default egress",
        "destinationRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "all"}],
    },
    {
        "name": "allow-icmp",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "INGRESS",
        "priority": 65534,
        "disabled": False,
        "description": "allow icmp",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "icmp"}],
    },
    {
        "name": "old-debug-rule",
        "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
        "direction": "INGRESS",
        "priority": 500,
        "disabled": True,
        "description": "temp debug rule",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["9999"]}],
    },
]


def _write_json(data) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    return path


# ══════════════════════════════════════════════════════════ PARSER ══


def test_parse_list():
    path = _write_json(RULES_CLEAN)
    try:
        rules, err = parse_gcp_firewall(path)
        assert err is None
        assert len(rules) == 2
    finally:
        os.unlink(path)


def test_parse_items_wrapper():
    path = _write_json({"items": RULES_CLEAN})
    try:
        rules, err = parse_gcp_firewall(path)
        assert err is None
        assert len(rules) == 2
    finally:
        os.unlink(path)


def test_parse_single_object():
    path = _write_json(RULES_CLEAN[0])
    try:
        rules, err = parse_gcp_firewall(path)
        assert err is None
        assert len(rules) == 1
        assert rules[0]["name"] == "allow-internal"
    finally:
        os.unlink(path)


def test_parse_invalid_json():
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write("not json {{")
    try:
        rules, err = parse_gcp_firewall(path)
        assert err is not None
        assert rules == []
    finally:
        os.unlink(path)


def test_parse_missing_file():
    rules, err = parse_gcp_firewall("/does/not/exist.json")
    assert err is not None
    assert rules == []


# ══════════════════════════════════════════════════ INGRESS CHECKS ══


def test_internet_ingress_all_traffic():
    findings = check_internet_ingress_gcp(RULES_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("allow-all-traffic" in m and "ALL ingress" in m for m in msgs)


def test_internet_ingress_ssh():
    findings = check_internet_ingress_gcp(RULES_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("SSH" in m and "default-allow-ssh" in m for m in msgs)


def test_internet_ingress_rdp():
    findings = check_internet_ingress_gcp(RULES_RISKY)
    msgs = [f["message"] for f in findings]
    assert any("RDP" in m and "default-allow-rdp" in m for m in msgs)


def test_internet_ingress_clean():
    findings = check_internet_ingress_gcp(RULES_CLEAN)
    assert findings == []


def test_internet_ingress_skips_disabled():
    findings = check_internet_ingress_gcp(RULES_RISKY)
    msgs = [f["message"] for f in findings]
    assert all("old-debug-rule" not in m for m in msgs)


def test_internet_ingress_wide_port_range():
    rules = [
        {
            "name": "wide-range",
            "network": "https://.../networks/test",
            "direction": "INGRESS",
            "priority": 1000,
            "disabled": False,
            "description": "test",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["1000-2000"]}],
        }
    ]
    findings = check_internet_ingress_gcp(rules)
    assert any("wide port range" in f["message"] for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


# ══════════════════════════════════════════════════ EGRESS CHECKS ══


def test_unrestricted_egress_flagged():
    findings = check_unrestricted_egress_gcp(RULES_RISKY)
    assert any("allow-all-egress" in f["message"] for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


def test_unrestricted_egress_clean():
    findings = check_unrestricted_egress_gcp(RULES_CLEAN)
    assert findings == []


# ══════════════════════════════════════════════ DEFAULT NETWORK ══


def test_default_network_flagged():
    findings = check_default_network_rules_gcp(RULES_RISKY)
    assert len(findings) == 1  # one finding per network, not per rule
    assert findings[0]["severity"] == "MEDIUM"


def test_default_network_clean():
    findings = check_default_network_rules_gcp(RULES_CLEAN)
    assert findings == []


# ══════════════════════════════════════════ MISSING DESCRIPTION ══


def test_missing_description_flagged():
    findings = check_missing_description_gcp(RULES_RISKY)
    names = [f["message"] for f in findings]
    assert any("default-allow-ssh" in n for n in names)
    assert any("allow-all-traffic" in n for n in names)


def test_missing_description_clean():
    assert check_missing_description_gcp(RULES_CLEAN) == []


def test_missing_description_skips_disabled():
    findings = check_missing_description_gcp(RULES_RISKY)
    msgs = [f["message"] for f in findings]
    assert all("old-debug-rule" not in m for m in msgs)


# ══════════════════════════════════════════════ DISABLED RULES ══


def test_disabled_rules_flagged():
    findings = check_disabled_rules_gcp(RULES_RISKY)
    assert len(findings) == 1
    assert "old-debug-rule" in findings[0]["message"]
    assert findings[0]["severity"] == "MEDIUM"


def test_disabled_rules_clean():
    assert check_disabled_rules_gcp(RULES_CLEAN) == []


# ══════════════════════════════════════════ NO TARGET RESTRICTION ══


def test_no_target_restriction_flagged():
    findings = check_no_target_restriction_gcp(RULES_RISKY)
    # allow-all-traffic and allow-ssh/rdp have no targetTags and source=0.0.0.0/0
    assert len(findings) >= 1


def test_no_target_restriction_clean():
    # RULES_CLEAN[0] has targetTags and sourceRanges=10.0.0.0/8 (not internet)
    findings = check_no_target_restriction_gcp(RULES_CLEAN)
    assert findings == []


# ══════════════════════════════════════════════════ ICMP CHECK ══


def test_icmp_unrestricted_flagged():
    findings = check_icmp_unrestricted_gcp(RULES_RISKY)
    assert any("allow-icmp" in f["message"] for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


def test_icmp_unrestricted_clean():
    assert check_icmp_unrestricted_gcp(RULES_CLEAN) == []


# ══════════════════════════════════════════════ audit_gcp_firewall ══


def test_audit_gcp_risky():
    path = _write_json(RULES_RISKY)
    try:
        findings, rules = audit_gcp_firewall(path)
        assert len(findings) > 0
        assert len(rules) == len(RULES_RISKY)
        assert any(f["severity"] == "HIGH" for f in findings)
    finally:
        os.unlink(path)


def test_audit_gcp_clean():
    path = _write_json(RULES_CLEAN)
    try:
        findings, rules = audit_gcp_firewall(path)
        assert isinstance(findings, list)
        assert len(rules) == len(RULES_CLEAN)
        high = [f for f in findings if f["severity"] == "HIGH"]
        assert len(high) == 0
    finally:
        os.unlink(path)


def test_audit_gcp_parse_error():
    findings, rules = audit_gcp_firewall("/nonexistent/file.json")
    assert len(findings) == 1
    assert rules == []


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_parse_list,
        test_parse_items_wrapper,
        test_parse_single_object,
        test_parse_invalid_json,
        test_parse_missing_file,
        test_internet_ingress_all_traffic,
        test_internet_ingress_ssh,
        test_internet_ingress_rdp,
        test_internet_ingress_clean,
        test_internet_ingress_skips_disabled,
        test_internet_ingress_wide_port_range,
        test_unrestricted_egress_flagged,
        test_unrestricted_egress_clean,
        test_default_network_flagged,
        test_default_network_clean,
        test_missing_description_flagged,
        test_missing_description_clean,
        test_missing_description_skips_disabled,
        test_disabled_rules_flagged,
        test_disabled_rules_clean,
        test_no_target_restriction_flagged,
        test_no_target_restriction_clean,
        test_icmp_unrestricted_flagged,
        test_icmp_unrestricted_clean,
        test_audit_gcp_risky,
        test_audit_gcp_clean,
        test_audit_gcp_parse_error,
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
