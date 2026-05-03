"""Tests for rule_quality.py shadow/unreachable rule detection.

Run with:  python -m pytest tests/test_rule_quality.py -v
       or:  python tests/test_rule_quality.py
"""

import os
import sys

# Allow running directly from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.rule_quality import (
    check_shadow_rules_asa,
    check_shadow_rules_azure,
    check_shadow_rules_forti,
    check_shadow_rules_juniper,
    check_shadow_rules_pa,
    check_shadow_rules_pfsense,
)
from cashel.fortinet import parse_fortinet
from cashel.paloalto import parse_paloalto

TESTS_DIR = os.path.dirname(__file__)


# ── helpers ──────────────────────────────────────────────────────────────────


def _msgs(findings):
    return [f["message"] for f in findings]


def _severities(findings):
    return [f["severity"] for f in findings]


def _assert_shadow_metadata(finding, shadowed, shadowing):
    metadata = finding["metadata"]
    assert metadata["shadowed_rule"] == shadowed
    assert metadata["shadowing_rule"] == shadowing


def _asa_parse(filepath):
    from ciscoconfparse import CiscoConfParse

    return CiscoConfParse(filepath, ignore_blank_lines=False)


# ── Test 1: Cisco ASA shadow detection ───────────────────────────────────────


def test_asa_shadow():
    """
    Fixture: tests/test_asa.txt
      Line 1: access-list OUTSIDE_IN extended permit ip any any   <- broad any-any
      Line 2: permit tcp any host 10.0.0.1 eq 80                  <- shadowed
      Line 3: permit tcp 192.168.1.0 ... host 10.0.0.2 eq 443     <- shadowed
      Line 4: permit ip any any log                                <- shadowed
      Line 5: permit tcp any host 10.0.0.1 eq 80                  <- shadowed
      Line 6: deny ip any any                                      <- shadowed

    Expected: 5 HIGH findings, all referencing OUTSIDE_IN and the broad rule.
    """
    path = os.path.join(TESTS_DIR, "test_asa.txt")
    parse = _asa_parse(path)
    result = check_shadow_rules_asa(parse)

    msgs = _msgs(result)

    assert len(result) == 5, f"Expected 5 shadow findings, got {len(result)}: {msgs}"
    assert all(f["severity"] == "HIGH" for f in result), (
        "All shadow findings should be HIGH"
    )
    assert all(f["category"] == "redundancy" for f in result), (
        "Category should be 'redundancy'"
    )
    assert all("OUTSIDE_IN" in m for m in msgs), (
        "All findings should reference the ACL name"
    )
    assert all("permit ip any any" in m for m in msgs), (
        "All findings should cite the shadowing rule"
    )
    # Specific shadowed rules mentioned
    assert any("permit tcp any host 10.0.0.1 eq 80" in m for m in msgs)
    assert any("deny ip any any" in m for m in msgs)
    _assert_shadow_metadata(
        result[0],
        "access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 80",
        "access-list OUTSIDE_IN extended permit ip any any",
    )


# ── Test 2: Fortinet shadow detection ────────────────────────────────────────


def test_fortinet_shadow():
    """
    Fixture: tests/test_forti.txt
      Policy 1 'Allow-All': srcaddr=all, dstaddr=all, service=ALL  <- broad
      Policy 2 'Allow-Web': srcaddr=all, dstaddr=WebServer, service=HTTP/HTTPS <- shadowed
      Policy 3 'Allow-Web-Duplicate': identical to Policy 2        <- shadowed
      Policy 4 'Block-All': srcaddr=all, dstaddr=all               <- shadowed

    Expected: 3 HIGH findings (policies 2, 3, 4 all shadowed by policy 1).
    'Allow-All' uses service=ALL which _covers treats as universal.
    """
    path = os.path.join(TESTS_DIR, "test_forti.txt")
    policies, err = parse_fortinet(path)
    assert err is None, f"Parse error: {err}"

    result = check_shadow_rules_forti(policies)
    msgs = _msgs(result)

    assert len(result) == 3, f"Expected 3 shadow findings, got {len(result)}: {msgs}"
    assert all(f["severity"] == "HIGH" for f in result)
    assert all(f["category"] == "redundancy" for f in result)

    shadowed_names = [
        m.split("'")[1] for m in msgs
    ]  # first quoted name = shadowed rule
    assert "Allow-Web" in shadowed_names, "Allow-Web should be shadowed"
    assert "Allow-Web-Duplicate" in shadowed_names, (
        "Allow-Web-Duplicate should be shadowed"
    )
    assert "Block-All" in shadowed_names, "Block-All should be shadowed"

    shadower_names = [
        m.split("'")[3] for m in msgs
    ]  # third quoted name = shadowing rule
    assert all(n == "Allow-All" for n in shadower_names), (
        "Allow-All should be the shadowing rule"
    )
    _assert_shadow_metadata(result[0], "Allow-Web", "Allow-All")


# ── Test 3: Palo Alto shadow detection ───────────────────────────────────────


def test_paloalto_shadow():
    """
    Fixture: tests/test_pa.xml
      Rule 'Allow-Any-Any': src=any, dst=any, app=any, svc=any  <- broad
      Rule 'Allow-Web': src=any, dst=10.0.0.1, app=web-browsing <- shadowed
      Rule 'Allow-Web-Duplicate': identical to Allow-Web         <- shadowed

    Expected: 2 HIGH findings (Allow-Web and Allow-Web-Duplicate both shadowed
    by Allow-Any-Any).
    """
    path = os.path.join(TESTS_DIR, "test_pa.xml")
    rules, err = parse_paloalto(path)
    assert err is None, f"Parse error: {err}"

    result = check_shadow_rules_pa(rules)
    msgs = _msgs(result)

    assert len(result) == 2, f"Expected 2 shadow findings, got {len(result)}: {msgs}"
    assert all(f["severity"] == "HIGH" for f in result)
    assert all(f["category"] == "redundancy" for f in result)

    shadowed_names = [m.split("'")[1] for m in msgs]
    assert "Allow-Web" in shadowed_names, "Allow-Web should be shadowed"
    assert "Allow-Web-Duplicate" in shadowed_names, (
        "Allow-Web-Duplicate should be shadowed"
    )

    shadower_names = [m.split("'")[3] for m in msgs]
    assert all(n == "Allow-Any-Any" for n in shadower_names), (
        "Allow-Any-Any should be the shadowing rule"
    )
    _assert_shadow_metadata(result[0], "Allow-Web", "Allow-Any-Any")


def test_shadow_metadata_for_pfsense_azure_and_juniper():
    pfsense = check_shadow_rules_pfsense(
        [
            {
                "descr": "Allow Any",
                "interface": "wan",
                "source": "1",
                "destination": "1",
                "protocol": "any",
            },
            {
                "descr": "Allow Web",
                "interface": "wan",
                "source": "10.0.0.0/24",
                "destination": "10.0.0.10",
                "protocol": "tcp",
            },
        ]
    )
    _assert_shadow_metadata(pfsense[0], "Allow Web", "Allow Any")

    azure = check_shadow_rules_azure(
        [
            {
                "name": "edge-nsg",
                "securityRules": [
                    {
                        "name": "AllowAny",
                        "properties": {
                            "direction": "Inbound",
                            "priority": 100,
                            "sourceAddressPrefix": "*",
                            "destinationPortRange": "*",
                            "protocol": "*",
                        },
                    },
                    {
                        "name": "AllowWeb",
                        "properties": {
                            "direction": "Inbound",
                            "priority": 200,
                            "sourceAddressPrefix": "10.0.0.0/24",
                            "destinationPortRange": "443",
                            "protocol": "Tcp",
                        },
                    },
                ],
            }
        ]
    )
    _assert_shadow_metadata(azure[0], "AllowWeb", "AllowAny")

    juniper = check_shadow_rules_juniper(
        [
            {
                "name": "allow-any",
                "from_zone": "trust",
                "to_zone": "untrust",
                "src": ["any"],
                "dst": ["any"],
                "app": ["any"],
            },
            {
                "name": "allow-web",
                "from_zone": "trust",
                "to_zone": "untrust",
                "src": ["web-clients"],
                "dst": ["web-server"],
                "app": ["junos-https"],
            },
        ]
    )
    _assert_shadow_metadata(juniper[0], "allow-web", "allow-any")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
