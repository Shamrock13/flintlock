"""Tests for Juniper SRX parser, auditor, and shadow detection.

Run with:  python3 tests/test_juniper.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.juniper import (
    _parse_set_style,
    _parse_hierarchical,
    check_any_any_juniper,
    check_missing_log_juniper,
    check_insecure_apps_juniper,
    check_deny_all_juniper,
    check_system_juniper,
    audit_juniper,
)
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


def test_any_any_detects_violation():
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_any_any_juniper(policies)
    assert len(findings) >= 1
    assert all(f["severity"] == "CRITICAL" for f in findings)


def test_any_any_clean_config():
    policies = _parse_set_style(SET_STYLE_CLEAN)
    assert check_any_any_juniper(policies) == []


def test_missing_log_detects():
    policies = _parse_set_style(SET_STYLE_RISKY)
    findings = check_missing_log_juniper(policies)
    # allow-all and allow-telnet both missing log
    assert len(findings) >= 1
    assert all(f["severity"] == "MEDIUM" for f in findings)


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
