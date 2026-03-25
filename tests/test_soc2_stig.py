"""Tests for SOC2 and DISA STIG compliance checks (all vendors).

Run with:  python3 tests/test_soc2_stig.py
"""

import os
import sys
import tempfile
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── Shared helpers ────────────────────────────────────────────────────────────


def _has(findings, tag):
    return any(tag in f for f in findings)


# ══════════════════════════════════════════════════════ CISCO ASA — SOC2 ══

from cashel.compliance import check_soc2_compliance  # noqa: E402

try:
    from ciscoconfparse import CiscoConfParse as _CCP

    _HAS_CISCO = True
except ImportError:
    _HAS_CISCO = False


def _asa_parse(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write(textwrap.dedent(text))
    parse = _CCP(path, ignore_blank_lines=False)
    os.unlink(path)
    return parse


def test_soc2_asa_any_any():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE permit ip any any
        access-list OUTSIDE deny ip any any
        logging host 10.0.0.1
    """)
    findings = check_soc2_compliance(parse)
    assert _has(findings, "SOC2-HIGH") and _has(findings, "CC6.6")


def test_soc2_asa_no_deny_all():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE permit tcp 10.0.0.0 255.0.0.0 any eq 443 log
        logging host 10.0.0.1
    """)
    findings = check_soc2_compliance(parse)
    assert _has(findings, "CC6.1")


def test_soc2_asa_telnet():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        telnet 10.0.0.0 255.255.255.0 inside
        access-list OUTSIDE deny ip any any log
        logging host 10.0.0.1
    """)
    findings = check_soc2_compliance(parse)
    assert _has(findings, "CC6.7")


def test_soc2_asa_missing_log():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE permit tcp 10.0.0.0 255.0.0.0 any eq 80
        access-list OUTSIDE deny ip any any log
        logging host 10.0.0.1
    """)
    findings = check_soc2_compliance(parse)
    assert _has(findings, "SOC2-MEDIUM") and _has(findings, "CC7.2")


def test_soc2_asa_no_syslog():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE deny ip any any log
    """)
    findings = check_soc2_compliance(parse)
    assert _has(findings, "CC7.2") and any(
        "syslog" in f.lower() or "logging" in f.lower() for f in findings
    )


# ══════════════════════════════════════════════════ FORTINET — SOC2 ══

from cashel.compliance import check_soc2_compliance_forti  # noqa: E402

_FORTI_ANY_ANY = [
    {
        "action": "accept",
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "logtraffic": "all",
        "name": "open-policy",
        "status": "enable",
    },
]
_FORTI_CLEAN = [
    {
        "action": "accept",
        "srcaddr": ["10.0.0.0/8"],
        "dstaddr": ["192.168.1.0/24"],
        "logtraffic": "all",
        "name": "internal",
        "status": "enable",
    },
    {
        "action": "deny",
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "logtraffic": "all",
        "name": "deny-all",
        "status": "enable",
    },
]


def test_soc2_forti_any_any():
    findings = check_soc2_compliance_forti(_FORTI_ANY_ANY)
    assert _has(findings, "SOC2-HIGH") and _has(findings, "CC6.6")


def test_soc2_forti_no_log():
    policies = [
        {
            "action": "accept",
            "srcaddr": ["10.0.0.0/8"],
            "dstaddr": ["any"],
            "logtraffic": "disable",
            "name": "nolog",
            "status": "enable",
        }
    ]
    findings = check_soc2_compliance_forti(policies)
    assert _has(findings, "SOC2-MEDIUM") and _has(findings, "CC7.2")


def test_soc2_forti_clean():
    findings = check_soc2_compliance_forti(_FORTI_CLEAN)
    assert not _has(findings, "SOC2-HIGH")


# ══════════════════════════════════════════════════ PFSENSE — SOC2 ══

from cashel.compliance import check_soc2_compliance_pf  # noqa: E402

_PF_ANY_ANY = [
    {
        "type": "pass",
        "source": "1",
        "destination": "1",
        "interface": "wan",
        "descr": "",
        "log": None,
    }
]
_PF_CLEAN = [
    {
        "type": "pass",
        "source": "10.0.0.0/8",
        "destination": "192.168.1.0/24",
        "interface": "lan",
        "descr": "LAN outbound",
        "log": True,
    }
]


def test_soc2_pf_any_any():
    findings = check_soc2_compliance_pf(_PF_ANY_ANY)
    assert _has(findings, "SOC2-HIGH")


def test_soc2_pf_no_log():
    rules = [
        {
            "type": "pass",
            "source": "10.0.0.0/8",
            "destination": "192.168.1.0/24",
            "interface": "lan",
            "descr": "LAN rule",
            "log": None,
        }
    ]
    findings = check_soc2_compliance_pf(rules)
    assert _has(findings, "SOC2-MEDIUM") and _has(findings, "CC7.2")


def test_soc2_pf_clean():
    findings = check_soc2_compliance_pf(_PF_CLEAN)
    assert not _has(findings, "SOC2-HIGH")


# ══════════════════════════════════════════════════ JUNIPER — SOC2 ══

from cashel.compliance import check_soc2_compliance_juniper  # noqa: E402

_JUN_SOC2_ANY = {
    "content": "set system syslog host 10.0.0.1 any any\n",
    "policies": [
        {
            "name": "any-any",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["any"],
            "dst": ["any"],
            "app": ["any"],
            "action": "permit",
            "log": False,
            "disabled": False,
        },
    ],
}
_JUN_SOC2_CLEAN = {
    "content": "set system syslog host 10.0.0.1 any any\nset system ntp server 10.0.0.2\n",
    "policies": [
        {
            "name": "permit-https",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["192.168.1.0/24"],
            "dst": ["10.0.0.5/32"],
            "app": ["junos-https"],
            "action": "permit",
            "log": True,
            "disabled": False,
        },
        {
            "name": "deny-all",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["any"],
            "dst": ["any"],
            "app": ["any"],
            "action": "deny",
            "log": True,
            "disabled": False,
        },
    ],
}


def test_soc2_juniper_any_any():
    findings = check_soc2_compliance_juniper(_JUN_SOC2_ANY)
    assert _has(findings, "SOC2-HIGH") and _has(findings, "CC6.6")


def test_soc2_juniper_no_syslog():
    data = {
        "content": "",
        "policies": _JUN_SOC2_CLEAN["policies"],
    }
    findings = check_soc2_compliance_juniper(data)
    assert _has(findings, "CC7.2")


def test_soc2_juniper_clean():
    findings = check_soc2_compliance_juniper(_JUN_SOC2_CLEAN)
    assert not _has(findings, "SOC2-HIGH")


# ══════════════════════════════════════════════════ CISCO ASA — STIG ══

from cashel.compliance import check_stig_compliance  # noqa: E402


def test_stig_asa_any_any():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE permit ip any any
        access-list OUTSIDE deny ip any any log
        logging host 10.0.0.1
    """)
    findings = check_stig_compliance(parse)
    assert _has(findings, "STIG-CAT-I")


def test_stig_asa_no_deny():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        access-list OUTSIDE permit tcp 10.0.0.0 255.0.0.0 any eq 443 log
        logging host 10.0.0.1
    """)
    findings = check_stig_compliance(parse)
    assert _has(findings, "STIG-CAT-I") or _has(findings, "STIG-CAT-II")


def test_stig_asa_telnet():
    if not _HAS_CISCO:
        return
    parse = _asa_parse("""
        telnet 10.0.0.0 255.255.255.0 inside
        access-list OUTSIDE deny ip any any log
        logging host 10.0.0.1
    """)
    findings = check_stig_compliance(parse)
    assert _has(findings, "STIG-CAT-I")


# ══════════════════════════════════════════════════ FORTINET — STIG ══

from cashel.compliance import check_stig_compliance_forti  # noqa: E402


def test_stig_forti_any_any():
    findings = check_stig_compliance_forti(_FORTI_ANY_ANY)
    assert _has(findings, "STIG-CAT-I")


def test_stig_forti_no_log():
    policies = [
        {
            "action": "accept",
            "srcaddr": ["10.0.0.0/8"],
            "dstaddr": ["any"],
            "logtraffic": "disable",
            "name": "nolog",
            "status": "enable",
        }
    ]
    findings = check_stig_compliance_forti(policies)
    assert _has(findings, "STIG-CAT-II")


def test_stig_forti_clean():
    clean = [
        {
            "action": "accept",
            "srcaddr": ["10.0.0.0/8"],
            "dstaddr": ["192.168.1.0/24"],
            "logtraffic": "all",
            "name": "internal",
            "status": "enable",
        }
    ]
    findings = check_stig_compliance_forti(clean)
    assert not _has(findings, "STIG-CAT-I")


# ══════════════════════════════════════════════════ PFSENSE — STIG ══

from cashel.compliance import check_stig_compliance_pf  # noqa: E402


def test_stig_pf_any_any():
    findings = check_stig_compliance_pf(_PF_ANY_ANY)
    assert _has(findings, "STIG-CAT-I")


def test_stig_pf_no_log():
    rules = [
        {
            "type": "pass",
            "source": "10.0.0.0/8",
            "destination": "any",
            "interface": "lan",
            "descr": "test",
            "log": None,
        }
    ]
    findings = check_stig_compliance_pf(rules)
    assert _has(findings, "STIG-CAT-II")


def test_stig_pf_clean():
    findings = check_stig_compliance_pf(_PF_CLEAN)
    assert not _has(findings, "STIG-CAT-I")


# ══════════════════════════════════════════════════ JUNIPER — STIG ══

from cashel.compliance import check_stig_compliance_juniper  # noqa: E402

_JUN_STIG_RISKY = {
    "content": (
        "set system services telnet\n"
        "set snmp community public\n"
        "set system services ssh root-login allow\n"
    ),
    "policies": [
        {
            "name": "any-any",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["any"],
            "dst": ["any"],
            "app": ["any"],
            "action": "permit",
            "log": False,
            "disabled": False,
        },
    ],
}
_JUN_STIG_CLEAN = {
    "content": (
        "set system ntp server 10.0.0.1\n"
        "set system syslog host 10.0.0.2 any any\n"
        'set system login message "Authorized users only"\n'
    ),
    "policies": [
        {
            "name": "permit-web",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["192.168.1.0/24"],
            "dst": ["10.0.0.5/32"],
            "app": ["junos-https"],
            "action": "permit",
            "log": True,
            "disabled": False,
        },
        {
            "name": "deny-all",
            "from_zone": "untrust",
            "to_zone": "trust",
            "src": ["any"],
            "dst": ["any"],
            "app": ["any"],
            "action": "deny",
            "log": True,
            "disabled": False,
        },
    ],
}


def test_stig_juniper_telnet():
    findings = check_stig_compliance_juniper(_JUN_STIG_RISKY)
    assert _has(findings, "STIG-CAT-I") and _has(findings, "V-66003")


def test_stig_juniper_snmp():
    findings = check_stig_compliance_juniper(_JUN_STIG_RISKY)
    assert _has(findings, "V-66019") and _has(findings, "public")


def test_stig_juniper_any_any():
    findings = check_stig_compliance_juniper(_JUN_STIG_RISKY)
    assert _has(findings, "V-65981") and _has(findings, "STIG-CAT-I")


def test_stig_juniper_root_login():
    findings = check_stig_compliance_juniper(_JUN_STIG_RISKY)
    assert _has(findings, "V-66001")


def test_stig_juniper_no_session_log():
    findings = check_stig_compliance_juniper(_JUN_STIG_RISKY)
    assert _has(findings, "V-65985")


def test_stig_juniper_clean_no_cat_i():
    findings = check_stig_compliance_juniper(_JUN_STIG_CLEAN)
    assert not _has(findings, "STIG-CAT-I")


# ══════════════════════════════════════════════ audit_engine summary ══

from cashel.audit_engine import _build_summary, _sort_findings  # noqa: E402


def test_build_summary_soc2():
    findings = [
        {
            "severity": "HIGH",
            "category": "compliance",
            "message": "[SOC2-HIGH] CC6.6: any/any",
            "remediation": "",
        },
        {
            "severity": "MEDIUM",
            "category": "compliance",
            "message": "[SOC2-MEDIUM] CC7.2: no log",
            "remediation": "",
        },
    ]
    s = _build_summary(findings)
    assert s["soc2_high"] == 1
    assert s["soc2_medium"] == 1
    assert s["high"] == 0  # not counted in core high (is_comp)
    assert s["medium"] == 0


def test_build_summary_stig():
    findings = [
        {
            "severity": "HIGH",
            "category": "compliance",
            "message": "[STIG-CAT-I] V-239001: any/any",
            "remediation": "",
        },
        {
            "severity": "MEDIUM",
            "category": "compliance",
            "message": "[STIG-CAT-II] V-239002: no log",
            "remediation": "",
        },
        {
            "severity": "MEDIUM",
            "category": "compliance",
            "message": "[STIG-CAT-III] V-239003: no banner",
            "remediation": "",
        },
    ]
    s = _build_summary(findings)
    assert s["stig_cat_i"] == 1
    assert s["stig_cat_ii"] == 1
    assert s["stig_cat_iii"] == 1
    assert s["high"] == 0
    assert s["medium"] == 0


def test_sort_findings_stig_order():
    findings = [
        "[STIG-CAT-III] low severity",
        "[HIGH] core high",
        "[STIG-CAT-I] critical",
        "[MEDIUM] core medium",
        "[STIG-CAT-II] high severity",
    ]
    sorted_f = _sort_findings(findings)
    labels = [f.split("]")[0] + "]" for f in sorted_f]
    assert labels.index("[HIGH]") < labels.index("[STIG-CAT-I]")
    assert labels.index("[STIG-CAT-I]") < labels.index("[STIG-CAT-II]")


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_soc2_asa_any_any,
        test_soc2_asa_no_deny_all,
        test_soc2_asa_telnet,
        test_soc2_asa_missing_log,
        test_soc2_asa_no_syslog,
        test_soc2_forti_any_any,
        test_soc2_forti_no_log,
        test_soc2_forti_clean,
        test_soc2_pf_any_any,
        test_soc2_pf_no_log,
        test_soc2_pf_clean,
        test_soc2_juniper_any_any,
        test_soc2_juniper_no_syslog,
        test_soc2_juniper_clean,
        test_stig_asa_any_any,
        test_stig_asa_no_deny,
        test_stig_asa_telnet,
        test_stig_forti_any_any,
        test_stig_forti_no_log,
        test_stig_forti_clean,
        test_stig_pf_any_any,
        test_stig_pf_no_log,
        test_stig_pf_clean,
        test_stig_juniper_telnet,
        test_stig_juniper_snmp,
        test_stig_juniper_any_any,
        test_stig_juniper_root_login,
        test_stig_juniper_no_session_log,
        test_stig_juniper_clean_no_cat_i,
        test_build_summary_soc2,
        test_build_summary_stig,
        test_sort_findings_stig_order,
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
