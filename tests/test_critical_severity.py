"""Tests for critical severity level in audit_engine.

Run with:  python -m pytest tests/test_critical_severity.py -v
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.audit_engine import _build_summary, _sort_findings


def _f(severity, msg):
    return {
        "severity": severity,
        "category": "exposure",
        "message": msg,
        "remediation": "",
    }


# ── _build_summary ─────────────────────────────────────────────────────────────


def test_summary_counts_critical():
    findings = [
        _f("CRITICAL", "[CRITICAL] permit any any found"),
        _f("HIGH", "[HIGH] no deny-all"),
        _f("MEDIUM", "[MEDIUM] no logging"),
    ]
    s = _build_summary(findings)
    assert s["critical"] == 1
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["total"] == 3


def test_summary_critical_zero_when_absent():
    findings = [_f("HIGH", "[HIGH] no deny-all")]
    s = _build_summary(findings)
    assert s["critical"] == 0
    assert s["high"] == 1


def test_summary_score_penalises_critical_more():
    # One CRITICAL: 100 - 20 = 80
    s_crit = _build_summary([_f("CRITICAL", "[CRITICAL] permit any any")])
    assert s_crit["score"] == 80

    # One HIGH: 100 - 10 = 90
    s_high = _build_summary([_f("HIGH", "[HIGH] no deny-all")])
    assert s_high["score"] == 90


def test_summary_score_combined():
    # 1 CRITICAL + 1 HIGH + 1 MEDIUM: 100 - 20 - 10 - 3 = 67
    findings = [
        _f("CRITICAL", "[CRITICAL] permit any any"),
        _f("HIGH", "[HIGH] no deny-all"),
        _f("MEDIUM", "[MEDIUM] no logging"),
    ]
    assert _build_summary(findings)["score"] == 67


def test_summary_score_floor_zero():
    findings = [_f("CRITICAL", f"[CRITICAL] finding {i}") for i in range(10)]
    assert _build_summary(findings)["score"] == 0


def test_summary_compliance_tags_not_counted_as_critical():
    # A compliance finding tagged [PCI-CRITICAL] is not a raw critical
    findings = [_f("HIGH", "[PCI-CRITICAL] some pci finding")]
    s = _build_summary(findings)
    assert s["critical"] == 0


# ── _sort_findings ─────────────────────────────────────────────────────────────


def test_sort_critical_before_high():
    findings = [
        _f("HIGH", "[HIGH] deny-all missing"),
        _f("CRITICAL", "[CRITICAL] permit any any"),
        _f("MEDIUM", "[MEDIUM] no logging"),
    ]
    sorted_f = _sort_findings(findings)
    assert "[CRITICAL]" in sorted_f[0]["message"]
    assert "[HIGH]" in sorted_f[1]["message"]
    assert "[MEDIUM]" in sorted_f[2]["message"]
