"""Tests for export.py — JSON, CSV, and SARIF serialization.

Run with:  python -m pytest tests/test_export.py -v
       or:  python tests/test_export.py
"""

import csv
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.export import to_json, to_csv, to_sarif, TOOL_VERSION

# ── Shared fixtures ───────────────────────────────────────────────────────────

ENTRY_ENRICHED = {
    "filename": "asa-lab.cfg",
    "vendor": "asa",
    "timestamp": "2026-03-21T00:00:00Z",
    "tag": "lab-device",
    "summary": {"high": 2, "medium": 1, "low": 0, "total": 3},
    "findings": [
        {
            "id": "CASHEL-ASA-EXPOSURE-001",
            "title": "Overly permissive any-any ACL rule",
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] Permit any any rule found — remove or restrict.",
            "evidence": "access-list OUTSIDE_IN permit ip any any",
            "remediation": "no access-list OUTSIDE_IN permit ip any any",
        },
        {
            "severity": "HIGH",
            "category": "management",
            "message": "[HIGH] Telnet enabled on management interface.",
            "remediation": "no telnet 0.0.0.0 0.0.0.0 mgmt",
        },
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "[MEDIUM] No remote syslog server configured.",
            "remediation": "logging host inside 10.0.0.1",
        },
    ],
}

# Plain-string findings as stored in the archive
ENTRY_PLAIN = {
    "filename": "forti-edge.conf",
    "vendor": "fortinet",
    "timestamp": "2026-03-21T00:00:00Z",
    "tag": "",
    "summary": {"high": 1, "medium": 1, "low": 0, "total": 2},
    "findings": [
        "[HIGH] Shadow rule detected: rule 5 is masked by rule 2.",
        "[MEDIUM] Admin interface reachable over HTTP — switch to HTTPS.",
    ],
}

ENTRY_EMPTY = {
    "filename": "clean.cfg",
    "vendor": "paloalto",
    "timestamp": "2026-03-21T00:00:00Z",
    "tag": "",
    "summary": {"high": 0, "medium": 0, "low": 0, "total": 0},
    "findings": [],
}

ENTRY_WITH_CRITICAL = {
    "filename": "asa-lab.cfg",
    "vendor": "asa",
    "timestamp": "2026-03-21T00:00:00Z",
    "tag": "lab-device",
    "summary": {"critical": 1, "high": 1, "medium": 0, "low": 0, "total": 2},
    "findings": [
        {
            "severity": "CRITICAL",
            "category": "exposure",
            "message": "[CRITICAL] permit any any found — remove immediately.",
            "remediation": "no access-list OUTSIDE_IN permit ip any any",
        },
        {
            "severity": "HIGH",
            "category": "hygiene",
            "message": "[HIGH] No explicit deny-all rule.",
            "remediation": "access-list OUTSIDE_IN deny ip any any log",
        },
    ],
}


# ══════════════════════════════════════════════════════════ JSON TESTS ══


def test_json_structure_enriched():
    """JSON output must contain all required top-level keys."""
    out = json.loads(to_json(ENTRY_ENRICHED))
    assert out["tool"] == "Cashel"
    assert out["version"] == "2.0.0"
    assert TOOL_VERSION == "2.0.0"
    assert out["vendor"] == "asa"
    assert out["filename"] == "asa-lab.cfg"
    assert out["summary"]["total"] == 3
    assert len(out["findings"]) == 3
    first = out["findings"][0]
    assert first["severity"] == "HIGH"
    assert first["category"] == "exposure"
    assert first["id"] == "CASHEL-ASA-EXPOSURE-001"
    assert first["evidence"] == "access-list OUTSIDE_IN permit ip any any"
    assert "remediation" in first


def test_json_structure_plain():
    """JSON export works for plain-string archive findings."""
    out = json.loads(to_json(ENTRY_PLAIN))
    assert out["vendor"] == "fortinet"
    assert len(out["findings"]) == 2
    assert "[HIGH]" in out["findings"][0]


def test_json_empty_findings():
    """JSON export handles zero findings without error."""
    out = json.loads(to_json(ENTRY_EMPTY))
    assert out["findings"] == []
    assert out["summary"]["total"] == 0


# ══════════════════════════════════════════════════════════ CSV TESTS ══


def _parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


def test_csv_columns_enriched():
    """CSV must include enriched columns and preserve standard fields."""
    rows = _parse_csv(to_csv(ENTRY_ENRICHED))
    assert len(rows) == 3
    assert set(rows[0].keys()) == {
        "id",
        "title",
        "severity",
        "category",
        "message",
        "evidence",
        "remediation",
    }
    assert rows[0]["id"] == "CASHEL-ASA-EXPOSURE-001"


def test_csv_severity_values_enriched():
    """Severity values must round-trip correctly for enriched findings."""
    rows = _parse_csv(to_csv(ENTRY_ENRICHED))
    severities = [r["severity"] for r in rows]
    assert severities == ["HIGH", "HIGH", "MEDIUM"]


def test_csv_plain_string_parsing():
    """CSV severity must be inferred from [HIGH]/[MEDIUM] prefix for plain-string findings."""
    rows = _parse_csv(to_csv(ENTRY_PLAIN))
    assert rows[0]["severity"] == "HIGH"
    assert rows[1]["severity"] == "MEDIUM"


def test_csv_empty_findings():
    """CSV for zero findings must still emit the header row only."""
    text = to_csv(ENTRY_EMPTY)
    rows = _parse_csv(text)
    assert rows == []
    assert "severity" in text


# ══════════════════════════════════════════════════════════ SARIF TESTS ══


def test_sarif_schema_version():
    """SARIF output must declare version 2.1.0."""
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    assert out["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in out["$schema"]


def test_sarif_tool_metadata():
    """SARIF driver name and version must match Cashel constants."""
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    drv = out["runs"][0]["tool"]["driver"]
    assert drv["name"] == "Cashel"
    assert drv["version"] == TOOL_VERSION


def test_sarif_result_levels_enriched():
    """HIGH findings map to 'error', MEDIUM map to 'warning'."""
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    results = out["runs"][0]["results"]
    assert results[0]["level"] == "error"  # HIGH
    assert results[1]["level"] == "error"  # HIGH
    assert results[2]["level"] == "warning"  # MEDIUM


def test_sarif_rule_deduplication():
    """Two findings with the same category must produce only one rule entry."""
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # exposure, management, logging — each category appears exactly once
    assert len(rule_ids) == len(set(rule_ids))
    assert "CASHEL-ASA-EXPOSURE-001" in rule_ids
    assert "FLK-MANAGEMENT" in rule_ids
    assert "FLK-LOGGING" in rule_ids


def test_sarif_uses_stable_finding_id():
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    result = out["runs"][0]["results"][0]
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    assert result["ruleId"] == "CASHEL-ASA-EXPOSURE-001"
    assert rules[0]["id"] == "CASHEL-ASA-EXPOSURE-001"


def test_sarif_fixes_present():
    """Findings with remediation must include a 'fixes' entry."""
    out = json.loads(to_sarif(ENTRY_ENRICHED))
    results = out["runs"][0]["results"]
    assert "fixes" in results[0]
    assert "no access-list" in results[0]["fixes"][0]["description"]["text"]


def test_sarif_plain_string_findings():
    """SARIF must handle plain-string archive findings without crashing."""
    out = json.loads(to_sarif(ENTRY_PLAIN))
    results = out["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"  # [HIGH] prefix
    assert results[1]["level"] == "warning"  # [MEDIUM] prefix


def test_sarif_empty_findings():
    """SARIF for zero findings must still be a valid document."""
    out = json.loads(to_sarif(ENTRY_EMPTY))
    assert out["runs"][0]["results"] == []
    assert out["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_critical_maps_to_error():
    """CRITICAL findings must map to SARIF 'error' level."""
    out = json.loads(to_sarif(ENTRY_WITH_CRITICAL))
    results = out["runs"][0]["results"]
    critical_results = [
        r for r in results if "CRITICAL" in r.get("message", {}).get("text", "")
    ]
    assert len(critical_results) == 1
    assert critical_results[0]["level"] == "error"


def test_json_export_preserves_critical_severity():
    out = json.loads(to_json(ENTRY_WITH_CRITICAL))
    severities = [f["severity"] for f in out["findings"]]
    assert "CRITICAL" in severities


# ── standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_json_structure_enriched,
        test_json_structure_plain,
        test_json_empty_findings,
        test_csv_columns_enriched,
        test_csv_severity_values_enriched,
        test_csv_plain_string_parsing,
        test_csv_empty_findings,
        test_sarif_schema_version,
        test_sarif_tool_metadata,
        test_sarif_result_levels_enriched,
        test_sarif_rule_deduplication,
        test_sarif_fixes_present,
        test_sarif_plain_string_findings,
        test_sarif_empty_findings,
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
