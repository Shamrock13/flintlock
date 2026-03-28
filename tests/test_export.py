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
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] Permit any any rule found — remove or restrict.",
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


# ══════════════════════════════════════════════════════════ JSON TESTS ══


def test_json_structure_enriched():
    """JSON output must contain all required top-level keys."""
    out = json.loads(to_json(ENTRY_ENRICHED))
    assert out["tool"] == "Cashel"
    assert out["vendor"] == "asa"
    assert out["filename"] == "asa-lab.cfg"
    assert out["summary"]["total"] == 3
    assert len(out["findings"]) == 3
    first = out["findings"][0]
    assert first["severity"] == "HIGH"
    assert first["category"] == "exposure"
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
    """CSV must have the four standard columns and correct row count."""
    rows = _parse_csv(to_csv(ENTRY_ENRICHED))
    assert len(rows) == 3
    assert set(rows[0].keys()) == {"severity", "category", "message", "remediation"}


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
    assert "FLK-EXPOSURE" in rule_ids
    assert "FLK-MANAGEMENT" in rule_ids
    assert "FLK-LOGGING" in rule_ids


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
