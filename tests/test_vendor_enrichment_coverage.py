"""Consistency tests for vendor enrichment coverage claims."""

from __future__ import annotations

from pathlib import Path

from cashel.audit_engine import run_vendor_audit
from cashel.models.findings import validate_finding_shape

ROOT = Path(__file__).resolve().parents[1]

VENDOR_SAMPLES = {
    "asa": ROOT / "examples/cisco_asa.txt",
    "ftd": ROOT / "examples/cisco_ftd.txt",
    "fortinet": ROOT / "examples/fortinet_fortigate.txt",
    "paloalto": ROOT / "examples/palo_alto.xml",
    "juniper": ROOT / "examples/juniper_srx.txt",
    "pfsense": ROOT / "examples/pfsense.xml",
    "iptables": ROOT / "examples/iptables.txt",
    "nftables": ROOT / "examples/nftables.txt",
    "aws": ROOT / "examples/aws_security_groups.json",
    "azure": ROOT / "examples/azure_nsg.json",
    "gcp": ROOT / "examples/gcp_vpc_firewall.json",
}

EXPECTED_COVERAGE_STATUS = {
    "ASA": "Fully enriched",
    "FTD": "Partially enriched",
    "Fortinet": "Fully enriched",
    "Palo Alto": "Fully enriched",
    "Juniper SRX": "Partially enriched",
    "pfSense": "Partially enriched",
    "iptables": "Fully enriched",
    "nftables": "Fully enriched",
    "AWS Security Groups": "Fully enriched",
    "Azure NSG": "Fully enriched",
    "GCP VPC Firewall": "Fully enriched",
}


def _coverage_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    doc = ROOT / "docs/vendor-enrichment-coverage.md"
    for line in doc.read_text().splitlines():
        if not line.startswith("| ") or line.startswith("| Vendor"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) >= 3 and columns[0] not in {"---", ""}:
            rows[columns[0]] = columns[2]
    return rows


def test_vendor_enrichment_coverage_doc_matches_expected_statuses():
    rows = _coverage_rows()

    for vendor, expected_status in EXPECTED_COVERAGE_STATUS.items():
        assert rows[vendor] == expected_status


def test_supported_vendor_samples_emit_enriched_findings():
    for vendor, sample in VENDOR_SAMPLES.items():
        findings, _parse, _extra = run_vendor_audit(vendor, str(sample))

        assert findings, vendor
        for finding in findings:
            assert isinstance(finding, dict), (vendor, finding)
            assert validate_finding_shape(finding) == [], (
                vendor,
                finding.get("message"),
            )
            assert finding["id"].startswith("CASHEL-"), (
                vendor,
                finding.get("message"),
            )
            assert finding["vendor"] == vendor, finding.get("message")
            assert finding["title"], (vendor, finding.get("message"))
            assert finding["message"], vendor
            assert finding["remediation"], finding.get("message")
            assert finding["evidence"], finding.get("message")
            assert finding["confidence"], finding.get("message")
            assert finding["verification"], finding.get("message")
            assert finding["rollback"], finding.get("message")
            assert isinstance(finding["metadata"], dict), finding.get("message")
            assert finding["metadata"], finding.get("message")
