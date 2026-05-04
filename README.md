# Cashel

![CI](https://github.com/Shamrock13/cashel/actions/workflows/ci.yml/badge.svg)

**Cashel** is a self-hosted firewall configuration auditing and remediation tool built for network security engineers, MSPs, and security teams. Upload firewall configs, audit live devices over SSH, schedule recurring checks, compare configuration changes, and generate client-ready reports, remediation plans, and export bundles.

Cashel's current direction is focused on **trusted, evidence-backed findings** rather than adding more vendor breadth. The app now supports a normalized finding model that preserves legacy UI/API compatibility while adding fields such as stable finding IDs, evidence, affected objects, confidence, verification guidance, rollback notes, compliance references, and suggested commands where available.

**Try the live demo:** [demo.cashel.app](https://demo.cashel.app)

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Cashel-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Current Application State

Cashel currently includes:

- Multi-vendor firewall and cloud security-group auditing
- Web UI and CLI audit workflows
- Single-file and bulk config audits
- Live SSH audits for supported network firewall platforms
- Scheduled SSH audits with alerting
- Audit history, activity logging, score trends, and saved report views
- Rule diffing between two configs of the same vendor
- Severity scoring with CRITICAL / HIGH / MEDIUM / LOW findings
- Compliance checks behind a license key
- Export formats: PDF, JSON, CSV, SARIF, and evidence bundles
- Structured remediation plans with Markdown and PDF output
- Vendor-specific suggested commands where safe and practical
- Normalized finding fields for evidence-backed reporting and future policy-as-code workflows

### Evidence-backed finding coverage

The normalized finding model is in place, but not every vendor/check has been fully migrated yet.

Currently enriched:

- Cisco ASA core checks:
  - overly permissive any-any ACL rules
  - permit rules missing logging
  - missing explicit deny-all logging
  - duplicate/redundant ACL entries
  - Telnet management exposure
  - unrestricted ICMP any-any rules
- Rule shadowing findings for:
  - Cisco ASA / FTD
  - Palo Alto Networks
  - Fortinet FortiGate
  - pfSense
  - Azure NSG
  - Juniper SRX
- Remediation plans now prefer structured finding fields such as `title`, `id`, `evidence`, `verification`, `rollback`, `affected_object`, and `suggested_commands` before falling back to legacy message parsing.
- JSON exports preserve enriched finding fields.
- CSV exports include `id`, `title`, `evidence`, and remediation columns.
- SARIF exports prefer stable finding IDs as rule IDs when available.

Still being migrated:

- Full structured finding coverage for Fortinet, Palo Alto, Juniper, pfSense, iptables/nftables, AWS, Azure, and GCP vendor-specific checks
- Deeper object expansion for Fortinet, Palo Alto, and ASA/FTD
- Data-driven compliance-control mappings
- Policy-as-code gates for CI/CD

---

## Supported Vendors

Cashel supports on-prem firewall configs, Linux host firewall configs, and cloud security-group style policies.

> **Cisco note:** Cashel exposes Cisco ASA and FTD under a single Cisco option in the UI. The platform can auto-detect ASA vs. FTD from config content and apply the relevant checks.

| Vendor | Config Format | Live SSH | Notes |
|---|---|---:|---|
| AWS Security Groups | JSON | — | Audit only; no rule-order shadowing |
| Azure NSG | JSON | — | Includes priority-based shadow checks |
| Cisco ASA / FTD | Text | ✓ | ASA audit findings are evidence-backed and normalized |
| Fortinet FortiGate | Text | ✓ | Enriched findings with address/service object expansion and shadow detection |
| GCP VPC Firewall | JSON | — | Audit only |
| iptables / nftables | Text | ✓ | Linux host firewall checks |
| Juniper SRX | Text | ✓ | Enriched findings with address-book/application-set expansion and zone-pair shadow detection |
| Palo Alto Networks | XML | ✓ | Enriched findings with address/service/application expansion and shadow detection |
| pfSense | XML | ✓ | Enriched findings with alias expansion and interface-aware shadow detection |

Full list of vendor-specific checks: [docs/checks.md](docs/checks.md)

---

## Features

### Audit Engine

- **Severity model** — CRITICAL / HIGH / MEDIUM / LOW findings sorted and color-coded by risk
- **Security scoring** — 0–100 per audit: `100 − (CRITICAL×20) − (HIGH×10) − (MEDIUM×3)`
- **Auto vendor detection** — identifies supported vendors from config content
- **Hostname extraction** — device hostname can auto-populate the Device Tag field when detectable
- **Category badges** — findings grouped by exposure, protocol, logging, hygiene, redundancy, and compliance
- **Normalized findings** — additive structured fields for evidence, stable IDs, affected objects, verification, rollback, and suggested commands
- **Legacy compatibility** — older string/dict findings still render and export

### Audit Modes

- **Single file** — upload one config and receive score, findings, remediation guidance, and exports
- **Bulk** — upload multiple configs and audit each independently
- **Live SSH** — connect to SSH-capable devices and audit running configs without storing one-time credentials
- **Scheduled** — recurring SSH audits with saved history and optional alerting

### Reports and Exports

- **Modern PDF reports** — HTML/CSS-rendered audit reports using Playwright/Chromium
- **Remediation reports** — grouped remediation steps with evidence, guidance, verification, rollback, and suggested commands when available
- **Evidence bundles** — ZIP package containing report artifacts such as PDF, JSON, CSV, SARIF, and cover material
- **JSON** — preserves full enriched finding dictionaries
- **CSV** — spreadsheet-friendly export with stable IDs, vendor, title, evidence, affected object, rule name, confidence, and remediation columns
- **SARIF** — security tooling integration using stable finding IDs where present
- **REST API** — pipeline-friendly audit endpoint returning JSON findings

### History and Trends

- **Audit History** — saved audits with vendor/date/tag filtering and search
- **Score Trends** — score-over-time visualization by device/vendor/tag
- **Archived comparisons** — compare two saved audits to identify resolved, new, and changed findings
- **Device tags** — track repeated audits for named devices
- **Activity Log** — records audits, SSH attempts, diffs, scheduled runs, and failures

### Rule Quality Analysis

- **Shadow detection** — flags rules that cannot match because earlier rules already cover the traffic scope
- **Duplicate detection** — identifies duplicate rules that add no policy value
- **Current limitation** — shadow logic is useful but not yet fully scope-aware across nested objects, CIDRs, service groups, NAT context, and all vendor-specific abstractions

### Alerts and Integrations

- Slack webhook
- Microsoft Teams webhook
- Email / SMTP
- Syslog forwarding over UDP/TCP
- Generic outbound webhooks with HMAC signing and SSRF protections

### Platform and Security

- Docker Compose deployment
- Flask web UI and Typer CLI
- SQLite persistence for audits, schedules, users, auth events, alert state, and integrations
- RBAC roles for admin/auditor/viewer style access patterns
- Configurable SSH host-key policy: Warn, Strict, or Auto-add
- HTTP security headers
- XML parsing via `defusedxml`
- CI checks for Ruff, format, mypy, tests, XML parser safety, dependency sync, and secret scanning

---

## Paid Features

Compliance checks require a license key and map audit findings to control references.

| Framework | Coverage | Vendors |
|---|---|---|
| CIS Benchmark | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| DISA STIG | CAT-I / CAT-II / CAT-III | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| HIPAA Security Rule | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| NIST SP 800-41 | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| PCI-DSS | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| SOC2 | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |

> Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/cashel)

---

## Installation

### Option 1 — Docker Compose

**Requirements:** Docker Desktop, OrbStack, or another Docker-compatible runtime.

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
docker compose up --build
```

Open **http://localhost:8080**.

Reports, audit history, activity log, schedules, and license settings persist in Docker storage across restarts.

Recommended `.env` value:

```bash
CASHEL_SECRET=replace-with-a-long-random-secret
```

Stop the app:

```bash
docker compose down
```

### Option 2 — Local Python

**Requirements:** Python 3.9+.

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
pip install -r requirements.txt
python -m playwright install chromium
```

Run the web UI:

```bash
PYTHONPATH=src python -m flask --app src/cashel/web.py run
```

Open **http://localhost:5000**.

Run the CLI:

```bash
PYTHONPATH=src python -m cashel.main --file examples/cisco_asa.txt --vendor cisco
```

### PDF rendering notes

Cashel renders audit, remediation, and evidence-bundle PDFs from HTML/CSS report templates. Playwright's Chromium browser is required for PDF export.

Optional environment variables:

```bash
CASHEL_PDF_PAGE_FORMAT=Letter
CASHEL_PDF_TIMEOUT_MS=30000
```

---

## Quick Start

```bash
# Cisco ASA example
PYTHONPATH=src python -m cashel.main --file examples/cisco_asa.txt --vendor cisco

# Palo Alto example
PYTHONPATH=src python -m cashel.main --file examples/palo_alto.xml --vendor paloalto

# Web UI
PYTHONPATH=src python -m flask --app src/cashel/web.py run
```

Full CLI reference: [docs/cli.md](docs/cli.md)

---

## Web UI

The interface is organized into six main areas:

| Area | Purpose |
|---|---|
| Audit | Single-file and bulk upload audits with findings and exports |
| Compare | Diff two configs of the same vendor |
| Live Connect | Pull and audit running configs over SSH |
| History | Browse saved audits, compare previous runs, and view trends |
| Schedules | Manage recurring SSH audits and alert behavior |
| Settings | Configure email, security settings, syslog, webhooks, license, and app preferences |

---

## Example Config Files

The `examples/` directory contains sample configurations for supported vendors.

| File | Vendor |
|---|---|
| `examples/cisco_asa.txt` | Cisco ASA |
| `examples/cisco_ftd.txt` | Cisco FTD |
| `examples/fortinet_fortigate.txt` | Fortinet FortiGate |
| `examples/palo_alto.xml` | Palo Alto Networks |
| `examples/pfsense.xml` | pfSense |
| `examples/juniper_srx.txt` | Juniper SRX |
| `examples/iptables.txt` | iptables |
| `examples/nftables.txt` | nftables |
| `examples/aws_security_groups.json` | AWS Security Groups |
| `examples/azure_nsg.json` | Azure NSG |
| `examples/gcp_vpc_firewall.json` | GCP VPC Firewall |

---

## Development Status

Current version in `pyproject.toml`: **2.0.0**.

Recently added or in-flight on the current development branch:

- Modern HTML/CSS-rendered audit PDFs
- Modern remediation PDFs
- Report view page
- HTML-based evidence bundle cover PDFs
- Normalized finding model
- Evidence-backed ASA findings
- Enriched shadow-rule findings across supported ordered-rule vendors
- Remediation plans that prefer structured fields over regex parsing
- JSON/CSV/SARIF enriched-field export support
- Expanded tests for reports, exports, remediation, HTML PDF rendering, and finding normalization

Known cleanup still needed:

- Replace placeholder package author metadata in `pyproject.toml`
- Continue migrating non-ASA vendor checks to enriched findings
- Add deeper object/service expansion for Fortinet, Palo Alto, and ASA/FTD
- Refactor compliance mappings toward data-driven controls
- Build policy-as-code gates after the finding model is consistently adopted

---

## Roadmap Priority

Near-term development should focus on depth and trust:

1. Finish structured finding migration for Fortinet and Palo Alto
2. Add object and service expansion for Fortinet, Palo Alto, and ASA/FTD
3. Make shadow detection scope-aware for CIDRs, ports, nested groups, and service objects
4. Improve compliance mapping using stable finding IDs
5. Add policy-as-code gates for CI/CD after findings are consistently normalized

Cashel should avoid adding more vendors until the top vendors produce consistently evidence-backed results.

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
