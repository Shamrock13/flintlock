# Cashel

![CI](https://github.com/Shamrock13/cashel/actions/workflows/ci.yml/badge.svg)

**Cashel** is a firewall configuration auditing tool built for network security engineers. Upload a config, get an instant security score, severity-graded findings with remediation guidance, compliance mapping, and export-ready reports — all from a clean web UI or CLI. Connect directly to live devices via SSH, schedule recurring audits, and track score trends across your fleet over time.

**Try the live demo:** [demo.cashel.app](https://demo.cashel.app)

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Cashel-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

Cashel supports **11 vendor platforms** spanning on-premises firewalls and cloud security groups.

> **Cisco note:** Cashel supports Cisco ASA and FTD under a single **Cisco** vendor option. The platform auto-detects which appliance type from the config content and applies the appropriate checks.

| Vendor | Config Format | Live SSH |
|---|---|---|
| AWS Security Groups | JSON | — |
| Azure NSG | JSON | — |
| Cisco (ASA / FTD) | Text | ✓ |
| Fortinet FortiGate | Text | ✓ |
| GCP VPC Firewall | JSON | — |
| iptables / nftables (Linux) | Text | ✓ |
| Juniper SRX | Text | ✓ |
| Palo Alto Networks | XML | ✓ |
| pfSense | XML | ✓ |

---

## Features

### Free (Open Source)

**Audit engine**
- **4-level severity** — CRITICAL / HIGH / MEDIUM / LOW, with findings sorted and color-coded by risk
- **Security scoring** — 0–100 per audit: `100 − (CRITICAL×20) − (HIGH×10) − (MEDIUM×3)`
- **Auto vendor detection** — identifies vendor from file content; no manual selection required
- **Hostname extraction** — device hostname auto-populated from the config file into the Device Tag field
- **Category badges** — findings tagged by type: Exposure, Protocol, Logging, Hygiene, Redundancy
- **Remediation guidance** — every finding includes a plain-English fix recommendation

**Audit modes**
- **Single file** — upload one config, get instant results with filterable findings
- **Bulk** — upload multiple configs at once; each audited independently with per-file score and expandable findings
- **Live SSH** — connect directly to any SSH-capable device to pull and audit its running config in real time (8 vendor types, PEM key support)
- **Scheduled** — recurring SSH audits (hourly, daily, weekly) with full CRUD management; results auto-save to Audit History

**Exports**
- **PDF report** — color-coded findings with score, categories, and remediation text; view inline or download
- **JSON** — structured findings with severity, category, remediation, and metadata
- **CSV** — tabular findings for spreadsheets or ticketing systems
- **SARIF** — Static Analysis Results Interchange Format for CI/CD and security tooling integration
- **REST API** — `POST /api/v1/audit` returns JSON findings for pipeline integration

**History & trends**
- **Audit History** — save, browse, filter (vendor / date / tag), and search past audits
- **Score Trends chart** — security score over time per device, with vendor and tag filters
- **Archival comparisons** — diff any two saved audits: resolved issues, new issues, severity deltas
- **Device tag system** — name devices (e.g. `ASA01`, `FortiGate-HQ`) for auto-versioned history and trend tracking
- **Activity Log** — complete record of every audit, SSH attempt, diff, and scheduled run — including failures

**Rule quality analysis**
- **Shadow rule detection** — flags rules that can never match because an earlier rule already covers the same traffic
- **Duplicate rule detection** — identifies exact duplicate rules that add no policy value

**Alerts & integrations**
- Slack webhook · Microsoft Teams webhook · Email (SMTP) · Syslog forwarding (UDP/TCP)
- All alert channels are available on scheduled audits; Syslog streams all application events for SIEM integration

**Platform**
- Rule change diff — upload two configs of the same vendor to see added, removed, and unchanged rules
- Configurable SSH host key policy — Warn (default), Strict, or Auto-add
- Webhook SSRF protection — hostname allowlist + private IP blocking
- HTTP security headers — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy on every response
- XXE injection protection — all XML parsing uses defusedxml
- Light / dark / auto theme · CLI · Docker Compose deployment

Full list of vendor-specific checks: [docs/checks.md](docs/checks.md)

---

### Paid (License Required)

Compliance checks require a license key and map findings to specific control references.

| Framework | Coverage | Vendors |
|---|---|---|
| CIS Benchmark | HIGH / MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |
| DISA STIG | CAT-I / CAT-II / CAT-III | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |
| HIPAA Security Rule (45 CFR §164) | HIGH / MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |
| NIST SP 800-41 | HIGH / MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |
| PCI-DSS | HIGH / MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |
| SOC2 | HIGH / MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto, pfSense |

> **Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/cashel)**

---

## Installation

### Option 1 — Docker Compose (Recommended)

**Requirements:** Docker Desktop or OrbStack

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
docker compose up --build
```

Open **http://localhost:8080** in your browser. Reports, audit history, activity log, schedules, and your license key are persisted in a Docker volume across restarts. To set a custom secret, create a `.env` file:

```
CASHEL_SECRET=your-secret-here
```

To stop: `docker compose down`

---

### Option 2 — Local Python

**Requirements:** Python 3.11+

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
pip install -r requirements.txt
python -m playwright install chromium
```

**Run the web UI:**
```bash
PYTHONPATH=src python -m flask --app src/cashel/web.py run
```
Open **http://localhost:5000**

Cashel renders audit, remediation, and evidence-bundle PDFs from the same
HTML/CSS report templates used by the web app. Playwright's Chromium browser is
required for PDF export. Set `CASHEL_PDF_PAGE_FORMAT` to override the default
`Letter` page size, or `CASHEL_PDF_TIMEOUT_MS` to tune the render timeout.

**Run the CLI:**
```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor cisco
```

---

## Quick Start

```bash
# CLI — audit a config file
PYTHONPATH=src python -m cashel.main --file examples/cisco_asa.txt --vendor cisco
PYTHONPATH=src python -m cashel.main --file examples/palo_alto.xml --vendor paloalto

# Web UI — upload any file from examples/ and select Auto-detect
```

Full CLI reference: [docs/cli.md](docs/cli.md)

---

## Web UI

The interface is organized into six tabs with SVG navigation icons.

**Audit** — Toggle between Single File and Bulk mode. Upload a config, optionally set a Device Tag and compliance framework, then click Run Audit. Results show a security score, severity counts, category-tagged findings with remediation, and export buttons (PDF, JSON, CSV, SARIF).

**Compare** — Upload two configs of the same vendor to diff added, removed, and unchanged rules. Vendor is auto-detected from the baseline file.

**Live Connect** — SSH directly to a device to pull and audit its running config. Credentials are used for the single connection only and are never stored.

**Schedules** — Configure recurring SSH audits (hourly, daily, weekly) with optional Slack, Teams, or email alerts on HIGH/CRITICAL findings or errors. Results are auto-saved to Audit History.

**History** — Browse all saved audits with vendor/date/tag filters. Select any two entries to run a full diff. The Score Trends chart plots each device's security score over time. The Activity Log records every audit, SSH attempt, diff, and scheduled run.

**Settings** — Two-column panel covering: General (auto-PDF, auto-archive, default compliance), Email/SMTP, Security (SSH host key policy, webhook domains, error detail level), and Syslog (host, port, protocol, facility).

---

## Example Config Files

The `examples/` directory contains sample configurations for all supported vendors — each with a mix of well-scoped rules and intentional misconfigurations that Cashel will detect.

| File | Vendor |
|---|---|
| `examples/cisco_asa.txt` | Cisco ASA |
| `examples/cisco_ftd.txt` | Cisco FTD |
| `examples/fortinet_fortigate.txt` | Fortinet FortiGate |
| `examples/palo_alto.xml` | Palo Alto Networks |
| `examples/pfsense.xml` | pfSense |
| `examples/juniper_srx.txt` | Juniper SRX |
| `examples/iptables.txt` | iptables (Linux) |
| `examples/nftables.txt` | nftables (Linux) |
| `examples/aws_security_groups.json` | AWS Security Groups |
| `examples/azure_nsg.json` | Azure NSG |
| `examples/gcp_vpc_firewall.json` | GCP VPC Firewall |

---

## Changelog

What's shipped and where to find it:

| Release | Highlights | PR |
|---|---|---|
| **v1.5.1** | CRITICAL severity level — engine, parsers, exports, CSS, UI, API | [#73](https://github.com/Shamrock13/cashel/pull/73) |
| **v1.5.0** | Threshold-based alerting — CRUD UI, alert channels, scheduled evaluation | [#72](https://github.com/Shamrock13/cashel/pull/72) |
| **v1.5.0** | Auth audit log, OpenAPI/Swagger docs, deployment guide | [#65](https://github.com/Shamrock13/cashel/pull/65) |
| **v1.4.x** | RBAC (admin/viewer roles), SQLite persistence, multi-user auth, Render deploy hardening | [#40](https://github.com/Shamrock13/cashel/pull/40) |
| **v1.4.0** | Blueprint decomposition, SQLite, session auth | [#31](https://github.com/Shamrock13/cashel/pull/31) |
| **Earlier** | All prior features — scoring, vendors, compliance, exports, SSH, scheduling, diff, rule quality | [full history](https://github.com/Shamrock13/cashel/pulls?q=is%3Apr+is%3Aclosed) |

---

## Support

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white&style=for-the-badge)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Buy%20me%20a%20coffee-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white&style=for-the-badge)](https://ko-fi.com/shamrock13)

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
