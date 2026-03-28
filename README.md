# Cashel

**Cashel** is a firewall configuration auditing tool with a web UI and CLI. It detects security misconfigurations, generates scored severity reports, compares configs across time, connects directly to live devices via SSH, and runs automated scheduled audits with alerting. Deployable in minutes via Docker Compose.

**Try the live demo:** [cashel-demo.sham.cloud](https://cashel-demo.sham.cloud)

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Cashel-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

Cashel supports **10 vendor platforms** spanning on-premises firewalls and cloud security groups.

> **Cisco note:** Cashel supports Cisco ASA and FTD under a single **Cisco** vendor option. The platform auto-detects which appliance type from the config content and applies the appropriate checks.

| Vendor | Config Format | Live SSH | Notes |
|---|---|---|---|
| AWS Security Groups | JSON | — | `aws ec2 describe-security-groups` export |
| Azure NSG | JSON | — | `az network nsg show` / `nsg list` export |
| Cisco (ASA / FTD) | Text | ✓ | Running config (`show running-config`); FTD auto-detected |
| Fortinet FortiGate | Text | ✓ | Running config (`show full-configuration`) |
| GCP VPC Firewall | JSON | — | `gcloud compute firewall-rules list --format json` |
| iptables (Linux) | Text | ✓ | `iptables-save` format |
| Juniper SRX | Text | ✓ | Set-format or hierarchical config |
| nftables (Linux) | Text | ✓ | `nft list ruleset` output |
| Palo Alto Networks | XML | ✓ | Candidate or running config |
| pfSense | XML | ✓ | Full config export (`config.xml`) |

---

## Features

### Free (Open Source)

**Core audit**
- **Auto-detect vendor** — identifies vendor from file content; no manual selection required
- **Security scoring** — 0–100 score per audit: `100 − (HIGH × 10) − (MEDIUM × 3)`
- **Category badges** — findings tagged by type: Exposure, Protocol, Logging, Hygiene, Redundancy
- **Remediation guidance** — every finding includes a plain-English fix recommendation
- **Hostname extraction** — device hostname auto-populated from the config file into the Device Tag field

**Audit modes**
- **Single file audit** — upload one config, get instant results with filterable findings
- **Bulk audit** — upload multiple configs at once; each is audited independently with per-file score and expandable findings
- **Live SSH connection** — connect directly to any supported SSH-capable device to pull and audit its running config in real time (8 vendor types)
- **Scheduled audits** — set up recurring SSH audits (hourly, daily, or weekly) with full CRUD management; results auto-save to Audit History

**Alerts & integrations** — Slack webhook, Microsoft Teams webhook, Email (SMTP), and Syslog forwarding (UDP/TCP) are all supported on scheduled audits. Syslog streams all application events to a remote server for SIEM integration.

**Exports**
- **PDF report** — download or view inline a color-coded findings report with score, categories, and remediation text
- **JSON export** — structured findings with severity, category, remediation, and metadata
- **CSV export** — tabular findings for import into spreadsheets or ticketing systems
- **SARIF export** — Static Analysis Results Interchange Format for CI/CD pipeline and security tooling integration

**History & comparison**
- **Audit History** — save, browse, filter (vendor/date/tag), and search past audits
- **Score Trends chart** — visualize security score over time per device, with vendor and tag filters
- **Archival comparisons** — select any two saved audits to see resolved issues, new issues, and HIGH/MEDIUM/Total deltas
- **Activity Log** — complete record of every audit, SSH attempt, diff, and scheduled run — including failures
- **Device tag system** — name devices (e.g. `ASA01`, `FortiGate-HQ`) for auto-versioned history and trend tracking

**Rule quality analysis**
- **Shadow rule detection** — flags rules that can never match because an earlier rule already covers the same traffic
- **Duplicate rule detection** — identifies exact duplicate rules that add no policy value

**Platform & security**
- **Rule change diff** — upload two configs of the same vendor to see added, removed, and unchanged rules
- **Configurable SSH host key policy** — Warn (default), Strict (reject unknown), or Auto-add (lab use only)
- **Webhook SSRF protection** — built-in hostname allowlist (Slack, Teams, Discord) + private IP blocking
- **HTTP security headers** — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy on every response
- **XXE injection protection** — all XML parsing uses defusedxml
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
```

**Run the web UI:**
```bash
PYTHONPATH=src python -m flask --app src/cashel/web.py run
```
Open **http://localhost:5000**

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

**Audit** — Toggle between Single File and Bulk mode. Upload a config, optionally set a Device Tag and compliance framework, then click Run Audit. Results show a security score, severity counts, category-tagged findings with remediation, and export buttons (PDF, JSON, CSV, SARIF). Bulk mode audits each uploaded file independently with per-file scores and expandable findings.

**Compare** — Upload two configs of the same vendor to diff added, removed, and unchanged rules. Vendor is auto-detected from the baseline file.

**Live Connect** — SSH directly to a device (Cisco, Fortinet, iptables, Juniper, nftables, Palo Alto, pfSense) to pull and audit its running config. Credentials are used for the single connection only and are never stored.

**Schedules** — Configure recurring SSH audits (hourly, daily, weekly) with optional Slack, Teams, or email alerts on HIGH findings or errors. Results are auto-saved to Audit History.

**History** — Browse all saved audits with vendor/date/tag filters. Select any two entries to run a full diff. The Score Trends chart plots each device's security score over time. The Activity Log records every audit, SSH attempt, diff, and scheduled run — including failures.

**Settings** — Two-column panel covering: General (auto-PDF, auto-archive, default compliance), Email/SMTP (outbound mail with live test), Security (SSH host key policy, allowed webhook domains, error detail level), and Syslog (host, port, protocol, facility).

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

## Roadmap

- [x] Activity Log (usage monitoring)
- [x] Archival reviews (compare historical audits)
- [x] Auto vendor detection
- [x] AWS Security Group support
- [x] Azure NSG support
- [x] Bulk multi-device audit
- [x] Category badges and remediation guidance
- [x] CIS Benchmark compliance framework
- [x] Cisco FTD / Firepower Threat Defense support (auto-detected alongside ASA)
- [x] Clickable severity filters
- [x] Client-side vendor auto-detection on file upload
- [x] CSRF protection (Flask-WTF)
- [x] CSV and SARIF export
- [x] Detailed / Compact results view toggle
- [x] Device tag system with auto-versioning
- [x] DISA STIG compliance framework
- [x] Docker Compose deployment
- [x] Email / webhook notifications for scheduled audit findings
- [x] Fernet encryption for stored credentials
- [x] Findings pagination with configurable page size
- [x] Fortinet v2 checks
- [x] GCP VPC Firewall support
- [x] HIPAA Security Rule compliance framework
- [x] Hostname auto-extraction from config files
- [x] HTTP security hardening headers
- [x] iptables / nftables (Linux) support with Live SSH
- [x] JSON export
- [x] Juniper SRX support with Live SSH
- [x] Light / dark / auto theme
- [x] Live SSH connection mode (8 vendors)
- [x] Microsoft Teams webhook alerts
- [x] NIST SP 800-41 compliance framework
- [x] PCI-DSS compliance framework
- [x] PDF report (score box, categories, remediation, inline view)
- [x] Rule change diff (compare two configs)
- [x] Rule quality analysis (shadow and duplicate detection)
- [x] Scheduled automated SSH audits (APScheduler)
- [x] Score Trends chart with device tag and vendor filters
- [x] Security scoring (0–100 per audit)
- [x] Settings panel (2-column: General, Email, Security, Syslog)
- [x] Slack webhook alerts
- [x] SOC2 compliance framework
- [x] Syslog forwarding for SIEM integration
- [x] Web UI with file upload and inline results
- [x] XXE injection protection (defusedxml)
- [x] API key authentication with session management
- [x] Multi-factor SSH authentication (PEM key support)
- [x] REST API for CI/CD pipeline integration

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
