# Flintlock

**Flintlock** is a firewall configuration auditing tool with a web UI and CLI. It detects security misconfigurations, generates scored severity reports, compares configs across time, connects directly to live devices via SSH, and runs automated scheduled audits with alerting. Deployable in minutes via Docker Compose.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Flintlock-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

| Vendor | Config Format | Live SSH | Notes |
|---|---|---|---|
| AWS Security Groups | JSON | — | `aws ec2 describe-security-groups` export |
| Azure NSG | JSON | — | `az network nsg show` / `nsg list` export |
| Cisco ASA | Text | ✓ | Running config (`show running-config`) |
| Cisco FTD | Text | ✓ | LINA CLI; auto-detected from ASA uploads |
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

**Alerts & integrations**
- **Slack webhook alerts** — notify a channel on HIGH findings or audit errors from scheduled runs
- **Microsoft Teams webhook alerts** — formatted MessageCard notifications to any Teams channel
- **Email alerts (SMTP)** — send severity summaries directly to an email address on each scheduled run
- **Syslog forwarding** — stream all application events to a remote syslog server over UDP or TCP; configurable facility for SIEM integration

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
- **Settings panel** — two-column sidebar layout with sections for General, Email (SMTP), Security, and Syslog
- **Rule change diff** — upload two configs of the same vendor to see added, removed, and unchanged rules
- **Configurable SSH host key policy** — Warn (default), Strict (reject unknown), or Auto-add (lab use only)
- **Webhook SSRF protection** — built-in hostname allowlist (Slack, Teams, Discord) + private IP blocking; extend via settings
- **Error detail control** — Sanitized (production) or Full (development) error reporting
- **HTTP security headers** — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy on every response
- **XXE injection protection** — all XML parsing uses defusedxml
- **Schedule input validation** — all numeric and enumerated schedule fields validated server-side before persistence
- Light / dark / auto theme
- CLI with audit summary output
- Docker Compose deployment

**Vendor-specific checks (free)**

| Check | Severity | Vendors |
|---|---|---|
| Any/any permit rules | HIGH | All |
| Missing deny-all rule | HIGH | Cisco, Juniper, Palo Alto, pfSense |
| Open ingress to 0.0.0.0/0 | HIGH | AWS, GCP |
| Internet-facing policy missing UTM | HIGH | Fortinet |
| WAN-facing any-source pass rule | HIGH | pfSense |
| Any-application rules | HIGH | Palo Alto |
| Inbound Any rules | HIGH | Azure |
| Default ACCEPT chain policy | HIGH | iptables, nftables |
| Any-any accept rule | HIGH | iptables, nftables |
| Permissive FORWARD chain | HIGH | iptables |
| All-service rules | MEDIUM | Fortinet |
| Default SG with active rules | MEDIUM | AWS |
| Default network in use | MEDIUM | GCP |
| Disabled policies | MEDIUM | Fortinet |
| Insecure services (Telnet/HTTP/FTP) | MEDIUM | Fortinet, Juniper |
| Internet ingress on sensitive ports | MEDIUM | GCP, iptables, nftables |
| Missing description | MEDIUM | GCP, Palo Alto, pfSense |
| Missing logging | MEDIUM | Cisco, iptables, Juniper, nftables, Palo Alto |
| No deny-all across zone pairs | MEDIUM | Juniper |
| Overly permissive NSG rules | MEDIUM | Azure |
| Shadowed/duplicate rules | MEDIUM | Cisco, Fortinet, Juniper, Palo Alto |
| Telnet management enabled | MEDIUM | Cisco, Juniper |
| SNMP community strings | MEDIUM | Juniper |
| Unnamed policies | MEDIUM | Fortinet |
| Unrestricted ICMP permit | MEDIUM | Cisco, GCP, iptables, nftables |
| Unrestricted egress | MEDIUM | GCP |
| Wide port range (>100 ports) | MEDIUM | AWS, Azure |

---

### Paid (License Required)

Compliance checks require a license key and map findings to specific control references.

| Framework | Coverage | Vendors |
|---|---|---|
| CIS Benchmark | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| DISA STIG | CAT-I / CAT-II / CAT-III | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| HIPAA Security Rule (45 CFR §164) | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| NIST SP 800-41 | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| PCI-DSS | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |
| SOC2 | HIGH / MEDIUM | Cisco ASA/FTD, Fortinet, Juniper, Palo Alto, pfSense |

> 💳 **Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/flintlock)**

---

## Installation

### Option 1 — Docker Compose (Recommended)

No Python environment setup required.

**Requirements:** Docker Desktop or OrbStack

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
docker compose up --build
```

Open **http://localhost:8080** in your browser.

Reports, audit history, activity log, schedules, and your license key are all persisted in a Docker volume across restarts. To set a custom secret, create a `.env` file in the project root:

```
FWAUDIT_SECRET=your-secret-here
```

To stop:
```bash
docker compose down
```

---

### Option 2 — Local Python

**Requirements:** Python 3.11+

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
pip install -r requirements.txt
```

**Run the web UI:**
```bash
PYTHONPATH=src python -m flask --app src/flintlock/web.py run
```
Open **http://localhost:5000**

**Run the CLI:**
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

---

## Web UI

The interface is organized into six tabs with SVG navigation icons.

### Audit
Toggle between **Single File** and **Bulk** mode.

**Single File:**
1. Enter a **Device Tag** (auto-filled from the config hostname when possible)
2. Upload a firewall config (text, XML, or JSON)
3. Select a vendor or leave on **Auto-detect**
4. Optionally select a compliance framework (license required)
5. Check **Generate PDF Report** and/or **Save to Audit History** as needed
6. Click **Run Audit**

Results show a security score, severity counts, category-tagged findings with remediation guidance, and export buttons (PDF, JSON, CSV, SARIF). Click summary boxes to filter findings by severity.

**Bulk:**
Upload multiple config files at once. Each file is audited independently with a per-file score, severity badges, and an expandable findings list.

### Compare
Upload two configs of the same vendor to see a diff — rules added, removed, and unchanged. Vendor is auto-detected from the baseline file.

### Live Connect
Connect to a device over SSH to pull and audit its running configuration without touching a file.

- **Supported vendors:** Cisco ASA, Cisco FTD, Fortinet, iptables (Linux), Juniper SRX, nftables (Linux), Palo Alto Networks, pfSense
- Credentials are used only for the single connection and are never stored
- Successful audits are automatically saved to Audit History
- Failed connections are recorded in the Activity Log only

**SSH notes by vendor:**

| Vendor | Command issued |
|---|---|
| Cisco ASA / FTD | `terminal pager 0` → `show running-config` |
| Fortinet | `show full-configuration firewall policy` |
| iptables (Linux) | `iptables-save` (sudo fallback) |
| Juniper SRX | `set cli screen-length 0` → `show configuration \| display set` |
| nftables (Linux) | `nft list ruleset` (sudo fallback) |
| Palo Alto | `show config running` |
| pfSense | `cat /conf/config.xml` |

### Schedules
Set up recurring SSH audits. Each schedule supports:

- **Vendors:** all 8 SSH-capable vendors
- **Frequency:** Hourly, Daily, or Weekly
- **Compliance framework** (license required)
- **Enable / Disable** toggle
- **Run Now** — trigger an immediate on-demand audit
- **Alerts:** Slack webhook, Microsoft Teams webhook, and/or email on HIGH findings or audit errors
- Results are auto-saved to Audit History

### History
Two sub-tabs:

**Audit History** — browse all saved audits. Filter by vendor (all 12 types), sort by date or issue count, search by tag or filename. Select any two entries and click **Compare Selected** to see a full diff. The Score Trends chart plots each device's security score over time.

**Activity Log** — a complete record of every file audit, SSH connection, config diff, and scheduled run — including failures. Entries can be deleted individually or cleared in bulk.

### Settings
Two-column panel with four sections:

- **General** — auto-PDF, auto-archive, default compliance framework
- **Email (SMTP)** — outbound mail server for scheduled audit notifications; includes a live Test SMTP button
- **Security** — SSH host key policy (Warn / Strict / Auto-add), allowed webhook domains, error detail level
- **Syslog** — enable/disable forwarding, host, port, protocol (UDP/TCP), facility

---

## Alerting

### Slack
Set a **Slack Webhook URL** on any schedule. Alerts fire on HIGH findings or audit errors.

### Microsoft Teams
Set a **Teams Webhook URL** (Office 365 incoming webhook) on any schedule. Alerts use the MessageCard format with colour-coded severity and a fact table.

### Email
Configure SMTP in Settings → Email. Set a **Alert Email** on any schedule. Alerts include a plain-text summary of findings.

### Syslog
Enable in Settings → Syslog. All application events (audit results, SSH attempts, scheduler runs) are forwarded to the configured server at INFO level with the prefix `flintlock LEVEL logger message`.

---

## CLI Usage

### Basic audit
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

### With compliance checks (license required)
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --compliance pci
```

### Export PDF report
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --report
```

### Supported vendors
```
--vendor asa        Cisco ASA
--vendor ftd        Cisco FTD (Firepower Threat Defense)
--vendor fortinet   Fortinet FortiGate
--vendor gcp        GCP VPC Firewall
--vendor iptables   iptables (Linux)
--vendor juniper    Juniper SRX
--vendor nftables   nftables (Linux)
--vendor paloalto   Palo Alto Networks
--vendor pfsense    pfSense
--vendor aws        AWS Security Groups
--vendor azure      Azure NSG
```

### Supported compliance frameworks
```
--compliance cis     CIS Benchmark
--compliance hipaa   HIPAA Security Rule
--compliance nist    NIST SP 800-41
--compliance pci     PCI-DSS
--compliance soc2    SOC2
--compliance stig    DISA STIG
```

### License activation
```bash
# Activate
PYTHONPATH=src python -m flintlock.main --activate YOUR-LICENSE-KEY

# Deactivate
PYTHONPATH=src python -m flintlock.main --deactivate
```

---

## Example CLI Output

```
Flintlock — Starting audit of firewall.xml (paloalto)

[HIGH] Overly permissive rule 'Allow-Any-Any': source=any destination=any
[HIGH] No explicit deny-all rule found
[MEDIUM] Permit rule 'Allow-Any-Any' missing logging
[MEDIUM] Redundant rule detected: 'Allow-Web-Duplicate'

--- PCI Compliance Checks ---
[PCI-HIGH] PCI Req 1.3: Rule 'Allow-Any-Any' - direct routes to cardholder data prohibited
[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found
[PCI-MEDIUM] PCI Req 10.2: Rule 'Allow-Any-Any' missing audit logging

--- Audit Summary ---
High Severity:         2
Medium Severity:       2
PCI Compliance High:   2
PCI Compliance Medium: 1
Total Issues:          7
Score:                 54/100
---------------------

Report saved to: report.pdf
```

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
- [x] Cisco FTD (Firepower Threat Defense) support
- [x] Clickable severity filters
- [x] CSV and SARIF export
- [x] Device tag system with auto-versioning
- [x] DISA STIG compliance framework
- [x] Docker Compose deployment
- [x] Email / webhook notifications for scheduled audit findings
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
- [ ] API key authentication with session management
- [ ] Fernet encryption for stored credentials
- [ ] CSRF protection (Flask-WTF)
- [ ] Multi-factor SSH authentication (key-based)
- [ ] REST API for CI/CD pipeline integration

---

## Support the Project

Flintlock is free and open source. If it's saved you time or caught something in your configs, consider buying me a coffee — it goes directly toward keeping this maintained and adding new features.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white&style=for-the-badge)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Buy%20me%20a%20coffee-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white&style=for-the-badge)](https://ko-fi.com/shamrock13)

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
