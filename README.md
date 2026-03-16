# 🔥 Flintlock

**Flintlock** is a firewall configuration auditing tool with a web UI and CLI. It detects common security misconfigurations, generates scored severity reports, compares configs across time, and connects directly to live devices via SSH. Deployable in minutes via Docker Compose.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Flintlock-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

| Vendor | Config Format | Status |
|---|---|---|
| AWS Security Groups | JSON | ✅ Supported |
| Azure NSG | JSON | ✅ Supported |
| Cisco | Text | ✅ Supported |
| Fortinet | Text | ✅ Supported |
| Palo Alto Networks | XML | ✅ Supported |
| pfSense | XML | ✅ Supported |

---

## Features

### Free (Open Source)
- **Web UI** — browser-based interface, no terminal required
- **Auto-detect vendor** — Flintlock identifies the vendor from file content automatically
- **Security scoring** — each audit produces a 0–100 score: `100 − (HIGH × 10) − (MEDIUM × 3)`
- **Category badges** — findings are tagged by type (Exposure, Protocol, Logging, Hygiene, Redundancy)
- **Remediation guidance** — every finding includes a plain-English fix recommendation
- **Device tag system** — name your devices (e.g. ASA01, FortiGate-HQ) for auto-versioned history tracking
- **Live SSH connection** — connect directly to a Cisco, Fortinet, or Palo Alto device to pull and audit its running config in real time
- **Rule change diff** — upload two configs of the same vendor to see exactly what was added, removed, and unchanged
- **Audit History** — save audit results and browse them later with vendor filter, sort, and device search
- **Score Trends chart** — visualize security score over time per device, with vendor and device tag filters
- **Archival reviews** — select any two saved audits and compare them: see resolved findings, new issues, and delta scores
- **Activity Log** — full record of every audit, SSH attempt, and config diff, including failures
- **PDF report export** — download a color-coded findings report
- Detect overly permissive any/any rules
- Detect permit rules missing logging
- Detect missing deny-all rule
- Detect redundant/shadowed rules
- Cisco: Telnet management enabled, unrestricted ICMP permit rules
- Palo Alto: any-application rules, rules missing security profiles, rules missing descriptions
- Fortinet: disabled policies, all-service rules, insecure services (Telnet/HTTP/FTP), unnamed policies, internet-facing policies missing UTM profiles
- pfSense: WAN-facing any-source pass rules, rules missing descriptions
- AWS: open ingress to 0.0.0.0/0, default SG with active rules, wide port ranges (>100 ports)
- Azure: inbound Any rules, overly permissive NSG rules, broad port ranges (>100 ports)
- **PDF report export** — color-coded findings report with score box, category labels, and remediation text
- Light / dark / auto theme (saved automatically)
- CLI output with audit summary
- Docker Compose deployment

### Paid (License Required)
- CIS Benchmark compliance checks
- PCI-DSS compliance checks
- NIST SP 800-41 compliance checks
- Specific control references (e.g. PCI Req 1.3, NIST AC-6)

> 💳 **Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/flintlock)**

---

## Installation

### Option 1 — Docker Compose (Recommended)

The fastest way to get Flintlock running. No Python environment setup required.

**Requirements:** Docker Desktop or OrbStack

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
docker compose up --build
```

Open **http://localhost:8080** in your browser.

Uploaded reports, audit history, activity log, and your license key are all persisted in a Docker volume across restarts. To set a custom secret, create a `.env` file in the project root:

```
FWAUDIT_SECRET=your-secret-here
```

To stop:
```bash
docker compose down
```

---

### Option 2 — Local Python

**Requirements:** Python 3.8+, and `paramiko` for live SSH support

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

The web interface provides the full feature set without needing a terminal. It is organized into five tabs.

### File Audit
1. Enter a **Device Tag** to name this device (e.g. ASA01, FortiGate-HQ) — used for versioned history and trend tracking
2. Upload a firewall config file (text, XML, or JSON)
3. Select a vendor or leave on **Auto-detect**
4. Optionally select a compliance framework (license required)
5. Check **Generate PDF Report** and/or **Save to Audit History** as needed
6. Click **Run Audit**

Results show a security score, severity counts, category-tagged findings, and remediation guidance. Click the summary boxes to filter by severity.

### Compare Configs
Upload two configs of the same vendor to see a line-by-line diff of what changed — rules added, removed, and unchanged. Auto-detects vendor from the baseline file.

### Live Connect
Connect directly to a device over SSH to pull and audit its running configuration without touching a file. Supported vendors: **Cisco**, **Fortinet**, **Palo Alto Networks**.

- Credentials are used only for the single connection and are never stored
- Successful audits are automatically saved to Audit History
- Failed connections are recorded in the Activity Log only

### Audit History
Browse all saved audits. Filter by vendor, sort by date or issue count, and search by device tag or filename. Select any two entries and click **Compare Selected** to see a full diff of findings — including resolved issues, new issues, and HIGH/MEDIUM/Total deltas. The older audit is always used as the baseline regardless of selection order.

The **Score Trends** chart below the history list plots each device's security score over time. Filter by vendor and device tag to focus on a specific device.

### Activity Log
A complete record of every action taken in Flintlock — file audits, SSH connections, and config diffs — including failures. Shows action type, vendor, timestamp, and error message for failed attempts. Entries can be deleted individually or cleared in bulk.

---

## CLI Usage

### Basic audit (free)

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

### With compliance checks (license required)

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --compliance pci
```

### Export PDF report (free — no license required)

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --report
```

### Supported vendors

```
--vendor asa
--vendor paloalto
--vendor fortinet
--vendor pfsense
```

### Supported compliance frameworks

```
--compliance cis
--compliance pci
--compliance nist
```

### License activation (CLI)

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

📄 Report saved to: report.pdf
```

---

## Checks Performed

| Check | Severity | Vendors | Tier |
|---|---|---|---|
| Any/any permit rules | HIGH | All | Free |
| Missing deny-all rule | HIGH | Cisco, Palo Alto, pfSense | Free |
| Permit rules missing logging | MEDIUM | Cisco, Palo Alto | Free |
| Redundant/shadowed rules | MEDIUM | All | Free |
| Telnet management enabled | MEDIUM | Cisco | Free |
| Unrestricted ICMP permit | MEDIUM | Cisco | Free |
| Any-application rules | HIGH | Palo Alto | Free |
| Rules missing security profile | MEDIUM | Palo Alto | Free |
| Rules missing description | MEDIUM | Palo Alto, pfSense | Free |
| Disabled policies | MEDIUM | Fortinet | Free |
| All-service rules | MEDIUM | Fortinet | Free |
| Insecure services (Telnet/HTTP/FTP) | MEDIUM | Fortinet | Free |
| Unnamed policies | MEDIUM | Fortinet | Free |
| Internet-facing policy missing UTM | HIGH | Fortinet | Free |
| WAN-facing any-source pass rule | HIGH | pfSense | Free |
| Open ingress 0.0.0.0/0 | HIGH | AWS | Free |
| Default SG with active rules | MEDIUM | AWS | Free |
| Wide port range (>100 ports) | MEDIUM | AWS, Azure | Free |
| Inbound Any rules | HIGH | Azure | Free |
| Overly permissive NSG rules | MEDIUM | Azure | Free |
| PDF report export | — | All | Free |
| CIS Benchmark controls | HIGH/MEDIUM | Cisco, PA, Fortinet, pfSense | Paid |
| PCI-DSS requirements | HIGH/MEDIUM | Cisco, PA, Fortinet, pfSense | Paid |
| NIST SP 800-41 controls | HIGH/MEDIUM | Cisco, PA, Fortinet, pfSense | Paid |

---

## Roadmap

- [x] Web UI with file upload and inline results
- [x] Docker Compose deployment
- [x] Auto vendor detection
- [x] Clickable severity filters
- [x] Light / dark / auto theme
- [x] PDF report redesign (score box, categories, remediation)
- [x] Live SSH connection mode
- [x] Fortinet v2 checks
- [x] AWS Security Group support
- [x] Azure NSG support
- [x] Rule change diff (compare two configs)
- [x] Activity Log (usage monitoring)
- [x] Archival reviews (compare historical audits)
- [x] Security scoring (0–100 per audit)
- [x] Category badges and remediation guidance
- [x] Score Trends chart with device tag and vendor filters
- [x] Device tag system with auto-versioning
- [ ] Settings tab (global defaults)
- [ ] Scheduled audits
- [ ] Multi-device bulk audit
- [ ] Cisco FTD (NGFW) support

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
