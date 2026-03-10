# 🔥 Flintlock

**Flintlock** is a firewall configuration auditing tool with both a web UI and CLI. It detects common security misconfigurations, generates scored severity reports, and optionally checks against compliance frameworks like CIS, PCI-DSS, and NIST. Deployable in minutes via Docker Compose.

---

## Supported Vendors

| Vendor | Config Format | Status |
|---|---|---|
| Cisco | Text | ✅ Supported |
| Palo Alto Networks | XML | ✅ Supported |
| Fortinet | Text | ✅ Supported |
| pfSense | XML | ✅ Supported |

---

## Features

### Free (Open Source)
- **Web UI** — browser-based interface, no terminal required
- **Auto-detect vendor** — upload a config and Flintlock identifies the vendor automatically
- Detect overly permissive any/any rules
- Detect permit rules missing logging
- Detect missing deny-all rule
- Detect redundant/shadowed rules
- Severity scoring (HIGH / MEDIUM)
- Results sorted high → medium, with clickable filters per severity
- **PDF report export** — download a color-coded findings report at any time
- Light and dark mode (preference saved automatically)
- CLI output with audit summary

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

Uploaded reports and your license key are persisted in a Docker volume across restarts. To set a custom license secret, create a `.env` file in the project root:

```
FWAUDIT_SECRET=your-secret-here
```

To stop:
```bash
docker compose down
```

---

### Option 2 — Local Python

**Requirements:** Python 3.8+

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

The web interface provides the full feature set without needing a terminal.

### Running an audit
1. Open **http://localhost:8080** (Docker) or **http://localhost:5000** (local)
2. Upload a firewall config file
3. Select a vendor or leave on **Auto-detect** — Flintlock will identify it from the file content
4. Optionally select a compliance framework (license required)
5. Check **Generate PDF Report** if you want a downloadable report
6. Click **Run Audit**

### Results
- Findings are displayed inline, sorted from highest to lowest severity
- Click the **High**, **Medium**, or **Total** summary boxes to filter the results list
- Click an active filter again to clear it
- If a PDF was generated, a download link appears below the findings

### License management
- The **Licensed / Unlicensed** badge in the top-right corner opens the license modal
- Enter your license key to activate; click Deactivate to remove it

### Light / Dark mode
- Click the ☀ / 🌙 button in the header to toggle — preference is saved automatically

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

### Export PDF report with compliance checks (license required)

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --compliance pci --report
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
Flintlock v1.0 — Starting audit of firewall.xml (paloalto)

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
---------------------

📄 Report saved to: report.pdf
```

---

## Checks Performed

| Check | Severity | Tier |
|---|---|---|
| Any/any permit rules | HIGH | Free |
| Missing deny-all rule | HIGH | Free |
| Permit rules missing logging | MEDIUM | Free |
| Redundant/shadowed rules | MEDIUM | Free |
| PDF report export | — | Free |
| CIS Benchmark controls | HIGH/MEDIUM | Paid |
| PCI-DSS requirements | HIGH/MEDIUM | Paid |
| NIST SP 800-41 controls | HIGH/MEDIUM | Paid |

---

## Roadmap

- [x] Web UI with file upload and inline results
- [x] Docker Compose deployment
- [x] Auto vendor detection
- [x] Clickable severity filters
- [x] Light / dark mode
- [x] PDF report redesign
- [ ] Live SSH/API connection mode
- [ ] Fortinet v2 checks
- [ ] AWS Security Group support
- [ ] Azure NSG support
- [ ] Rule change diff (compare two configs)

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
