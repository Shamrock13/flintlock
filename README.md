# 🔒 Flintlock

**Flintlock** is an open-source CLI tool for auditing firewall configurations across multiple vendors. It detects common security misconfigurations, generates scored reports, and optionally checks against compliance frameworks like CIS, PCI-DSS, and NIST.

---

## Supported Vendors

| Vendor | Config Format | Status |
|---|---|---|
| Cisco ASA | Text | ✅ Supported |
| Palo Alto | XML | ✅ Supported |
| Fortinet FortiGate | Text | ✅ Supported |
| pfSense | XML | ✅ Supported |

---

## Features

### Free (Open Source)
- Detect overly permissive any/any rules
- Detect permit rules missing logging
- Detect missing deny-all rule
- Detect redundant/shadowed rules
- Severity scoring (HIGH / MEDIUM)
- CLI output with audit summary

### Paid (License Required)
- CIS Benchmark compliance checks
- PCI-DSS compliance checks
- NIST SP 800-41 compliance checks
- PDF report export with grouped findings
- Specific control references (e.g. PCI Req 1.3, NIST AC-6)

> 💳 **Purchase a license at [Gumroad](https://saffronanthers.gumroad.com/l/flintlock)**

---

## Installation

### Requirements
- Python 3.8+
- pip

### Install dependencies

    pip3 install typer ciscoconfparse fpdf2

### Clone the repo

    git clone https://github.com/Shamrock13/flintlock.git
    cd flintlock

---

## Usage

### Basic audit (free)

    python3 src/flintlock/main.py --file config.txt --vendor asa

### With compliance checks (license required)

    python3 src/flintlock/main.py --file config.txt --vendor asa --compliance pci

### Export PDF report

    python3 src/flintlock/main.py --file config.txt --vendor asa --compliance pci --report

### Supported vendors

    --vendor asa
    --vendor paloalto
    --vendor fortinet
    --vendor pfsense

### Supported compliance frameworks

    --compliance cis
    --compliance pci
    --compliance nist

---

## License Activation

After purchasing a license, activate it with:

    python3 src/flintlock/main.py --activate YOUR-LICENSE-KEY

To deactivate:

    python3 src/flintlock/main.py --deactivate

---

## Example Output

    Flintlock v1.0 — Starting audit of firewall.xml (paloalto)

    [HIGH] Overly permissive rule 'Allow-Any-Any': source=any destination=any
    [MEDIUM] Permit rule 'Allow-Any-Any' missing logging
    [HIGH] No explicit deny-all rule found
    [MEDIUM] Redundant rule detected: 'Allow-Web-Duplicate'

    --- PCI Compliance Checks ---
    [PCI-HIGH] PCI Req 1.3: Rule 'Allow-Any-Any' - direct routes to cardholder data prohibited
    [PCI-MEDIUM] PCI Req 10.2: Rule 'Allow-Any-Any' missing audit logging
    [PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found

    --- Audit Summary ---
    High Severity:         2
    Medium Severity:       2
    PCI Compliance High:   2
    PCI Compliance Medium: 1
    Total Issues:          7
    ---------------------

    📄 Report saved to: report.pdf

---

## Checks Performed

| Check | Severity | Tier |
|---|---|---|
| Any/any permit rules | HIGH | Free |
| Permit rules missing logging | MEDIUM | Free |
| Missing deny-all rule | HIGH | Free |
| Redundant/shadowed rules | MEDIUM | Free |
| CIS Benchmark controls | HIGH/MEDIUM | Paid |
| PCI-DSS requirements | HIGH/MEDIUM | Paid |
| NIST SP 800-41 controls | HIGH/MEDIUM | Paid |

---

## Roadmap

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