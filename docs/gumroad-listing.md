# Gumroad Product Listing — Cashel

## Product Name
Cashel — Firewall Configuration Auditor

## Tagline
Audit any firewall in seconds. Find misconfigurations, score your security posture, and prove compliance — from the command line or a web browser.

## Description

Cashel is a firewall auditing tool that reads your configuration files and tells you exactly what's wrong — and how to fix it.

Point it at a Cisco ASA config, a Palo Alto XML export, an AWS Security Group dump, or a plain iptables ruleset. Within seconds you get a 0–100 security score, severity-ranked findings, and step-by-step remediation guidance. No cloud upload. No agent. No subscription required to use the core tool.

**What Cashel checks:**
- Any-any permit rules (the silent killer in every network)
- Missing ingress/egress logging
- Absent default-deny policies
- Redundant, shadowed, and duplicate rules
- Overly permissive administrative access
- Weak encryption and legacy protocol usage
- And more — vendor-specific checks per platform

**Supported platforms (11 vendor platforms):**
- Cisco ASA and FTD
- Palo Alto Networks (PAN-OS XML)
- Fortinet FortiGate
- pfSense
- Juniper SRX (set-style and hierarchical)
- iptables and nftables
- AWS Security Groups (JSON)
- Azure Network Security Groups (JSON)
- GCP VPC Firewall Rules (JSON)

**Multiple ways to audit:**
- Upload a config file via the web UI
- Bulk-audit multiple configs at once
- Connect live to a device over SSH (on-premises vendors; cloud platforms import JSON exports)
- Schedule recurring audits with Slack, Teams, or email alerts
- Run from the command line (`cashel --vendor asa --file myconfig.txt`)
- Call via REST API from your CI/CD pipeline (`POST /api/v1/audit`)

**Export everything:**
PDF reports, JSON, CSV, and SARIF (for GitHub Code Scanning and other SAST tools).

**Compare configs over time:**
Diff two configs side by side to see exactly what changed between audits — score deltas and new/resolved findings included (supported for Cisco ASA/FTD, Palo Alto, FortiGate, pfSense, AWS, and Azure).

---

**Compliance frameworks (paid license — included with purchase):**

Cashel maps findings to six frameworks so you can generate audit-ready evidence without manual cross-referencing:

- CIS Benchmark
- DISA STIG
- HIPAA
- NIST SP 800-41
- PCI-DSS
- SOC 2

One license key. No recurring fees. Activate offline.

---

**Who uses Cashel:**
- Homelab operators who want to know if their edge firewall is actually doing its job
- Freelance consultants and MSPs auditing client environments before handing over a report
- Security engineers who need compliance evidence without a six-figure GRC platform
- DevOps teams who want firewall audits in their CI/CD pipeline alongside code scans
- Enterprise security teams who need a lightweight second opinion alongside their SIEM

**Try before you buy:** [demo.cashel.app](https://demo.cashel.app) — full UI, real sample configs, no account required.

## Pricing Notes (fill in before publishing)
- Price: $_____
- License: Single-user perpetual (one key, unlimited audits)
- Delivery: Instant — license key emailed automatically after purchase
