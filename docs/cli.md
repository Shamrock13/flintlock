# Cashel — CLI Reference

## Basic usage

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa
```

## With compliance checks (license required)

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa --compliance pci
```

## Export PDF report

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa --report
```

## Supported `--vendor` values

```
--vendor cisco      Cisco ASA or FTD (auto-detected from config content)
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

Omit `--vendor` to use auto-detection.

## Supported `--compliance` values

```
--compliance cis     CIS Benchmark
--compliance hipaa   HIPAA Security Rule
--compliance nist    NIST SP 800-41
--compliance pci     PCI-DSS
--compliance soc2    SOC2
--compliance stig    DISA STIG
```

## License activation

```bash
# Activate
PYTHONPATH=src python -m cashel.main --activate YOUR-LICENSE-KEY

# Deactivate
PYTHONPATH=src python -m cashel.main --deactivate
```

## Example output

```
Cashel — Starting audit of firewall.xml (paloalto)

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

## SSH commands by vendor

These are the commands Cashel issues when connecting to a device via Live SSH.

| Vendor | Command issued |
|---|---|
| Cisco (ASA / FTD) | `terminal pager 0` → `show running-config` |
| Fortinet | `show full-configuration firewall policy` |
| iptables (Linux) | `iptables-save` (sudo fallback) |
| Juniper SRX | `set cli screen-length 0` → `show configuration \| display set` |
| nftables (Linux) | `nft list ruleset` (sudo fallback) |
| Palo Alto | `show config running` |
| pfSense | `cat /conf/config.xml` |
