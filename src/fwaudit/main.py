import typer
import logging

from loguru import logger
logger.disable("ciscoconfparse")

from compliance import check_cis_compliance, check_pci_compliance, check_nist_compliance

from ciscoconfparse import CiscoConfParse

from paloalto import audit_paloalto

from reporter import generate_report

app = typer.Typer()

def check_any_any(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit.*any any"):
        findings.append(f"[HIGH] Overly permissive rule found: {rule.text}")
    return findings
def check_missing_logging(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[MEDIUM] Permit rule missing logging: {rule.text}")
    return findings
def check_deny_all(parse):
    findings = []
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[HIGH] No explicit deny-all rule found at end of ACL")
    return findings
def check_redundant_rules(parse):
    findings = []
    seen = []
    for rule in parse.find_objects(r"access-list.*permit"):
        # Strip the line down to core components to compare
        text = rule.text.strip().lower()
        # Remove 'log' from end for comparison purposes
        text_clean = text.replace(" log", "").strip()
        if text_clean in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: {rule.text}")
        else:
            seen.append(text_clean)
    return findings

@app.command()
def audit(
    file: str = typer.Option(None, "--file", "-f", help="Path to firewall config file"),
    vendor: str = typer.Option(None, "--vendor", "-v", help="Firewall vendor: paloalto, asa, pfsense"),
    compliance: str = typer.Option(None, "--compliance", "-c", help="Compliance framework: cis, pci, nist"),
    report: bool = typer.Option(False, "--report", "-r", help="Export PDF report")
):
    """FWAudit - Firewall configuration auditing tool"""

    if not file or not vendor:
        typer.echo("FWAudit v0.1")
        typer.echo("Usage: python3 src/fwaudit/main.py --file config.txt --vendor asa")
        raise typer.Exit()

    typer.echo(f"\nFWAudit v0.1 — Starting audit of {file} ({vendor})\n")

    if vendor == "asa":
        parse = CiscoConfParse(file, ignore_blank_lines=False)
        findings = []
        findings += check_any_any(parse)
        findings += check_missing_logging(parse)
        findings += check_deny_all(parse)
        findings += check_redundant_rules(parse)
    
        if findings:
            for f in findings:
                typer.echo(f)
        else:
            typer.echo("[PASS] No issues found")
        
        if compliance:
            typer.echo(f"\n--- {compliance.upper()} Compliance Checks ---")
            if compliance == "cis":
                cf = check_cis_compliance(parse)
            elif compliance == "pci":
                cf = check_pci_compliance(parse)
            elif compliance == "nist":
                cf = check_nist_compliance(parse)
            else:
                cf = []
                typer.echo(f"Unknown framework: {compliance}. Use cis, pci, or nist")

        for f in cf:
            typer.echo(f)
        findings += cf

        if report:
            output = generate_report(findings, file, vendor, compliance)
            typer.echo(f"\n📄 Report saved to: {output}")

        high = [f for f in findings if "[HIGH]" in f and "PCI" not in f and "CIS" not in f and "NIST" not in f]
        medium = [f for f in findings if "[MEDIUM]" in f and "PCI" not in f and "CIS" not in f and "NIST" not in f]
        pci_high = [f for f in findings if "PCI-HIGH" in f]
        pci_medium = [f for f in findings if "PCI-MEDIUM" in f]
        cis_high = [f for f in findings if "CIS-HIGH" in f]
        cis_medium = [f for f in findings if "CIS-MEDIUM" in f]
        nist_high = [f for f in findings if "NIST-HIGH" in f]
        nist_medium = [f for f in findings if "NIST-MEDIUM" in f]

        typer.echo(f"\n--- Audit Summary ---")
        typer.echo(f"High Severity:         {len(high)}")
        typer.echo(f"Medium Severity:       {len(medium)}")
        if pci_high or pci_medium:
            typer.echo(f"PCI Compliance High:   {len(pci_high)}")
            typer.echo(f"PCI Compliance Medium: {len(pci_medium)}")
        if cis_high or cis_medium:
            typer.echo(f"CIS Compliance High:   {len(cis_high)}")
            typer.echo(f"CIS Compliance Medium: {len(cis_medium)}")
        if nist_high or nist_medium:
            typer.echo(f"NIST Compliance High:  {len(nist_high)}")
            typer.echo(f"NIST Compliance Medium:{len(nist_medium)}")
        typer.echo(f"Total Issues:          {len(findings)}")
        typer.echo(f"---------------------")
    
    elif vendor == "paloalto":
        findings = audit_paloalto(file)

        if findings:
            for f in findings:
                typer.echo(f)
        else:
            typer.echo("[PASS] No issues found")

        if compliance:
            typer.echo(f"\n--- {compliance.upper()} Compliance Checks ---")
            from paloalto import parse_paloalto
            from compliance import check_cis_compliance_pa, check_pci_compliance_pa, check_nist_compliance_pa
            rules, _ = parse_paloalto(file)
            if compliance == "cis":
                cf = check_cis_compliance_pa(rules)
            elif compliance == "pci":
                cf = check_pci_compliance_pa(rules)
            elif compliance == "nist":
                cf = check_nist_compliance_pa(rules)
            else:
                cf = []
                typer.echo(f"Unknown framework: {compliance}. Use cis, pci, or nist")
            for f in cf:
                typer.echo(f)
            findings += cf
            if report:
                output = generate_report(findings, file, vendor, compliance)
                typer.echo(f"\n📄 Report saved to: {output}")

            high = [f for f in findings if "[HIGH]" in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
            medium = [f for f in findings if "[MEDIUM]" in f and not any(x in f for x in ["PCI-", "CIS-", "NIST-"])]
            pci_high = [f for f in findings if "PCI-HIGH" in f]
            pci_medium = [f for f in findings if "PCI-MEDIUM" in f]
            cis_high = [f for f in findings if "CIS-HIGH" in f]
            cis_medium = [f for f in findings if "CIS-MEDIUM" in f]
            nist_high = [f for f in findings if "NIST-HIGH" in f]
            nist_medium = [f for f in findings if "NIST-MEDIUM" in f]

            typer.echo(f"\n--- Audit Summary ---")
            typer.echo(f"High Severity:         {len(high)}")
            typer.echo(f"Medium Severity:       {len(medium)}")
            if pci_high or pci_medium:
                typer.echo(f"PCI Compliance High:   {len(pci_high)}")
                typer.echo(f"PCI Compliance Medium: {len(pci_medium)}")
            if cis_high or cis_medium:
                typer.echo(f"CIS Compliance High:   {len(cis_high)}")
                typer.echo(f"CIS Compliance Medium: {len(cis_medium)}")
            if nist_high or nist_medium:
                typer.echo(f"NIST Compliance High:  {len(nist_high)}")
                typer.echo(f"NIST Compliance Medium:{len(nist_medium)}")
            typer.echo(f"Total Issues:          {len(findings)}")
            typer.echo(f"---------------------")

if __name__ == "__main__":
    app()