import typer
from rich.console import Console
from .license import activate_license, check_license, deactivate_license
from .reporter import generate_report
from .audit_engine import (
    _build_summary,
    _finding_msg,
    run_compliance_checks,
    run_vendor_audit,
)

_console = Console()
app = typer.Typer()

_VALID_VENDORS = [
    "asa",
    "ftd",
    "paloalto",
    "fortinet",
    "pfsense",
    "aws",
    "azure",
    "gcp",
    "juniper",
    "iptables",
    "nftables",
]
_VALID_FRAMEWORKS = ["cis", "pci", "nist", "hipaa", "soc2", "stig"]


@app.command()
def audit(
    file: str = typer.Option(None, "--file", "-f", help="Path to firewall config file"),
    vendor: str = typer.Option(
        None,
        "--vendor",
        "-v",
        help="Firewall vendor: asa, ftd, paloalto, fortinet, pfsense, aws, azure, gcp, juniper, iptables, nftables",
    ),
    compliance: str = typer.Option(
        None,
        "--compliance",
        "-c",
        help="Compliance framework: cis, pci, nist, hipaa, soc2, stig",
    ),
    report: bool = typer.Option(False, "--report", "-r", help="Export PDF report"),
    activate: str = typer.Option(None, "--activate", help="Activate a license key"),
    deactivate: bool = typer.Option(
        False, "--deactivate", help="Deactivate current license"
    ),
):
    """Cashel - Firewall configuration auditing tool"""

    if activate:
        success, message = activate_license(activate)
        typer.echo(message)
        raise typer.Exit()

    if deactivate:
        success, message = deactivate_license()
        typer.echo(message)
        raise typer.Exit()

    if not file or not vendor:
        typer.echo("Cashel v1.0")
        typer.echo("Usage: python3 src/cashel/main.py --file config.txt --vendor asa")
        raise typer.Exit()

    if vendor not in _VALID_VENDORS:
        typer.echo(f"Unknown vendor: {vendor}. Use: {', '.join(_VALID_VENDORS)}")
        raise typer.Exit(1)

    if compliance and compliance not in _VALID_FRAMEWORKS:
        typer.echo(
            f"Unknown framework: {compliance}. Use: {', '.join(_VALID_FRAMEWORKS)}"
        )
        raise typer.Exit(1)

    typer.echo(f"\nCashel v1.0 — Starting audit of {file} ({vendor})\n")

    findings, parse, extra_data = run_vendor_audit(vendor, file)

    if findings:
        for f in findings:
            typer.echo(_finding_msg(f))
    else:
        typer.echo("[PASS] No issues found")

    if compliance:
        licensed, message = check_license()
        if not licensed:
            typer.echo("\n⚠️  Compliance checks require a valid license.")
            _console.print(
                "   Purchase a license at: [link=https://shamrock13.gumroad.com/l/cashel]"
                "https://shamrock13.gumroad.com/l/cashel[/link]"
            )
            typer.echo(
                "   Once purchased, activate your key: cashel --activate YOUR-LICENSE-KEY"
            )
            raise typer.Exit()
        typer.echo(f"\n--- {compliance.upper()} Compliance Checks ---")
        cf = run_compliance_checks(vendor, compliance, parse, extra_data, file)
        for f in cf:
            typer.echo(_finding_msg(f) if isinstance(f, dict) else f)
        findings = list(findings) + list(cf)

    if report:
        output = generate_report(findings, file, vendor, compliance)
        typer.echo(f"\n📄 Report saved to: {output}")

    s = _build_summary(findings)
    typer.echo("\n--- Audit Summary ---")
    typer.echo(f"High Severity:         {s['high']}")
    typer.echo(f"Medium Severity:       {s['medium']}")
    if s["pci_high"] or s["pci_medium"]:
        typer.echo(f"PCI Compliance High:   {s['pci_high']}")
        typer.echo(f"PCI Compliance Medium: {s['pci_medium']}")
    if s["cis_high"] or s["cis_medium"]:
        typer.echo(f"CIS Compliance High:   {s['cis_high']}")
        typer.echo(f"CIS Compliance Medium: {s['cis_medium']}")
    if s["nist_high"] or s["nist_medium"]:
        typer.echo(f"NIST Compliance High:  {s['nist_high']}")
        typer.echo(f"NIST Compliance Medium:{s['nist_medium']}")
    if s["hipaa_high"] or s["hipaa_medium"]:
        typer.echo(f"HIPAA Compliance High: {s['hipaa_high']}")
        typer.echo(f"HIPAA Compliance Medium:{s['hipaa_medium']}")
    if s["soc2_high"] or s["soc2_medium"]:
        typer.echo(f"SOC2 Compliance High:  {s['soc2_high']}")
        typer.echo(f"SOC2 Compliance Medium:{s['soc2_medium']}")
    if s["stig_cat_i"] or s["stig_cat_ii"] or s["stig_cat_iii"]:
        typer.echo(f"STIG CAT I:            {s['stig_cat_i']}")
        typer.echo(f"STIG CAT II:           {s['stig_cat_ii']}")
        typer.echo(f"STIG CAT III:          {s['stig_cat_iii']}")
    typer.echo(f"Total Issues:          {s['total']}")
    typer.echo("---------------------")


if __name__ == "__main__":
    app()
