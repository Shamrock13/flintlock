"""Remediation Plan Generator — structured fix plans from audit findings.

Given a list of enriched findings (severity, category, message, remediation),
produces a prioritized, grouped remediation plan with vendor-specific CLI
commands where available.  Output formats: dict (for JSON/UI), markdown, and
PDF.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# ── Effort classification ────────────────────────────────────────────────────

_QUICK_KEYWORDS = (
    "set logtraffic",
    "log-end",
    "logging",
    "iptables -P",
    "iptables -A",
    "nft add rule",
    "set snmp",
    "set service",
    "set ntp",
    "log enable",
)

_CHANGE_WINDOW_KEYWORDS = (
    "deny-all",
    "deny ip any any",
    "remove",
    "delete",
    "replace",
    "disable",
    "restrict",
    "redesign",
    "migrate",
)


def _estimate_effort(remediation: str) -> str:
    """Classify remediation effort as 'quick-fix', 'moderate', or 'change-window'."""
    lower = remediation.lower()
    if any(k in lower for k in _QUICK_KEYWORDS):
        return "quick-fix"
    if any(k in lower for k in _CHANGE_WINDOW_KEYWORDS):
        return "change-window"
    return "moderate"


# ── Vendor CLI command generation ────────────────────────────────────────────

_CLI_GENERATORS: dict[str, Any] = {}


def _cli_asa(finding: dict) -> str | None:
    """Generate suggested Cisco ASA CLI commands."""
    msg = finding["message"].lower()
    cat = finding.get("category", "")

    if "deny-all" in msg or "no explicit deny" in msg:
        return "access-list <ACL_NAME> deny ip any any log"
    if "missing logging" in msg or cat == "logging":
        rule_match = re.search(r":\s*(.+)", finding["message"])
        if rule_match:
            rule = rule_match.group(1).strip()
            if "log" not in rule.lower():
                return f"{rule} log"
    if "telnet" in msg:
        return "no telnet 0.0.0.0 0.0.0.0 inside\nno telnet 0.0.0.0 0.0.0.0 outside"
    if "any any" in msg and "permit" in msg:
        return (
            "! Remove or restrict the overly permissive rule:\n"
            "no access-list <ACL_NAME> permit ip any any\n"
            "! Replace with specific source/destination:\n"
            "access-list <ACL_NAME> permit ip <SRC_NET> <SRC_MASK> <DST_NET> <DST_MASK>"
        )
    if "icmp" in msg and "unrestrict" in msg:
        return (
            "access-list <ACL_NAME> permit icmp <TRUSTED_SRC> <MASK> any echo\n"
            "access-list <ACL_NAME> deny icmp any any"
        )
    return None


def _cli_fortinet(finding: dict) -> str | None:
    """Generate suggested Fortinet FortiGate CLI commands."""
    msg = finding["message"].lower()
    cat = finding.get("category", "")

    # Extract policy name from message like "rule 'MyPolicy'"
    name_match = re.search(r"(?:rule|policy)\s+'([^']+)'", finding["message"])
    policy_ref = name_match.group(1) if name_match else "<POLICY_ID>"

    if cat == "logging" or "missing logging" in msg:
        return (
            f"config firewall policy\n"
            f"  edit {policy_ref}\n"
            f"    set logtraffic all\n"
            f"  next\n"
            f"end"
        )
    if "security profile" in msg or "utm" in msg:
        return (
            f"config firewall policy\n"
            f"  edit {policy_ref}\n"
            f"    set av-profile default\n"
            f"    set ips-sensor default\n"
            f"    set application-list default\n"
            f"    set webfilter-profile default\n"
            f"  next\n"
            f"end"
        )
    if "any" in msg and "permissive" in msg:
        return (
            f"config firewall policy\n"
            f"  edit {policy_ref}\n"
            f"    set srcaddr <SPECIFIC_ADDR_OBJ>\n"
            f"    set dstaddr <SPECIFIC_ADDR_OBJ>\n"
            f"  next\n"
            f"end"
        )
    if "insecure service" in msg or "telnet" in msg or "ftp" in msg:
        return (
            f"config firewall policy\n"
            f"  edit {policy_ref}\n"
            f"    unset service TELNET FTP TFTP\n"
            f"    set service SSH HTTPS SFTP\n"
            f"  next\n"
            f"end"
        )
    return None


def _cli_iptables(finding: dict) -> str | None:
    """Generate suggested iptables CLI commands."""
    msg = finding["message"].lower()

    if "default policy accept" in msg:
        chain_match = re.search(r"chain '(\w+)'", msg) or re.search(
            r"'(\w+)' has default", msg
        )
        chain = chain_match.group(1) if chain_match else "INPUT"
        return f"iptables -P {chain} DROP"
    if "no log target" in msg or "no log" in msg:
        chain = "INPUT"
        if "forward" in msg:
            chain = "FORWARD"
        return f'iptables -A {chain} -j LOG --log-prefix "[{chain}] " --log-level 4'
    if "ssh" in msg and "0.0.0.0" in msg:
        return (
            "iptables -D INPUT -p tcp --dport 22 -j ACCEPT\n"
            "iptables -A INPUT -s <TRUSTED_CIDR> -p tcp --dport 22 -j ACCEPT"
        )
    if "icmp" in msg and ("unrestrict" in msg or "rate" in msg):
        return (
            "iptables -A INPUT -p icmp --icmp-type echo-request "
            "-m limit --limit 10/sec -j ACCEPT\n"
            "iptables -A INPUT -p icmp -j DROP"
        )
    if "forward" in msg and "unrestrict" in msg:
        return "iptables -P FORWARD DROP"
    return None


def _cli_nftables(finding: dict) -> str | None:
    """Generate suggested nftables CLI commands."""
    msg = finding["message"].lower()

    if "default policy accept" in msg or "policy accept" in msg:
        chain = "input"
        if "forward" in msg:
            chain = "forward"
        return f"nft chain inet filter {chain} '{{ policy drop; }}'"
    if "no log" in msg or "logging" in msg:
        return 'nft add rule inet filter input log prefix "[INPUT] " accept'
    if "ssh" in msg and ("0.0.0.0" in msg or "any" in msg):
        return (
            "nft add rule inet filter input ip saddr <TRUSTED_CIDR> tcp dport 22 accept"
        )
    return None


def _cli_juniper(finding: dict) -> str | None:
    """Generate suggested Juniper SRX CLI commands."""
    msg = finding["message"].lower()

    if "any any" in msg or "permissive" in msg:
        return (
            "set security policies from-zone <SRC> to-zone <DST> policy <NAME>\n"
            "  match source-address <SPECIFIC_ADDR>\n"
            "  match destination-address <SPECIFIC_ADDR>"
        )
    if "logging" in msg or "session" in msg:
        return (
            "set security policies from-zone <SRC> to-zone <DST> policy <NAME>\n"
            "  then log session-init session-close"
        )
    if "telnet" in msg:
        return "delete system services telnet"
    if "snmp" in msg and ("v1" in msg or "v2" in msg):
        return (
            "delete snmp community <COMMUNITY>\n"
            "set snmp v3 usm local-engine user <USER> authentication-sha ..."
        )
    return None


def _cli_paloalto(finding: dict) -> str | None:
    """Generate suggested Palo Alto CLI commands."""
    msg = finding["message"].lower()

    name_match = re.search(r"rule '([^']+)'", finding["message"])
    rule_ref = name_match.group(1) if name_match else "<RULE_NAME>"

    if "logging" in msg or "log-end" in msg:
        return f"set rulebase security rules {rule_ref} log-end yes"
    if "any application" in msg:
        return f"set rulebase security rules {rule_ref} application <APP_NAME>"
    if "security profile" in msg:
        return (
            f"set rulebase security rules {rule_ref} profile-setting "
            f"group <SECURITY_PROFILE_GROUP>"
        )
    if "any" in msg and "permissive" in msg:
        return (
            f"set rulebase security rules {rule_ref} source <SPECIFIC_ADDR>\n"
            f"set rulebase security rules {rule_ref} destination <SPECIFIC_ADDR>"
        )
    return None


_CLI_GENERATORS = {
    "asa": _cli_asa,
    "ftd": _cli_asa,  # FTD uses same CLI syntax as ASA
    "fortinet": _cli_fortinet,
    "iptables": _cli_iptables,
    "nftables": _cli_nftables,
    "juniper": _cli_juniper,
    "paloalto": _cli_paloalto,
}

# Vendors where we only provide guidance (no CLI generation)
_GUIDANCE_ONLY = {"aws", "azure", "gcp", "pfsense"}


# ── Plan builder ─────────────────────────────────────────────────────────────

_CATEGORY_ORDER = [
    "exposure",
    "protocol",
    "logging",
    "hygiene",
    "redundancy",
    "compliance",
]
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_CATEGORY_LABELS = {
    "exposure": "Access Control & Exposure",
    "protocol": "Protocol Security",
    "logging": "Logging & Visibility",
    "hygiene": "Configuration Hygiene",
    "redundancy": "Rule Cleanup",
    "compliance": "Compliance Gaps",
}


def _consolidate_findings(findings: list[dict]) -> list[dict]:
    """Group related findings that share a common fix.

    For example, multiple 'missing logging' findings on different rules
    can be consolidated into a single remediation step.
    """
    groups: dict[str, list[dict]] = {}
    ungrouped: list[dict] = []

    for f in findings:
        cat = f.get("category", "")
        sev = f.get("severity", "MEDIUM")
        key = f"{sev}:{cat}"

        # Consolidate logging findings
        if cat == "logging":
            groups.setdefault(key, []).append(f)
        # Consolidate redundancy findings
        elif cat == "redundancy":
            groups.setdefault(key, []).append(f)
        else:
            ungrouped.append(f)

    consolidated: list[dict] = list(ungrouped)

    for key, group in groups.items():
        if len(group) == 1:
            consolidated.append(group[0])
        else:
            sev, cat = key.split(":", 1)
            consolidated.append(
                {
                    "severity": sev,
                    "category": cat,
                    "message": f"[{sev}] {len(group)} rules require {cat} fixes (consolidated)",
                    "remediation": group[0].get("remediation", ""),
                    "_consolidated_count": len(group),
                    "_consolidated_items": [f["message"] for f in group],
                }
            )

    return consolidated


def generate_plan(
    findings: list[dict],
    vendor: str,
    filename: str = "",
    compliance: str | None = None,
    summary: dict | None = None,
) -> dict:
    """Build a structured remediation plan from audit findings.

    Returns a dict with the plan structure suitable for JSON serialization,
    markdown rendering, or PDF export.
    """
    if not findings:
        return {
            "filename": filename,
            "vendor": vendor,
            "compliance": compliance,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": summary or {},
            "total_steps": 0,
            "phases": [],
            "disclaimer": "",
        }

    # Filter to only dict findings (skip plain strings)
    enriched = [f for f in findings if isinstance(f, dict) and f.get("remediation")]

    # Consolidate related findings
    consolidated = _consolidate_findings(enriched)

    # Sort: severity first, then category order
    consolidated.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(f.get("severity", "MEDIUM"), 1),
            _CATEGORY_ORDER.index(f.get("category", "compliance"))
            if f.get("category", "compliance") in _CATEGORY_ORDER
            else 99,
        )
    )

    # Build phases grouped by category
    phases: list[dict] = []
    category_groups: dict[str, list[dict]] = {}
    for f in consolidated:
        cat = f.get("category", "other")
        category_groups.setdefault(cat, []).append(f)

    # Order phases by category priority
    step_num = 0
    cli_gen = _CLI_GENERATORS.get(vendor)
    has_cli = vendor not in _GUIDANCE_ONLY

    for cat_key in _CATEGORY_ORDER:
        group = category_groups.pop(cat_key, [])
        if not group:
            continue

        steps = []
        for f in group:
            step_num += 1
            effort = _estimate_effort(f.get("remediation", ""))

            step: dict[str, Any] = {
                "step": step_num,
                "severity": f["severity"],
                "effort": effort,
                "description": f["message"],
                "guidance": f.get("remediation", ""),
            }

            # Generate CLI commands if available
            if has_cli and cli_gen:
                cmd = cli_gen(f)
                if cmd:
                    step["suggested_commands"] = cmd

            # Include consolidated details if applicable
            if f.get("_consolidated_count"):
                step["consolidated_count"] = f["_consolidated_count"]
                step["consolidated_items"] = f["_consolidated_items"]

            steps.append(step)

        phases.append(
            {
                "phase": _CATEGORY_LABELS.get(cat_key, cat_key.title()),
                "category": cat_key,
                "steps": steps,
            }
        )

    # Handle any remaining categories not in the standard order
    for cat_key, group in category_groups.items():
        steps = []
        for f in group:
            step_num += 1
            effort = _estimate_effort(f.get("remediation", ""))
            step = {
                "step": step_num,
                "severity": f["severity"],
                "effort": effort,
                "description": f["message"],
                "guidance": f.get("remediation", ""),
            }
            if has_cli and cli_gen:
                cmd = cli_gen(f)
                if cmd:
                    step["suggested_commands"] = cmd
            steps.append(step)

        phases.append(
            {
                "phase": _CATEGORY_LABELS.get(cat_key, cat_key.title()),
                "category": cat_key,
                "steps": steps,
            }
        )

    has_commands = any("suggested_commands" in s for p in phases for s in p["steps"])

    return {
        "filename": filename,
        "vendor": vendor,
        "compliance": compliance,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary or {},
        "total_steps": step_num,
        "phases": phases,
        "disclaimer": (
            "Commands are SUGGESTED and must be reviewed by a qualified engineer "
            "before applying to production devices. Test in a maintenance window."
        )
        if has_commands
        else "",
    }


# ── Markdown export ──────────────────────────────────────────────────────────

_EFFORT_ICONS = {
    "quick-fix": "Quick Fix",
    "moderate": "Moderate",
    "change-window": "Change Window",
}


def plan_to_markdown(plan: dict) -> str:
    """Render a remediation plan as a markdown document."""
    lines = [
        "# Remediation Plan",
        "",
        f"**Device**: {plan['filename'] or 'N/A'}  ",
        f"**Vendor**: {plan['vendor']}  ",
    ]
    if plan.get("compliance"):
        lines.append(f"**Compliance**: {plan['compliance'].upper()}  ")
    lines.append(f"**Generated**: {plan['generated']}  ")
    lines.append(f"**Total Steps**: {plan['total_steps']}  ")

    summary = plan.get("summary", {})
    if summary:
        score = summary.get("score", "N/A")
        lines.extend(
            [
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Score | {score}/100 |",
                f"| High Severity | {summary.get('high', 0)} |",
                f"| Medium Severity | {summary.get('medium', 0)} |",
                f"| Total Findings | {summary.get('total', 0)} |",
            ]
        )

    if plan.get("disclaimer"):
        lines.extend(
            [
                "",
                f"> **Disclaimer**: {plan['disclaimer']}",
            ]
        )

    lines.append("")

    for phase in plan.get("phases", []):
        lines.extend(
            [
                "---",
                "",
                f"## {phase['phase']}",
                "",
            ]
        )

        for step in phase.get("steps", []):
            effort_label = _EFFORT_ICONS.get(step["effort"], step["effort"])
            sev = step["severity"]
            lines.append(f"### Step {step['step']}: [{sev}] {effort_label}")
            lines.append("")
            lines.append(f"**Finding**: {step['description']}")
            lines.append("")

            if step.get("consolidated_count"):
                lines.append(
                    f"*This step covers {step['consolidated_count']} related findings:*"
                )
                for item in step.get("consolidated_items", [])[:5]:
                    lines.append(f"  - {item}")
                if step["consolidated_count"] > 5:
                    lines.append(f"  - ... and {step['consolidated_count'] - 5} more")
                lines.append("")

            lines.append(f"**Guidance**: {step['guidance']}")
            lines.append("")

            if step.get("suggested_commands"):
                lines.append("**Suggested Commands**:")
                lines.append("```")
                lines.append(step["suggested_commands"])
                lines.append("```")
                lines.append("")

    return "\n".join(lines)


# ── PDF export ───────────────────────────────────────────────────────────────


def plan_to_pdf(plan: dict, output_path: str) -> str:
    """Render a remediation plan as a branded PDF.

    Reuses the CashelReport class from reporter.py for consistent branding.
    """
    from .reporter import (
        CashelReport,
        _sanitize,
        _draw_summary_boxes,
        _section_header,
        VENDOR_DISPLAY,
        _NAVY,
        _WHITE,
        _LIGHT_BG,
        _BORDER,
        _TEXT,
        _MUTED,
        _HIGH,
        _HIGH_BG,
        _MEDIUM,
        _MEDIUM_BG,
        _COMP,
        _PASS,
    )

    _EFFORT_COLORS = {
        "quick-fix": (26, 128, 85),  # green
        "moderate": (153, 102, 0),  # amber
        "change-window": (204, 34, 0),  # red
    }

    _CATEGORY_BAR_COLORS = {
        "exposure": _HIGH,
        "protocol": (170, 68, 255),
        "logging": _MEDIUM,
        "hygiene": _COMP,
        "redundancy": _MUTED,
        "compliance": _COMP,
    }

    class RemediationReport(CashelReport):
        def header(self):
            self.set_fill_color(*_NAVY)
            self.rect(0, 0, 210, 30, "F")
            self.set_text_color(*_WHITE)
            self.set_font("Helvetica", "B", 17)
            self.set_xy(12, 8)
            self.cell(120, 9, "Cashel")
            self.set_font("Helvetica", "", 8)
            self.set_text_color(180, 200, 235)
            self.set_xy(12, 19)
            self.cell(120, 6, "Remediation Plan")
            self.set_xy(0, 19)
            self.cell(
                198,
                6,
                f"Generated: {plan.get('generated', '')}",
                align="R",
            )
            self.set_fill_color(126, 174, 255)  # blue accent for remediation
            self.rect(0, 29.5, 210, 0.6, "F")
            self.set_y(36)

    pdf = RemediationReport()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Meta bar
    vendor_name = VENDOR_DISPLAY.get(plan["vendor"], plan["vendor"].upper())
    framework = plan["compliance"].upper() if plan.get("compliance") else "None"
    pdf.set_fill_color(*_LIGHT_BG)
    y = pdf.get_y()
    pdf.rect(10, y, 190, 10, "F")
    meta = f"Device: {plan.get('filename', 'N/A')}   |   Vendor: {vendor_name}   |   Framework: {framework}   |   Steps: {plan['total_steps']}"
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_MUTED)
    pdf.set_xy(13, y + 2)
    pdf.cell(184, 6, _sanitize(meta))
    pdf.set_y(y + 13)

    # Summary boxes
    summary = plan.get("summary", {})
    if summary:
        _draw_summary_boxes(
            pdf,
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("total", 0),
            score=summary.get("score"),
        )

    # Disclaimer
    if plan.get("disclaimer"):
        pdf.set_fill_color(255, 248, 230)
        pdf.set_draw_color(*_MEDIUM)
        y = pdf.get_y()
        pdf.set_line_width(0.4)
        pdf.rect(10, y, 190, 12, "FD")
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*_MEDIUM)
        pdf.set_xy(13, y + 2)
        pdf.multi_cell(184, 4, _sanitize(plan["disclaimer"]))
        pdf.set_y(y + 15)

    # Divider
    pdf.set_draw_color(*_BORDER)
    pdf.set_line_width(0.3)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    if not plan.get("phases"):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_PASS)
        pdf.cell(0, 8, "No remediation steps required — all checks passed.", align="C")
    else:
        for phase in plan["phases"]:
            bar_color = _CATEGORY_BAR_COLORS.get(phase["category"], _COMP)
            _section_header(pdf, phase["phase"], bar_color)

            for step in phase["steps"]:
                sev_color = _HIGH if step["severity"] == "HIGH" else _MEDIUM
                effort_color = _EFFORT_COLORS.get(step["effort"], _MUTED)
                bg = _HIGH_BG if step["severity"] == "HIGH" else _MEDIUM_BG

                # Estimate row height
                desc = step["description"]
                guidance = step.get("guidance", "")
                cmds = step.get("suggested_commands", "")
                char_w = 2.3
                inner_w = 183
                desc_lines = max(
                    1, (len(desc) + int(inner_w / char_w) - 1) // int(inner_w / char_w)
                )
                row_h: float = 14 + desc_lines * 4
                if guidance:
                    g_lines = max(
                        1,
                        (len(guidance) + int(inner_w / 2.0) - 1) // int(inner_w / 2.0),
                    )
                    row_h += g_lines * 3.8 + 2
                if cmds:
                    c_lines = cmds.count("\n") + 1
                    row_h += c_lines * 3.5 + 6

                y = pdf.get_y()
                if y + row_h > 272:
                    pdf.add_page()
                    y = pdf.get_y()

                # Step header bar
                pdf.set_fill_color(*bar_color)
                pdf.rect(10, y, 3, row_h, "F")
                pdf.set_fill_color(*bg)
                pdf.rect(13, y, 187, row_h, "F")

                cur_y = y + 2

                # Step number + severity + effort badges
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*sev_color)
                pdf.set_xy(15, cur_y)
                pdf.cell(20, 5, f"Step {step['step']}")

                pdf.set_font("Helvetica", "B", 6.5)
                pdf.set_xy(35, cur_y)
                pdf.cell(15, 5, f"[{step['severity']}]")

                pdf.set_text_color(*effort_color)
                pdf.set_font("Helvetica", "", 6.5)
                pdf.set_xy(50, cur_y)
                effort_label = _EFFORT_ICONS.get(step["effort"], step["effort"])
                pdf.cell(30, 5, effort_label)
                cur_y += 7

                # Finding description
                pdf.set_text_color(*_TEXT)
                pdf.set_font("Courier", "", 7)
                pdf.set_xy(15, cur_y)
                pdf.multi_cell(inner_w, 4, _sanitize(desc))
                cur_y = pdf.get_y() + 1

                # Guidance
                if guidance:
                    pdf.set_text_color(*_MUTED)
                    pdf.set_font("Helvetica", "", 6.5)
                    pdf.set_xy(17, cur_y)
                    pdf.multi_cell(inner_w - 4, 3.8, _sanitize("-> " + guidance))
                    cur_y = pdf.get_y() + 1

                # CLI commands
                if cmds:
                    pdf.set_fill_color(240, 240, 248)
                    cmd_y = cur_y
                    cmd_lines = cmds.count("\n") + 1
                    cmd_h = cmd_lines * 3.5 + 3
                    pdf.rect(17, cmd_y, inner_w - 4, cmd_h, "F")
                    pdf.set_text_color(60, 60, 100)
                    pdf.set_font("Courier", "", 6.5)
                    pdf.set_xy(19, cmd_y + 1.5)
                    pdf.multi_cell(inner_w - 8, 3.5, _sanitize(cmds))

                pdf.set_y(y + row_h + 2)

            pdf.ln(3)

    pdf.output(output_path)
    return output_path
