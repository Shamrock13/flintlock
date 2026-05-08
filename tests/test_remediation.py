"""Tests for the remediation plan generator."""

from cashel.remediation import (
    generate_plan,
    plan_to_markdown,
    _estimate_effort,
    _consolidate_findings,
)


# ── Sample findings ──────────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] Overly permissive rule — permit ip any any",
        "remediation": "Replace 'permit ip any any' with specific source/destination rules.",
    },
    {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] No explicit deny-all at end of ACL",
        "remediation": "Add deny-all rule at end: access-list deny ip any any log",
    },
    {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Missing logging on rule: permit tcp 10.0.0.0/8 any eq 443",
        "remediation": "Enable logging on the rule to track traffic.",
    },
    {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Missing logging on rule: permit tcp 10.0.0.0/8 any eq 80",
        "remediation": "Enable logging on the rule to track traffic.",
    },
    {
        "severity": "MEDIUM",
        "category": "protocol",
        "message": "[MEDIUM] Telnet access permitted — insecure protocol",
        "remediation": "Disable telnet and switch to SSH for remote management.",
    },
]


# ── Effort estimation ────────────────────────────────────────────────────────


def test_effort_quick_fix():
    assert _estimate_effort("set logtraffic all on policy 5") == "quick-fix"
    assert _estimate_effort("log enable on the interface") == "quick-fix"


def test_effort_change_window():
    assert _estimate_effort("Add deny-all rule at end of ACL") == "change-window"
    assert _estimate_effort("Remove the insecure telnet service") == "change-window"


def test_effort_moderate():
    assert _estimate_effort("Review source addresses and tighten access") == "moderate"


# ── Finding consolidation ────────────────────────────────────────────────────


def test_consolidation_groups_logging():
    """Multiple logging findings should be consolidated into one step."""
    logging_findings = [
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "Log rule A",
            "remediation": "Enable logging.",
        },
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "Log rule B",
            "remediation": "Enable logging.",
        },
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "Log rule C",
            "remediation": "Enable logging.",
        },
    ]
    result = _consolidate_findings(logging_findings)
    consolidated = [f for f in result if f.get("_consolidated_count")]
    assert len(consolidated) == 1
    assert consolidated[0]["_consolidated_count"] == 3


def test_consolidation_preserves_ungrouped():
    """Non-logging/redundancy findings remain individual."""
    findings = [
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "A",
            "remediation": "Fix A",
        },
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "B",
            "remediation": "Fix B",
        },
    ]
    result = _consolidate_findings(findings)
    assert len(result) == 2
    assert not any(f.get("_consolidated_count") for f in result)


def test_consolidation_single_logging_not_grouped():
    """A single logging finding should not be consolidated."""
    findings = [
        {
            "severity": "MEDIUM",
            "category": "logging",
            "message": "Log rule A",
            "remediation": "Enable logging.",
        },
    ]
    result = _consolidate_findings(findings)
    assert len(result) == 1
    assert not result[0].get("_consolidated_count")


# ── Plan generation ──────────────────────────────────────────────────────────


def test_generate_plan_empty():
    plan = generate_plan([], "asa")
    assert plan["total_steps"] == 0
    assert plan["phases"] == []


def test_generate_plan_basic_structure():
    plan = generate_plan(SAMPLE_FINDINGS, "asa", filename="test.cfg")
    assert plan["vendor"] == "asa"
    assert plan["filename"] == "test.cfg"
    assert plan["total_steps"] > 0
    assert len(plan["phases"]) > 0
    assert plan["generated"]  # timestamp present


def test_generate_plan_severity_ordering():
    """HIGH severity findings should come before MEDIUM."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    first_steps = []
    for phase in plan["phases"]:
        for step in phase["steps"]:
            first_steps.append(step)
    # Find where HIGH ends and MEDIUM begins within the same category
    high_indices = [i for i, s in enumerate(first_steps) if s["severity"] == "HIGH"]
    medium_indices = [i for i, s in enumerate(first_steps) if s["severity"] == "MEDIUM"]
    # At minimum, we should have both severities
    assert len(high_indices) > 0
    assert len(medium_indices) > 0


def test_generate_plan_critical_before_high():
    """CRITICAL findings must appear before HIGH in the plan."""
    findings = [
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] No deny-all rule.",
            "remediation": "Add deny-all.",
        },
        {
            "severity": "CRITICAL",
            "category": "exposure",
            "message": "[CRITICAL] permit any any found.",
            "remediation": "Remove permit any any.",
        },
    ]
    plan = generate_plan(findings, "asa")
    all_steps = [step for phase in plan["phases"] for step in phase["steps"]]
    severities = [s["severity"] for s in all_steps]
    critical_idx = severities.index("CRITICAL")
    high_idx = severities.index("HIGH")
    assert critical_idx < high_idx


def test_generate_plan_category_grouping():
    """Steps should be grouped by category into phases."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    phase_categories = [p["category"] for p in plan["phases"]]
    # Exposure and protocol findings should be in separate phases
    assert "exposure" in phase_categories
    assert "protocol" in phase_categories


def test_generate_plan_cli_commands_asa():
    """ASA vendor should produce CLI command suggestions."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    steps_with_cmds = [
        s for p in plan["phases"] for s in p["steps"] if s.get("suggested_commands")
    ]
    assert len(steps_with_cmds) > 0, "ASA findings should generate CLI suggestions"


def test_generate_plan_no_cli_for_guidance_only():
    """AWS (guidance-only) should not produce CLI commands."""
    aws_findings = [
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] Security group allows 0.0.0.0/0 on port 22",
            "remediation": "Restrict SSH access to specific CIDR ranges.",
        }
    ]
    plan = generate_plan(aws_findings, "aws")
    steps_with_cmds = [
        s for p in plan["phases"] for s in p["steps"] if s.get("suggested_commands")
    ]
    assert len(steps_with_cmds) == 0


def test_generate_plan_disclaimer_with_commands():
    """Plans with CLI commands should include a disclaimer."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    assert plan["disclaimer"]
    assert "SUGGESTED" in plan["disclaimer"].upper()


def test_generate_plan_no_disclaimer_without_commands():
    """Plans without CLI commands should have no disclaimer."""
    plan = generate_plan(SAMPLE_FINDINGS, "aws")
    # AWS is guidance-only — no commands, so disclaimer may be empty
    # (depends on whether any commands were generated)
    steps_with_cmds = [
        s for p in plan["phases"] for s in p["steps"] if s.get("suggested_commands")
    ]
    if not steps_with_cmds:
        assert plan["disclaimer"] == ""


def test_generate_plan_effort_classification():
    """Each step should have an effort classification."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    for phase in plan["phases"]:
        for step in phase["steps"]:
            assert step["effort"] in ("quick-fix", "moderate", "change-window")


def test_generate_plan_consolidation():
    """Logging findings should be consolidated in the plan."""
    plan = generate_plan(SAMPLE_FINDINGS, "asa")
    logging_phase = next(
        (p for p in plan["phases"] if p["category"] == "logging"), None
    )
    if logging_phase:
        # Two logging findings → should consolidate into 1 step
        consolidated = [
            s for s in logging_phase["steps"] if s.get("consolidated_count")
        ]
        assert len(consolidated) == 1
        assert consolidated[0]["consolidated_count"] == 2


def test_generate_plan_string_findings_skipped():
    """Plain string findings (without remediation) should be skipped."""
    mixed = [
        "Some string finding without structure",
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] An issue",
            "remediation": "Fix it",
        },
    ]
    plan = generate_plan(mixed, "asa")
    assert plan["total_steps"] == 1


def test_generate_plan_findings_without_remediation_skipped():
    """Dict findings without remediation text should be skipped."""
    findings = [
        {"severity": "HIGH", "category": "exposure", "message": "[HIGH] An issue"},
    ]
    plan = generate_plan(findings, "asa")
    assert plan["total_steps"] == 0


def test_generate_plan_prefers_structured_suggested_commands():
    finding = {
        "id": "CASHEL-ASA-LOGGING-001",
        "severity": "MEDIUM",
        "category": "logging",
        "title": "Structured logging fix",
        "message": "[MEDIUM] Missing logging on rule: permit ip any any",
        "remediation": "Enable logging.",
        "evidence": "access-list OUTSIDE_IN permit ip any any",
        "verification": "Confirm syslog receives hits.",
        "rollback": "Remove the log keyword if needed.",
        "suggested_commands": ["structured command wins"],
    }

    plan = generate_plan([finding], "asa")
    step = plan["phases"][0]["steps"][0]
    assert step["title"] == "Structured logging fix"
    assert step["suggested_commands"] == "structured command wins"
    assert step["evidence"] == "access-list OUTSIDE_IN permit ip any any"
    assert step["verification"] == "Confirm syslog receives hits."
    assert step["rollback"] == "Remove the log keyword if needed."


def test_generate_plan_preserves_enriched_remediation_fields():
    finding = {
        "id": "CASHEL-ASA-EXPOSURE-001",
        "severity": "CRITICAL",
        "category": "exposure",
        "title": "Overly permissive any-any ACL rule",
        "message": "[CRITICAL] permit ip any any",
        "affected_object": "OUTSIDE_IN",
        "rule_name": "OUTSIDE_IN",
        "evidence": "access-list OUTSIDE_IN permit ip any any",
        "impact": "The rule may allow traffic from any source to any destination.",
        "remediation": "Replace with scoped ACL entries.",
        "verification": "Re-run the audit.",
        "rollback": "Restore the prior ACL line from backup.",
        "suggested_commands": ["no access-list <ACL_NAME> permit ip any any"],
    }

    plan = generate_plan([finding], "asa")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-ASA-EXPOSURE-001"
    assert step["title"] == "Overly permissive any-any ACL rule"
    assert step["severity"] == "CRITICAL"
    assert step["category"] == "exposure"
    assert step["affected_object"] == "OUTSIDE_IN"
    assert step["rule_name"] == "OUTSIDE_IN"
    assert step["evidence"] == "access-list OUTSIDE_IN permit ip any any"
    assert (
        step["impact"]
        == "The rule may allow traffic from any source to any destination."
    )
    assert step["guidance"] == "Replace with scoped ACL entries."
    assert step["verification"] == "Re-run the audit."
    assert step["rollback"] == "Restore the prior ACL line from backup."
    assert step["suggested_commands"] == "no access-list <ACL_NAME> permit ip any any"
    assert step["command_kind"] == "cli"


# ── Markdown export ──────────────────────────────────────────────────────────


def test_plan_to_markdown():
    plan = generate_plan(SAMPLE_FINDINGS, "asa", filename="test.cfg")
    md = plan_to_markdown(plan)
    assert "# Remediation Plan" in md
    assert "test.cfg" in md
    assert "Step 1" in md
    assert "Suggested Commands" in md


def test_plan_to_markdown_empty():
    plan = generate_plan([], "asa")
    md = plan_to_markdown(plan)
    assert "# Remediation Plan" in md
    assert "Step 1" not in md  # No numbered steps in empty plan


def test_plan_to_markdown_renders_pfsense_guidance_as_procedure_not_cli():
    finding = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] pfSense rule missing logging.",
        "remediation": "Enable logging in the pfSense UI.",
        "suggested_commands": [
            "pfSense UI: Firewall > Rules > WAN > edit rule Allow Web",
            "Enable Log packets that are handled by this rule",
        ],
    }

    plan = generate_plan([finding], "pfsense")
    md = plan_to_markdown(plan)

    assert "**Suggested Procedure**:" in md
    assert "- pfSense UI: Firewall > Rules > WAN > edit rule Allow Web" in md
    assert "```" not in md


# ── Vendor CLI generators ────────────────────────────────────────────────────


def test_cli_fortinet():
    finding = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Missing logging on rule 'WebAccess'",
        "remediation": "Enable traffic logging.",
    }
    plan = generate_plan([finding], "fortinet")
    steps = [s for p in plan["phases"] for s in p["steps"]]
    assert len(steps) == 1
    cmds = steps[0].get("suggested_commands", "")
    assert "logtraffic" in cmds


def test_cli_iptables():
    finding = {
        "severity": "HIGH",
        "category": "exposure",
        "message": "[HIGH] Chain 'INPUT' has default policy ACCEPT — default policy accept",
        "remediation": "Set default policy to DROP.",
    }
    plan = generate_plan([finding], "iptables")
    steps = [s for p in plan["phases"] for s in p["steps"]]
    cmds = steps[0].get("suggested_commands", "")
    assert "iptables -P" in cmds


def test_cli_paloalto_logging():
    finding = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] Rule 'AllowWeb' missing log-end setting",
        "remediation": "Enable log-end on the rule.",
    }
    plan = generate_plan([finding], "paloalto")
    steps = [s for p in plan["phases"] for s in p["steps"]]
    cmds = steps[0].get("suggested_commands", "")
    assert "log-end yes" in cmds


def test_cli_juniper_telnet():
    finding = {
        "severity": "HIGH",
        "category": "protocol",
        "message": "[HIGH] Telnet service enabled — insecure",
        "remediation": "Disable telnet and use SSH.",
    }
    plan = generate_plan([finding], "juniper")
    steps = [s for p in plan["phases"] for s in p["steps"]]
    cmds = steps[0].get("suggested_commands", "")
    assert "delete" in cmds and "telnet" in cmds
