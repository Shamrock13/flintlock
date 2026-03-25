# defusedxml prevents XXE (XML External Entity) injection attacks when parsing
# user-supplied firewall configs.  Drop-in replacement for ElementTree.
from defusedxml import ElementTree as ET


def _f(severity, category, message, remediation=""):
    """Build a structured finding dict."""
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


def parse_pfsense(filepath):
    """Parse a pfSense XML config and return firewall rules"""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return None, f"Failed to parse pfSense config: {e}"

    rules = []
    for rule in root.findall(".//filter/rule"):
        r = {
            "type": rule.findtext("type") or "pass",
            "interface": rule.findtext("interface") or "",
            "source": rule.findtext("source/any")
            or rule.findtext("source/address")
            or "specific",
            "destination": rule.findtext("destination/any")
            or rule.findtext("destination/address")
            or "specific",
            "protocol": rule.findtext("protocol") or "any",
            "log": rule.find("log") is not None,
            "descr": rule.findtext("descr") or "",
        }
        rules.append(r)

    return rules, None


def check_any_any_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=any destination=any",
                    "Restrict source and destination to specific hosts or networks. "
                    "Pass-all rules allow unrestricted traffic between all segments.",
                )
            )
    return findings


def check_missing_logging_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and not r["log"]:
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] Permit rule '{name}' missing logging",
                    "Enable logging on all pass rules to ensure permitted traffic is recorded "
                    "for audit trail, compliance, and incident response purposes.",
                )
            )
    return findings


def check_deny_all_pf(rules):
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if has_deny_all:
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found",
            "Add an explicit block-all rule at the bottom of the ruleset. "
            "pfSense has a default deny, but an explicit logged rule confirms the policy and aids monitoring.",
        )
    ]


def check_redundant_rules_pf(rules):
    findings = []
    seen = []
    for r in rules:
        name = r["descr"] or "unnamed"
        sig = (r["type"], r["source"], r["destination"], r["protocol"])
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Remove duplicate rules to keep the ruleset concise. "
                    "Duplicate rules can mask effective policy intent and complicate reviews.",
                )
            )
        else:
            seen.append(sig)
    return findings


def check_missing_description_pf(rules):
    """Flag rules with no meaningful description."""
    generic = {
        "",
        "unnamed",
        "default allow lan to any rule",
        "default deny rule",
        "anti-lockout rule",
    }
    findings = []
    for r in rules:
        desc = (r.get("descr") or "").strip().lower()
        if desc in generic:
            display = r.get("descr") or "unnamed"
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Rule '{display}' has no meaningful description",
                    "Add a descriptive label to every rule documenting its purpose, owner, and associated change request.",
                )
            )
    return findings


def check_wan_any_source_pf(rules):
    """Flag WAN-facing pass rules that allow any source."""
    findings = []
    for r in rules:
        if (
            r["type"] == "pass"
            and r["interface"].lower() == "wan"
            and r["source"] == "1"
        ):
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] WAN-facing pass rule '{name}' allows any source — internet-exposed",
                    "Restrict WAN-facing pass rules to specific known source IP ranges. "
                    "Any-source rules on the WAN interface are directly internet-exposed.",
                )
            )
    return findings


def audit_pfsense(filepath):
    rules, error = parse_pfsense(filepath)
    if error:
        return [_f("HIGH", "hygiene", f"[ERROR] {error}", "")], []

    findings = []
    findings += check_any_any_pf(rules)
    findings += check_missing_logging_pf(rules)
    findings += check_deny_all_pf(rules)
    findings += check_redundant_rules_pf(rules)
    findings += check_missing_description_pf(rules)
    findings += check_wan_any_source_pf(rules)
    return findings, rules
