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


def parse_paloalto(filepath):
    """Parse a Palo Alto XML config and return security rules"""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return None, f"Failed to parse Palo Alto config: {e}"

    rules = root.findall(".//security/rules/entry")
    return rules, None


def check_any_any_pa(rules):
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")

        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=any destination=any",
                    "Restrict source and destination to specific zones, address objects, or address groups. "
                    "Any-to-any allow rules expose all services to all traffic flows.",
                )
            )
    return findings


def check_missing_logging_pa(rules):
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        action = rule.findtext(".//action")

        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] Permit rule '{name}' missing logging",
                    "Enable log-at-session-end (log-end yes) on all allow rules. "
                    "Without logging, permitted traffic is invisible to security monitoring.",
                )
            )
    return findings


def check_deny_all_pa(rules):
    for rule in rules:
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        if action == "deny" and "any" in src and "any" in dst:
            return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found",
            "Add a catch-all deny rule at the bottom of the rulebase. "
            "Explicitly denying and logging unmatched traffic improves visibility and confirms implicit-deny intent.",
        )
    ]


def check_redundant_rules_pa(rules):
    findings = []
    seen = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = tuple(sorted([s.text for s in rule.findall(".//source/member")]))
        dst = tuple(sorted([d.text for d in rule.findall(".//destination/member")]))
        app = tuple(sorted([a.text for a in rule.findall(".//application/member")]))
        action = rule.findtext(".//action")

        sig = (src, dst, app, action)
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Remove duplicate rules to keep the rulebase clean and auditable. "
                    "Redundant rules suggest configuration drift and make change management harder.",
                )
            )
        else:
            seen.append(sig)
    return findings


def check_any_application_pa(rules):
    """Flag allow rules that permit any application."""
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        apps = [a.text for a in rule.findall(".//application/member")]
        if action == "allow" and "any" in apps:
            findings.append(
                _f(
                    "MEDIUM",
                    "exposure",
                    f"[MEDIUM] Rule '{name}' allows any application",
                    "Replace 'any' with an explicit application or App-ID group. "
                    "App-ID enforcement is a core Palo Alto feature — use it to enforce least-privilege application access.",
                )
            )
    return findings


def check_no_security_profile_pa(rules):
    """Flag allow rules with no security profile (AV/IPS/URL filtering) attached."""
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        if action != "allow":
            continue
        profile = rule.find(".//profile-setting")
        if profile is None:
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Rule '{name}' has no security profile (AV/IPS/URL filtering) applied",
                    "Attach a security profile group with antivirus, Threat Prevention, and URL filtering "
                    "to all allow rules to detect and block threats within permitted traffic flows.",
                )
            )
    return findings


def check_missing_description_pa(rules):
    """Flag allow rules with no description."""
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        desc = (rule.findtext(".//description") or "").strip()
        if action == "allow" and not desc:
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Rule '{name}' has no description",
                    "Add a description to every rule that documents its purpose, owner, and change ticket reference. "
                    "Undocumented rules increase review time and incident response risk.",
                )
            )
    return findings


def audit_paloalto(filepath):
    """Return (findings, rules). rules is the parsed rule list for reuse in compliance checks."""
    rules, error = parse_paloalto(filepath)
    if error:
        return [_f("HIGH", "hygiene", f"[ERROR] {error}", "")], []

    findings = []
    findings += check_any_any_pa(rules)
    findings += check_missing_logging_pa(rules)
    findings += check_deny_all_pa(rules)
    findings += check_redundant_rules_pa(rules)
    findings += check_any_application_pa(rules)
    findings += check_no_security_profile_pa(rules)
    findings += check_missing_description_pa(rules)
    return findings, rules
