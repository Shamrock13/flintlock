# defusedxml prevents XXE (XML External Entity) injection attacks when parsing
# user-supplied firewall configs.  Drop-in replacement for ElementTree.
from defusedxml import ElementTree as ET

from .models.findings import make_finding


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="paloalto",
    title=None,
    evidence=None,
    affected_object=None,
    rule_id=None,
    rule_name=None,
    confidence="medium",
    impact=None,
    verification=None,
    rollback=None,
    compliance_refs=None,
    suggested_commands=None,
    metadata=None,
):
    """Build a structured finding dict."""
    return make_finding(
        severity,
        category,
        message,
        remediation,
        id=id,
        vendor=vendor,
        title=title,
        evidence=evidence,
        affected_object=affected_object,
        rule_id=rule_id,
        rule_name=rule_name,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        compliance_refs=compliance_refs,
        suggested_commands=suggested_commands,
        metadata=metadata,
    )


def _members(rule, path):
    return [m.text or "" for m in rule.findall(path)]


def _rule_name(rule):
    return rule.get("name", "unnamed")


def _profile_group(rule):
    return rule.findtext(".//profile-setting/group/member") or rule.findtext(
        ".//profile-setting/group"
    )


def _rule_metadata(rule):
    profile = rule.find(".//profile-setting")
    return {
        "rule_name": _rule_name(rule),
        "source_zones": _members(rule, ".//from/member"),
        "destination_zones": _members(rule, ".//to/member"),
        "source_addresses": _members(rule, ".//source/member"),
        "destination_addresses": _members(rule, ".//destination/member"),
        "applications": _members(rule, ".//application/member"),
        "services": _members(rule, ".//service/member"),
        "action": rule.findtext(".//action") or "",
        "disabled": rule.findtext(".//disabled") or "",
        "log_start": rule.findtext(".//log-start") or "",
        "log_end": rule.findtext(".//log-end") or "",
        "profile_setting": ET.tostring(profile, encoding="unicode")
        if profile is not None
        else "",
        "profile_group": _profile_group(rule) or "",
        "description": (rule.findtext(".//description") or "").strip(),
    }


def _rule_evidence(rule):
    return ET.tostring(rule, encoding="unicode")


def _base_kwargs(rule, title, confidence="high", **extra):
    name = _rule_name(rule)
    kwargs = {
        "title": title,
        "evidence": _rule_evidence(rule),
        "affected_object": name,
        "rule_id": name,
        "rule_name": name,
        "confidence": confidence,
        "metadata": _rule_metadata(rule),
    }
    kwargs.update(extra)
    return kwargs


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
        name = _rule_name(rule)
        src = _members(rule, ".//source/member")
        dst = _members(rule, ".//destination/member")
        action = rule.findtext(".//action")

        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=any destination=any",
                    "Restrict source and destination to specific zones, address objects, or address groups. "
                    "Any-to-any allow rules expose all services to all traffic flows.",
                    id="CASHEL-PA-EXPOSURE-001",
                    impact="Broad permit rules can expose unintended applications and destinations.",
                    verification=(
                        "Confirm the rule no longer uses any for both source and destination, "
                        "then re-run the audit."
                    ),
                    rollback=(
                        "Restore the previous source and destination values from the committed "
                        "configuration if legitimate traffic is blocked."
                    ),
                    suggested_commands=[
                        "set rulebase security rules <RULE_NAME> source <SOURCE_OBJECT>",
                        "set rulebase security rules <RULE_NAME> destination <DESTINATION_OBJECT>",
                    ],
                    **_base_kwargs(
                        rule,
                        "Palo Alto rule allows any source to any destination",
                    ),
                )
            )
    return findings


def check_missing_logging_pa(rules):
    findings = []
    for rule in rules:
        name = _rule_name(rule)
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
                    id="CASHEL-PA-LOGGING-001",
                    impact="Allowed traffic may be absent from traffic logs and monitoring workflows.",
                    verification=(
                        "Confirm log-end is enabled for the rule and that matched sessions "
                        "produce traffic log entries."
                    ),
                    rollback="Restore the prior log-start/log-end values if logging volume is unacceptable.",
                    suggested_commands=[
                        "set rulebase security rules <RULE_NAME> log-end yes",
                    ],
                    **_base_kwargs(
                        rule, "Palo Alto allow rule is missing traffic logging"
                    ),
                )
            )
    return findings


def check_deny_all_pa(rules):
    for rule in rules:
        src = _members(rule, ".//source/member")
        dst = _members(rule, ".//destination/member")
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
            id="CASHEL-PA-HYGIENE-001",
            title="Palo Alto rulebase is missing an explicit deny-all rule",
            evidence="No security rule with action=deny, source=any, and destination=any was found.",
            affected_object="security rulebase",
            confidence="medium",
            impact="Unmatched traffic relies on implicit behavior and may not be logged consistently.",
            verification=(
                "Confirm a final deny rule exists below permit rules, logs denied sessions, "
                "and the audit no longer reports this finding."
            ),
            rollback="Disable or remove the new placeholder deny rule if it blocks approved traffic.",
            suggested_commands=[
                "set rulebase security rules <DENY_RULE_NAME> source any",
                "set rulebase security rules <DENY_RULE_NAME> destination any",
                "set rulebase security rules <DENY_RULE_NAME> application any",
                "set rulebase security rules <DENY_RULE_NAME> service any",
                "set rulebase security rules <DENY_RULE_NAME> action deny",
                "set rulebase security rules <DENY_RULE_NAME> log-end yes",
            ],
            metadata={"checked_rules": [_rule_name(rule) for rule in rules]},
        )
    ]


def check_redundant_rules_pa(rules):
    findings = []
    seen = {}
    for rule in rules:
        name = _rule_name(rule)
        src = tuple(sorted(_members(rule, ".//source/member")))
        dst = tuple(sorted(_members(rule, ".//destination/member")))
        app = tuple(sorted(_members(rule, ".//application/member")))
        svc = tuple(sorted(_members(rule, ".//service/member")))
        action = rule.findtext(".//action")

        sig = (src, dst, app, svc, action)
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Remove duplicate rules to keep the rulebase clean and auditable. "
                    "Redundant rules suggest configuration drift and make change management harder.",
                    id="CASHEL-PA-REDUNDANCY-002",
                    impact="Duplicate rules increase review effort and make policy intent harder to verify.",
                    verification="Confirm the duplicated rule is removed or consolidated, then re-run the audit.",
                    rollback="Re-add the duplicated rule from configuration history if removal affects traffic.",
                    suggested_commands=[
                        "delete rulebase security rules <DUPLICATE_RULE_NAME>",
                    ],
                    **_base_kwargs(
                        rule,
                        "Palo Alto rule duplicates an earlier rule",
                        metadata={
                            **_rule_metadata(rule),
                            "duplicate_of_rule": seen[sig],
                            "duplicate_rule": name,
                        },
                    ),
                )
            )
        else:
            seen[sig] = name
    return findings


def check_any_application_pa(rules):
    """Flag allow rules that permit any application."""
    findings = []
    for rule in rules:
        name = _rule_name(rule)
        action = rule.findtext(".//action")
        apps = _members(rule, ".//application/member")
        if action == "allow" and "any" in apps:
            findings.append(
                _f(
                    "MEDIUM",
                    "exposure",
                    f"[MEDIUM] Rule '{name}' allows any application",
                    "Replace 'any' with an explicit application or App-ID group. "
                    "App-ID enforcement is a core Palo Alto feature — use it to enforce least-privilege application access.",
                    id="CASHEL-PA-EXPOSURE-002",
                    impact="Application any bypasses App-ID intent and may allow protocols beyond the business need.",
                    verification=(
                        "Confirm the rule uses explicit applications or application groups and "
                        "no longer contains application any."
                    ),
                    rollback="Restore the previous application any value if App-ID narrowing blocks approved traffic.",
                    suggested_commands=[
                        "set rulebase security rules <RULE_NAME> application <APP_NAME>",
                    ],
                    **_base_kwargs(rule, "Palo Alto rule allows any application"),
                )
            )
    return findings


def check_any_service_pa(rules):
    """Flag allow rules that permit any service."""
    findings = []
    for rule in rules:
        name = _rule_name(rule)
        action = rule.findtext(".//action")
        services = _members(rule, ".//service/member")
        if action == "allow" and "any" in services:
            findings.append(
                _f(
                    "MEDIUM",
                    "exposure",
                    f"[MEDIUM] Rule '{name}' allows any service",
                    "Replace 'any' with application-default or an explicit service object. "
                    "Service any allows ports beyond the intended application path.",
                    id="CASHEL-PA-EXPOSURE-003",
                    impact="Service any may expose unintended TCP/UDP ports for the matched rule.",
                    verification=(
                        "Confirm the rule uses application-default or explicit services and "
                        "no longer contains service any."
                    ),
                    rollback="Restore the previous service any value if service narrowing blocks approved traffic.",
                    suggested_commands=[
                        "set rulebase security rules <RULE_NAME> service <SERVICE_NAME>",
                    ],
                    **_base_kwargs(rule, "Palo Alto rule allows any service"),
                )
            )
    return findings


def check_no_security_profile_pa(rules):
    """Flag allow rules with no security profile (AV/IPS/URL filtering) attached."""
    findings = []
    for rule in rules:
        name = _rule_name(rule)
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
                    id="CASHEL-PA-HYGIENE-002",
                    impact="Permitted traffic may bypass threat prevention, antivirus, or URL filtering controls.",
                    verification=(
                        "Confirm a security profile group is attached to the allow rule and "
                        "that traffic inspection logs show the expected profiles."
                    ),
                    rollback="Restore the prior profile-setting if the selected profile group disrupts approved traffic.",
                    suggested_commands=[
                        "set rulebase security rules <RULE_NAME> profile-setting group <PROFILE_GROUP>",
                    ],
                    **_base_kwargs(
                        rule,
                        "Palo Alto allow rule is missing a security profile",
                    ),
                )
            )
    return findings


def check_missing_description_pa(rules):
    """Flag allow rules with no description."""
    findings = []
    for rule in rules:
        name = _rule_name(rule)
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
                    id="CASHEL-PA-HYGIENE-003",
                    impact="Missing rule context slows access reviews, incident response, and change validation.",
                    verification="Confirm the rule description includes purpose, owner, and change reference.",
                    rollback="Restore the previous description field if the new text is inaccurate.",
                    suggested_commands=[
                        'set rulebase security rules <RULE_NAME> description "<PURPOSE_OWNER_TICKET>"',
                    ],
                    **_base_kwargs(
                        rule,
                        "Palo Alto allow rule is missing a description",
                    ),
                )
            )
    return findings


def audit_paloalto(filepath):
    """Return (findings, rules). rules is the parsed rule list for reuse in compliance checks."""
    rules, error = parse_paloalto(filepath)
    if error:
        return [
            _f(
                "HIGH",
                "hygiene",
                f"[ERROR] {error}",
                "",
                id="CASHEL-PA-HYGIENE-000",
                title="Palo Alto configuration could not be parsed",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the uploaded file is valid Palo Alto XML and re-run the audit.",
                metadata={"filepath": filepath},
            )
        ], []

    findings = []
    findings += check_any_any_pa(rules)
    findings += check_missing_logging_pa(rules)
    findings += check_deny_all_pa(rules)
    findings += check_redundant_rules_pa(rules)
    findings += check_any_application_pa(rules)
    findings += check_any_service_pa(rules)
    findings += check_no_security_profile_pa(rules)
    findings += check_missing_description_pa(rules)
    return findings, rules
