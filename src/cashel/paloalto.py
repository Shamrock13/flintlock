# defusedxml prevents XXE (XML External Entity) injection attacks when parsing
# user-supplied firewall configs.  Drop-in replacement for ElementTree.
from typing import Any

from defusedxml import ElementTree as ET

from .models.findings import make_finding

_RULE_CONTEXT: dict[int, dict[str, Any]] = {}
_BROAD_VALUES = {"any", "all", "*"}


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


def _entry_name(entry):
    return entry.get("name", "")


def _normalize_broad(value):
    text = (value or "").strip()
    if text.lower() in _BROAD_VALUES:
        return "any"
    return text


def _stable_unique(values):
    seen = set()
    output = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return sorted(output)


def _rule_name(rule):
    return rule.get("name", "unnamed")


def _profile_group(rule):
    return rule.findtext(".//profile-setting/group/member") or rule.findtext(
        ".//profile-setting/group"
    )


def _rule_context(rule):
    return _RULE_CONTEXT.get(id(rule), {})


def _rule_scope(rule):
    context = _rule_context(rule)
    raw_src = _members(rule, ".//source/member")
    raw_dst = _members(rule, ".//destination/member")
    raw_apps = _members(rule, ".//application/member")
    raw_services = _members(rule, ".//service/member")
    return {
        "raw_source_addresses": raw_src,
        "raw_destination_addresses": raw_dst,
        "raw_applications": raw_apps,
        "raw_services": raw_services,
        "expanded_source_addresses": expand_addresses(
            raw_src,
            context.get("address_objects", {}),
            context.get("address_groups", {}),
        ),
        "expanded_destination_addresses": expand_addresses(
            raw_dst,
            context.get("address_objects", {}),
            context.get("address_groups", {}),
        ),
        "expanded_applications": expand_applications(
            raw_apps,
            context.get("application_groups", {}),
        ),
        "expanded_services": expand_services(
            raw_services,
            context.get("service_objects", {}),
            context.get("service_groups", {}),
        ),
    }


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
        **_rule_scope(rule),
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


def _parse_address_objects(root):
    objects = {}
    for entry in root.findall(".//address/entry"):
        name = _entry_name(entry)
        if not name:
            continue
        objects[name] = {
            "name": name,
            "ip-netmask": entry.findtext("ip-netmask") or "",
            "fqdn": entry.findtext("fqdn") or "",
            "ip-range": entry.findtext("ip-range") or "",
        }
    return objects


def _parse_address_groups(root):
    groups = {}
    for entry in root.findall(".//address-group/entry"):
        name = _entry_name(entry)
        if not name:
            continue
        groups[name] = {
            "name": name,
            "members": _members(entry, "static/member"),
            "dynamic": entry.findtext("dynamic/filter") or "",
        }
    return groups


def _parse_service_objects(root):
    services = {}
    for entry in root.findall(".//service/entry"):
        name = _entry_name(entry)
        if not name:
            continue
        protocol = ""
        port = ""
        if entry.find("protocol/tcp") is not None:
            protocol = "tcp"
            port = entry.findtext("protocol/tcp/port") or ""
        elif entry.find("protocol/udp") is not None:
            protocol = "udp"
            port = entry.findtext("protocol/udp/port") or ""
        services[name] = {"name": name, "protocol": protocol, "port": port}
    return services


def _parse_service_groups(root):
    groups = {}
    for entry in root.findall(".//service-group/entry"):
        name = _entry_name(entry)
        if not name:
            continue
        groups[name] = {"name": name, "members": _members(entry, "members/member")}
    return groups


def _parse_application_groups(root):
    groups = {}
    for entry in root.findall(".//application-group/entry"):
        name = _entry_name(entry)
        if not name:
            continue
        groups[name] = {"name": name, "members": _members(entry, "members/member")}
    return groups


def expand_address(name, objects, groups, _seen=None):
    """Expand a Palo Alto address object or static group into deterministic values."""
    normalized = _normalize_broad(name)
    if normalized == "any":
        return ["any"]

    seen = set() if _seen is None else set(_seen)
    if normalized in seen:
        return []
    seen.add(normalized)

    if normalized in groups:
        members = groups[normalized].get("members", [])
        return _stable_unique(
            value
            for member in members
            for value in expand_address(member, objects, groups, seen)
        )

    if normalized in objects:
        obj = objects[normalized]
        for key in ("ip-netmask", "fqdn", "ip-range"):
            if obj.get(key):
                return [obj[key]]
        return [normalized]

    return [normalized]


def expand_addresses(names, objects, groups):
    return _stable_unique(
        value for name in names for value in expand_address(name, objects, groups)
    )


def expand_service(name, services, service_groups, _seen=None):
    """Expand a Palo Alto service object or group into deterministic values."""
    normalized = _normalize_broad(name)
    if normalized == "any":
        return ["any"]

    seen = set() if _seen is None else set(_seen)
    if normalized in seen:
        return []
    seen.add(normalized)

    if normalized in service_groups:
        members = service_groups[normalized].get("members", [])
        return _stable_unique(
            value
            for member in members
            for value in expand_service(member, services, service_groups, seen)
        )

    if normalized in services:
        service = services[normalized]
        protocol = service.get("protocol", "")
        port = service.get("port", "")
        if protocol and port:
            return [f"{protocol}/{port}"]
        return [normalized]

    return [normalized]


def expand_services(names, services, service_groups):
    return _stable_unique(
        value
        for name in names
        for value in expand_service(name, services, service_groups)
    )


def expand_application(name, application_groups, _seen=None):
    """Expand a Palo Alto application group into deterministic application names."""
    normalized = _normalize_broad(name)
    if normalized == "any":
        return ["any"]

    seen = set() if _seen is None else set(_seen)
    if normalized in seen:
        return []
    seen.add(normalized)

    if normalized in application_groups:
        members = application_groups[normalized].get("members", [])
        return _stable_unique(
            value
            for member in members
            for value in expand_application(member, application_groups, seen)
        )

    return [normalized]


def expand_applications(names, application_groups):
    return _stable_unique(
        value
        for name in names
        for value in expand_application(name, application_groups)
    )


def parse_paloalto_config(filepath):
    """Parse Palo Alto XML into rules plus policy object dictionaries."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return None, f"Failed to parse Palo Alto config: {e}"

    config = {
        "rules": root.findall(".//security/rules/entry"),
        "address_objects": _parse_address_objects(root),
        "address_groups": _parse_address_groups(root),
        "service_objects": _parse_service_objects(root),
        "service_groups": _parse_service_groups(root),
        "application_groups": _parse_application_groups(root),
    }
    for rule in config["rules"]:
        _RULE_CONTEXT[id(rule)] = config
    return config, None


def parse_paloalto(filepath):
    """Parse a Palo Alto XML config and return security rules"""
    config, error = parse_paloalto_config(filepath)
    if error:
        return None, error
    return config["rules"], None


def _is_broad(values):
    return "any" in values


def check_any_any_pa(rules):
    findings = []
    for rule in rules:
        name = _rule_name(rule)
        scope = _rule_scope(rule)
        src = scope["expanded_source_addresses"]
        dst = scope["expanded_destination_addresses"]
        action = rule.findtext(".//action")

        if action == "allow" and _is_broad(src) and _is_broad(dst):
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
        scope = _rule_scope(rule)
        src = scope["expanded_source_addresses"]
        dst = scope["expanded_destination_addresses"]
        action = rule.findtext(".//action")
        if action == "deny" and _is_broad(src) and _is_broad(dst):
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
        scope = _rule_scope(rule)
        src = tuple(scope["expanded_source_addresses"])
        dst = tuple(scope["expanded_destination_addresses"])
        app = tuple(scope["expanded_applications"])
        svc = tuple(scope["expanded_services"])
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
        apps = _rule_scope(rule)["expanded_applications"]
        if action == "allow" and _is_broad(apps):
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
        services = _rule_scope(rule)["expanded_services"]
        if action == "allow" and _is_broad(services):
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
