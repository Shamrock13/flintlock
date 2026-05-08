# defusedxml prevents XXE (XML External Entity) injection attacks when parsing
# user-supplied firewall configs.  Drop-in replacement for ElementTree.
from defusedxml import ElementTree as ET

from .models.findings import make_finding

_BROAD_VALUES = {"", "1", "any", "*"}


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="pfsense",
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


def _rule_name(rule):
    return rule.get("descr") or rule.get("tracker") or "unnamed"


def _rule_ref(rule):
    return rule.get("tracker") or _rule_name(rule)


def _rule_evidence(rule):
    return rule.get("_raw") or (
        f"interface={rule.get('interface', '')} type={rule.get('type', '')} "
        f"source={rule.get('source', '')} destination={rule.get('destination', '')} "
        f"protocol={rule.get('protocol', '')} log={rule.get('log', False)}"
    )


def _rule_metadata(rule):
    scope = _rule_scope(rule)
    return {
        "rule_description": rule.get("descr", ""),
        "interface": rule.get("interface", ""),
        "type": rule.get("type", ""),
        "action": rule.get("type", ""),
        "protocol": rule.get("protocol", ""),
        "source": rule.get("source", ""),
        "destination": rule.get("destination", ""),
        "source_port": rule.get("source_port", ""),
        "destination_port": rule.get("destination_port", ""),
        "log": rule.get("log", False),
        "disabled": rule.get("disabled", False),
        "tracker": rule.get("tracker", ""),
        "raw": _rule_evidence(rule),
        **scope,
    }


def _rule_kwargs(
    rule,
    title,
    *,
    id,
    confidence="high",
    impact=None,
    verification=None,
    rollback=None,
    suggested_commands=None,
    metadata=None,
):
    merged_metadata = _rule_metadata(rule)
    if metadata:
        merged_metadata.update(metadata)
    return {
        "id": id,
        "title": title,
        "evidence": _rule_evidence(rule),
        "affected_object": _rule_ref(rule),
        "rule_id": rule.get("tracker") or None,
        "rule_name": _rule_name(rule),
        "confidence": confidence,
        "impact": impact,
        "verification": verification,
        "rollback": rollback,
        "suggested_commands": suggested_commands or [],
        "metadata": merged_metadata,
    }


def _ui_rule_path(rule):
    interface = (rule.get("interface") or "<INTERFACE>").upper()
    ref = _rule_ref(rule)
    return f"pfSense UI: Firewall > Rules > {interface} > edit rule {ref}"


def _rule_guidance(rule, *actions):
    return [_ui_rule_path(rule), *actions]


def _rule_endpoint(rule, field):
    if rule.find(f"{field}/any") is not None:
        return "1"
    return rule.findtext(f"{field}/address") or "specific"


def _split_alias_values(value):
    return sorted(part for part in (value or "").split() if part)


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


def _parse_aliases(root):
    aliases = {}
    address_aliases = {}
    port_aliases = {}
    url_aliases = {}

    for alias in root.findall(".//aliases/alias"):
        name = alias.findtext("name") or ""
        if not name:
            continue
        alias_type = (alias.findtext("type") or "unknown").lower()
        address_values = _split_alias_values(alias.findtext("address") or "")
        data = {
            "name": name,
            "type": alias_type,
            "address": address_values,
            "url": alias.findtext("url") or "",
            "descr": alias.findtext("descr") or "",
        }
        aliases[name] = data
        if alias_type == "port":
            port_aliases[name] = data
        if alias_type in {"host", "network", "url", "urltable", "urltable_ports"}:
            address_aliases[name] = data
        if alias_type in {"url", "urltable", "urltable_ports"}:
            url_aliases[name] = data

    return aliases, address_aliases, port_aliases, url_aliases


def expand_address(name, aliases):
    normalized = _normalize_broad(name)
    if normalized == "any":
        return ["any"]
    alias = aliases.get(normalized)
    if alias:
        if alias.get("url"):
            return [alias["url"]]
        values = alias.get("address") or []
        if values:
            return _stable_unique(_normalize_broad(value) for value in values)
    return [normalized]


def expand_addresses(names, aliases):
    return _stable_unique(
        value for name in names for value in expand_address(name, aliases)
    )


def expand_port(name, aliases):
    normalized = _normalize_broad(name)
    if normalized == "any":
        return ["any"]
    alias = aliases.get(normalized)
    if alias:
        values = alias.get("address") or []
        if values:
            return _stable_unique(_normalize_broad(value) for value in values)
    return [normalized]


def expand_ports(names, aliases):
    return _stable_unique(
        value for name in names for value in expand_port(name, aliases)
    )


def _attach_alias_context(config):
    for rule in config["rules"]:
        rule["_aliases"] = config["aliases"]
        rule["_address_aliases"] = config["address_aliases"]
        rule["_port_aliases"] = config["port_aliases"]
        rule["_url_aliases"] = config["url_aliases"]


def _rule_scope(rule):
    address_aliases = rule.get("_address_aliases", {})
    port_aliases = rule.get("_port_aliases", {})
    raw_source = rule.get("source", "")
    raw_destination = rule.get("destination", "")
    raw_source_port = rule.get("source_port", "")
    raw_destination_port = rule.get("destination_port", "")
    return {
        "raw_source": raw_source,
        "raw_destination": raw_destination,
        "raw_source_port": raw_source_port,
        "raw_destination_port": raw_destination_port,
        "expanded_source": expand_addresses([raw_source], address_aliases),
        "expanded_destination": expand_addresses([raw_destination], address_aliases),
        "expanded_source_port": expand_ports([raw_source_port], port_aliases),
        "expanded_destination_port": expand_ports([raw_destination_port], port_aliases),
    }


def _is_broad(values):
    return "any" in {_normalize_broad(value).lower() for value in values}


def parse_pfsense_config(filepath):
    """Parse a pfSense XML config into rules and alias dictionaries."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return {}, f"Failed to parse pfSense config: {e}"

    rules = []
    for rule in root.findall(".//filter/rule"):
        r = {
            "type": rule.findtext("type") or "pass",
            "interface": rule.findtext("interface") or "",
            "source": _rule_endpoint(rule, "source"),
            "destination": _rule_endpoint(rule, "destination"),
            "source_port": rule.findtext("source/port") or "",
            "destination_port": rule.findtext("destination/port") or "",
            "protocol": rule.findtext("protocol") or "any",
            "log": rule.find("log") is not None,
            "disabled": rule.find("disabled") is not None,
            "descr": rule.findtext("descr") or "",
            "tracker": rule.findtext("tracker") or "",
            "_raw": ET.tostring(rule, encoding="unicode"),
        }
        rules.append(r)

    aliases, address_aliases, port_aliases, url_aliases = _parse_aliases(root)
    config = {
        "rules": rules,
        "aliases": aliases,
        "address_aliases": address_aliases,
        "port_aliases": port_aliases,
        "url_aliases": url_aliases,
    }
    _attach_alias_context(config)
    return config, None


def parse_pfsense(filepath):
    """Parse a pfSense XML config and return firewall rules"""
    config, error = parse_pfsense_config(filepath)
    if error:
        return None, error
    return config["rules"], None


def check_any_any_pf(rules):
    findings = []
    for r in rules:
        scope = _rule_scope(r)
        if (
            r["type"] == "pass"
            and _is_broad(scope["expanded_source"])
            and _is_broad(scope["expanded_destination"])
        ):
            name = r["descr"] or "unnamed"
            source_action = (
                f"Replace source alias {r['source']} with <SPECIFIC_SOURCE_ALIAS>"
                if r["source"] not in {"1", "any", "*", ""}
                else "Set source to <SPECIFIC_SOURCE_ALIAS>"
            )
            destination_action = (
                f"Replace destination alias {r['destination']} with <SPECIFIC_DESTINATION_ALIAS>"
                if r["destination"] not in {"1", "any", "*", ""}
                else "Set destination to <SPECIFIC_DESTINATION_ALIAS>"
            )
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=any destination=any",
                    "Restrict source and destination to specific hosts or networks. "
                    "Pass-all rules allow unrestricted traffic between all segments.",
                    **_rule_kwargs(
                        r,
                        "pfSense pass rule allows any source to any destination",
                        id="CASHEL-PFSENSE-EXPOSURE-001",
                        impact="A broad pass rule can allow unintended traffic through the interface.",
                        verification=(
                            "Confirm the rule no longer uses any for both source and destination, "
                            "then re-run the audit."
                        ),
                        rollback="Restore the prior rule from a pfSense config backup if approved traffic is disrupted.",
                        suggested_commands=_rule_guidance(
                            r,
                            source_action,
                            destination_action,
                            "Disable or remove the rule only after confirming no approved traffic depends on it",
                        ),
                    ),
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
                    **_rule_kwargs(
                        r,
                        "pfSense pass rule is missing logging",
                        id="CASHEL-PFSENSE-LOGGING-001",
                        impact="Permitted traffic may not appear in firewall logs for investigation or compliance review.",
                        verification="Confirm firewall logs show traffic handled by the rule after enabling logging.",
                        rollback="Disable rule logging if volume is excessive and an approved alternate logging control exists.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Enable Log packets that are handled by this rule",
                        ),
                    ),
                )
            )
    return findings


def check_deny_all_pf(rules):
    has_deny_all = any(
        r["type"] == "block"
        and _is_broad(_rule_scope(r)["expanded_source"])
        and _is_broad(_rule_scope(r)["expanded_destination"])
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
            id="CASHEL-PFSENSE-HYGIENE-001",
            title="pfSense ruleset is missing an explicit deny-all rule",
            evidence="No block rule with source any and destination any was found.",
            affected_object="filter rules",
            confidence="medium",
            impact="The ruleset relies on implicit default behavior and may lack logged deny evidence.",
            verification="Confirm a final logged block rule exists after pass rules on relevant interfaces.",
            rollback="Disable or remove the new block rule from the pfSense UI if it blocks approved traffic.",
            suggested_commands=[
                "pfSense UI: Firewall > Rules > <INTERFACE> > add rule at bottom",
                "Set action to Block",
                "Set source to any",
                "Set destination to any",
                "Enable Log packets that are handled by this rule",
            ],
            metadata={"checked_rules": [_rule_name(rule) for rule in rules]},
        )
    ]


def check_redundant_rules_pf(rules):
    findings = []
    seen = []
    for r in rules:
        name = r["descr"] or "unnamed"
        scope = _rule_scope(r)
        sig = (
            r["type"],
            tuple(scope["expanded_source"]),
            tuple(scope["expanded_destination"]),
            r["protocol"],
            tuple(scope["expanded_source_port"]),
            tuple(scope["expanded_destination_port"]),
        )
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Remove duplicate rules to keep the ruleset concise. "
                    "Duplicate rules can mask effective policy intent and complicate reviews.",
                    **_rule_kwargs(
                        r,
                        "pfSense rule duplicates an earlier rule",
                        id="CASHEL-PFSENSE-REDUNDANCY-002",
                        impact="Duplicate rules increase review effort and can obscure the intended policy.",
                        verification="Confirm duplicate rules are removed or consolidated, then re-run the audit.",
                        rollback="Restore the removed rule from a pfSense config backup if traffic changes unexpectedly.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Disable or remove the duplicate rule only after confirming no approved traffic depends on it",
                        ),
                        metadata={"duplicate_signature": sig},
                    ),
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
                    **_rule_kwargs(
                        r,
                        "pfSense rule is missing a meaningful description",
                        id="CASHEL-PFSENSE-HYGIENE-002",
                        impact="Missing descriptions slow audits, troubleshooting, and change reviews.",
                        verification="Confirm the rule description documents purpose, owner, and change reference.",
                        rollback="Restore the prior description if the new description is inaccurate.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Set description to <PURPOSE_OWNER_CHANGE_REFERENCE>",
                        ),
                    ),
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
            and _is_broad(_rule_scope(r)["expanded_source"])
        ):
            name = r["descr"] or "unnamed"
            source_action = (
                f"Replace source alias {r['source']} with <APPROVED_EXTERNAL_SOURCE_ALIAS>"
                if r["source"] not in {"1", "any", "*", ""}
                else "Set source to <APPROVED_EXTERNAL_SOURCE_ALIAS>"
            )
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] WAN-facing pass rule '{name}' allows any source — internet-exposed",
                    "Restrict WAN-facing pass rules to specific known source IP ranges. "
                    "Any-source rules on the WAN interface are directly internet-exposed.",
                    **_rule_kwargs(
                        r,
                        "pfSense WAN pass rule allows any source",
                        id="CASHEL-PFSENSE-EXPOSURE-002",
                        impact="WAN any-source rules can expose services to the internet.",
                        verification=(
                            "Confirm the WAN rule source is limited to approved external addresses "
                            "or aliases, then re-run the audit."
                        ),
                        rollback="Restore the prior source value from a pfSense config backup if approved access is disrupted.",
                        suggested_commands=_rule_guidance(
                            r,
                            source_action,
                            "Confirm destination and destination port match only the required service",
                        ),
                    ),
                )
            )
    return findings


def audit_pfsense(filepath):
    config, error = parse_pfsense_config(filepath)
    if error:
        return [
            _f(
                "HIGH",
                "hygiene",
                f"[ERROR] {error}",
                "",
                id="CASHEL-PFSENSE-PARSE-001",
                title="pfSense configuration could not be parsed",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the uploaded file is valid pfSense XML and re-run the audit.",
                metadata={"filepath": filepath},
            )
        ], []
    rules = config["rules"]

    findings = []
    findings += check_any_any_pf(rules)
    findings += check_missing_logging_pf(rules)
    findings += check_deny_all_pf(rules)
    findings += check_redundant_rules_pf(rules)
    findings += check_missing_description_pf(rules)
    findings += check_wan_any_source_pf(rules)
    return findings, rules
