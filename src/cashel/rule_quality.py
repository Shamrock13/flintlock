"""Rule quality analysis: shadow/unreachable rule detection across all vendors.

A rule is "shadowed" when an earlier rule in the same policy covers a superset
of its traffic scope, meaning the shadowed rule will never be evaluated.  This
is distinct from a duplicate rule — duplicates have identical scope; shadowed
rules have a *subset* scope that is fully absorbed by a broader earlier rule.

Supported vendors: asa, ftd, paloalto, fortinet, pfsense, azure, juniper.
AWS Security Groups are intentionally excluded: SG rules have no evaluation
order (all matching rules apply, most-permissive wins), so shadow analysis
does not apply.
"""

import hashlib
import json
import re

from .models.findings import make_finding


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="unknown",
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


def _shadow_metadata(shadowed, shadowing, **extra):
    metadata = {
        "shadowed_rule": shadowed,
        "shadowing_rule": shadowing,
    }
    metadata.update(extra)
    return metadata


def _covers(broad, narrow):
    """Return True if the 'broad' collection covers all members of 'narrow'.

    'any', 'all', or '*' anywhere in broad is treated as a universal match.
    Otherwise every member of narrow must appear in broad (name-based match).
    """
    b = {str(x).lower() for x in (broad or [])}
    n = {str(x).lower() for x in (narrow or [])}
    if b & {"any", "all", "*"}:
        return True
    return n.issubset(b)


def _forti_policy_name(policy):
    return policy.get("name") or f"Policy ID {policy.get('id')}"


def _forti_policy_values(policy, key):
    values = policy.get(key, [])
    if isinstance(values, list):
        return values
    if values:
        return [values]
    return []


def _forti_policy_context(policy, prefix):
    profile_fields = {
        "utm-status": "utm_status",
        "av-profile": "av_profile",
        "ips-sensor": "ips_sensor",
        "application-list": "application_list",
        "webfilter-profile": "webfilter_profile",
        "profile-protocol-options": "profile_protocol_options",
    }
    context = {
        f"{prefix}_policy_id": str(policy.get("id") or ""),
        f"{prefix}_policy_name": _forti_policy_name(policy),
        f"{prefix}_srcintf": _forti_policy_values(policy, "srcintf"),
        f"{prefix}_dstintf": _forti_policy_values(policy, "dstintf"),
        f"{prefix}_srcaddr": _forti_policy_values(policy, "srcaddr"),
        f"{prefix}_dstaddr": _forti_policy_values(policy, "dstaddr"),
        f"{prefix}_service": _forti_policy_values(policy, "service"),
        f"{prefix}_action": policy.get("action", ""),
        f"{prefix}_logtraffic": policy.get("logtraffic", ""),
        f"{prefix}_status": policy.get("status", ""),
        f"{prefix}_schedule": policy.get("schedule", ""),
        f"{prefix}_nat": policy.get("nat", ""),
        f"{prefix}_comments": policy.get("comments", ""),
    }
    for raw_key, metadata_key in profile_fields.items():
        context[f"{prefix}_{metadata_key}"] = policy.get(raw_key, "")
    return context


def _forti_shadow_evidence(shadowed_policy, shadowing_policy):
    shadowed_name = _forti_policy_name(shadowed_policy)
    shadowing_name = _forti_policy_name(shadowing_policy)
    fields = [
        f"shadowed_policy_id={shadowed_policy.get('id')}",
        f"shadowed_name={shadowed_name}",
        f"shadowed_srcaddr={','.join(_forti_policy_values(shadowed_policy, 'srcaddr')) or 'unset'}",
        f"shadowed_dstaddr={','.join(_forti_policy_values(shadowed_policy, 'dstaddr')) or 'unset'}",
        f"shadowed_service={','.join(_forti_policy_values(shadowed_policy, 'service')) or 'unset'}",
        f"shadowed_action={shadowed_policy.get('action') or 'unset'}",
        f"shadowed_logtraffic={shadowed_policy.get('logtraffic') or 'unset'}",
        f"shadowing_policy_id={shadowing_policy.get('id')}",
        f"shadowing_name={shadowing_name}",
        f"shadowing_srcaddr={','.join(_forti_policy_values(shadowing_policy, 'srcaddr')) or 'unset'}",
        f"shadowing_dstaddr={','.join(_forti_policy_values(shadowing_policy, 'dstaddr')) or 'unset'}",
        f"shadowing_service={','.join(_forti_policy_values(shadowing_policy, 'service')) or 'unset'}",
        f"shadowing_action={shadowing_policy.get('action') or 'unset'}",
        f"shadowing_logtraffic={shadowing_policy.get('logtraffic') or 'unset'}",
    ]
    return "; ".join(fields)


# ── Palo Alto ────────────────────────────────────────────────────────────────


def check_shadow_rules_pa(rules):
    """Detect shadowed rules in a Palo Alto rulebase.

    A rule is shadowed if an earlier enabled rule covers a superset of its
    source, destination, and application/service scope.
    """
    findings = []
    active = []  # list of (name, src, dst, app, svc)

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text or "" for s in rule.findall(".//source/member")]
        dst = [d.text or "" for d in rule.findall(".//destination/member")]
        app = [a.text or "" for a in rule.findall(".//application/member")]
        svc = [s.text or "" for s in rule.findall(".//service/member")]
        disabled = rule.findtext(".//disabled") == "yes"

        if disabled:
            continue

        for e_name, e_src, e_dst, e_app, e_svc in active:
            if (
                _covers(e_src, src)
                and _covers(e_dst, dst)
                and (_covers(e_app, app) or _covers(e_svc, svc))
            ):
                findings.append(
                    _f(
                        "HIGH",
                        "redundancy",
                        f"[HIGH] Rule '{name}' is shadowed by earlier rule '{e_name}' — it will never match",
                        f"Rule '{e_name}' appears before '{name}' and covers a superset of its "
                        f"source/destination/application scope. Either remove '{name}' if it is "
                        f"obsolete, or move it above '{e_name}' so it is evaluated first.",
                        id="CASHEL-PA-REDUNDANCY-001",
                        vendor="paloalto",
                        title="Palo Alto rule is shadowed",
                        evidence=f"Rule '{e_name}' covers rule '{name}'",
                        affected_object=name,
                        rule_name=name,
                        confidence="medium",
                        verification="Review rule order and traffic logs, then re-run the audit after removing, narrowing, or moving the shadowed rule.",
                        metadata=_shadow_metadata(
                            name,
                            e_name,
                            source=src,
                            destination=dst,
                            application=app,
                            service=svc,
                        ),
                    )
                )
                break

        active.append((name, src, dst, app, svc))

    return findings


# ── Fortinet ────────────────────────────────────────────────────────────────


def check_shadow_rules_forti(policies):
    """Detect shadowed policies in a FortiGate policy list.

    Disabled policies are skipped.  A policy is shadowed if an earlier active
    policy covers a superset of its srcaddr, dstaddr, and service scope.
    """
    findings = []
    active = []  # list of (name, srcaddr, dstaddr, service, policy)

    for p in policies:
        if p.get("status") == "disable":
            continue

        name = _forti_policy_name(p)
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        svc = p.get("service", [])

        for e_name, e_src, e_dst, e_svc, e_policy in active:
            if _covers(e_src, src) and _covers(e_dst, dst) and _covers(e_svc, svc):
                findings.append(
                    _f(
                        "HIGH",
                        "redundancy",
                        f"[HIGH] Policy '{name}' is shadowed by earlier policy '{e_name}' — it will never match",
                        f"Policy '{e_name}' precedes '{name}' and covers a superset of its "
                        f"source/destination/service scope. Remove '{name}' if it is obsolete, "
                        f"or reorder it above '{e_name}' so it is evaluated first.",
                        id="CASHEL-FORTINET-REDUNDANCY-001",
                        vendor="fortinet",
                        title="Fortinet policy is shadowed",
                        evidence=_forti_shadow_evidence(p, e_policy),
                        affected_object=name,
                        rule_id=str(p.get("id") or ""),
                        rule_name=name,
                        confidence="medium",
                        verification="Review policy order and hit counts, then re-run the audit after removing, narrowing, or moving the shadowed policy.",
                        rollback="Restore the previous policy order from configuration backup if reordering or removal affects approved traffic.",
                        metadata={
                            **_shadow_metadata(
                                name,
                                e_name,
                                source=src,
                                destination=dst,
                                service=svc,
                            ),
                            **_forti_policy_context(p, "shadowed"),
                            **_forti_policy_context(e_policy, "shadowing"),
                        },
                    )
                )
                break

        active.append((name, src, dst, svc, p))

    return findings


# ── pfSense ──────────────────────────────────────────────────────────────────


def check_shadow_rules_pfsense(rules):
    """Detect shadowed rules in a pfSense ruleset.

    pfSense rules are grouped per interface and evaluated top-to-bottom.
    The parser represents source/destination=any as the string "1".
    """
    findings = []

    # Group by interface — pfSense evaluates rules per interface independently
    by_intf: dict = {}
    for r in rules:
        intf = r.get("interface", "")
        by_intf.setdefault(intf, []).append(r)

    for intf, intf_rules in by_intf.items():
        active = []  # list of (name, src, dst, proto)

        for r in intf_rules:
            name = r.get("descr") or "unnamed"
            src = r.get("source", "")
            dst = r.get("destination", "")
            proto = (r.get("protocol") or "any").lower()

            for e_name, e_src, e_dst, e_proto in active:
                src_covered = (e_src == "1") or (e_src == src)
                dst_covered = (e_dst == "1") or (e_dst == dst)
                proto_covered = (e_proto == "any") or (e_proto == proto)

                if src_covered and dst_covered and proto_covered:
                    intf_label = intf or "unknown"
                    findings.append(
                        _f(
                            "HIGH",
                            "redundancy",
                            f"[HIGH] pfSense rule '{name}' (interface: {intf_label}) is shadowed by "
                            f"earlier rule '{e_name}' — it will never match",
                            f"Rule '{e_name}' precedes '{name}' on interface '{intf_label}' and "
                            f"covers a superset of its source/destination/protocol scope. "
                            f"Remove or reorder '{name}' to ensure it is evaluated as intended.",
                            id="CASHEL-PFSENSE-REDUNDANCY-001",
                            vendor="pfsense",
                            title="pfSense rule is shadowed",
                            evidence=f"Interface '{intf_label}': rule '{e_name}' covers rule '{name}'",
                            affected_object=name,
                            rule_name=name,
                            confidence="medium",
                            verification="Review interface rule order, then re-run the audit after removing, narrowing, or moving the shadowed rule.",
                            metadata=_shadow_metadata(
                                name,
                                e_name,
                                interface=intf_label,
                                source=src,
                                destination=dst,
                                protocol=proto,
                            ),
                        )
                    )
                    break

            active.append((name, src, dst, proto))

    return findings


# ── Cisco ASA / FTD ──────────────────────────────────────────────────────────

_ACL_RE = re.compile(
    r"access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(\S+)\s+(.*)",
    re.IGNORECASE,
)


def _parse_asa_rule(text):
    """Extract structured fields from a Cisco ASA/FTD ACL entry.

    Returns a dict with keys: acl, action, proto, src_any, dst_any, raw.
    Returns None if the line does not match the expected ACL format.
    """
    m = _ACL_RE.match(text.strip())
    if not m:
        return None
    acl_name = m.group(1)
    action = m.group(2).lower()
    proto = m.group(3).lower()
    rest = m.group(4).split()
    src_any = bool(rest) and rest[0].lower() == "any"
    dst_any = "any" in [t.lower() for t in rest[1:]]
    return {
        "acl": acl_name,
        "action": action,
        "proto": proto,
        "src_any": src_any,
        "dst_any": dst_any,
        "raw": text.strip(),
    }


def check_shadow_rules_asa(parse, vendor: str = "asa"):
    """Detect rules made unreachable by a broad any-any entry in the same ACL.

    When a 'permit|deny ip any any' rule exists at position N in an ACL,
    every subsequent entry in that ACL can never be evaluated.  This is the
    most impactful and common shadowing pattern in Cisco ASA/FTD configs.
    """
    findings = []
    acl_rules: dict = {}
    from .audit_engine import (
        _asa_acl_entries,
        _asa_scope_is_any,
        parse_asa_object_context,
    )

    context = parse_asa_object_context(parse)
    for parsed in _asa_acl_entries(parse, context):
        acl_rules.setdefault(parsed["acl_name"], []).append(parsed)

    for acl_name, rules in acl_rules.items():
        for i, rule in enumerate(rules):
            if (
                _asa_scope_is_any(rule["expanded_source"])
                and _asa_scope_is_any(rule["expanded_destination"])
                and rule["protocol"] in ("ip", "any")
            ):
                # Every entry after position i in this ACL is unreachable
                for shadowed in rules[i + 1 :]:
                    findings.append(
                        _f(
                            "HIGH",
                            "redundancy",
                            f"[HIGH] ACL '{acl_name}': rule '{shadowed['acl_line']}' is unreachable — "
                            f"shadowed by earlier '{rule['action']} {rule['protocol']} any any'",
                            f"The '{rule['action']} {rule['protocol']} any any' entry in ACL "
                            f"'{acl_name}' matches all traffic, making every subsequent entry "
                            f"unreachable. Move specific rules above the broad any-any entry, "
                            f"or remove them if they are no longer needed.",
                            id=f"CASHEL-{vendor.upper()}-REDUNDANCY-002",
                            vendor=vendor,
                            title="ACL rule is shadowed by earlier any-any rule",
                            evidence=f"{rule['acl_line']} -> {shadowed['acl_line']}",
                            affected_object=acl_name,
                            rule_name=shadowed["acl_line"],
                            confidence="high",
                            verification="Review ACL order and hit counts, then re-run the audit after moving, narrowing, or removing unreachable rules.",
                            metadata=_shadow_metadata(
                                shadowed["acl_line"],
                                rule["acl_line"],
                                acl=acl_name,
                                shadowing_action=rule["action"],
                                shadowing_protocol=rule["protocol"],
                                raw_source=shadowed["raw_source"],
                                raw_destination=shadowed["raw_destination"],
                                raw_service=shadowed["raw_service"],
                                expanded_source=shadowed["expanded_source"],
                                expanded_destination=shadowed["expanded_destination"],
                                expanded_service=shadowed["expanded_service"],
                            ),
                        )
                    )
                break  # Only report the first shadowing rule per ACL to avoid noise

    return findings


# ── Azure NSG ────────────────────────────────────────────────────────────────

_AZURE_ANY = {"*", "internet", "any", "0.0.0.0/0", "::/0"}


def _azure_shadow_id(
    nsg_name, direction, name, priority, shadowing_name, shadowing_priority
):
    payload = json.dumps(
        [
            "azure_shadow_rule",
            nsg_name,
            direction,
            name,
            priority,
            shadowing_name,
            shadowing_priority,
        ],
        sort_keys=True,
        default=str,
    )
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:10].upper()
    return f"CASHEL-AZURE-REDUNDANCY-{digest}"


def _azure_src_any(props):
    return props.get("sourceAddressPrefix", "").lower() in _AZURE_ANY


def _azure_port_any(props):
    port = props.get("destinationPortRange", "")
    multi = props.get("destinationPortRanges", [])
    return port == "*" or (not port and not multi)


def _azure_list_or_single(props, single_key, multi_key):
    multi = props.get(multi_key, [])
    if multi:
        return list(multi)
    single = props.get(single_key, "")
    if single:
        return [single]
    return []


def _azure_port_ranges(props):
    return _azure_list_or_single(props, "destinationPortRange", "destinationPortRanges")


def _azure_flow_log_state(nsg):
    if "flowLogs" in nsg:
        return nsg.get("flowLogs")
    if "diagnosticSettings" in nsg:
        return nsg.get("diagnosticSettings")
    return "unknown"


def _azure_shadow_rule_context(rule):
    props = rule.get("properties", rule)
    return {
        "rule_name": rule.get("name", "unnamed"),
        "direction": props.get("direction", ""),
        "priority": props.get("priority", "?"),
        "protocol": props.get("protocol", ""),
        "source_address_prefixes": _azure_list_or_single(
            props, "sourceAddressPrefix", "sourceAddressPrefixes"
        ),
        "destination_address_prefixes": _azure_list_or_single(
            props, "destinationAddressPrefix", "destinationAddressPrefixes"
        ),
        "source_port_ranges": _azure_list_or_single(
            props, "sourcePortRange", "sourcePortRanges"
        ),
        "destination_port_ranges": _azure_port_ranges(props),
        "action": props.get("access", ""),
    }


def _azure_shadow_metadata(nsg, direction, shadowed_rule, shadowing_rule):
    shadowed = _azure_shadow_rule_context(shadowed_rule)
    shadowing = _azure_shadow_rule_context(shadowing_rule)
    return _shadow_metadata(
        shadowed["rule_name"],
        shadowing["rule_name"],
        nsg_name=nsg.get("name", "unnamed"),
        rule_name=shadowed["rule_name"],
        direction=direction,
        priority=shadowed["priority"],
        protocol=shadowed["protocol"],
        source_address_prefixes=shadowed["source_address_prefixes"],
        destination_address_prefixes=shadowed["destination_address_prefixes"],
        source_port_ranges=shadowed["source_port_ranges"],
        destination_port_ranges=shadowed["destination_port_ranges"],
        action=shadowed["action"],
        flow_log_state=_azure_flow_log_state(nsg),
        shadowing_rule_name=shadowing["rule_name"],
        shadowing_direction=shadowing["direction"],
        shadowing_priority=shadowing["priority"],
        shadowing_protocol=shadowing["protocol"],
        shadowing_source_address_prefixes=shadowing["source_address_prefixes"],
        shadowing_destination_address_prefixes=shadowing[
            "destination_address_prefixes"
        ],
        shadowing_source_port_ranges=shadowing["source_port_ranges"],
        shadowing_destination_port_ranges=shadowing["destination_port_ranges"],
        shadowing_action=shadowing["action"],
        raw_rule_context=shadowed_rule,
        raw_shadowing_rule_context=shadowing_rule,
    )


def _azure_shadow_evidence(
    nsg_name, direction, name, priority, shadowing_name, shadowing_priority
):
    return (
        f"nsg={nsg_name}; direction={direction}; "
        f"shadowing_rule={shadowing_name}; shadowing_priority={shadowing_priority}; "
        f"shadowed_rule={name}; shadowed_priority={priority}"
    )


def check_shadow_rules_azure(nsgs):
    """Detect shadowed rules in Azure NSG security rules.

    Azure evaluates NSG rules in ascending priority order (lower number first).
    A rule is shadowed when an earlier (lower-priority-number) rule already
    covers the same or broader source, destination port, and protocol scope.
    """
    findings = []

    for nsg in nsgs:
        nsg_name = nsg.get("name", "unnamed")
        all_rules = nsg.get("securityRules", [])

        for direction in ("Inbound", "Outbound"):
            dir_rules = [
                r
                for r in all_rules
                if (r.get("properties", r)).get("direction") == direction
            ]
            sorted_rules = sorted(
                dir_rules,
                key=lambda r: int((r.get("properties", r)).get("priority", 999)),
            )

            active = []  # (name, priority, src_any, port_any, proto, rule)

            for rule in sorted_rules:
                props = rule.get("properties", rule)
                name = rule.get("name", "unnamed")
                priority = props.get("priority", "?")
                src_any = _azure_src_any(props)
                port_any = _azure_port_any(props)
                proto = props.get("protocol", "*")

                for (
                    e_name,
                    e_prio,
                    e_src_any,
                    e_port_any,
                    e_proto,
                    earlier_rule,
                ) in active:
                    proto_covered = e_proto in ("*", proto)
                    # broad rule covers narrow if it is at least as permissive in every dimension
                    if (
                        (e_src_any or not src_any)
                        and (e_port_any or not port_any)
                        and proto_covered
                    ):
                        findings.append(
                            _f(
                                "HIGH",
                                "redundancy",
                                f"[HIGH] NSG '{nsg_name}' {direction} rule '{name}' (priority {priority}) "
                                f"is shadowed by rule '{e_name}' (priority {e_prio}) — it will never be evaluated",
                                f"Rule '{e_name}' has a higher priority (lower number) and covers the "
                                f"same or broader scope. Remove '{name}' if it is redundant, or adjust "
                                f"its scope to handle traffic not already processed by '{e_name}'.",
                                id=_azure_shadow_id(
                                    nsg_name, direction, name, priority, e_name, e_prio
                                ),
                                vendor="azure",
                                title="Azure NSG rule is shadowed",
                                evidence=_azure_shadow_evidence(
                                    nsg_name, direction, name, priority, e_name, e_prio
                                ),
                                affected_object=name,
                                rule_id=str(priority),
                                rule_name=name,
                                confidence="medium",
                                verification="Review NSG effective security rules, then re-run the audit after removing, narrowing, or reprioritizing the shadowed rule.",
                                rollback=(
                                    "Restore the previous NSG rule priority or scope "
                                    "from Azure activity logs, IaC, or a saved NSG "
                                    "export if removing or reprioritizing the rule "
                                    "blocks approved traffic."
                                ),
                                metadata=_azure_shadow_metadata(
                                    nsg, direction, rule, earlier_rule
                                ),
                            )
                        )
                        break

                active.append((name, priority, src_any, port_any, proto, rule))

    return findings


# ── Juniper SRX ──────────────────────────────────────────────────────────────

_JUNIPER_BROAD = {"any", "any-ipv4", "any-ipv6"}


def check_shadow_rules_juniper(policies: list) -> list:
    """Detect shadowed rules in a Juniper SRX security policy.

    Juniper evaluates policies top-to-bottom within each from-zone/to-zone pair.
    A policy is shadowed when an earlier policy in the same zone pair covers a
    superset of its source-address, destination-address, and application scope.
    """
    findings = []
    # Group active (non-disabled) policies by zone pair
    zone_pairs: dict = {}
    for p in policies:
        if p.get("disabled"):
            continue
        key = (p.get("from_zone", ""), p.get("to_zone", ""))
        zone_pairs.setdefault(key, []).append(p)

    for (fz, tz), pollist in zone_pairs.items():
        active: list[tuple] = []  # list of (name, src, dst, app, action)

        for p in pollist:
            name = p.get("name", "unnamed")
            src = [s.lower() for s in (p.get("src") or ["any"])]
            dst = [d.lower() for d in (p.get("dst") or ["any"])]
            app = [a.lower() for a in (p.get("app") or ["any"])]

            for e_name, e_src, e_dst, e_app, _ in active:
                if _covers(e_src, src) and _covers(e_dst, dst) and _covers(e_app, app):
                    findings.append(
                        _f(
                            "HIGH",
                            "redundancy",
                            f"[HIGH] Zone pair {fz}→{tz}: policy '{name}' is shadowed by earlier policy "
                            f"'{e_name}' — it will never be evaluated.",
                            f"Review policies in from-zone {fz} to-zone {tz}.  Either remove '{name}' "
                            f"if it is redundant, or reorder it before '{e_name}', or narrow the scope "
                            f"of '{e_name}' so that '{name}' can be reached.",
                            id="CASHEL-JUNIPER-REDUNDANCY-001",
                            vendor="juniper",
                            title="Juniper policy is shadowed",
                            evidence=f"Zone pair {fz}->{tz}: policy '{e_name}' covers policy '{name}'",
                            affected_object=name,
                            rule_name=name,
                            confidence="medium",
                            verification="Review policy order for the zone pair, then re-run the audit after removing, narrowing, or moving the shadowed policy.",
                            metadata=_shadow_metadata(
                                name,
                                e_name,
                                from_zone=fz,
                                to_zone=tz,
                                source=src,
                                destination=dst,
                                application=app,
                            ),
                        )
                    )
                    break

            active.append((name, src, dst, app, p.get("action")))

    return findings


# ── Dispatch ─────────────────────────────────────────────────────────────────


def run_rule_quality_checks(vendor: str, parse, extra_data) -> list:
    """Run rule quality (shadow detection) checks for the given vendor.

    Args:
        vendor:     Vendor string (asa, ftd, paloalto, fortinet, pfsense, azure).
                    AWS SGs are excluded — their rules have no evaluation order.
        parse:      CiscoConfParse object for asa/ftd; None for all other vendors.
        extra_data: Parsed rules/policies list for non-Cisco vendors; None for asa/ftd.

    Returns a (possibly empty) list of finding dicts.  Never raises — errors are
    swallowed so that a rule-quality bug cannot break the main audit.
    """
    try:
        if vendor in ("asa", "ftd") and parse is not None:
            return check_shadow_rules_asa(parse, vendor=vendor)
        if vendor == "paloalto" and extra_data:
            return check_shadow_rules_pa(extra_data)
        if vendor == "fortinet" and extra_data:
            return check_shadow_rules_forti(extra_data)
        if vendor == "pfsense" and extra_data:
            return check_shadow_rules_pfsense(extra_data)
        if vendor == "azure" and extra_data:
            return check_shadow_rules_azure(extra_data)
        if vendor == "juniper" and extra_data:
            return check_shadow_rules_juniper(extra_data)
    except Exception:
        pass  # Never let rule-quality analysis break the main audit flow

    return []
