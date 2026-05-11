"""Shared audit engine utilities used by both web.py and scheduler_runner.py.

Extracts the vendor-dispatch logic and finding helpers so they can be
imported without creating circular dependencies.
"""

from ciscoconfparse import CiscoConfParse

from .models.findings import make_finding


# ── Finding helpers ────────────────────────────────────────────────────────────


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


def _finding_msg(f):
    return f["message"] if isinstance(f, dict) else f


def _findings_to_strings(findings):
    return [_finding_msg(f) for f in findings]


def _wrap_compliance(s):
    if isinstance(s, dict):
        return s
    sev = "HIGH" if any(x in s for x in ("-HIGH", "[HIGH]")) else "MEDIUM"
    return {
        "severity": sev,
        "category": "compliance",
        "message": s,
        "remediation": None,
    }


def _sort_findings(findings: list) -> list:
    def priority(f):
        msg = _finding_msg(f)
        is_comp = any(
            x in msg for x in ("PCI-", "CIS-", "NIST-", "HIPAA-", "SOC2-", "STIG-")
        )
        if "[CRITICAL]" in msg and not is_comp:
            return 0
        if "[HIGH]" in msg and not is_comp:
            return 1
        if "[MEDIUM]" in msg and not is_comp:
            return 2
        if "STIG-CAT-I" in msg:
            return 3
        if "HIGH" in msg and is_comp:
            return 3
        if "STIG-CAT-II" in msg:
            return 4
        if "MEDIUM" in msg and is_comp:
            return 4
        return 5

    return sorted(findings, key=priority)


def _build_summary(findings):
    def _count(tag):
        return len([f for f in findings if tag in _finding_msg(f)])

    _comp_tags = ["PCI-", "CIS-", "NIST-", "HIPAA-", "SOC2-", "STIG-"]
    critical = [
        f
        for f in findings
        if "[CRITICAL]" in _finding_msg(f)
        and not any(x in _finding_msg(f) for x in _comp_tags)
    ]
    high = [
        f
        for f in findings
        if "[HIGH]" in _finding_msg(f)
        and not any(x in _finding_msg(f) for x in _comp_tags)
    ]
    medium = [
        f
        for f in findings
        if "[MEDIUM]" in _finding_msg(f)
        and not any(x in _finding_msg(f) for x in _comp_tags)
    ]
    score = max(0, 100 - len(critical) * 20 - len(high) * 10 - len(medium) * 3)
    return {
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "pci_high": _count("PCI-HIGH"),
        "pci_medium": _count("PCI-MEDIUM"),
        "cis_high": _count("CIS-HIGH"),
        "cis_medium": _count("CIS-MEDIUM"),
        "nist_high": _count("NIST-HIGH"),
        "nist_medium": _count("NIST-MEDIUM"),
        "hipaa_high": _count("HIPAA-HIGH"),
        "hipaa_medium": _count("HIPAA-MEDIUM"),
        "soc2_high": _count("SOC2-HIGH"),
        "soc2_medium": _count("SOC2-MEDIUM"),
        "stig_cat_i": _count("STIG-CAT-I]"),
        "stig_cat_ii": _count("STIG-CAT-II]"),
        "stig_cat_iii": _count("STIG-CAT-III]"),
        "total": len(findings),
        "score": score,
    }


# ── ASA audit helpers ──────────────────────────────────────────────────────────


def _acl_name_from_line(line: str) -> str | None:
    parts = line.strip().split()
    if len(parts) >= 2 and parts[0].lower() == "access-list":
        return parts[1]
    return None


def _dedupe_stable(values):
    seen = set()
    out = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        key = text.lower()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _asa_broad_value(value: str) -> bool:
    return str(value).strip().lower() in {"any", "any4", "any6", "*"}


def _normalize_asa_value(value: str) -> str:
    text = str(value).strip()
    return "any" if _asa_broad_value(text) else text


def _asa_obj_lines(parse):
    return [obj for obj in parse.ConfigObjs if obj.text and not obj.text[:1].isspace()]


def parse_asa_network_objects(parse):
    objects = {}
    for obj in _asa_obj_lines(parse):
        parts = obj.text.strip().split()
        if len(parts) < 3 or parts[:2] != ["object", "network"]:
            continue
        name = parts[2]
        entry = {
            "name": name,
            "type": "unknown",
            "value": name,
            "raw_lines": [obj.text.strip()],
        }
        for child in obj.children:
            line = child.text.strip()
            entry["raw_lines"].append(line)
            tokens = line.split()
            if len(tokens) >= 2 and tokens[0] == "host":
                entry.update({"type": "host", "value": tokens[1]})
            elif len(tokens) >= 3 and tokens[0] == "subnet":
                entry.update({"type": "subnet", "value": f"{tokens[1]} {tokens[2]}"})
            elif len(tokens) >= 3 and tokens[0] == "range":
                entry.update({"type": "range", "value": f"{tokens[1]}-{tokens[2]}"})
        objects[name] = entry
    return objects


def parse_asa_network_object_groups(parse):
    groups = {}
    for obj in _asa_obj_lines(parse):
        parts = obj.text.strip().split()
        if len(parts) < 3 or parts[:2] != ["object-group", "network"]:
            continue
        name = parts[2]
        entry = {
            "name": name,
            "members": [],
            "group_members": [],
            "raw_lines": [obj.text.strip()],
        }
        for child in obj.children:
            line = child.text.strip()
            entry["raw_lines"].append(line)
            tokens = line.split()
            if len(tokens) >= 2 and tokens[0] == "group-object":
                entry["group_members"].append(tokens[1])
            elif len(tokens) >= 3 and tokens[:2] == ["network-object", "object"]:
                entry["members"].append({"kind": "object", "value": tokens[2]})
            elif len(tokens) >= 3 and tokens[:2] == ["network-object", "host"]:
                entry["members"].append({"kind": "literal", "value": tokens[2]})
            elif len(tokens) >= 3 and tokens[0] == "network-object":
                value = (
                    "any" if _asa_broad_value(tokens[1]) else f"{tokens[1]} {tokens[2]}"
                )
                entry["members"].append({"kind": "literal", "value": value})
        groups[name] = entry
    return groups


def parse_asa_service_objects(parse):
    services = {}
    for obj in _asa_obj_lines(parse):
        parts = obj.text.strip().split()
        if len(parts) < 3 or parts[:2] != ["object", "service"]:
            continue
        name = parts[2]
        entry = {
            "name": name,
            "protocol": None,
            "source_operator": None,
            "source_port": None,
            "destination_operator": None,
            "destination_port": None,
            "raw_lines": [obj.text.strip()],
        }
        for child in obj.children:
            line = child.text.strip()
            entry["raw_lines"].append(line)
            tokens = line.split()
            if len(tokens) >= 2 and tokens[0] == "service":
                entry["protocol"] = tokens[1].lower()
                if "source" in tokens:
                    idx = tokens.index("source")
                    if len(tokens) > idx + 2:
                        entry["source_operator"] = tokens[idx + 1]
                        entry["source_port"] = tokens[idx + 2]
                if "destination" in tokens:
                    idx = tokens.index("destination")
                    if len(tokens) > idx + 2:
                        entry["destination_operator"] = tokens[idx + 1]
                        entry["destination_port"] = tokens[idx + 2]
        services[name] = entry
    return services


def parse_asa_service_object_groups(parse):
    groups = {}
    for obj in _asa_obj_lines(parse):
        parts = obj.text.strip().split()
        if len(parts) < 3 or parts[:2] != ["object-group", "service"]:
            continue
        name = parts[2]
        entry = {
            "name": name,
            "protocol": parts[3].lower() if len(parts) > 3 else None,
            "port_objects": [],
            "service_objects": [],
            "group_members": [],
            "raw_lines": [obj.text.strip()],
        }
        for child in obj.children:
            line = child.text.strip()
            entry["raw_lines"].append(line)
            tokens = line.split()
            if len(tokens) >= 2 and tokens[0] == "group-object":
                entry["group_members"].append(tokens[1])
            elif len(tokens) >= 3 and tokens[:2] == ["service-object", "object"]:
                entry["service_objects"].append({"kind": "object", "value": tokens[2]})
            elif len(tokens) >= 2 and tokens[0] == "service-object":
                entry["service_objects"].append(
                    {"kind": "literal", "tokens": tokens[1:]}
                )
            elif len(tokens) >= 3 and tokens[0] == "port-object":
                entry["port_objects"].append({"operator": tokens[1], "port": tokens[2]})
        groups[name] = entry
    return groups


def parse_asa_object_context(parse):
    return {
        "network_objects": parse_asa_network_objects(parse),
        "network_groups": parse_asa_network_object_groups(parse),
        "service_objects": parse_asa_service_objects(parse),
        "service_groups": parse_asa_service_object_groups(parse),
    }


def expand_asa_address(name, objects, groups, _seen=None):
    text = _normalize_asa_value(name)
    if text == "any":
        return ["any"]
    seen = _seen or set()
    key = text.lower()
    if key in seen:
        return []
    seen.add(key)
    if text in objects:
        return [_normalize_asa_value(objects[text].get("value", text))]
    if text in groups:
        group = groups[text]
        expanded = []
        for member in group.get("members", []):
            if member["kind"] == "object":
                expanded += expand_asa_address(
                    member["value"], objects, groups, seen.copy()
                )
            else:
                expanded.append(_normalize_asa_value(member["value"]))
        for group_name in group.get("group_members", []):
            expanded += expand_asa_address(group_name, objects, groups, seen.copy())
        return _dedupe_stable(expanded)
    return [text]


def expand_asa_addresses(names, objects, groups):
    return _dedupe_stable(
        value for name in names for value in expand_asa_address(name, objects, groups)
    )


def _format_asa_service(protocol, operator=None, port=None):
    proto = (protocol or "ip").lower()
    if _asa_broad_value(proto):
        return "any"
    if not port:
        return proto
    if str(port).lower() in {"any", "*"}:
        return proto
    return f"{proto}/{port}"


def expand_asa_service(name, services, service_groups, _seen=None):
    text = _normalize_asa_value(name)
    if text == "any":
        return ["any"]
    seen = _seen or set()
    key = text.lower()
    if key in seen:
        return []
    seen.add(key)
    if text in services:
        service = services[text]
        return [
            _format_asa_service(
                service.get("protocol"),
                service.get("destination_operator") or service.get("source_operator"),
                service.get("destination_port") or service.get("source_port"),
            )
        ]
    if text in service_groups:
        group = service_groups[text]
        expanded = []
        for port_obj in group.get("port_objects", []):
            expanded.append(
                _format_asa_service(group.get("protocol"), port=port_obj.get("port"))
            )
        for service_obj in group.get("service_objects", []):
            if service_obj["kind"] == "object":
                expanded += expand_asa_service(
                    service_obj["value"], services, service_groups, seen.copy()
                )
            else:
                tokens = service_obj.get("tokens", [])
                proto = tokens[0].lower() if tokens else group.get("protocol")
                port = None
                if "destination" in tokens:
                    idx = tokens.index("destination")
                    if len(tokens) > idx + 2:
                        port = tokens[idx + 2]
                elif "eq" in tokens:
                    idx = tokens.index("eq")
                    if len(tokens) > idx + 1:
                        port = tokens[idx + 1]
                expanded.append(_format_asa_service(proto, port=port))
        for group_name in group.get("group_members", []):
            expanded += expand_asa_service(
                group_name, services, service_groups, seen.copy()
            )
        return _dedupe_stable(expanded)
    return [text]


def expand_asa_services(names, services, service_groups):
    return _dedupe_stable(
        value
        for name in names
        for value in expand_asa_service(name, services, service_groups)
    )


def _parse_asa_endpoint(tokens, idx):
    if idx >= len(tokens):
        return {"raw": "", "refs": []}, idx
    token = tokens[idx].lower()
    if _asa_broad_value(token):
        return {"raw": "any", "refs": ["any"]}, idx + 1
    if token in {"object", "object-group"} and idx + 1 < len(tokens):
        return {"raw": f"{token} {tokens[idx + 1]}", "refs": [tokens[idx + 1]]}, idx + 2
    if token == "host" and idx + 1 < len(tokens):
        return {"raw": f"host {tokens[idx + 1]}", "refs": [tokens[idx + 1]]}, idx + 2
    if idx + 1 < len(tokens):
        return {
            "raw": f"{tokens[idx]} {tokens[idx + 1]}",
            "refs": [f"{tokens[idx]} {tokens[idx + 1]}"],
        }, idx + 2
    return {"raw": tokens[idx], "refs": [tokens[idx]]}, idx + 1


def _parse_asa_acl_line(line, context=None):
    parts = line.strip().split()
    if len(parts) < 6 or parts[0].lower() != "access-list":
        return None
    idx = 2
    if idx < len(parts) and parts[idx].lower() == "line":
        idx += 2
    if idx < len(parts) and parts[idx].lower() == "extended":
        idx += 1
    if len(parts) <= idx + 1:
        return None
    action = parts[idx].lower()
    protocol = parts[idx + 1].lower()
    idx += 2
    service_refs = []
    if protocol == "object-group" and idx < len(parts):
        service_refs.append(parts[idx])
        protocol = f"object-group {parts[idx]}"
        idx += 1
    src, idx = _parse_asa_endpoint(parts, idx)
    dst, idx = _parse_asa_endpoint(parts, idx)
    service_raw = " ".join(parts[idx:])
    if service_raw:
        if (
            len(parts) > idx
            and parts[idx].lower() == "object-group"
            and len(parts) > idx + 1
        ):
            service_refs.append(parts[idx + 1])
        elif (
            len(parts) > idx and parts[idx].lower() == "object" and len(parts) > idx + 1
        ):
            service_refs.append(parts[idx + 1])
        elif (
            len(parts) > idx
            and parts[idx].lower() in {"eq", "lt", "gt", "neq", "range"}
            and len(parts) > idx + 1
        ):
            service_refs.append(f"{protocol}/{parts[idx + 1]}")
        else:
            service_refs.append(service_raw)
    elif protocol in {"tcp", "udp", "icmp"}:
        service_refs.append(protocol)
    elif protocol in {"ip", "any"}:
        service_refs.append("any")
    ctx = context or {}
    expanded_source = expand_asa_addresses(
        src["refs"], ctx.get("network_objects", {}), ctx.get("network_groups", {})
    )
    expanded_destination = expand_asa_addresses(
        dst["refs"], ctx.get("network_objects", {}), ctx.get("network_groups", {})
    )
    expanded_service = expand_asa_services(
        service_refs, ctx.get("service_objects", {}), ctx.get("service_groups", {})
    )
    if protocol.startswith("object-group "):
        expanded_service = expand_asa_services(
            [protocol.split(" ", 1)[1]],
            ctx.get("service_objects", {}),
            ctx.get("service_groups", {}),
        )
    return {
        "acl_name": parts[1],
        "action": action,
        "protocol": protocol,
        "raw_source": src["raw"],
        "raw_destination": dst["raw"],
        "raw_service": service_raw or protocol,
        "expanded_source": expanded_source,
        "expanded_destination": expanded_destination,
        "expanded_service": expanded_service,
        "acl_line": line.strip(),
    }


def _asa_acl_entries(parse, context=None, action=None):
    entries = []
    for obj in parse.find_objects(
        r"^access-list\s+\S+\s+(?:line\s+\d+\s+)?(?:extended\s+)?(?:permit|deny)"
    ):
        parsed = _parse_asa_acl_line(obj.text, context)
        if parsed and (action is None or parsed["action"] == action):
            entries.append(parsed)
    return entries


def _asa_metadata(entry, extra=None):
    metadata = {
        "acl_name": entry["acl_name"],
        "acl_line": entry["acl_line"],
        "action": entry["action"],
        "protocol": entry["protocol"],
        "raw_source": entry["raw_source"],
        "raw_destination": entry["raw_destination"],
        "raw_service": entry["raw_service"],
        "expanded_source": entry["expanded_source"],
        "expanded_destination": entry["expanded_destination"],
        "expanded_service": entry["expanded_service"],
    }
    if extra:
        metadata.update(extra)
    return metadata


def _asa_scope_is_any(values):
    return any(_asa_broad_value(value) for value in values)


def _check_any_any(parse):
    context = parse_asa_object_context(parse)
    findings = []
    for entry in _asa_acl_entries(parse, context, action="permit"):
        if not (
            entry["protocol"] in {"ip", "any"}
            and _asa_scope_is_any(entry["expanded_source"])
            and _asa_scope_is_any(entry["expanded_destination"])
        ):
            continue
        findings.append(
            _f(
                "CRITICAL",
                "exposure",
                f"[CRITICAL] Overly permissive rule found: {entry['acl_line']}",
                "Restrict source and destination to specific IP ranges. "
                "Remove or scope down any/any permit rules to enforce least-privilege access.",
                id="CASHEL-ASA-EXPOSURE-001",
                vendor="asa",
                title="Overly permissive any-any ACL rule",
                evidence=entry["acl_line"],
                affected_object=entry["acl_name"],
                rule_name=entry["acl_name"],
                confidence="high",
                impact="The rule may allow traffic from any source to any destination.",
                verification="Review hit counts and traffic logs, then re-run the audit after replacing the rule with scoped source and destination objects.",
                rollback="Restore the original ACL entry from configuration backup if the scoped replacement blocks required traffic.",
                suggested_commands=[
                    "no access-list <ACL_NAME> permit ip any any",
                    "access-list <ACL_NAME> permit ip <SRC_NET> <SRC_MASK> <DST_NET> <DST_MASK> log",
                ],
                metadata=_asa_metadata(entry),
            )
        )
    return findings


def _check_missing_logging(parse):
    context = parse_asa_object_context(parse)
    findings = []
    for entry in _asa_acl_entries(parse, context, action="permit"):
        if "log" in entry["acl_line"]:
            continue
        findings.append(
            _f(
                "MEDIUM",
                "logging",
                f"[MEDIUM] Permit rule missing logging: {entry['acl_line']}",
                "Add the 'log' keyword to all permit rules. "
                "Without logging, permitted traffic produces no syslog entries for monitoring.",
                id="CASHEL-ASA-LOGGING-001",
                vendor="asa",
                title="Permit ACL rule missing logging",
                evidence=entry["acl_line"],
                affected_object=entry["acl_name"],
                rule_name=entry["acl_name"],
                confidence="high",
                impact="Permitted traffic for this rule may not be visible in syslog or incident review.",
                verification="Confirm the rule includes the log keyword and verify new matching traffic appears in syslog.",
                rollback="Remove the log keyword from this ACL entry if logging volume causes operational issues.",
                suggested_commands=[f"{entry['acl_line']} log"],
                metadata=_asa_metadata(entry),
            )
        )
    return findings


def _check_deny_all(parse):
    context = parse_asa_object_context(parse)
    for entry in _asa_acl_entries(parse, context, action="deny"):
        if (
            entry["protocol"] in {"ip", "any"}
            and _asa_scope_is_any(entry["expanded_source"])
            and _asa_scope_is_any(entry["expanded_destination"])
        ):
            return []
    if parse.find_objects(r"access-list.*deny ip any any"):
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found at end of ACL",
            "Add an explicit 'access-list <name> deny ip any any log' at the end of each ACL. "
            "Relying on implicit deny produces no log entries and is not auditable.",
            id="CASHEL-ASA-HYGIENE-001",
            vendor="asa",
            title="Explicit deny-all ACL rule missing",
            evidence=None,
            affected_object="ACL termination",
            rule_name="explicit deny-all",
            confidence="medium",
            impact="Traffic denied by the implicit rule may not produce auditable deny logs.",
            verification="Confirm each ACL terminates with an explicit deny ip any any log entry, then re-run the audit.",
            rollback="Remove the added explicit deny entry if it creates unexpected logging or policy behavior.",
            suggested_commands=["access-list <ACL_NAME> deny ip any any log"],
        )
    ]


def _check_redundant_rules(parse):
    findings, seen = [], {}
    context = parse_asa_object_context(parse)
    for entry in _asa_acl_entries(parse, context, action="permit"):
        key = (
            entry["acl_name"].lower(),
            entry["action"],
            tuple(v.lower() for v in entry["expanded_source"]),
            tuple(v.lower() for v in entry["expanded_destination"]),
            tuple(v.lower() for v in entry["expanded_service"]),
        )
        if key in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: {entry['acl_line']}",
                    "Remove duplicate ACL entries to keep the access-list clean and auditable. "
                    "Redundant rules indicate configuration drift and complicate change management.",
                    id="CASHEL-ASA-REDUNDANCY-001",
                    vendor="asa",
                    title="Redundant ACL rule",
                    evidence=entry["acl_line"],
                    affected_object=entry["acl_name"],
                    rule_name=entry["acl_name"],
                    confidence="high",
                    impact="Duplicate ACL entries add review noise and can obscure intentional policy changes.",
                    verification="Confirm the remaining ACL entry preserves intended access and re-run the audit.",
                    rollback="Re-add the duplicate ACL entry from backup if removal affects an approved workflow.",
                    suggested_commands=["no <DUPLICATE_ACCESS_LIST_LINE>"],
                    metadata=_asa_metadata(
                        entry,
                        {
                            "duplicate_normalized_rule": " ".join(
                                [
                                    entry["acl_name"],
                                    entry["action"],
                                    entry["protocol"],
                                    ",".join(entry["expanded_source"]),
                                    ",".join(entry["expanded_destination"]),
                                    ",".join(entry["expanded_service"]),
                                ]
                            ),
                            "duplicate_of": seen[key]["acl_line"],
                        },
                    ),
                )
            )
        else:
            seen[key] = entry
    return findings


def _check_telnet_asa(parse):
    findings = [
        _f(
            "CRITICAL",
            "protocol",
            f"[CRITICAL] Telnet management access configured: {r.text.strip()}",
            "Disable Telnet management (no telnet ...) and enforce SSH. "
            "Telnet transmits all data including credentials in cleartext.",
            id="CASHEL-ASA-PROTOCOL-001",
            vendor="asa",
            title="Telnet management access enabled",
            evidence=r.text.strip(),
            affected_object="management access",
            confidence="high",
            impact="Telnet sends management credentials and session data in cleartext.",
            verification="Confirm no telnet lines remain and SSH management access is available from approved networks.",
            rollback="Restore the removed telnet line only if emergency access is required and compensating controls are approved.",
            suggested_commands=[f"no {r.text.strip()}"],
        )
        for r in parse.find_objects(r"^telnet\s")
    ]
    context = parse_asa_object_context(parse)
    for entry in _asa_acl_entries(parse, context, action="permit"):
        if not any(
            service.lower() in {"tcp/23", "telnet"}
            for service in entry["expanded_service"]
        ):
            continue
        findings.append(
            _f(
                "CRITICAL",
                "protocol",
                f"[CRITICAL] Telnet service permitted by ACL: {entry['acl_line']}",
                "Replace Telnet with SSH or a secure application protocol and scope the rule to approved sources only.",
                id="CASHEL-ASA-PROTOCOL-002",
                vendor="asa",
                title="Telnet service permitted by ACL",
                evidence=entry["acl_line"],
                affected_object=entry["acl_name"],
                rule_name=entry["acl_name"],
                confidence="high",
                impact="Telnet sends credentials and session data in cleartext when used by matching traffic.",
                verification="Confirm tcp/23 is removed from the ACL or service group, then re-run the audit.",
                rollback="Restore the prior ACL or service-group entry from backup only if an approved exception requires Telnet.",
                suggested_commands=["no <TELNET_ACCESS_LIST_LINE>"],
                metadata=_asa_metadata(entry),
            )
        )
    return findings


def _check_icmp_any_asa(parse):
    context = parse_asa_object_context(parse)
    findings = []
    for entry in _asa_acl_entries(parse, context, action="permit"):
        if not (
            entry["protocol"] == "icmp"
            and _asa_scope_is_any(entry["expanded_source"])
            and _asa_scope_is_any(entry["expanded_destination"])
        ):
            continue
        findings.append(
            _f(
                "MEDIUM",
                "exposure",
                f"[MEDIUM] Unrestricted ICMP permit rule: {entry['acl_line']}",
                "Restrict ICMP to specific source ranges or permit only echo-reply, "
                "unreachable, and time-exceeded message types needed for diagnostics.",
                id="CASHEL-ASA-EXPOSURE-002",
                vendor="asa",
                title="Unrestricted ICMP any-any ACL rule",
                evidence=entry["acl_line"],
                affected_object=entry["acl_name"],
                rule_name=entry["acl_name"],
                confidence="high",
                impact="Unrestricted ICMP can increase reconnaissance signal and bypass intended diagnostic scoping.",
                verification="Confirm ICMP is limited to approved sources and required message types, then re-run the audit.",
                rollback="Restore the original ICMP ACL entry from backup if troubleshooting traffic is unintentionally blocked.",
                suggested_commands=[
                    "no access-list <ACL_NAME> permit icmp any any",
                    "access-list <ACL_NAME> permit icmp <TRUSTED_SRC> <MASK> any echo-reply log",
                ],
                metadata=_asa_metadata(entry),
            )
        )
    return findings


def _audit_asa(filepath):
    parse = CiscoConfParse(filepath, ignore_blank_lines=False)
    findings = (
        _check_any_any(parse)
        + _check_missing_logging(parse)
        + _check_deny_all(parse)
        + _check_redundant_rules(parse)
        + _check_telnet_asa(parse)
        + _check_icmp_any_asa(parse)
    )
    return findings, parse


# ── Vendor dispatch ────────────────────────────────────────────────────────────


def run_vendor_audit(vendor: str, temp_path: str):
    """
    Run the appropriate auditor for the given vendor.
    Returns (findings, parse_obj_or_None, extra_data_or_None).
    parse_obj is set for ASA/FTD (CiscoConfParse).
    extra_data is set for Fortinet/pfSense (list of policy dicts).

    Rule quality checks (shadow detection) are appended to findings automatically
    for all vendors that support ordered rule evaluation.
    """
    from .ftd import audit_ftd
    from .paloalto import audit_paloalto
    from .fortinet import audit_fortinet
    from .iptables import audit_iptables, audit_nftables
    from .pfsense import audit_pfsense
    from .aws import audit_aws_sg
    from .azure import audit_azure_nsg
    from .juniper import audit_juniper
    from .gcp import audit_gcp_firewall
    from .rule_quality import run_rule_quality_checks

    if vendor == "ftd":
        findings, parse = audit_ftd(temp_path)
        findings += run_rule_quality_checks(vendor, parse, None)
        return findings, parse, None
    if vendor == "asa":
        findings, parse = _audit_asa(temp_path)
        findings += run_rule_quality_checks(vendor, parse, None)
        return findings, parse, None
    if vendor == "paloalto":
        findings, rules = audit_paloalto(temp_path)
        findings += run_rule_quality_checks(vendor, None, rules)
        return (
            findings,
            None,
            rules,
        )  # rules returned as extra_data for compliance reuse
    if vendor == "fortinet":
        findings, extra_data = audit_fortinet(temp_path)
        findings += run_rule_quality_checks(vendor, None, extra_data)
        return findings, None, extra_data
    if vendor == "pfsense":
        findings, extra_data = audit_pfsense(temp_path)
        findings += run_rule_quality_checks(vendor, None, extra_data)
        return findings, None, extra_data
    if vendor == "aws":
        # AWS SG rules have no evaluation order (most-permissive wins);
        # shadow detection does not apply.
        findings, extra_data = audit_aws_sg(temp_path)
        return findings, None, extra_data
    if vendor == "azure":
        findings, extra_data = audit_azure_nsg(temp_path)
        findings += run_rule_quality_checks(vendor, None, extra_data)
        return findings, None, extra_data
    if vendor == "juniper":
        findings, policies = audit_juniper(temp_path)
        findings += run_rule_quality_checks(vendor, None, policies)
        return findings, None, policies
    if vendor == "gcp":
        # GCP firewall rules have no strict evaluation order per-rule (priority-based);
        # shadow detection is not applied (similar to AWS SGs).
        findings, extra_data = audit_gcp_firewall(temp_path)
        return findings, None, extra_data
    if vendor == "iptables":
        # iptables rules are ordered; shadow detection not yet implemented for host firewalls.
        findings, extra_data = audit_iptables(temp_path)
        return findings, None, extra_data
    if vendor == "nftables":
        findings, extra_data = audit_nftables(temp_path)
        return findings, None, extra_data
    raise ValueError(f"Unknown vendor: {vendor}")


def run_compliance_checks(
    vendor: str, compliance: str, parse, extra_data, temp_path: str = ""
) -> list:
    """Run compliance checks for the given vendor and framework. Returns raw finding strings.

    For paloalto, extra_data should be the rules list returned by run_vendor_audit — the file
    is NOT re-parsed here, eliminating the double-parse that would otherwise occur.
    """
    from .compliance import (
        check_cis_compliance,
        check_pci_compliance,
        check_nist_compliance,
        check_hipaa_compliance,
        check_soc2_compliance,
        check_stig_compliance,
        check_cis_compliance_ftd,
        check_pci_compliance_ftd,
        check_nist_compliance_ftd,
        check_hipaa_compliance_ftd,
        check_soc2_compliance_ftd,
        check_stig_compliance_ftd,
        check_cis_compliance_pa,
        check_pci_compliance_pa,
        check_nist_compliance_pa,
        check_hipaa_compliance_pa,
        check_soc2_compliance_pa,
        check_stig_compliance_pa,
        check_cis_compliance_forti,
        check_pci_compliance_forti,
        check_nist_compliance_forti,
        check_hipaa_compliance_forti,
        check_soc2_compliance_forti,
        check_stig_compliance_forti,
        check_cis_compliance_pf,
        check_pci_compliance_pf,
        check_nist_compliance_pf,
        check_hipaa_compliance_pf,
        check_soc2_compliance_pf,
        check_stig_compliance_pf,
        check_cis_compliance_juniper,
        check_pci_compliance_juniper,
        check_nist_compliance_juniper,
        check_hipaa_compliance_juniper,
        check_soc2_compliance_juniper,
        check_stig_compliance_juniper,
    )

    if vendor in ("aws", "azure", "gcp", "iptables", "nftables"):
        return []

    fn_map: dict = {}
    juniper_data = None
    if vendor == "juniper":
        # Compliance checks need both raw content and parsed policies;
        # extra_data from run_vendor_audit is the policies list.
        try:
            with open(temp_path) as _fh:
                _content = _fh.read()
        except OSError:
            _content = ""
        juniper_data = {"content": _content, "policies": extra_data or []}

    if vendor == "asa":
        fn_map = {
            "cis": (check_cis_compliance, parse),
            "hipaa": (check_hipaa_compliance, parse),
            "nist": (check_nist_compliance, parse),
            "pci": (check_pci_compliance, parse),
            "soc2": (check_soc2_compliance, parse),
            "stig": (check_stig_compliance, parse),
        }
    elif vendor == "ftd":
        fn_map = {
            "cis": (check_cis_compliance_ftd, parse),
            "hipaa": (check_hipaa_compliance_ftd, parse),
            "nist": (check_nist_compliance_ftd, parse),
            "pci": (check_pci_compliance_ftd, parse),
            "soc2": (check_soc2_compliance_ftd, parse),
            "stig": (check_stig_compliance_ftd, parse),
        }
    elif vendor == "paloalto":
        # extra_data is the rules list already parsed by run_vendor_audit — no re-parse needed
        rules = extra_data or []
        fn_map = {
            "cis": (check_cis_compliance_pa, rules),
            "hipaa": (check_hipaa_compliance_pa, rules),
            "nist": (check_nist_compliance_pa, rules),
            "pci": (check_pci_compliance_pa, rules),
            "soc2": (check_soc2_compliance_pa, rules),
            "stig": (check_stig_compliance_pa, rules),
        }
    elif vendor == "fortinet":
        fn_map = {
            "cis": (check_cis_compliance_forti, extra_data),
            "hipaa": (check_hipaa_compliance_forti, extra_data),
            "nist": (check_nist_compliance_forti, extra_data),
            "pci": (check_pci_compliance_forti, extra_data),
            "soc2": (check_soc2_compliance_forti, extra_data),
            "stig": (check_stig_compliance_forti, extra_data),
        }
    elif vendor == "pfsense":
        fn_map = {
            "cis": (check_cis_compliance_pf, extra_data),
            "hipaa": (check_hipaa_compliance_pf, extra_data),
            "nist": (check_nist_compliance_pf, extra_data),
            "pci": (check_pci_compliance_pf, extra_data),
            "soc2": (check_soc2_compliance_pf, extra_data),
            "stig": (check_stig_compliance_pf, extra_data),
        }
    elif vendor == "juniper":
        fn_map = {
            "cis": (check_cis_compliance_juniper, juniper_data),
            "hipaa": (check_hipaa_compliance_juniper, juniper_data),
            "nist": (check_nist_compliance_juniper, juniper_data),
            "pci": (check_pci_compliance_juniper, juniper_data),
            "soc2": (check_soc2_compliance_juniper, juniper_data),
            "stig": (check_stig_compliance_juniper, juniper_data),
        }

    entry = fn_map.get(compliance)
    if not entry:
        return []
    fn, arg = entry
    if arg is None:
        return []
    return fn(arg)
