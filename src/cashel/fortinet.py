# Services considered insecure if allowed to broad destinations
import shlex

from .models.findings import make_finding

_INSECURE_SERVICES = {"TELNET", "HTTP", "FTP", "TFTP", "SNMP"}

_WAN_INTFS = {"wan", "wan1", "wan2", "internet", "outside", "untrust"}
_BROAD_VALUES = {"all", "any", "*"}


def _dedupe_stable(values):
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _normalize_broad(value):
    if str(value).lower() in _BROAD_VALUES:
        return "ALL"
    return value


def _is_broad(values):
    return "ALL" in values


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="fortinet",
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


def _policy_name(p):
    return p.get("name") or f"Policy ID {p.get('id')}"


def _policy_id(p):
    value = p.get("id")
    return str(value) if value is not None else None


def _policy_evidence(p):
    expanded_src = ",".join(_expanded_srcaddr(p)) or "unset"
    expanded_dst = ",".join(_expanded_dstaddr(p)) or "unset"
    expanded_service = ",".join(_expanded_service(p)) or "unset"
    fields = [
        f"policy_id={p.get('id')}",
        f"name={_policy_name(p)}",
        f"srcintf={','.join(p.get('srcintf', [])) or 'unset'}",
        f"dstintf={','.join(p.get('dstintf', [])) or 'unset'}",
        f"srcaddr={','.join(p.get('srcaddr', [])) or 'unset'}",
        f"dstaddr={','.join(p.get('dstaddr', [])) or 'unset'}",
        f"service={','.join(p.get('service', [])) or 'unset'}",
        f"expanded_srcaddr={expanded_src}",
        f"expanded_dstaddr={expanded_dst}",
        f"expanded_service={expanded_service}",
        f"action={p.get('action') or 'unset'}",
        f"logtraffic={p.get('logtraffic') or 'unset'}",
        f"status={p.get('status') or 'unset'}",
        f"utm-status={p.get('utm-status') or 'unset'}",
        f"schedule={p.get('schedule') or 'unset'}",
        f"nat={p.get('nat') or 'unset'}",
        f"comments={p.get('comments') or 'unset'}",
        f"av-profile={p.get('av-profile') or 'unset'}",
        f"ips-sensor={p.get('ips-sensor') or 'unset'}",
        f"application-list={p.get('application-list') or 'unset'}",
        f"webfilter-profile={p.get('webfilter-profile') or 'unset'}",
        f"profile-protocol-options={p.get('profile-protocol-options') or 'unset'}",
    ]
    return "; ".join(fields)


def _policy_metadata(p):
    return {
        "policy_id": _policy_id(p),
        "policy_name": _policy_name(p),
        "raw_srcaddr": p.get("srcaddr", []),
        "raw_dstaddr": p.get("dstaddr", []),
        "raw_service": p.get("service", []),
        "expanded_srcaddr": _expanded_srcaddr(p),
        "expanded_dstaddr": _expanded_dstaddr(p),
        "expanded_service": _expanded_service(p),
        "srcintf": p.get("srcintf", []),
        "dstintf": p.get("dstintf", []),
        "srcaddr": p.get("srcaddr", []),
        "dstaddr": p.get("dstaddr", []),
        "service": p.get("service", []),
        "action": p.get("action", ""),
        "logtraffic": p.get("logtraffic", ""),
        "status": p.get("status", ""),
        "utm_status": p.get("utm-status", ""),
        "schedule": p.get("schedule", ""),
        "nat": p.get("nat", ""),
        "comments": p.get("comments", ""),
        "av_profile": p.get("av-profile", ""),
        "ips_sensor": p.get("ips-sensor", ""),
        "application_list": p.get("application-list", ""),
        "webfilter_profile": p.get("webfilter-profile", ""),
        "profile_protocol_options": p.get("profile-protocol-options", ""),
    }


def _address_objects(p):
    return p.get("_address_objects", {})


def _address_groups(p):
    return p.get("_address_groups", {})


def _service_objects(p):
    return p.get("_service_objects", {})


def _service_groups(p):
    return p.get("_service_groups", {})


def _expanded_srcaddr(p):
    return expand_addresses(
        p.get("srcaddr", []), _address_objects(p), _address_groups(p)
    )


def _expanded_dstaddr(p):
    return expand_addresses(
        p.get("dstaddr", []), _address_objects(p), _address_groups(p)
    )


def _expanded_service(p):
    return expand_services(
        p.get("service", []), _service_objects(p), _service_groups(p)
    )


def _set_values(line, prefix):
    return [x.strip('"') for x in shlex.split(line.replace(prefix, "", 1).strip())]


def _set_value(line, prefix):
    values = _set_values(line, prefix)
    return " ".join(values)


def expand_address(name, objects, groups) -> list[str]:
    return _expand_address(name, objects, groups, set())


def _expand_address(name, objects, groups, seen) -> list[str]:
    normalized = _normalize_broad(name)
    if normalized == "ALL":
        return ["ALL"]
    if name in seen:
        return [name]
    if name in groups:
        seen.add(name)
        values = []
        for member in groups[name].get("member", []):
            values.extend(_expand_address(member, objects, groups, seen.copy()))
        return _dedupe_stable(values)
    if name in objects:
        obj = objects[name]
        if obj.get("subnet"):
            return [obj["subnet"]]
    return [name]


def expand_addresses(names, objects, groups) -> list[str]:
    values = []
    for name in names or []:
        values.extend(expand_address(name, objects, groups))
    return _dedupe_stable(values)


def expand_service(name, services, service_groups) -> list[str]:
    return _expand_service(name, services, service_groups, set())


def _expand_service(name, services, service_groups, seen) -> list[str]:
    normalized = _normalize_broad(name)
    if normalized == "ALL":
        return ["ALL"]
    if name in seen:
        return [name]
    if name in service_groups:
        seen.add(name)
        values = []
        for member in service_groups[name].get("member", []):
            values.extend(
                _expand_service(member, services, service_groups, seen.copy())
            )
        return _dedupe_stable(values)
    if name in services:
        service = services[name]
        values = []
        if service.get("tcp-portrange"):
            values.append(f"tcp/{service['tcp-portrange']}")
        if service.get("udp-portrange"):
            values.append(f"udp/{service['udp-portrange']}")
        if not values and service.get("protocol"):
            values.append(f"protocol/{service['protocol']}")
        return values or [name]
    return [normalized]


def expand_services(names, services, service_groups) -> list[str]:
    values = []
    for name in names or []:
        values.extend(expand_service(name, services, service_groups))
    return _dedupe_stable(values)


def _new_policy(policy_id):
    return {
        "id": policy_id,
        "name": "",
        "srcintf": [],
        "dstintf": [],
        "srcaddr": [],
        "dstaddr": [],
        "service": [],
        "action": "",
        "logtraffic": "",
        "status": "enable",
        "utm-status": "",
        "schedule": "",
        "nat": "",
        "comments": "",
        "av-profile": "",
        "ips-sensor": "",
        "application-list": "",
        "webfilter-profile": "",
        "profile-protocol-options": "",
    }


def parse_fortinet(filepath):
    """Parse a FortiGate config and return firewall policies."""
    try:
        with open(filepath, "r") as f:
            content = f.read()
    except Exception as e:
        return None, f"Failed to read FortiGate config: {e}"

    policies = []
    address_objects = {}
    address_groups = {}
    service_objects = {}
    service_groups = {}
    section = None
    current = None

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue
        if line == "config firewall policy":
            section = "policy"
            continue
        if line == "config firewall address":
            section = "address"
            continue
        if line == "config firewall addrgrp":
            section = "addrgrp"
            continue
        if line == "config firewall service custom":
            section = "service"
            continue
        if line == "config firewall service group":
            section = "service_group"
            continue
        if line == "end":
            section = None
            current = None
            continue
        if line.startswith("edit ") and section:
            name = _set_value(line, "edit ")
            if section == "policy":
                current = _new_policy(name)
            elif section == "address":
                current = {"name": name, "subnet": ""}
            elif section == "addrgrp":
                current = {"name": name, "member": []}
            elif section == "service":
                current = {
                    "name": name,
                    "tcp-portrange": "",
                    "udp-portrange": "",
                    "protocol": "",
                }
            elif section == "service_group":
                current = {"name": name, "member": []}
            continue

        if current is not None:
            if line.startswith("set name "):
                current["name"] = _set_value(line, "set name ")
            elif line.startswith("set srcintf "):
                current["srcintf"] = _set_values(line, "set srcintf ")
            elif line.startswith("set dstintf "):
                current["dstintf"] = _set_values(line, "set dstintf ")
            elif line.startswith("set srcaddr "):
                current["srcaddr"] = _set_values(line, "set srcaddr ")
            elif line.startswith("set dstaddr "):
                current["dstaddr"] = _set_values(line, "set dstaddr ")
            elif line.startswith("set service "):
                current["service"] = _set_values(line, "set service ")
            elif line.startswith("set action "):
                current["action"] = _set_value(line, "set action ")
            elif line.startswith("set logtraffic "):
                current["logtraffic"] = _set_value(line, "set logtraffic ")
            elif line.startswith("set status "):
                current["status"] = _set_value(line, "set status ")
            elif line.startswith("set utm-status "):
                current["utm-status"] = _set_value(line, "set utm-status ")
            elif line.startswith("set schedule "):
                current["schedule"] = _set_value(line, "set schedule ")
            elif line.startswith("set nat "):
                current["nat"] = _set_value(line, "set nat ")
            elif line.startswith("set comments "):
                current["comments"] = _set_value(line, "set comments ")
            elif line.startswith("set av-profile "):
                current["av-profile"] = _set_value(line, "set av-profile ")
            elif line.startswith("set ips-sensor "):
                current["ips-sensor"] = _set_value(line, "set ips-sensor ")
            elif line.startswith("set application-list "):
                current["application-list"] = _set_value(line, "set application-list ")
            elif line.startswith("set webfilter-profile "):
                current["webfilter-profile"] = _set_value(
                    line, "set webfilter-profile "
                )
            elif line.startswith("set profile-protocol-options "):
                current["profile-protocol-options"] = _set_value(
                    line, "set profile-protocol-options "
                )
            elif line.startswith("set subnet "):
                parts = _set_values(line, "set subnet ")
                current["subnet"] = " ".join(parts)
            elif line.startswith("set member "):
                current["member"] = _set_values(line, "set member ")
            elif line.startswith("set tcp-portrange "):
                current["tcp-portrange"] = _set_value(line, "set tcp-portrange ")
            elif line.startswith("set udp-portrange "):
                current["udp-portrange"] = _set_value(line, "set udp-portrange ")
            elif line.startswith("set protocol "):
                current["protocol"] = _set_value(line, "set protocol ")
            elif line == "next":
                if section == "policy":
                    policies.append(current)
                elif section == "address":
                    address_objects[current["name"]] = current
                elif section == "addrgrp":
                    address_groups[current["name"]] = current
                elif section == "service":
                    service_objects[current["name"]] = current
                elif section == "service_group":
                    service_groups[current["name"]] = current
                current = None

    for policy in policies:
        policy["_address_objects"] = address_objects
        policy["_address_groups"] = address_groups
        policy["_service_objects"] = service_objects
        policy["_service_groups"] = service_groups

    return policies, None


# ── Core checks ───────────────────────────────────────────────────────────────


def check_any_any_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = _policy_name(p)
        src = _expanded_srcaddr(p)
        dst = _expanded_dstaddr(p)
        if p.get("action") == "accept" and _is_broad(src) and _is_broad(dst):
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=all destination=all",
                    "Restrict source and destination to specific, required address objects. "
                    "Any-to-any accept rules expose every service to every network segment.",
                    id="CASHEL-FORTINET-EXPOSURE-001",
                    title="Fortinet policy allows all sources to all destinations",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="high",
                    impact="Any-to-any accept policies can expose broad network access across segments.",
                    verification="Confirm the policy uses specific source and destination address objects, then re-run the audit.",
                    rollback="Restore the previous source and destination address objects from configuration backup if approved traffic is interrupted.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set srcaddr <SPECIFIC_ADDR_OBJ>",
                        "    set dstaddr <SPECIFIC_ADDR_OBJ>",
                        "  next",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


def check_missing_logging_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = _policy_name(p)
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        if action == "accept" and logtraffic not in ["all", "utm"]:
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] Permit rule '{name}' missing logging",
                    "Set 'set logtraffic all' or 'set logtraffic utm' on all accept policies "
                    "to maintain a complete audit trail for incident response and compliance.",
                    id="CASHEL-FORTINET-LOGGING-001",
                    title="Fortinet accept policy missing traffic logging",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="high",
                    impact="Accepted sessions may not be available in FortiGate traffic logs for investigations or audit review.",
                    verification="Confirm the policy has logtraffic set to all or utm and verify new matching traffic appears in logs.",
                    rollback="Set logtraffic back to the previous value if logging volume causes operational issues.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set logtraffic all",
                        "  next",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


def check_deny_all_forti(policies):
    has_deny_all = any(
        p.get("action") == "deny"
        and _is_broad(_expanded_srcaddr(p))
        and _is_broad(_expanded_dstaddr(p))
        for p in policies
    )
    if has_deny_all:
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found",
            "Add a deny-all policy at the bottom of the policy list. FortiGate's implicit deny "
            "produces no log entries — an explicit deny rule ensures unmatched traffic is logged.",
            id="CASHEL-FORTINET-HYGIENE-001",
            title="Fortinet explicit deny-all policy missing",
            evidence="No policy with action=deny, srcaddr=all, and dstaddr=all was found.",
            affected_object="policy list",
            confidence="medium",
            impact="Traffic denied only by the implicit policy may not have explicit policy logging context.",
            verification="Confirm a final deny-all policy exists at the bottom of the policy list and logs denied traffic.",
            rollback="Remove the explicit deny-all policy if it creates unexpected logging or operational impact.",
            suggested_commands=[
                "config firewall policy",
                "  edit <NEW_POLICY_ID>",
                "    set name explicit-deny-all",
                "    set srcaddr all",
                "    set dstaddr all",
                "    set service ALL",
                "    set action deny",
                "    set logtraffic all",
                "  next",
                "end",
            ],
        )
    ]


def check_redundant_rules_forti(policies):
    findings = []
    seen = []
    for p in policies:
        name = _policy_name(p)
        sig = (
            tuple(sorted(p.get("srcintf", []))),
            tuple(sorted(p.get("dstintf", []))),
            tuple(sorted(_expanded_srcaddr(p))),
            tuple(sorted(_expanded_dstaddr(p))),
            tuple(sorted(_expanded_service(p))),
            p.get("action", ""),
            p.get("schedule", ""),
            p.get("nat", ""),
        )
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Review and remove duplicate policies. Redundant rules create ambiguity, "
                    "complicate audits, and may indicate a configuration drift or error.",
                    id="CASHEL-FORTINET-REDUNDANCY-002",
                    title="Fortinet policy duplicates an earlier policy",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="medium",
                    impact="Duplicate policies add review noise and can hide configuration drift.",
                    verification="Confirm the earlier policy preserves the intended access before removing the duplicate, then re-run the audit.",
                    rollback="Restore the duplicate policy from backup if removal affects an approved workflow.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  delete {_policy_id(p) or '<POLICY_ID>'}",
                        "end",
                    ],
                    metadata={**_policy_metadata(p), "duplicate_signature": sig},
                )
            )
        else:
            seen.append(sig)
    return findings


# ── Enhanced checks ───────────────────────────────────────────────────────────


def check_disabled_policies_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            name = _policy_name(p)
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Policy '{name}' is disabled — review and remove if no longer needed",
                    "Remove disabled policies that are no longer required. Stale policies obscure "
                    "the effective policy set and make audits and reviews harder.",
                    id="CASHEL-FORTINET-HYGIENE-002",
                    title="Fortinet policy is disabled",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="high",
                    impact="Disabled policies can obscure review of the effective policy set.",
                    verification="Confirm the disabled policy is no longer needed and re-run the audit after removal.",
                    rollback="Restore the disabled policy from backup if it is required for a pending change window.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  delete {_policy_id(p) or '<POLICY_ID>'}",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


def check_any_service_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = _policy_name(p)
        action = p.get("action", "")
        service = _expanded_service(p)
        if action == "accept" and _is_broad(service):
            src = ",".join(p.get("srcaddr", []))
            dst = ",".join(p.get("dstaddr", []))
            findings.append(
                _f(
                    "HIGH",
                    "protocol",
                    f"[HIGH] Policy '{name}' allows ALL services: {src} \u2192 {dst}",
                    "Replace the ALL service with an enumerated list of required services only. "
                    "Allowing all services expands the attack surface to every protocol and port number.",
                    id="CASHEL-FORTINET-PROTOCOL-001",
                    title="Fortinet policy allows all services",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="high",
                    impact="Allowing ALL services expands the policy to every protocol and port.",
                    verification="Confirm the policy lists only required service objects, then re-run the audit.",
                    rollback="Restore the prior service list from backup if required traffic is interrupted.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set service <REQUIRED_SERVICE_OBJECTS>",
                        "  next",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


def check_insecure_services_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = _policy_name(p)
        action = p.get("action", "")
        service = {s.upper() for s in _expanded_service(p)}
        bad = service & _INSECURE_SERVICES
        if "TCP/23" in service:
            bad.add("TELNET")
        if action == "accept" and bad:
            findings.append(
                _f(
                    "MEDIUM",
                    "protocol",
                    f"[MEDIUM] Policy '{name}' allows insecure service(s): {', '.join(sorted(bad))}",
                    "Replace cleartext protocols with encrypted alternatives: "
                    "SSH instead of Telnet, HTTPS instead of HTTP, SFTP/SCP instead of FTP.",
                    id="CASHEL-FORTINET-PROTOCOL-002",
                    title="Fortinet policy allows insecure services",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="high",
                    impact="Cleartext or legacy services can expose credentials and sensitive traffic.",
                    verification="Confirm insecure services are removed or replaced with encrypted alternatives, then re-run the audit.",
                    rollback="Restore the previous service list from backup if an approved legacy dependency is disrupted.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set service <SECURE_SERVICE_OBJECTS>",
                        "  next",
                        "end",
                    ],
                    metadata={
                        **_policy_metadata(p),
                        "insecure_services": sorted(bad),
                    },
                )
            )
    return findings


def check_missing_names_forti(policies):
    findings = []
    for p in policies:
        if not p.get("name"):
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Policy ID {p.get('id')} has no name set",
                    "Add a descriptive name to every policy that documents its purpose, owner, "
                    "and associated change ticket. Unnamed policies are difficult to audit and manage.",
                    id="CASHEL-FORTINET-HYGIENE-003",
                    title="Fortinet policy is missing a name",
                    evidence=_policy_evidence(p),
                    affected_object=_policy_name(p),
                    rule_id=_policy_id(p),
                    rule_name=_policy_name(p),
                    confidence="high",
                    impact="Unnamed policies are harder to review, approve, and map to business intent.",
                    verification="Confirm the policy has a descriptive name and re-run the audit.",
                    rollback="Unset the policy name if a naming change must be reverted.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set name <DESCRIPTIVE_POLICY_NAME>",
                        "  next",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


def check_missing_utm_forti(policies):
    """Flag internet-facing accept policies with no UTM security profile."""
    findings = []
    for p in policies:
        if p.get("status") == "disable" or p.get("action") != "accept":
            continue
        dstintf = {i.lower() for i in p.get("dstintf", [])}
        srcintf = {i.lower() for i in p.get("srcintf", [])}
        is_internet_facing = bool(_WAN_INTFS & dstintf) or bool(_WAN_INTFS & srcintf)
        if not is_internet_facing:
            continue
        if p.get("utm-status") != "enable":
            name = _policy_name(p)
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Internet-facing policy '{name}' has no UTM/security profile enabled",
                    "Enable UTM features (antivirus, IPS, application control, web filtering) "
                    "on all policies handling internet-facing traffic.",
                    id="CASHEL-FORTINET-HYGIENE-004",
                    title="Fortinet internet-facing policy missing UTM profile",
                    evidence=_policy_evidence(p),
                    affected_object=name,
                    rule_id=_policy_id(p),
                    rule_name=name,
                    confidence="medium",
                    impact="Internet-facing traffic may bypass antivirus, IPS, application control, or web filtering inspection.",
                    verification="Confirm UTM is enabled with approved security profiles and re-run the audit.",
                    rollback="Disable UTM or restore the prior security profile settings if inspection causes approved traffic impact.",
                    suggested_commands=[
                        "config firewall policy",
                        f"  edit {_policy_id(p) or '<POLICY_ID>'}",
                        "    set utm-status enable",
                        "    set av-profile <AV_PROFILE>",
                        "    set ips-sensor <IPS_SENSOR>",
                        "    set application-list <APP_CONTROL_PROFILE>",
                        "    set webfilter-profile <WEBFILTER_PROFILE>",
                        "  next",
                        "end",
                    ],
                    metadata=_policy_metadata(p),
                )
            )
    return findings


# ── Audit entrypoint ─────────────────────────────────────────────────────────


def audit_fortinet(filepath):
    policies, error = parse_fortinet(filepath)
    if error:
        return [
            _f(
                "HIGH",
                "hygiene",
                f"[ERROR] {error}",
                "",
                id="CASHEL-FORTINET-HYGIENE-000",
                title="Fortinet configuration could not be read",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the file exists, is readable, and contains FortiGate configuration text.",
            )
        ], []

    findings = []
    findings += check_any_any_forti(policies)
    findings += check_missing_logging_forti(policies)
    findings += check_deny_all_forti(policies)
    findings += check_redundant_rules_forti(policies)
    findings += check_disabled_policies_forti(policies)
    findings += check_any_service_forti(policies)
    findings += check_insecure_services_forti(policies)
    findings += check_missing_names_forti(policies)
    findings += check_missing_utm_forti(policies)
    return findings, policies
