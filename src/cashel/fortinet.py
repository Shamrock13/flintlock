# Services considered insecure if allowed to broad destinations
from .models.findings import make_finding

_INSECURE_SERVICES = {"TELNET", "HTTP", "FTP", "TFTP", "SNMP"}

_WAN_INTFS = {"wan", "wan1", "wan2", "internet", "outside", "untrust"}


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
    fields = [
        f"policy_id={p.get('id')}",
        f"name={_policy_name(p)}",
        f"srcintf={','.join(p.get('srcintf', [])) or 'unset'}",
        f"dstintf={','.join(p.get('dstintf', [])) or 'unset'}",
        f"srcaddr={','.join(p.get('srcaddr', [])) or 'unset'}",
        f"dstaddr={','.join(p.get('dstaddr', [])) or 'unset'}",
        f"service={','.join(p.get('service', [])) or 'unset'}",
        f"action={p.get('action') or 'unset'}",
        f"logtraffic={p.get('logtraffic') or 'unset'}",
        f"status={p.get('status') or 'unset'}",
        f"utm-status={p.get('utm-status') or 'unset'}",
    ]
    return "; ".join(fields)


def _policy_metadata(p):
    return {
        "policy_id": _policy_id(p),
        "policy_name": _policy_name(p),
        "srcintf": p.get("srcintf", []),
        "dstintf": p.get("dstintf", []),
        "srcaddr": p.get("srcaddr", []),
        "dstaddr": p.get("dstaddr", []),
        "service": p.get("service", []),
        "action": p.get("action", ""),
        "logtraffic": p.get("logtraffic", ""),
        "status": p.get("status", ""),
        "utm_status": p.get("utm-status", ""),
    }


def parse_fortinet(filepath):
    """Parse a FortiGate config and return firewall policies."""
    try:
        with open(filepath, "r") as f:
            content = f.read()
    except Exception as e:
        return None, f"Failed to read FortiGate config: {e}"

    policies = []
    current_policy = None

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("edit "):
            current_policy = {
                "id": line.split("edit ")[1],
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
            }

        elif current_policy is not None:
            if line.startswith("set name "):
                current_policy["name"] = line.split("set name ")[1].strip('"')
            elif line.startswith("set srcintf "):
                current_policy["srcintf"] = [
                    x.strip('"')
                    for x in line.replace("set srcintf ", "").strip().split()
                ]
            elif line.startswith("set dstintf "):
                current_policy["dstintf"] = [
                    x.strip('"')
                    for x in line.replace("set dstintf ", "").strip().split()
                ]
            elif line.startswith("set srcaddr "):
                current_policy["srcaddr"] = [
                    x.strip('"')
                    for x in line.replace("set srcaddr ", "").strip().split()
                ]
            elif line.startswith("set dstaddr "):
                current_policy["dstaddr"] = [
                    x.strip('"')
                    for x in line.replace("set dstaddr ", "").strip().split()
                ]
            elif line.startswith("set service "):
                current_policy["service"] = [
                    x.strip('"')
                    for x in line.replace("set service ", "").strip().split()
                ]
            elif line.startswith("set action "):
                current_policy["action"] = (
                    line.split("set action ")[1].strip().strip('"')
                )
            elif line.startswith("set logtraffic "):
                current_policy["logtraffic"] = (
                    line.split("set logtraffic ")[1].strip().strip('"')
                )
            elif line.startswith("set status "):
                current_policy["status"] = (
                    line.split("set status ")[1].strip().strip('"')
                )
            elif line.startswith("set utm-status "):
                current_policy["utm-status"] = (
                    line.split("set utm-status ")[1].strip().strip('"')
                )
            elif line == "next":
                policies.append(current_policy)
                current_policy = None

    return policies, None


# ── Core checks ───────────────────────────────────────────────────────────────


def check_any_any_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = _policy_name(p)
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        if p.get("action") == "accept" and "all" in src and "all" in dst:
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
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
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
            tuple(sorted(p.get("srcaddr", []))),
            tuple(sorted(p.get("dstaddr", []))),
            tuple(sorted(p.get("service", []))),
            p.get("action", ""),
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
        service = p.get("service", [])
        if action == "accept" and "ALL" in [s.upper() for s in service]:
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
        service = {s.upper() for s in p.get("service", [])}
        bad = service & _INSECURE_SERVICES
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
