# Services considered insecure if allowed to broad destinations
_INSECURE_SERVICES = {"TELNET", "HTTP", "FTP", "TFTP", "SNMP"}

_WAN_INTFS = {"wan", "wan1", "wan2", "internet", "outside", "untrust"}


def _f(severity, category, message, remediation=""):
    """Build a structured finding dict."""
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
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
        name = p.get("name") or f"Policy ID {p.get('id')}"
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
                )
            )
    return findings


def check_missing_logging_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = p.get("name") or f"Policy ID {p.get('id')}"
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
        )
    ]


def check_redundant_rules_forti(policies):
    findings = []
    seen = []
    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
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
            name = p.get("name") or f"Policy ID {p.get('id')}"
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Policy '{name}' is disabled — review and remove if no longer needed",
                    "Remove disabled policies that are no longer required. Stale policies obscure "
                    "the effective policy set and make audits and reviews harder.",
                )
            )
    return findings


def check_any_service_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = p.get("name") or f"Policy ID {p.get('id')}"
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
                )
            )
    return findings


def check_insecure_services_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name = p.get("name") or f"Policy ID {p.get('id')}"
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
            name = p.get("name") or f"Policy ID {p.get('id')}"
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Internet-facing policy '{name}' has no UTM/security profile enabled",
                    "Enable UTM features (antivirus, IPS, application control, web filtering) "
                    "on all policies handling internet-facing traffic.",
                )
            )
    return findings


# ── Audit entrypoint ─────────────────────────────────────────────────────────


def audit_fortinet(filepath):
    policies, error = parse_fortinet(filepath)
    if error:
        return [_f("HIGH", "hygiene", f"[ERROR] {error}", "")], []

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
