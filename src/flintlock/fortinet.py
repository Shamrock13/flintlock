
# Services considered insecure if allowed to broad destinations
_INSECURE_SERVICES = {"TELNET", "HTTP", "FTP", "TFTP", "SNMP"}


def parse_fortinet(filepath):
    """Parse a FortiGate config and return firewall policies."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        return None, f"Failed to read FortiGate config: {e}"

    policies = []
    current_policy = None

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("edit "):
            current_policy = {
                "id":         line.split("edit ")[1],
                "name":       "",
                "srcintf":    [],
                "dstintf":    [],
                "srcaddr":    [],
                "dstaddr":    [],
                "service":    [],
                "action":     "",
                "logtraffic": "",
                "status":     "enable",   # default is enabled
            }

        elif current_policy is not None:
            if line.startswith("set name "):
                current_policy["name"] = line.split("set name ")[1].strip('"')
            elif line.startswith("set srcintf "):
                current_policy["srcintf"] = [x.strip('"') for x in line.replace("set srcintf ", "").strip().split()]
            elif line.startswith("set dstintf "):
                current_policy["dstintf"] = [x.strip('"') for x in line.replace("set dstintf ", "").strip().split()]
            elif line.startswith("set srcaddr "):
                current_policy["srcaddr"] = [x.strip('"') for x in line.replace("set srcaddr ", "").strip().split()]
            elif line.startswith("set dstaddr "):
                current_policy["dstaddr"] = [x.strip('"') for x in line.replace("set dstaddr ", "").strip().split()]
            elif line.startswith("set service "):
                current_policy["service"] = [x.strip('"') for x in line.replace("set service ", "").strip().split()]
            elif line.startswith("set action "):
                current_policy["action"] = line.split("set action ")[1].strip().strip('"')
            elif line.startswith("set logtraffic "):
                current_policy["logtraffic"] = line.split("set logtraffic ")[1].strip().strip('"')
            elif line.startswith("set status "):
                current_policy["status"] = line.split("set status ")[1].strip().strip('"')
            elif line == "next":
                policies.append(current_policy)
                current_policy = None

    return policies, None


# ── Core checks (v1) ─────────────────────────────────────────────────────────

def check_any_any_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name   = p.get("name") or f"Policy ID {p.get('id')}"
        src    = p.get("srcaddr", [])
        dst    = p.get("dstaddr", [])
        action = p.get("action", "")
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(f"[HIGH] Overly permissive rule '{name}': source=all destination=all")
    return findings


def check_missing_logging_forti(policies):
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name      = p.get("name") or f"Policy ID {p.get('id')}"
        action    = p.get("action", "")
        logtraffic= p.get("logtraffic", "")
        if action == "accept" and logtraffic not in ["all", "utm"]:
            findings.append(f"[MEDIUM] Permit rule '{name}' missing logging")
    return findings


def check_deny_all_forti(policies):
    has_deny_all = any(
        p.get("action") == "deny" and "all" in p.get("srcaddr", []) and "all" in p.get("dstaddr", [])
        for p in policies
    )
    return [] if has_deny_all else ["[HIGH] No explicit deny-all rule found"]


def check_redundant_rules_forti(policies):
    findings = []
    seen = []
    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        sig  = (
            tuple(sorted(p.get("srcaddr", []))),
            tuple(sorted(p.get("dstaddr", []))),
            tuple(sorted(p.get("service", []))),
            p.get("action", ""),
        )
        if sig in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: '{name}'")
        else:
            seen.append(sig)
    return findings


# ── v2 enhanced checks ────────────────────────────────────────────────────────

def check_disabled_policies_forti(policies):
    """Flag disabled policies — they add confusion and should be removed if unused."""
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            name = p.get("name") or f"Policy ID {p.get('id')}"
            findings.append(
                f"[MEDIUM] Policy '{name}' is disabled — "
                f"review and remove if no longer needed"
            )
    return findings


def check_any_service_forti(policies):
    """Flag accept policies that allow ALL services (service=ALL)."""
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name    = p.get("name") or f"Policy ID {p.get('id')}"
        action  = p.get("action", "")
        service = p.get("service", [])
        if action == "accept" and "ALL" in [s.upper() for s in service]:
            src = ",".join(p.get("srcaddr", []))
            dst = ",".join(p.get("dstaddr", []))
            findings.append(
                f"[HIGH] Policy '{name}' allows ALL services: {src} → {dst} — "
                f"restrict to required services only"
            )
    return findings


def check_insecure_services_forti(policies):
    """Flag accept policies that allow known-insecure services (Telnet, HTTP, FTP, TFTP, SNMP)."""
    findings = []
    for p in policies:
        if p.get("status") == "disable":
            continue
        name    = p.get("name") or f"Policy ID {p.get('id')}"
        action  = p.get("action", "")
        service = {s.upper() for s in p.get("service", [])}
        bad     = service & _INSECURE_SERVICES
        if action == "accept" and bad:
            findings.append(
                f"[MEDIUM] Policy '{name}' allows insecure service(s): "
                f"{', '.join(sorted(bad))} — use encrypted alternatives"
            )
    return findings


def check_missing_names_forti(policies):
    """Flag policies with no human-readable name set."""
    findings = []
    for p in policies:
        if not p.get("name"):
            findings.append(
                f"[MEDIUM] Policy ID {p.get('id')} has no name set — "
                f"add a descriptive name for auditability"
            )
    return findings


# ── Audit entrypoint ─────────────────────────────────────────────────────────

def audit_fortinet(filepath):
    policies, error = parse_fortinet(filepath)
    if error:
        return [f"[ERROR] {error}"], []

    findings = []
    # v1 core checks
    findings += check_any_any_forti(policies)
    findings += check_missing_logging_forti(policies)
    findings += check_deny_all_forti(policies)
    findings += check_redundant_rules_forti(policies)
    # v2 enhanced checks
    findings += check_disabled_policies_forti(policies)
    findings += check_any_service_forti(policies)
    findings += check_insecure_services_forti(policies)
    findings += check_missing_names_forti(policies)
    return findings, policies
