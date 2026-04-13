"""Juniper SRX firewall config parser and auditor.

Handles two Juniper configuration styles:
  - "set" style (flat commands): ``set security policies from-zone X to-zone Y ...``
  - Hierarchical (brace) style:  ``security { policies { from-zone X to-zone Y { ... } } }``

Returns normalised policy dicts compatible with the rest of the Cashel
audit pipeline plus system-level findings from management-plane checks.
"""

import re

# Applications Juniper ships as insecure defaults
_INSECURE_APPS = {
    "junos-telnet",
    "telnet",
    "junos-ftp",
    "ftp",
    "junos-tftp",
    "tftp",
    "junos-snmp-agentx",
}
_BROAD_ADDRS = {"any", "any-ipv4", "any-ipv6"}


def _f(severity, category, message, remediation=""):
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


# ── Config-style detection ────────────────────────────────────────────────────


def _is_set_style(content: str) -> bool:
    return bool(re.search(r"^\s*set security", content, re.MULTILINE))


# ── "set" style parser ────────────────────────────────────────────────────────

_SET_POLICY_RE = re.compile(
    r"^set security policies from-zone (\S+) to-zone (\S+) policy (\S+)\s+(.+)$"
)
_DEACTIVATE_RE = re.compile(
    r"^deactivate security policies from-zone (\S+) to-zone (\S+) policy (\S+)"
)


def _parse_set_style(content: str) -> list[dict]:
    """Parse flat ``set`` commands into normalised policy dicts."""
    policies: dict = {}  # (fz, tz, name) → dict

    for raw_line in content.splitlines():
        line = raw_line.strip()

        m = _SET_POLICY_RE.match(line)
        if m:
            fz, tz, name, rest = m.groups()
            key = (fz, tz, name)
            if key not in policies:
                policies[key] = {
                    "name": name,
                    "from_zone": fz,
                    "to_zone": tz,
                    "src": [],
                    "dst": [],
                    "app": [],
                    "action": None,
                    "log": False,
                    "disabled": False,
                }
            p = policies[key]

            if rest.startswith("match source-address "):
                p["src"].append(rest[len("match source-address ") :].strip())
            elif rest.startswith("match destination-address "):
                p["dst"].append(rest[len("match destination-address ") :].strip())
            elif rest.startswith("match application "):
                p["app"].append(rest[len("match application ") :].strip())
            elif rest.startswith("then reject"):
                p["action"] = "reject"
            elif rest.startswith("then deny"):
                p["action"] = "deny"
            elif "then permit" in rest:
                p["action"] = "permit"
                if "log" in rest:
                    p["log"] = True
            continue

        m2 = _DEACTIVATE_RE.match(line)
        if m2:
            fz, tz, name = m2.groups()
            key = (fz, tz, name)
            if key in policies:
                policies[key]["disabled"] = True

    return list(policies.values())


# ── Hierarchical (brace) style parser ────────────────────────────────────────


def _parse_hierarchical(content: str) -> list[dict]:
    """Parse brace-style Juniper config into normalised policy dicts.

    Uses a simple depth-tracking state machine; does not require a full
    grammar parser and handles multi-line configurations reliably.
    """
    policies = []
    in_security_policies = False
    current_fz = current_tz = current_name = None
    current_policy: dict | None = None
    in_match = in_then = False
    depth = 0

    for raw_line in content.splitlines():
        line = raw_line.strip().rstrip(";")

        opens = raw_line.count("{")
        closes = raw_line.count("}")
        depth += opens - closes

        # Entering/leaving security.policies block
        if "security {" in raw_line and depth <= 2:
            in_security_policies = True
        if in_security_policies and depth == 0:
            in_security_policies = False

        if not in_security_policies:
            continue

        # Zone-pair header: from-zone X to-zone Y {
        m = re.match(r"from-zone\s+(\S+)\s+to-zone\s+(\S+)", line)
        if m:
            current_fz, current_tz = m.group(1), m.group(2)
            current_name = None
            current_policy = None
            in_match = in_then = False
            continue

        # Policy block: [inactive: ]policy <name> {
        m = re.match(r"(?:inactive:\s*)?policy\s+(\S+)", line)
        if m and current_fz:
            if current_policy is not None:
                policies.append(current_policy)
            current_name = m.group(1)
            inactive = "inactive:" in line
            current_policy = {
                "name": current_name,
                "from_zone": current_fz,
                "to_zone": current_tz,
                "src": [],
                "dst": [],
                "app": [],
                "action": None,
                "log": False,
                "disabled": inactive,
            }
            in_match = in_then = False
            continue

        if current_policy is None:
            continue

        if line == "match {":
            in_match, in_then = True, False
            continue
        if line == "then {":
            in_match, in_then = False, True
            continue
        if line in ("}", "};"):
            in_match = in_then = False
            continue

        if in_match:
            if line.startswith("source-address "):
                current_policy["src"].append(line.split(None, 1)[1])
            elif line.startswith("destination-address "):
                current_policy["dst"].append(line.split(None, 1)[1])
            elif line.startswith("application "):
                current_policy["app"].append(line.split(None, 1)[1])

        if in_then:
            if current_policy["action"] is None:
                if "reject" in line:
                    current_policy["action"] = "reject"
                elif "deny" in line:
                    current_policy["action"] = "deny"
                elif "permit" in line:
                    current_policy["action"] = "permit"
            if "log" in line:
                current_policy["log"] = True

    if current_policy is not None:
        policies.append(current_policy)

    return policies


# ── Public parser ─────────────────────────────────────────────────────────────


def parse_juniper(filepath: str) -> tuple[list[dict], str | None]:
    """Parse a Juniper SRX config file.

    Returns (policies, error_message).  error_message is None on success.
    """
    try:
        with open(filepath) as fh:
            content = fh.read()
    except OSError as exc:
        return [], f"Failed to read Juniper config: {exc}"

    if _is_set_style(content):
        policies = _parse_set_style(content)
    else:
        policies = _parse_hierarchical(content)

    return policies, content  # return content so caller can do system checks


# ── Policy-level checks ───────────────────────────────────────────────────────


def check_any_any_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that allow any source, any destination, any application."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit":
            continue
        src_broad = all(s.lower() in _BROAD_ADDRS for s in (p["src"] or ["any"]))
        dst_broad = all(d.lower() in _BROAD_ADDRS for d in (p["dst"] or ["any"]))
        app_any = any(
            a.lower() in ("any", "any-ipv4", "any-ipv6", "junos-any")
            for a in (p["app"] or ["any"])
        )
        if src_broad and dst_broad and app_any:
            label = f"{p['from_zone']}→{p['to_zone']} policy '{p['name']}'"
            findings.append(
                _f(
                    "CRITICAL",
                    "exposure",
                    f"[CRITICAL] {label}: permits any source, any destination, any application.",
                    f"Restrict source-address, destination-address, and application in policy '{p['name']}'. "
                    "Apply least-privilege — allow only the specific zones, addresses, and applications needed.",
                )
            )
    return findings


def check_missing_log_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that do not enable session logging."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit" or p.get("log"):
            continue
        label = f"{p['from_zone']}→{p['to_zone']} policy '{p['name']}'"
        findings.append(
            _f(
                "MEDIUM",
                "logging",
                f"[MEDIUM] {label}: permit policy has no session logging enabled.",
                f"Add 'then permit log session-close' (set style) or a 'log {{ session-close; }}' block "
                f"under 'then permit' in policy '{p['name']}' to enable traffic logging.",
            )
        )
    return findings


def check_insecure_apps_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that allow known-insecure applications (Telnet, FTP, TFTP)."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit":
            continue
        bad = [a for a in p.get("app", []) if a.lower() in _INSECURE_APPS]
        if not bad:
            continue
        label = f"{p['from_zone']}→{p['to_zone']} policy '{p['name']}'"
        # Telnet is CRITICAL; other insecure apps are HIGH
        has_telnet = any(a.lower() in ("telnet", "junos-telnet") for a in bad)
        severity = "CRITICAL" if has_telnet else "HIGH"
        findings.append(
            _f(
                severity,
                "protocol",
                f"[{severity}] {label}: permits insecure application(s): {', '.join(bad)}.",
                "Replace cleartext protocols with encrypted equivalents: "
                "use SSH instead of Telnet, SFTP/SCP instead of FTP, and SNMPv3 instead of SNMP. "
                f"Remove or restrict the application term in policy '{p['name']}'.",
            )
        )
    return findings


def check_deny_all_juniper(policies: list[dict]) -> list[dict]:
    """Flag zone-pairs that have no explicit deny-all catch-all at the end of the policy list."""
    # Group policies by zone-pair; the last active policy should be a deny/reject
    zone_pairs: dict = {}
    for p in policies:
        if p.get("disabled"):
            continue
        key = (p["from_zone"], p["to_zone"])
        zone_pairs.setdefault(key, []).append(p)

    findings = []
    for (fz, tz), pollist in zone_pairs.items():
        last = pollist[-1]
        src_any = all(s.lower() in _BROAD_ADDRS for s in (last["src"] or ["any"]))
        dst_any = all(d.lower() in _BROAD_ADDRS for d in (last["dst"] or ["any"]))
        app_any = any(
            a.lower() in ("any", "junos-any") for a in (last["app"] or ["any"])
        )
        is_deny = last.get("action") in ("deny", "reject")
        if not (src_any and dst_any and app_any and is_deny):
            findings.append(
                _f(
                    "HIGH",
                    "hygiene",
                    f"[HIGH] Zone pair {fz}→{tz}: no explicit deny-all catch-all policy at end of rule list.",
                    f"Add a final policy under from-zone {fz} to-zone {tz} that matches "
                    "source-address any, destination-address any, application any "
                    "with action deny to ensure a documented, auditable default-deny posture.",
                )
            )
    return findings


# ── System-level checks ───────────────────────────────────────────────────────


def check_system_juniper(content: str) -> list[dict]:
    """Checks against the raw config text for management-plane weaknesses."""
    findings = []
    cl = content.lower()

    # Telnet enabled on management plane
    has_telnet = bool(re.search(r"set system services telnet", content)) or (
        "services {" in content and re.search(r"\btelnet;", content)
    )
    if has_telnet:
        findings.append(
            _f(
                "CRITICAL",
                "management",
                "[CRITICAL] Telnet management service is enabled.",
                "Disable Telnet: 'delete system services telnet' (set style) or remove the "
                "telnet stanza from 'system { services { ... } }'. Use SSH exclusively.",
            )
        )

    # SSH not explicitly configured
    has_ssh = bool(re.search(r"set system services ssh", content)) or (
        "services {" in content and re.search(r"\bssh\s*\{", content)
    )
    if not has_ssh:
        findings.append(
            _f(
                "MEDIUM",
                "management",
                "[MEDIUM] SSH management service not explicitly configured.",
                "Enable SSH: 'set system services ssh' and optionally enforce "
                "'set system services ssh root-login deny' and protocol-version v2.",
            )
        )

    # No NTP configured
    has_ntp = bool(re.search(r"set system ntp", content)) or "ntp {" in cl
    if not has_ntp:
        findings.append(
            _f(
                "MEDIUM",
                "hygiene",
                "[MEDIUM] No NTP server configured.",
                "Add at least one NTP server: 'set system ntp server <IP>'. "
                "Accurate timestamps are required for log correlation and compliance.",
            )
        )

    # No syslog configured
    has_syslog = bool(re.search(r"set system syslog", content)) or "syslog {" in cl
    if not has_syslog:
        findings.append(
            _f(
                "HIGH",
                "logging",
                "[HIGH] No syslog configuration found.",
                "Configure remote syslog: 'set system syslog host <IP> any any'. "
                "Without remote logging, audit trails are lost if the device is compromised.",
            )
        )

    # Weak SNMP (v1/v2c community)
    snmp_community = re.findall(r"set snmp community (\S+)", content)
    if snmp_community:
        for comm in snmp_community:
            findings.append(
                _f(
                    "HIGH",
                    "protocol",
                    f"[HIGH] SNMPv1/v2c community string '{comm}' configured.",
                    "Migrate to SNMPv3 with authentication and privacy: "
                    "'set snmp v3 usm local-engine user <name> authentication-sha ...' "
                    "and remove all 'set snmp community' statements.",
                )
            )

    # Root login over SSH permitted
    if re.search(r"set system services ssh root-login allow", content):
        findings.append(
            _f(
                "HIGH",
                "management",
                "[HIGH] SSH root login is explicitly allowed.",
                "Disable root SSH login: 'set system services ssh root-login deny'. "
                "Use named admin accounts with appropriate privileges instead.",
            )
        )

    # No zone screens (SYN-flood / DoS protection)
    has_screens = (
        bool(
            re.search(
                r"set security zones security-zone \S+ host-inbound-traffic", content
            )
        )
        or bool(re.search(r"set security screen", content))
        or "screen {" in cl
    )
    if not has_screens:
        findings.append(
            _f(
                "MEDIUM",
                "exposure",
                "[MEDIUM] No security screen (DoS protection) configuration found.",
                "Configure zone screens to protect against SYN-flood and other DoS attacks: "
                "'set security screen ids-option <name> icmp flood' and apply to relevant zones.",
            )
        )

    return findings


# ── Top-level auditor ─────────────────────────────────────────────────────────


def audit_juniper(filepath: str) -> tuple[list[dict], list[dict]]:
    """Full audit of a Juniper SRX config file.

    Returns (findings, policies) where policies is the normalised list of
    security policy dicts (used for compliance re-checks and shadow detection).
    """
    policies, content_or_err = parse_juniper(filepath)

    if isinstance(content_or_err, str) and not policies:
        # parse_juniper returned an error string
        return [_f("HIGH", "parse", f"[HIGH] Parse error: {content_or_err}")], []

    content: str = content_or_err or ""  # parse_juniper returns content on success

    findings: list[dict] = []
    findings += check_system_juniper(content)
    findings += check_any_any_juniper(policies)
    findings += check_missing_log_juniper(policies)
    findings += check_insecure_apps_juniper(policies)
    findings += check_deny_all_juniper(policies)

    return findings, policies
