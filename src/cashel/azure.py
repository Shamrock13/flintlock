"""Azure Network Security Group (NSG) parser and auditor."""

import json

SENSITIVE_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "3389": "RDP",
    "5900": "VNC",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "6379": "Redis",
    "27017": "MongoDB",
}

_ANY_SOURCES = {"*", "Internet", "Any", "0.0.0.0/0", "::/0"}


def _f(severity, category, message, remediation=""):
    """Build a structured finding dict."""
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


def parse_azure_nsg(filepath):
    """
    Parse an Azure NSG JSON file.

    Accepts output from:
      az network nsg show / az network nsg list
      (single NSG object, array, or {value: [...]} wrapper)
    Returns (list[nsg_dict], error_str_or_None).
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except Exception as e:
        return None, f"Failed to parse Azure NSG JSON: {e}"

    if isinstance(data, list):
        nsgs = data
    elif isinstance(data, dict):
        if "value" in data:
            nsgs = data["value"]
        elif "name" in data or "securityRules" in data:
            nsgs = [data]
        else:
            return None, "Unrecognized Azure NSG JSON format."
    else:
        return None, "Unrecognized Azure NSG JSON format."

    return nsgs, None


def _props(rule):
    """Return the properties dict, handling both flat and nested ('properties') formats."""
    return rule.get("properties", rule)


def _port_ranges(rule_props):
    """Return a flat list of destination port range strings."""
    single = rule_props.get("destinationPortRange", "")
    multi = rule_props.get("destinationPortRanges", [])
    ports = list(multi) if multi else []
    if single:
        ports.append(single)
    return ports


def check_inbound_any(nsgs):
    findings = []
    for nsg in nsgs:
        nsg_name = nsg.get("name", "unnamed")
        rules = nsg.get("securityRules", []) + nsg.get("defaultSecurityRules", [])
        for rule in rules:
            props = _props(rule)
            direction = props.get("direction", "")
            access = props.get("access", "")
            src = props.get("sourceAddressPrefix", "")
            rule_name = rule.get("name", "unnamed")
            priority = props.get("priority", "?")

            if direction != "Inbound" or access != "Allow":
                continue
            if src not in _ANY_SOURCES:
                continue

            ports = _port_ranges(props)
            if not ports or "*" in ports:
                findings.append(
                    _f(
                        "HIGH",
                        "exposure",
                        f"[HIGH] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): ALL inbound traffic from Any source allowed",
                        "Restrict source address prefix to specific IP ranges or Azure service tags. "
                        "Any-source allow-all rules expose every port to the internet.",
                    )
                )
            else:
                for port in ports:
                    if port in SENSITIVE_PORTS:
                        svc = SENSITIVE_PORTS[port]
                        findings.append(
                            _f(
                                "HIGH",
                                "exposure",
                                f"[HIGH] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): {svc} port {port} open to Any source",
                                f"Remove public access to {svc} (port {port}). "
                                "Use Azure Bastion, Just-in-Time VM access, or a VPN for administrative connectivity.",
                            )
                        )
                    else:
                        findings.append(
                            _f(
                                "MEDIUM",
                                "exposure",
                                f"[MEDIUM] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): Port {port} open to Any source",
                                "Restrict the source address prefix to known CIDRs or Azure service tags. "
                                "Avoid 'Any' source unless the service is intentionally public.",
                            )
                        )
    return findings


def check_missing_flow_logs(nsgs):
    """Flag NSGs where flow log status cannot be confirmed from the JSON."""
    findings = []
    for nsg in nsgs:
        nsg_name = nsg.get("name", "unnamed")
        if "flowLogs" not in nsg and "diagnosticSettings" not in nsg:
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] NSG '{nsg_name}': Flow log status unknown — verify NSG flow logs are enabled",
                    "Enable NSG flow logs via Azure Network Watcher. Flow logs are essential for "
                    "traffic analysis, compliance, and incident response. "
                    "Verify with: az network watcher flow-log show",
                )
            )
    return findings


def check_high_priority_allow_all(nsgs):
    """Flag high-priority (low number) Allow-All inbound rules."""
    findings = []
    for nsg in nsgs:
        nsg_name = nsg.get("name", "unnamed")
        for rule in nsg.get("securityRules", []):
            props = _props(rule)
            priority = props.get("priority", 9999)
            if (
                props.get("direction") == "Inbound"
                and props.get("access") == "Allow"
                and props.get("sourceAddressPrefix") in _ANY_SOURCES
                and ("*" in _port_ranges(props) or not _port_ranges(props))
                and int(priority) < 500
            ):
                rule_name = rule.get("name", "unnamed")
                findings.append(
                    _f(
                        "HIGH",
                        "exposure",
                        f"[HIGH] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): High-priority allow-all inbound rule may override downstream security rules",
                        "Move broad allow rules to higher priority numbers (lower precedence) or replace with "
                        "specific rules. Low priority numbers take precedence and can silently bypass deny rules.",
                    )
                )
    return findings


def check_broad_port_ranges(nsgs):
    """Flag inbound allow rules with wide port ranges (>100 ports)."""
    findings = []
    for nsg in nsgs:
        nsg_name = nsg.get("name", "unnamed")
        for rule in nsg.get("securityRules", []):
            props = _props(rule)
            rule_name = rule.get("name", "unnamed")
            priority = props.get("priority", "?")
            if props.get("direction") != "Inbound" or props.get("access") != "Allow":
                continue
            for port in _port_ranges(props):
                if "-" in str(port) and port != "*":
                    parts = str(port).split("-")
                    try:
                        lo, hi = int(parts[0]), int(parts[1])
                        if hi - lo > 100:
                            findings.append(
                                _f(
                                    "MEDIUM",
                                    "exposure",
                                    f"[MEDIUM] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): Wide inbound port range {port} ({hi - lo + 1} ports)",
                                    "Restrict inbound rules to specific required ports rather than broad ranges. "
                                    "Wide port ranges significantly increase the attack surface.",
                                )
                            )
                    except (ValueError, IndexError):
                        pass
    return findings


def audit_azure_nsg(filepath):
    """Run all checks. Returns (findings_list, nsgs_list)."""
    nsgs, error = parse_azure_nsg(filepath)
    if error:
        return [_f("HIGH", "hygiene", f"[ERROR] {error}", "")], []
    findings = []
    findings += check_inbound_any(nsgs)
    findings += check_missing_flow_logs(nsgs)
    findings += check_high_priority_allow_all(nsgs)
    findings += check_broad_port_ranges(nsgs)
    return findings, nsgs
