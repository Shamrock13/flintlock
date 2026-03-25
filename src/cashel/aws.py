"""AWS Security Group parser and auditor."""

import json

# Ports that should never be open to the world
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    3389: "RDP",
    5900: "VNC",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    9200: "Elasticsearch",
}

_ANY_CIDRS = {"0.0.0.0/0", "::/0"}


def _f(severity, category, message, remediation=""):
    """Build a structured finding dict."""
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


def parse_aws_sg(filepath):
    """
    Parse an AWS Security Group JSON file.

    Accepts output from:
      aws ec2 describe-security-groups
      (or a single group object / bare list)
    Returns (list[group_dict], error_str_or_None).
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except Exception as e:
        return None, f"Failed to parse AWS Security Group JSON: {e}"

    if isinstance(data, dict) and "SecurityGroups" in data:
        groups = data["SecurityGroups"]
    elif isinstance(data, list):
        groups = data
    elif isinstance(data, dict) and "GroupId" in data:
        groups = [data]
    else:
        return (
            None,
            "Unrecognized AWS Security Group JSON format. Expected SecurityGroups key or a group/list.",
        )

    return groups, None


def _is_any(cidr):
    return cidr in _ANY_CIDRS


def _all_cidrs(rule):
    """Yield all CIDR strings referenced in a rule (IPv4 + IPv6)."""
    for r in rule.get("IpRanges", []):
        yield r.get("CidrIp", ""), r.get("Description", ""), "ipv4"
    for r in rule.get("Ipv6Ranges", []):
        yield r.get("CidrIpv6", ""), r.get("Description", ""), "ipv6"


def check_wide_open_ingress(groups):
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        for rule in sg.get("IpPermissions", []):
            proto = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            for cidr, _desc, _ver in _all_cidrs(rule):
                if not _is_any(cidr):
                    continue
                tag = f"Security Group '{sg_name}' ({sg_id})"
                if proto == "-1":
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] {tag}: ALL traffic allowed inbound from {cidr}",
                            "Restrict inbound rules to specific ports and source CIDRs. "
                            "All-traffic rules expose every port and protocol to the internet.",
                        )
                    )
                elif from_port in SENSITIVE_PORTS:
                    svc = SENSITIVE_PORTS[from_port]
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] {tag}: {svc} (port {from_port}) open to {cidr}",
                            f"Remove public access to {svc} (port {from_port}). "
                            "Use a VPN, bastion host, or AWS Systems Manager Session Manager for administrative access.",
                        )
                    )
                elif from_port == 0 and to_port == 65535:
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] {tag}: All ports open inbound from {cidr} (proto {proto})",
                            "Restrict to specific required ports only. "
                            "Full port-range rules are equivalent to all-traffic exposure.",
                        )
                    )
                else:
                    port_str = (
                        f"{from_port}"
                        if from_port == to_port
                        else f"{from_port}-{to_port}"
                    )
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] {tag}: Port {port_str} ({proto}) open to {cidr}",
                            "Restrict source CIDRs to known IP ranges. "
                            "Avoid 0.0.0.0/0 unless the service is intentionally public-facing.",
                        )
                    )
    return findings


def check_wide_open_egress(groups):
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        flagged = False
        for rule in sg.get("IpPermissionsEgress", []):
            if flagged:
                break
            proto = rule.get("IpProtocol", "")
            for cidr, _desc, _ver in _all_cidrs(rule):
                if _is_any(cidr) and proto == "-1":
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): Unrestricted outbound traffic to {cidr}",
                            "Consider restricting egress to required destinations and ports. "
                            "Unrestricted egress can facilitate data exfiltration and C2 communication.",
                        )
                    )
                    flagged = True
                    break
    return findings


def check_missing_descriptions(groups):
    findings = []
    seen = set()
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        desc = (sg.get("Description") or "").strip().lower()
        if not desc or desc in ("launch-wizard", "default", ""):
            key = f"sg-desc-{sg_id}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    _f(
                        "MEDIUM",
                        "hygiene",
                        f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): Missing or generic group description",
                        "Add a meaningful description documenting the group's purpose, owner team, and workload. "
                        "Generic descriptions ('launch-wizard', 'default') provide no context for auditors.",
                    )
                )
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            for ip_range in rule.get("IpRanges", []):
                if not ip_range.get("Description", "").strip():
                    port_str = (
                        f"{from_port}"
                        if from_port == to_port
                        else f"{from_port}-{to_port}"
                    )
                    key = f"rule-desc-{sg_id}-{port_str}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            _f(
                                "MEDIUM",
                                "hygiene",
                                f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): Inbound rule port {port_str} has no description",
                                "Add a description to each inbound rule explaining what service it allows and why. "
                                "Rule descriptions are essential context for security reviews.",
                            )
                        )
    return findings


def check_default_sg_has_rules(groups):
    """Flag default security groups that have non-empty inbound rules."""
    findings = []
    for sg in groups:
        if sg.get("GroupName", "").lower() != "default":
            continue
        sg_id = sg.get("GroupId", "unknown")
        inbound = [
            r
            for r in sg.get("IpPermissions", [])
            if r.get("IpRanges") or r.get("Ipv6Ranges") or r.get("UserIdGroupPairs")
        ]
        if inbound:
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Default security group ({sg_id}) has active inbound rules",
                    "The default security group should have no rules. "
                    "Use named, purpose-specific security groups for all resources to enforce least-privilege access.",
                )
            )
    return findings


def check_large_port_ranges(groups):
    """Flag inbound rules with unusually wide port ranges (>100 ports)."""
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            proto = rule.get("IpProtocol", "")
            if from_port < 0 or to_port < 0 or proto == "-1":
                continue
            port_range = to_port - from_port
            if port_range > 100 and not (from_port == 0 and to_port == 65535):
                for cidr, _desc, _ver in _all_cidrs(rule):
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): Wide port range {from_port}-{to_port} ({port_range + 1} ports) open to {cidr}",
                            "Restrict open port ranges to the minimum required ports. "
                            "Wide ranges significantly increase attack surface and should be scoped to specific service ports.",
                        )
                    )
    return findings


def audit_aws_sg(filepath):
    """Run all checks. Returns (findings_list, groups_list)."""
    groups, error = parse_aws_sg(filepath)
    if error:
        return [_f("HIGH", "hygiene", f"[ERROR] {error}", "")], []
    findings = []
    findings += check_wide_open_ingress(groups)
    findings += check_wide_open_egress(groups)
    findings += check_missing_descriptions(groups)
    findings += check_default_sg_has_rules(groups)
    findings += check_large_port_ranges(groups)
    return findings, groups
