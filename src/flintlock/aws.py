"""AWS Security Group parser and auditor."""
import json

# Ports that should never be open to the world
SENSITIVE_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    3389:  "RDP",
    5900:  "VNC",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    1433:  "MSSQL",
    6379:  "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    9200:  "Elasticsearch",
}

_ANY_CIDRS = {"0.0.0.0/0", "::/0"}


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
        return None, "Unrecognized AWS Security Group JSON format. Expected SecurityGroups key or a group/list."

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
        sg_id   = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        for rule in sg.get("IpPermissions", []):
            proto     = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", -1)
            to_port   = rule.get("ToPort", -1)
            for cidr, _desc, _ver in _all_cidrs(rule):
                if not _is_any(cidr):
                    continue
                tag = f"Security Group '{sg_name}' ({sg_id})"
                if proto == "-1":
                    findings.append(
                        f"[HIGH] {tag}: ALL traffic allowed inbound from {cidr}"
                    )
                elif from_port in SENSITIVE_PORTS:
                    svc = SENSITIVE_PORTS[from_port]
                    findings.append(
                        f"[HIGH] {tag}: {svc} (port {from_port}) open to {cidr}"
                    )
                elif from_port == 0 and to_port == 65535:
                    findings.append(
                        f"[HIGH] {tag}: All ports open inbound from {cidr} (proto {proto})"
                    )
                else:
                    port_str = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                    findings.append(
                        f"[MEDIUM] {tag}: Port {port_str} ({proto}) open to {cidr}"
                    )
    return findings


def check_wide_open_egress(groups):
    findings = []
    for sg in groups:
        sg_id   = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        flagged = False
        for rule in sg.get("IpPermissionsEgress", []):
            if flagged:
                break
            proto = rule.get("IpProtocol", "")
            for cidr, _desc, _ver in _all_cidrs(rule):
                if _is_any(cidr) and proto == "-1":
                    findings.append(
                        f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): "
                        f"Unrestricted outbound traffic to {cidr} — consider restricting egress"
                    )
                    flagged = True
                    break
    return findings


def check_missing_descriptions(groups):
    findings = []
    for sg in groups:
        sg_id   = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")
        desc = (sg.get("Description") or "").strip().lower()
        if not desc or desc in ("launch-wizard", "default", ""):
            findings.append(
                f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): Missing or generic group description"
            )
        # Flag individual rules with no description
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port   = rule.get("ToPort", -1)
            for ip_range in rule.get("IpRanges", []):
                if not ip_range.get("Description", "").strip():
                    port_str = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                    findings.append(
                        f"[MEDIUM] Security Group '{sg_name}' ({sg_id}): "
                        f"Inbound rule port {port_str} has no description"
                    )
    # Deduplicate while preserving order
    return list(dict.fromkeys(findings))


def audit_aws_sg(filepath):
    """Run all checks. Returns (findings_list, groups_list)."""
    groups, error = parse_aws_sg(filepath)
    if error:
        return [f"[ERROR] {error}"], []
    findings = []
    findings += check_wide_open_ingress(groups)
    findings += check_wide_open_egress(groups)
    findings += check_missing_descriptions(groups)
    return findings, groups
