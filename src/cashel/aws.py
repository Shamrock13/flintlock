"""AWS Security Group parser and auditor."""

from __future__ import annotations

import hashlib
import json

from .models.findings import make_finding

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


def _stable_id(check: str, *parts) -> str:
    payload = json.dumps([check, *parts], sort_keys=True, default=str)
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:10].upper()
    return f"CASHEL-AWS-{check.upper().replace('_', '-')}-{digest}"


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    title=None,
    evidence=None,
    affected_object=None,
    rule_name=None,
    confidence="medium",
    impact=None,
    verification=None,
    rollback=None,
    metadata=None,
):
    """Build a structured finding dict."""
    return make_finding(
        severity,
        category,
        message,
        remediation,
        id=id,
        vendor="aws",
        title=title,
        evidence=evidence,
        affected_object=affected_object,
        rule_name=rule_name,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        metadata=metadata,
    )


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


def _sg_label(sg):
    return f"Security Group '{sg.get('GroupName', 'unnamed')}' ({sg.get('GroupId', 'unknown')})"


def _rule_port_label(rule):
    from_port = rule.get("FromPort", -1)
    to_port = rule.get("ToPort", -1)
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def _referenced_groups(rule):
    refs = []
    for pair in rule.get("UserIdGroupPairs", []):
        ref = pair.get("GroupId") or pair.get("GroupName") or pair.get("Description")
        if ref:
            refs.append(ref)
    return refs


def _rule_name(sg, direction, rule, cidr=""):
    source = cidr or ",".join(_referenced_groups(rule)) or "unspecified-source"
    return (
        f"{sg.get('GroupId', 'unknown')} {direction} "
        f"{rule.get('IpProtocol', '')} {_rule_port_label(rule)} {source}"
    )


def _rule_metadata(sg, rule, direction, cidr="", description="", ip_version="") -> dict:
    return {
        "security_group_id": sg.get("GroupId", "unknown"),
        "security_group_name": sg.get("GroupName", "unnamed"),
        "security_group_description": sg.get("Description", ""),
        "rule_direction": direction,
        "protocol": rule.get("IpProtocol", ""),
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "cidr": cidr,
        "ip_version": ip_version,
        "referenced_group": ",".join(_referenced_groups(rule)),
        "description": description,
        "raw_permission_context": rule,
    }


def _group_metadata(sg, *, direction="", raw_permission_context=None) -> dict:
    return {
        "security_group_id": sg.get("GroupId", "unknown"),
        "security_group_name": sg.get("GroupName", "unnamed"),
        "security_group_description": sg.get("Description", ""),
        "rule_direction": direction,
        "protocol": "",
        "from_port": None,
        "to_port": None,
        "cidr": "",
        "referenced_group": "",
        "description": sg.get("Description", ""),
        "raw_permission_context": raw_permission_context,
    }


def _rule_evidence(sg, direction, rule, cidr="", description=""):
    desc = description.strip() or "unset"
    return (
        f"security_group={sg.get('GroupName', 'unnamed')} ({sg.get('GroupId', 'unknown')}); "
        f"direction={direction}; protocol={rule.get('IpProtocol', '')}; "
        f"ports={_rule_port_label(rule)}; cidr={cidr or 'unset'}; "
        f"referenced_group={','.join(_referenced_groups(rule)) or 'unset'}; "
        f"description={desc}"
    )


def _verification_text(sg_id):
    return (
        "Re-run the AWS Security Group audit and confirm the finding is absent "
        f"for security group {sg_id}."
    )


def _rollback_text():
    return (
        "Restore the previous security group rule from change history or a saved "
        "describe-security-groups export if the change blocks legitimate traffic."
    )


def check_wide_open_ingress(groups):
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        for rule in sg.get("IpPermissions", []):
            proto = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            for cidr, desc, ver in _all_cidrs(rule):
                if not _is_any(cidr):
                    continue
                tag = _sg_label(sg)
                common = {
                    "affected_object": tag,
                    "rule_name": _rule_name(sg, "ingress", rule, cidr),
                    "evidence": _rule_evidence(sg, "ingress", rule, cidr, desc),
                    "confidence": "high",
                    "verification": _verification_text(sg_id),
                    "rollback": _rollback_text(),
                    "metadata": _rule_metadata(sg, rule, "ingress", cidr, desc, ver),
                }
                if proto == "-1":
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] {tag}: ALL traffic allowed inbound from {cidr}",
                            "Restrict inbound rules to specific ports and source CIDRs. "
                            "All-traffic rules expose every port and protocol to the internet.",
                            id=_stable_id(
                                "wide_open_ingress_all",
                                sg_id,
                                proto,
                                from_port,
                                to_port,
                                cidr,
                            ),
                            title="All inbound traffic allowed from the internet",
                            **common,
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
                            id=_stable_id(
                                "wide_open_ingress_sensitive",
                                sg_id,
                                proto,
                                from_port,
                                to_port,
                                cidr,
                            ),
                            title=f"{svc} exposed to the internet",
                            **common,
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
                            id=_stable_id(
                                "wide_open_ingress_all_ports",
                                sg_id,
                                proto,
                                from_port,
                                to_port,
                                cidr,
                            ),
                            title="All inbound ports exposed to the internet",
                            **common,
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
                            id=_stable_id(
                                "wide_open_ingress_port",
                                sg_id,
                                proto,
                                from_port,
                                to_port,
                                cidr,
                            ),
                            title="Inbound service exposed to the internet",
                            **common,
                        )
                    )
    return findings


def check_wide_open_egress(groups):
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        flagged = False
        for rule in sg.get("IpPermissionsEgress", []):
            if flagged:
                break
            proto = rule.get("IpProtocol", "")
            for cidr, desc, ver in _all_cidrs(rule):
                if _is_any(cidr) and proto == "-1":
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] {_sg_label(sg)}: Unrestricted outbound traffic to {cidr}",
                            "Consider restricting egress to required destinations and ports. "
                            "Unrestricted egress can facilitate data exfiltration and C2 communication.",
                            id=_stable_id(
                                "unrestricted_egress",
                                sg_id,
                                proto,
                                rule.get("FromPort", -1),
                                rule.get("ToPort", -1),
                                cidr,
                            ),
                            title="Unrestricted outbound traffic",
                            evidence=_rule_evidence(sg, "egress", rule, cidr, desc),
                            affected_object=_sg_label(sg),
                            rule_name=_rule_name(sg, "egress", rule, cidr),
                            confidence="high",
                            verification=_verification_text(sg_id),
                            rollback=_rollback_text(),
                            metadata=_rule_metadata(
                                sg, rule, "egress", cidr, desc, ver
                            ),
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
        desc = (sg.get("Description") or "").strip().lower()
        if not desc or desc in ("launch-wizard", "default", ""):
            key = f"sg-desc-{sg_id}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    _f(
                        "MEDIUM",
                        "hygiene",
                        f"[MEDIUM] {_sg_label(sg)}: Missing or generic group description",
                        "Add a meaningful description documenting the group's purpose, owner team, and workload. "
                        "Generic descriptions ('launch-wizard', 'default') provide no context for auditors.",
                        id=_stable_id("missing_group_description", sg_id),
                        title="Missing or generic security group description",
                        evidence=(
                            f"security_group={sg.get('GroupName', 'unnamed')} ({sg_id}); "
                            f"group_description={sg.get('Description') or 'unset'}"
                        ),
                        affected_object=_sg_label(sg),
                        confidence="medium",
                        verification=_verification_text(sg_id),
                        rollback=(
                            "Restore the previous security group description if the new "
                            "description is inaccurate."
                        ),
                        metadata=_group_metadata(sg),
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
                                f"[MEDIUM] {_sg_label(sg)}: Inbound rule port {port_str} has no description",
                                "Add a description to each inbound rule explaining what service it allows and why. "
                                "Rule descriptions are essential context for security reviews.",
                                id=_stable_id(
                                    "missing_rule_description",
                                    sg_id,
                                    rule.get("IpProtocol", ""),
                                    from_port,
                                    to_port,
                                    ip_range.get("CidrIp", ""),
                                ),
                                title="Inbound security group rule has no description",
                                evidence=_rule_evidence(
                                    sg,
                                    "ingress",
                                    rule,
                                    ip_range.get("CidrIp", ""),
                                    ip_range.get("Description", ""),
                                ),
                                affected_object=_sg_label(sg),
                                rule_name=_rule_name(
                                    sg, "ingress", rule, ip_range.get("CidrIp", "")
                                ),
                                confidence="medium",
                                verification=_verification_text(sg_id),
                                rollback=(
                                    "Restore the previous rule description if the new "
                                    "description is inaccurate."
                                ),
                                metadata=_rule_metadata(
                                    sg,
                                    rule,
                                    "ingress",
                                    ip_range.get("CidrIp", ""),
                                    ip_range.get("Description", ""),
                                    "ipv4",
                                ),
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
                    id=_stable_id("default_sg_ingress", sg_id, inbound),
                    title="Default security group has active inbound rules",
                    evidence=(
                        f"security_group=default ({sg_id}); direction=ingress; "
                        f"active_inbound_rules={len(inbound)}"
                    ),
                    affected_object=f"Default security group ({sg_id})",
                    confidence="high",
                    verification=_verification_text(sg_id),
                    rollback=_rollback_text(),
                    metadata=_group_metadata(
                        sg, direction="ingress", raw_permission_context=inbound
                    ),
                )
            )
    return findings


def check_large_port_ranges(groups):
    """Flag inbound rules with unusually wide port ranges (>100 ports)."""
    findings = []
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            proto = rule.get("IpProtocol", "")
            if from_port < 0 or to_port < 0 or proto == "-1":
                continue
            port_range = to_port - from_port
            if port_range > 100 and not (from_port == 0 and to_port == 65535):
                for cidr, desc, ver in _all_cidrs(rule):
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] {_sg_label(sg)}: Wide port range {from_port}-{to_port} ({port_range + 1} ports) open to {cidr}",
                            "Restrict open port ranges to the minimum required ports. "
                            "Wide ranges significantly increase attack surface and should be scoped to specific service ports.",
                            id=_stable_id(
                                "large_port_range",
                                sg_id,
                                proto,
                                from_port,
                                to_port,
                                cidr,
                            ),
                            title="Wide inbound port range",
                            evidence=_rule_evidence(sg, "ingress", rule, cidr, desc),
                            affected_object=_sg_label(sg),
                            rule_name=_rule_name(sg, "ingress", rule, cidr),
                            confidence="medium",
                            verification=_verification_text(sg_id),
                            rollback=_rollback_text(),
                            metadata=_rule_metadata(
                                sg, rule, "ingress", cidr, desc, ver
                            ),
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
