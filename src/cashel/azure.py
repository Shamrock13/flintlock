"""Azure Network Security Group (NSG) parser and auditor."""

from __future__ import annotations

import hashlib
import json

from .models.findings import make_finding

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


def _stable_id(check: str, *parts) -> str:
    payload = json.dumps([check, *parts], sort_keys=True, default=str)
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:10].upper()
    return f"CASHEL-AZURE-{check.upper().replace('_', '-')}-{digest}"


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
    rule_id=None,
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
        vendor="azure",
        title=title,
        evidence=evidence,
        affected_object=affected_object,
        rule_id=rule_id,
        rule_name=rule_name,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        metadata=metadata,
    )


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


def _list_or_single(props, single_key, multi_key):
    multi = props.get(multi_key, [])
    if multi:
        return list(multi)
    single = props.get(single_key, "")
    if single:
        return [single]
    return []


def _nsg_name(nsg):
    return nsg.get("name", "unnamed")


def _nsg_label(nsg):
    return f"NSG '{_nsg_name(nsg)}'"


def _flow_log_state(nsg):
    if "flowLogs" in nsg:
        return nsg.get("flowLogs")
    if "diagnosticSettings" in nsg:
        return nsg.get("diagnosticSettings")
    return "unknown"


def _rule_metadata(nsg, rule) -> dict:
    props = _props(rule)
    return {
        "nsg_name": _nsg_name(nsg),
        "rule_name": rule.get("name", "unnamed"),
        "direction": props.get("direction", ""),
        "priority": props.get("priority", "?"),
        "protocol": props.get("protocol", ""),
        "source_address_prefixes": _list_or_single(
            props, "sourceAddressPrefix", "sourceAddressPrefixes"
        ),
        "destination_address_prefixes": _list_or_single(
            props, "destinationAddressPrefix", "destinationAddressPrefixes"
        ),
        "source_port_ranges": _list_or_single(
            props, "sourcePortRange", "sourcePortRanges"
        ),
        "destination_port_ranges": _port_ranges(props),
        "action": props.get("access", ""),
        "flow_log_state": _flow_log_state(nsg),
        "raw_rule_context": rule,
    }


def _nsg_metadata(nsg) -> dict:
    return {
        "nsg_name": _nsg_name(nsg),
        "rule_name": "",
        "direction": "",
        "priority": "",
        "protocol": "",
        "source_address_prefixes": [],
        "destination_address_prefixes": [],
        "source_port_ranges": [],
        "destination_port_ranges": [],
        "action": "",
        "flow_log_state": _flow_log_state(nsg),
    }


def _rule_evidence(nsg, rule, port=None):
    props = _props(rule)
    ports = [str(port)] if port is not None else [str(p) for p in _port_ranges(props)]
    if not ports:
        ports = ["*"]
    return (
        f"nsg={_nsg_name(nsg)}; rule={rule.get('name', 'unnamed')}; "
        f"direction={props.get('direction', '')}; priority={props.get('priority', '?')}; "
        f"protocol={props.get('protocol', '')}; access={props.get('access', '')}; "
        f"source={','.join(_list_or_single(props, 'sourceAddressPrefix', 'sourceAddressPrefixes')) or 'unset'}; "
        f"destination={','.join(_list_or_single(props, 'destinationAddressPrefix', 'destinationAddressPrefixes')) or 'unset'}; "
        f"source_ports={','.join(_list_or_single(props, 'sourcePortRange', 'sourcePortRanges')) or 'unset'}; "
        f"destination_ports={','.join(ports)}"
    )


def _verification_text(nsg_name):
    return (
        "Review Azure effective security rules and re-run the Azure NSG audit "
        f"to confirm the finding is absent for NSG '{nsg_name}'."
    )


def _rollback_text():
    return (
        "Restore the previous NSG rule from Azure activity logs, IaC, or a saved "
        "NSG export if the change blocks approved traffic."
    )


def check_inbound_any(nsgs):
    findings = []
    for nsg in nsgs:
        nsg_name = _nsg_name(nsg)
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
            common = {
                "affected_object": _nsg_label(nsg),
                "rule_id": str(priority),
                "rule_name": rule_name,
                "confidence": "high",
                "verification": _verification_text(nsg_name),
                "rollback": _rollback_text(),
                "metadata": _rule_metadata(nsg, rule),
            }
            if not ports or "*" in ports:
                findings.append(
                    _f(
                        "HIGH",
                        "exposure",
                        f"[HIGH] NSG '{nsg_name}' rule '{rule_name}' (priority {priority}): ALL inbound traffic from Any source allowed",
                        "Restrict source address prefix to specific IP ranges or Azure service tags. "
                        "Any-source allow-all rules expose every port to the internet.",
                        id=_stable_id(
                            "inbound_any_all",
                            nsg_name,
                            rule_name,
                            priority,
                            src,
                        ),
                        title="All inbound traffic allowed from any source",
                        evidence=_rule_evidence(nsg, rule),
                        **common,
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
                                id=_stable_id(
                                    "inbound_any_sensitive",
                                    nsg_name,
                                    rule_name,
                                    priority,
                                    src,
                                    port,
                                ),
                                title=f"{svc} exposed to any source",
                                evidence=_rule_evidence(nsg, rule, port),
                                **common,
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
                                id=_stable_id(
                                    "inbound_any_port",
                                    nsg_name,
                                    rule_name,
                                    priority,
                                    src,
                                    port,
                                ),
                                title="Inbound port exposed to any source",
                                evidence=_rule_evidence(nsg, rule, port),
                                **common,
                            )
                        )
    return findings


def check_missing_flow_logs(nsgs):
    """Flag NSGs where flow log status cannot be confirmed from the JSON."""
    findings = []
    for nsg in nsgs:
        nsg_name = _nsg_name(nsg)
        if "flowLogs" not in nsg and "diagnosticSettings" not in nsg:
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] NSG '{nsg_name}': Flow log status unknown — verify NSG flow logs are enabled",
                    "Enable NSG flow logs via Azure Network Watcher. Flow logs are essential for "
                    "traffic analysis, compliance, and incident response. "
                    "Verify with: az network watcher flow-log show",
                    id=_stable_id("missing_flow_log_confirmation", nsg_name),
                    title="NSG flow log status is unknown",
                    evidence=f"nsg={nsg_name}; flow_log_state=unknown",
                    affected_object=_nsg_label(nsg),
                    confidence="medium",
                    verification=(
                        "Confirm NSG flow logs or diagnostic settings are enabled "
                        f"for NSG '{nsg_name}', then include that state in the next audit export."
                    ),
                    rollback=(
                        "If enabling flow logs creates unexpected cost or volume, adjust "
                        "retention and destination settings instead of disabling visibility."
                    ),
                    metadata=_nsg_metadata(nsg),
                )
            )
    return findings


def check_high_priority_allow_all(nsgs):
    """Flag high-priority (low number) Allow-All inbound rules."""
    findings = []
    for nsg in nsgs:
        nsg_name = _nsg_name(nsg)
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
                        id=_stable_id(
                            "high_priority_allow_all",
                            nsg_name,
                            rule_name,
                            priority,
                            props.get("sourceAddressPrefix", ""),
                        ),
                        title="High-priority allow-all inbound rule",
                        evidence=_rule_evidence(nsg, rule),
                        affected_object=_nsg_label(nsg),
                        rule_id=str(priority),
                        rule_name=rule_name,
                        confidence="high",
                        verification=_verification_text(nsg_name),
                        rollback=_rollback_text(),
                        metadata=_rule_metadata(nsg, rule),
                    )
                )
    return findings


def check_broad_port_ranges(nsgs):
    """Flag inbound allow rules with wide port ranges (>100 ports)."""
    findings = []
    for nsg in nsgs:
        nsg_name = _nsg_name(nsg)
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
                                    id=_stable_id(
                                        "broad_port_range",
                                        nsg_name,
                                        rule_name,
                                        priority,
                                        port,
                                    ),
                                    title="Wide inbound port range",
                                    evidence=_rule_evidence(nsg, rule, port),
                                    affected_object=_nsg_label(nsg),
                                    rule_id=str(priority),
                                    rule_name=rule_name,
                                    confidence="medium",
                                    verification=_verification_text(nsg_name),
                                    rollback=_rollback_text(),
                                    metadata=_rule_metadata(nsg, rule),
                                )
                            )
                    except (ValueError, IndexError):
                        pass
    return findings


def audit_azure_nsg(filepath):
    """Run all checks. Returns (findings_list, nsgs_list)."""
    nsgs, error = parse_azure_nsg(filepath)
    if error:
        return [
            _f(
                "HIGH",
                "hygiene",
                f"[ERROR] {error}",
                "",
                id=_stable_id("parse_error", error),
                title="Azure NSG JSON parse error",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the file is a valid Azure NSG JSON export and re-run the audit.",
                metadata={"nsg_name": "", "flow_log_state": "unknown"},
            )
        ], []
    findings = []
    findings += check_inbound_any(nsgs)
    findings += check_missing_flow_logs(nsgs)
    findings += check_high_priority_allow_all(nsgs)
    findings += check_broad_port_ranges(nsgs)
    return findings, nsgs
