"""GCP VPC Firewall rule parser and auditor.

Parses the JSON output of:
  gcloud compute firewall-rules list --format=json
  gcloud compute firewall-rules describe <name> --format=json

GCP VPC firewall rules are global to a VPC network and evaluated by priority
(lower number = higher precedence, range 0–65534).  Each rule either allows
or denies traffic matching its protocol/port/source criteria.

Key differences from AWS SGs / Azure NSGs:
  - Rules are global per VPC, not attached to individual resources.
  - Applied to instances via network tags or service accounts.
  - "direction" is always explicitly "INGRESS" or "EGRESS" (uppercase).
  - Each rule has either an "allowed" list or a "denied" list, never both.
  - GCP has implied rules not returned by the API:
      priority 65535 deny-all ingress, priority 65536 allow-all egress.
"""

from __future__ import annotations

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
    "9200": "Elasticsearch",
    "11211": "Memcached",
}

_ANY_RANGES = {"0.0.0.0/0", "::/0"}


def _f(severity, category, message, remediation=""):
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_gcp_firewall(filepath: str) -> tuple[list[dict], str | None]:
    """Parse a GCP VPC firewall rules JSON file.

    Accepts:
      - A JSON array of firewall rule objects (gcloud list output)
      - A single firewall rule object (gcloud describe output)
      - A dict with an ``"items"`` key wrapping a list of rules

    Returns (rules_list, error_str_or_None).
    """
    try:
        with open(filepath) as fh:
            data = json.load(fh)
    except Exception as exc:
        return [], f"Failed to parse GCP firewall JSON: {exc}"

    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict):
        if "items" in data:
            rules = data["items"]
        elif "name" in data and "direction" in data:
            rules = [data]
        else:
            return (
                [],
                "Unrecognized GCP firewall JSON format. Expected a list of firewall rules or a single rule object.",
            )
    else:
        return [], "Unrecognized GCP firewall JSON format."

    return rules, None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _rule_name(rule: dict) -> str:
    return rule.get("name") or "unnamed"


def _network_short(rule: dict) -> str:
    """Return just the network name from the full self-link URL."""
    network = rule.get("network", "")
    return network.rsplit("/", 1)[-1] if "/" in network else (network or "unknown")


def _is_any_range(ranges: list) -> bool:
    return any(r in _ANY_RANGES for r in (ranges or []))


def _allowed_protocols(rule: dict) -> list[dict]:
    """Return the list of allow-protocol dicts, or [] for deny rules."""
    return rule.get("allowed") or []


def _is_disabled(rule: dict) -> bool:
    return bool(rule.get("disabled", False))


def _ports_for_proto(proto_dict: dict) -> list[str]:
    return proto_dict.get("ports") or []


# ── Checks ────────────────────────────────────────────────────────────────────


def check_internet_ingress_gcp(rules: list[dict]) -> list[dict]:
    """Flag INGRESS allow rules with source 0.0.0.0/0 or ::/0."""
    findings = []
    for rule in rules:
        if _is_disabled(rule) or rule.get("direction") != "INGRESS":
            continue
        if not _allowed_protocols(rule):
            continue  # deny rule — not our focus here
        if not _is_any_range(rule.get("sourceRanges", [])):
            continue

        name = _rule_name(rule)
        network = _network_short(rule)
        src = ", ".join(r for r in rule.get("sourceRanges", []) if r in _ANY_RANGES)

        for proto_dict in _allowed_protocols(rule):
            proto = proto_dict.get("IPProtocol", "?")
            ports = _ports_for_proto(proto_dict)

            if proto == "all" or not ports:
                findings.append(
                    _f(
                        "HIGH",
                        "exposure",
                        f"[HIGH] VPC '{network}' rule '{name}': allows ALL ingress traffic from {src}",
                        f"Restrict 'gcloud compute firewall-rules update {name}' to specific source CIDRs "
                        "and protocols. All-traffic rules expose every port to the internet.",
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
                                f"[HIGH] VPC '{network}' rule '{name}': {svc} (TCP/{port}) open to {src}",
                                f"Remove public {svc} access: 'gcloud compute firewall-rules update {name} "
                                f"--source-ranges=<trusted-cidr>'. Use IAP or Cloud VPN for administrative access.",
                            )
                        )
                    elif "-" in port:
                        lo, _, hi = port.partition("-")
                        try:
                            span = int(hi) - int(lo) + 1
                        except ValueError:
                            span = 0
                        if span > 100:
                            findings.append(
                                _f(
                                    "MEDIUM",
                                    "exposure",
                                    f"[MEDIUM] VPC '{network}' rule '{name}': wide port range {port} ({span} ports/{proto}) open to {src}",
                                    f"Restrict port range in rule '{name}' to only the specific ports required. "
                                    "Wide ranges significantly increase attack surface.",
                                )
                            )
                        else:
                            findings.append(
                                _f(
                                    "MEDIUM",
                                    "exposure",
                                    f"[MEDIUM] VPC '{network}' rule '{name}': port {port}/{proto} open to {src}",
                                    f"Restrict source CIDRs for rule '{name}' to known IP ranges. "
                                    "Avoid 0.0.0.0/0 unless the service is intentionally public-facing.",
                                )
                            )
                    else:
                        findings.append(
                            _f(
                                "MEDIUM",
                                "exposure",
                                f"[MEDIUM] VPC '{network}' rule '{name}': port {port}/{proto} open to {src}",
                                f"Restrict source CIDRs for rule '{name}' to known IP ranges. "
                                "Avoid 0.0.0.0/0 unless the service is intentionally public-facing.",
                            )
                        )
    return findings


def check_unrestricted_egress_gcp(rules: list[dict]) -> list[dict]:
    """Flag EGRESS allow-all rules to 0.0.0.0/0."""
    findings = []
    for rule in rules:
        if _is_disabled(rule) or rule.get("direction") != "EGRESS":
            continue
        if not _allowed_protocols(rule):
            continue
        if not _is_any_range(rule.get("destinationRanges", [])):
            continue

        for proto_dict in _allowed_protocols(rule):
            if proto_dict.get("IPProtocol") == "all" or not _ports_for_proto(
                proto_dict
            ):
                name = _rule_name(rule)
                network = _network_short(rule)
                findings.append(
                    _f(
                        "MEDIUM",
                        "exposure",
                        f"[MEDIUM] VPC '{network}' rule '{name}': unrestricted egress to 0.0.0.0/0 (all protocols/ports)",
                        f"Restrict outbound traffic for rule '{name}' to required destinations and ports. "
                        "Unrestricted egress can facilitate data exfiltration and C2 communication.",
                    )
                )
                break  # one finding per rule is enough
    return findings


def check_default_network_rules_gcp(rules: list[dict]) -> list[dict]:
    """Flag active rules attached to the 'default' VPC network.

    The GCP 'default' network ships with pre-created allow rules that are
    intentionally permissive.  Production workloads should use dedicated VPCs.
    """
    findings = []
    seen: set = set()
    for rule in rules:
        if _is_disabled(rule):
            continue
        network = _network_short(rule)
        if network == "default" and network not in seen:
            seen.add(network)
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    "[MEDIUM] Firewall rules exist on the 'default' VPC network.",
                    "Migrate workloads to a dedicated VPC with purpose-built firewall rules. "
                    "The 'default' network's pre-populated rules (default-allow-ssh, default-allow-rdp, etc.) "
                    "are overly permissive for production use.",
                )
            )
    return findings


def check_missing_description_gcp(rules: list[dict]) -> list[dict]:
    """Flag allow rules with no description field."""
    findings = []
    for rule in rules:
        if _is_disabled(rule) or not _allowed_protocols(rule):
            continue
        desc = (rule.get("description") or "").strip()
        if not desc:
            name = _rule_name(rule)
            network = _network_short(rule)
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] VPC '{network}' rule '{name}': no description set.",
                    f"Add a description: 'gcloud compute firewall-rules update {name} "
                    '--description="<purpose, owner, ticket>"\'. '
                    "Descriptions are essential for security reviews and change management.",
                )
            )
    return findings


def check_disabled_rules_gcp(rules: list[dict]) -> list[dict]:
    """Flag disabled firewall rules — they indicate configuration debt."""
    disabled = [r for r in rules if _is_disabled(r)]
    if not disabled:
        return []
    names = ", ".join(_rule_name(r) for r in disabled[:5])
    extra = len(disabled) - 5
    label = names + (f" … and {extra} more" if extra > 0 else "")
    return [
        _f(
            "MEDIUM",
            "hygiene",
            f"[MEDIUM] {len(disabled)} disabled firewall rule(s) found: {label}",
            "Remove disabled rules that are no longer needed. "
            "Disabled rules represent configuration drift and complicate audits. "
            "If a rule may be needed again, document it in a ticket and delete it from the firewall.",
        )
    ]


def check_no_target_restriction_gcp(rules: list[dict]) -> list[dict]:
    """Flag inbound allow rules with no targetTags or targetServiceAccounts.

    Rules without target restrictions apply to ALL instances in the VPC,
    which is rarely the intended scope for a least-privilege posture.
    """
    findings = []
    for rule in rules:
        if _is_disabled(rule) or rule.get("direction") != "INGRESS":
            continue
        if not _allowed_protocols(rule):
            continue
        if not _is_any_range(rule.get("sourceRanges", [])):
            continue  # not internet-sourced, lower risk
        has_tags = bool(rule.get("targetTags"))
        has_sa = bool(rule.get("targetServiceAccounts"))
        if not has_tags and not has_sa:
            name = _rule_name(rule)
            network = _network_short(rule)
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] VPC '{network}' rule '{name}': no targetTags or targetServiceAccounts — applies to ALL instances.",
                    f"Add target network tags or a target service account to rule '{name}': "
                    f"'gcloud compute firewall-rules update {name} --target-tags=<tag>'. "
                    "Rules without targets apply to every VM in the network, violating least-privilege.",
                )
            )
    return findings


def check_icmp_unrestricted_gcp(rules: list[dict]) -> list[dict]:
    """Flag INGRESS ICMP allow rules from 0.0.0.0/0.

    Unrestricted ICMP aids reconnaissance (ping sweeps, traceroute).
    """
    findings = []
    for rule in rules:
        if _is_disabled(rule) or rule.get("direction") != "INGRESS":
            continue
        if not _is_any_range(rule.get("sourceRanges", [])):
            continue
        for proto_dict in _allowed_protocols(rule):
            if proto_dict.get("IPProtocol") == "icmp":
                name = _rule_name(rule)
                network = _network_short(rule)
                findings.append(
                    _f(
                        "MEDIUM",
                        "exposure",
                        f"[MEDIUM] VPC '{network}' rule '{name}': ICMP allowed inbound from 0.0.0.0/0.",
                        f"Restrict ICMP to known management CIDRs: "
                        f"'gcloud compute firewall-rules update {name} --source-ranges=<mgmt-cidr>'. "
                        "Unrestricted ICMP aids network reconnaissance.",
                    )
                )
    return findings


# ── Top-level auditor ─────────────────────────────────────────────────────────


def audit_gcp_firewall(filepath: str) -> tuple[list[dict], list[dict]]:
    """Run all checks on a GCP VPC firewall rules JSON export.

    Returns (findings_list, rules_list).
    """
    rules, error = parse_gcp_firewall(filepath)
    if error:
        return [_f("HIGH", "parse", f"[HIGH] {error}")], []

    findings: list[dict] = []
    findings += check_internet_ingress_gcp(rules)
    findings += check_unrestricted_egress_gcp(rules)
    findings += check_default_network_rules_gcp(rules)
    findings += check_missing_description_gcp(rules)
    findings += check_disabled_rules_gcp(rules)
    findings += check_no_target_restriction_gcp(rules)
    findings += check_icmp_unrestricted_gcp(rules)
    return findings, rules
