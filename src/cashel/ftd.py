"""Cisco FTD (Firepower Threat Defense) parser and auditor.

Supports FTD LINA CLI output (show running-config) which shares ASA syntax
but includes FTD-specific commands such as access-control-policy, threat-detection,
and intrusion-policy references.
"""

from ciscoconfparse import CiscoConfParse

from .audit_engine import (
    _asa_acl_entries,
    _asa_metadata,
    _asa_scope_is_any,
    parse_asa_object_context,
)
from .models.findings import make_finding


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="ftd",
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


def _ftd_acl_entries(parse, action=None):
    return _asa_acl_entries(parse, parse_asa_object_context(parse), action=action)


def _ftd_metadata(entry, extra=None):
    metadata = _asa_metadata(entry, extra)
    metadata["syntax_family"] = "asa-compatible"
    return metadata


def _ftd_acl_finding(
    *,
    severity,
    category,
    message,
    remediation,
    id,
    title,
    entry,
    impact,
    verification,
    rollback,
    suggested_commands=None,
    metadata_extra=None,
):
    return _f(
        severity,
        category,
        message,
        remediation,
        id=id,
        title=title,
        evidence=entry["acl_line"],
        affected_object=entry["acl_name"],
        rule_name=entry["acl_name"],
        confidence="high",
        impact=impact,
        verification=verification,
        rollback=rollback,
        suggested_commands=suggested_commands,
        metadata=_ftd_metadata(entry, metadata_extra),
    )


def _ftd_has_any_any_deny(entries):
    return any(
        entry["protocol"] in {"ip", "any"}
        and _asa_scope_is_any(entry["expanded_source"])
        and _asa_scope_is_any(entry["expanded_destination"])
        for entry in entries
    )


def _ftd_duplicate_key(entry):
    return (
        entry["acl_name"].lower(),
        entry["action"],
        tuple(v.lower() for v in entry["expanded_source"]),
        tuple(v.lower() for v in entry["expanded_destination"]),
        tuple(v.lower() for v in entry["expanded_service"]),
    )


def _ftd_allows_telnet(entry):
    return any(
        str(service).lower() in {"tcp/23", "telnet"}
        for service in entry["expanded_service"]
    )


def _ftd_is_icmp_any_any(entry):
    return (
        entry["protocol"] == "icmp"
        and _asa_scope_is_any(entry["expanded_source"])
        and _asa_scope_is_any(entry["expanded_destination"])
    )


def _ftd_is_ip_any_any(entry):
    return (
        entry["protocol"] in {"ip", "any"}
        and _asa_scope_is_any(entry["expanded_source"])
        and _asa_scope_is_any(entry["expanded_destination"])
    )


# ── Detection ─────────────────────────────────────────────────────────────────

FTD_MARKERS = (
    "access-control-policy",
    "firepower threat defense",
    "firepower-module",
    "intrusion-policy",
    "snort",
)


def is_ftd_config(content: str) -> bool:
    """Return True if the config content contains FTD-specific markers."""
    lower = content.lower()
    return any(m in lower for m in FTD_MARKERS)


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_ftd(filepath):
    """Parse an FTD running config using CiscoConfParse (LINA/ASA-compatible CLI)."""
    return CiscoConfParse(filepath, ignore_blank_lines=False)


# ── Individual checks ─────────────────────────────────────────────────────────


def _check_access_control_policy(parse):
    """Warn if no access-control-policy reference is present (NGFW enforcement)."""
    if not parse.find_objects(r"^access-control-policy"):
        return [
            _f(
                "MEDIUM",
                "hygiene",
                "[MEDIUM] No access-control-policy reference found in config",
                "Ensure a Firepower access control policy is applied to this FTD device. "
                "Without an explicit policy, traffic handling falls back to the default action "
                "which may permit all traffic.",
            )
        ]
    return []


def _check_threat_detection(parse):
    """Verify threat-detection is enabled."""
    if not parse.find_objects(r"^threat-detection"):
        return [
            _f(
                "HIGH",
                "exposure",
                "[HIGH] Threat detection is not enabled",
                "Enable threat detection: 'threat-detection basic-threat' and "
                "'threat-detection statistics'. Threat detection identifies and blocks "
                "scanning, DoS, and brute-force attempts in real time.",
            )
        ]
    return []


def _check_intrusion_policy(parse):
    """Check that an intrusion/Snort policy is referenced."""
    has_ips = parse.find_objects(r"^intrusion-policy") or parse.find_objects(r"snort")
    if not has_ips:
        return [
            _f(
                "HIGH",
                "exposure",
                "[HIGH] No intrusion prevention policy (IPS/Snort) reference detected",
                "Assign a Firepower intrusion policy to traffic flows in the access control "
                "policy. IPS/Snort is a core FTD NGFW capability — without it, Layer-7 "
                "threats are not inspected.",
            )
        ]
    return []


def _check_ssl_inspection(parse):
    """Flag absence of SSL/TLS decryption configuration."""
    if not parse.find_objects(r"^ssl"):
        return [
            _f(
                "MEDIUM",
                "exposure",
                "[MEDIUM] No SSL/TLS decryption policy configured",
                "Configure SSL inspection to decrypt and inspect encrypted traffic. "
                "Without decryption, threats concealed in HTTPS, SMTPS, and other "
                "TLS-wrapped sessions bypass all content inspection.",
            )
        ]
    return []


def _check_any_any(parse):
    findings = []
    for entry in _ftd_acl_entries(parse, action="permit"):
        if not _ftd_is_ip_any_any(entry):
            continue
        findings.append(
            _ftd_acl_finding(
                severity="CRITICAL",
                category="exposure",
                message=f"[CRITICAL] Overly permissive rule found: {entry['acl_line']}",
                remediation=(
                    "Restrict source and destination to specific IP ranges. "
                    "Remove or scope down any/any permit rules to enforce least-privilege access."
                ),
                id="CASHEL-FTD-EXPOSURE-001",
                title="FTD ACL permits any source to any destination",
                entry=entry,
                impact="The rule may allow traffic from any source to any destination.",
                verification=(
                    "Review hit counts and traffic logs, then re-run the audit after replacing "
                    "the rule with scoped source and destination objects."
                ),
                rollback=(
                    "Restore the original ACL entry from configuration backup if the scoped "
                    "replacement blocks required traffic."
                ),
                suggested_commands=[
                    "no access-list <ACL_NAME> permit ip any any",
                    "access-list <ACL_NAME> permit ip <SRC_NET> <SRC_MASK> <DST_NET> <DST_MASK> log",
                ],
            )
        )
    return findings


def _check_missing_logging(parse):
    findings = []
    for entry in _ftd_acl_entries(parse, action="permit"):
        if "log" in entry["acl_line"]:
            continue
        findings.append(
            _ftd_acl_finding(
                severity="MEDIUM",
                category="logging",
                message=f"[MEDIUM] Permit rule missing logging: {entry['acl_line']}",
                remediation=(
                    "Add the 'log' keyword to all permit rules. Without logging, permitted "
                    "traffic generates no syslog entries and cannot be correlated in a SIEM."
                ),
                id="CASHEL-FTD-LOGGING-001",
                title="FTD permit ACL rule missing logging",
                entry=entry,
                impact="Permitted traffic for this rule may not be visible in syslog or incident review.",
                verification=(
                    "Confirm the rule includes the log keyword and verify new matching traffic "
                    "appears in syslog."
                ),
                rollback="Remove the log keyword from this ACL entry if logging volume causes operational issues.",
                suggested_commands=[f"{entry['acl_line']} log"],
            )
        )
    return findings


def _check_deny_all(parse):
    if _ftd_has_any_any_deny(_ftd_acl_entries(parse, action="deny")):
        return []
    if parse.find_objects(r"access-list.*deny ip any any"):
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found at end of ACL",
            "Add 'access-list <name> deny ip any any log' as the last entry in each ACL. "
            "Implicit deny produces no log entries and cannot be verified during audits.",
            id="CASHEL-FTD-HYGIENE-001",
            title="Explicit deny-all ACL rule missing",
            affected_object="ACL termination",
            rule_name="explicit deny-all",
            confidence="medium",
            impact="Traffic denied by the implicit rule may not produce auditable deny logs.",
            verification=(
                "Confirm each ACL terminates with an explicit deny ip any any log entry, "
                "then re-run the audit."
            ),
            rollback="Remove the added explicit deny entry if it creates unexpected logging or policy behavior.",
            suggested_commands=["access-list <ACL_NAME> deny ip any any log"],
        )
    ]


def _check_telnet(parse):
    findings = [
        _f(
            "CRITICAL",
            "protocol",
            f"[CRITICAL] Telnet management access configured: {r.text.strip()}",
            "Disable Telnet (no telnet ...) and enforce SSH for all management access. "
            "Telnet transmits credentials and session data in cleartext.",
            id="CASHEL-FTD-PROTOCOL-001",
            title="Telnet management access enabled",
            evidence=r.text.strip(),
            affected_object="management access",
            confidence="high",
            impact="Telnet sends management credentials and session data in cleartext.",
            verification="Confirm no telnet lines remain and SSH management access is available from approved networks.",
            rollback=(
                "Restore the removed telnet line only if emergency access is required "
                "and compensating controls are approved."
            ),
            suggested_commands=[f"no {r.text.strip()}"],
        )
        for r in parse.find_objects(r"^telnet\s")
    ]
    for entry in _ftd_acl_entries(parse, action="permit"):
        if not _ftd_allows_telnet(entry):
            continue
        findings.append(
            _ftd_acl_finding(
                severity="CRITICAL",
                category="protocol",
                message=f"[CRITICAL] Telnet service permitted by ACL: {entry['acl_line']}",
                remediation=(
                    "Replace Telnet with SSH or a secure application protocol and scope "
                    "the rule to approved sources only."
                ),
                id="CASHEL-FTD-PROTOCOL-002",
                title="Telnet service permitted by ACL",
                entry=entry,
                impact="Telnet sends credentials and session data in cleartext when used by matching traffic.",
                verification="Confirm tcp/23 is removed from the ACL or service group, then re-run the audit.",
                rollback=(
                    "Restore the prior ACL or service-group entry from backup only if an "
                    "approved exception requires Telnet."
                ),
                suggested_commands=["no <TELNET_ACCESS_LIST_LINE>"],
            )
        )
    return findings


def _check_snmp_community(parse):
    """Flag SNMPv1/v2c community strings; SNMPv3 auth+priv is required."""
    return [
        _f(
            "HIGH",
            "protocol",
            f"[HIGH] SNMPv1/v2c community string in use: {r.text.strip()}",
            "Migrate to SNMPv3 with authentication and encryption (authPriv). "
            "SNMPv1/v2c transmit community strings in cleartext and lack per-user auth.",
        )
        for r in parse.find_objects(r"^snmp-server community")
    ]


def _check_syslog_server(parse):
    """Require at least one remote syslog host."""
    if not parse.find_objects(r"^logging host"):
        return [
            _f(
                "MEDIUM",
                "logging",
                "[MEDIUM] No remote syslog server configured",
                "Configure 'logging host <interface> <ip>' to forward logs to a SIEM or "
                "syslog aggregator. Local-only logging is lost on reboot and cannot be "
                "correlated across devices.",
            )
        ]
    return []


def _check_ssh_version(parse):
    """Require SSHv2; flag if SSHv1 or no SSH version lock is set."""
    v2 = parse.find_objects(r"^ssh version 2")
    v1 = parse.find_objects(r"^ssh version 1")
    if v1:
        return [
            _f(
                "HIGH",
                "protocol",
                "[HIGH] SSHv1 is enabled for management access",
                "Set 'ssh version 2' and remove any 'ssh version 1' statements. "
                "SSHv1 has known cryptographic weaknesses and should not be used.",
            )
        ]
    if not v2:
        return [
            _f(
                "MEDIUM",
                "protocol",
                "[MEDIUM] SSH version not explicitly locked to SSHv2",
                "Add 'ssh version 2' to prevent fallback to SSHv1. "
                "Explicit version locking ensures only strong SSH cipher suites are offered.",
            )
        ]
    return []


def _check_http_server(parse):
    """Flag HTTP server (ASDM) enabled without restriction."""
    enabled = parse.find_objects(r"^http server enable")
    if enabled:
        # Check if access is restricted to specific hosts
        restricted = parse.find_objects(r"^http\s+\d")
        if not restricted:
            return [
                _f(
                    "MEDIUM",
                    "exposure",
                    "[MEDIUM] HTTP/ASDM server enabled with no host restriction",
                    "Either disable the HTTP server ('no http server enable') if ASDM is not "
                    "needed, or restrict access with 'http <network> <mask> <interface>' "
                    "to limit management to trusted hosts only.",
                )
            ]
    return []


def _check_redundant_rules(parse):
    findings, seen = [], {}
    for entry in _ftd_acl_entries(parse, action="permit"):
        key = _ftd_duplicate_key(entry)
        if key in seen:
            findings.append(
                _ftd_acl_finding(
                    severity="MEDIUM",
                    category="redundancy",
                    message=f"[MEDIUM] Redundant rule detected: {entry['acl_line']}",
                    remediation=(
                        "Remove duplicate ACL entries. Redundant rules cause configuration drift "
                        "and complicate change management audits."
                    ),
                    id="CASHEL-FTD-REDUNDANCY-001",
                    title="Redundant FTD ACL rule",
                    entry=entry,
                    impact="Duplicate ACL entries add review noise and can obscure intentional policy changes.",
                    verification="Confirm the remaining ACL entry preserves intended access and re-run the audit.",
                    rollback="Re-add the duplicate ACL entry from backup if removal affects an approved workflow.",
                    suggested_commands=["no <DUPLICATE_ACCESS_LIST_LINE>"],
                    metadata_extra={
                        "duplicate_normalized_rule": " ".join(
                            [
                                entry["acl_name"],
                                entry["action"],
                                entry["protocol"],
                                ",".join(entry["expanded_source"]),
                                ",".join(entry["expanded_destination"]),
                                ",".join(entry["expanded_service"]),
                            ]
                        ),
                        "duplicate_of": seen[key]["acl_line"],
                    },
                )
            )
        else:
            seen[key] = entry
    return findings


def _check_icmp_any(parse):
    findings = []
    for entry in _ftd_acl_entries(parse, action="permit"):
        if not _ftd_is_icmp_any_any(entry):
            continue
        findings.append(
            _ftd_acl_finding(
                severity="MEDIUM",
                category="exposure",
                message=f"[MEDIUM] Unrestricted ICMP permit rule: {entry['acl_line']}",
                remediation=(
                    "Restrict ICMP to specific source ranges, or permit only echo-reply, "
                    "unreachable, and time-exceeded types required for diagnostics."
                ),
                id="CASHEL-FTD-EXPOSURE-002",
                title="Unrestricted ICMP any-any ACL rule",
                entry=entry,
                impact="Unrestricted ICMP can increase reconnaissance signal and bypass intended diagnostic scoping.",
                verification=(
                    "Confirm ICMP is limited to approved sources and required message types, "
                    "then re-run the audit."
                ),
                rollback=(
                    "Restore the original ICMP ACL entry from backup if troubleshooting "
                    "traffic is unintentionally blocked."
                ),
                suggested_commands=[
                    "no access-list <ACL_NAME> permit icmp any any",
                    "access-list <ACL_NAME> permit icmp <TRUSTED_SRC> <MASK> any echo-reply log",
                ],
            )
        )
    return findings


# ── Main auditor ──────────────────────────────────────────────────────────────


def audit_ftd(filepath):
    """Audit a Cisco FTD running config. Returns (findings, parse_obj)."""
    parse = parse_ftd(filepath)
    findings = (
        _check_access_control_policy(parse)
        + _check_threat_detection(parse)
        + _check_intrusion_policy(parse)
        + _check_ssl_inspection(parse)
        + _check_any_any(parse)
        + _check_missing_logging(parse)
        + _check_deny_all(parse)
        + _check_telnet(parse)
        + _check_snmp_community(parse)
        + _check_syslog_server(parse)
        + _check_ssh_version(parse)
        + _check_http_server(parse)
        + _check_redundant_rules(parse)
        + _check_icmp_any(parse)
    )
    return findings, parse
