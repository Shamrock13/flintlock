"""Cisco FTD (Firepower Threat Defense) parser and auditor.

Supports FTD LINA CLI output (show running-config) which shares ASA syntax
but includes FTD-specific commands such as access-control-policy, threat-detection,
and intrusion-policy references.
"""

import re
from ciscoconfparse import CiscoConfParse


def _f(severity, category, message, remediation=""):
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


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
    return [
        _f(
            "HIGH",
            "exposure",
            f"[HIGH] Overly permissive rule found: {r.text.strip()}",
            "Restrict source and destination to specific IP ranges. "
            "Remove or scope down any/any permit rules to enforce least-privilege access.",
        )
        for r in parse.find_objects(r"access-list.*permit.*any any")
    ]


def _check_missing_logging(parse):
    return [
        _f(
            "MEDIUM",
            "logging",
            f"[MEDIUM] Permit rule missing logging: {r.text.strip()}",
            "Add the 'log' keyword to all permit rules. Without logging, permitted "
            "traffic generates no syslog entries and cannot be correlated in a SIEM.",
        )
        for r in parse.find_objects(r"access-list.*permit")
        if "log" not in r.text
    ]


def _check_deny_all(parse):
    if parse.find_objects(r"access-list.*deny ip any any"):
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found at end of ACL",
            "Add 'access-list <name> deny ip any any log' as the last entry in each ACL. "
            "Implicit deny produces no log entries and cannot be verified during audits.",
        )
    ]


def _check_telnet(parse):
    return [
        _f(
            "MEDIUM",
            "protocol",
            f"[MEDIUM] Telnet management access configured: {r.text.strip()}",
            "Disable Telnet (no telnet ...) and enforce SSH for all management access. "
            "Telnet transmits credentials and session data in cleartext.",
        )
        for r in parse.find_objects(r"^telnet\s")
    ]


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
    findings, seen = [], []
    for rule in parse.find_objects(r"access-list.*permit"):
        text_clean = re.sub(
            r"\s+", " ", rule.text.strip().lower().replace(" log", "")
        ).strip()
        if text_clean in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: {rule.text.strip()}",
                    "Remove duplicate ACL entries. Redundant rules cause configuration drift "
                    "and complicate change management audits.",
                )
            )
        else:
            seen.append(text_clean)
    return findings


def _check_icmp_any(parse):
    return [
        _f(
            "MEDIUM",
            "exposure",
            f"[MEDIUM] Unrestricted ICMP permit rule: {r.text.strip()}",
            "Restrict ICMP to specific source ranges, or permit only echo-reply, "
            "unreachable, and time-exceeded types required for diagnostics.",
        )
        for r in parse.find_objects(r"access-list.*permit icmp any any")
    ]


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
