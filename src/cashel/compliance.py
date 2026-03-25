"""Compliance framework checks — CIS, PCI-DSS, NIST SP 800-41, HIPAA Security Rule.

Each check function returns a list of finding strings tagged with the framework
prefix (CIS-HIGH, PCI-MEDIUM, NIST-HIGH, HIPAA-HIGH, etc.).

Vendors covered: Cisco ASA, Cisco FTD, Palo Alto, Fortinet, pfSense, Juniper SRX.
"""

# ══════════════════════════════════════════════════════════════ CISCO ASA ══


def check_cis_compliance(parse):
    """CIS Cisco ASA Firewall Benchmark checks."""
    findings = []

    # CIS 1 — Explicit deny-all at end of ACL
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[CIS-HIGH] CIS Control 1: No default deny-all rule found")

    # CIS 2 — No any/any permit rules (least privilege)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[CIS-HIGH] CIS Control 2: {len(any_any)} any/any permit rule(s) violate least privilege"
        )

    # CIS 3 — All permit rules must have logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Permit rule missing logging: {rule.text.strip()}"
            )

    # CIS 4 — SSH must be locked to version 2
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[CIS-HIGH] CIS Control 4: SSHv1 is enabled — disable it and enforce SSHv2 only"
        )
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 4: SSH version not explicitly locked to version 2"
        )

    # CIS 5 — SNMPv1/v2c community strings must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[CIS-HIGH] CIS Control 5: SNMPv1/v2c community string in use: {r.text.strip()} — migrate to SNMPv3"
        )

    # CIS 6 — Telnet management access must be disabled
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[CIS-HIGH] CIS Control 6: Telnet management access is configured — disable and use SSH"
        )

    # CIS 7 — HTTP/ASDM server should be disabled or restricted
    if parse.find_objects(r"^http server enable"):
        if not parse.find_objects(r"^http\s+\d"):
            findings.append(
                "[CIS-MEDIUM] CIS Control 7: HTTP/ASDM server enabled with no host restriction"
            )

    # CIS 8 — NTP server must be configured
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 8: No NTP server configured — accurate timestamps are required for log integrity"
        )

    # CIS 9 — Login banner must be set
    if not parse.find_objects(r"^banner (login|motd|exec)"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 9: No login banner configured — banners provide legal notice and deter unauthorized access"
        )

    # CIS 10 — Password encryption must be enabled
    if not parse.find_objects(r"^password encryption aes") and not parse.find_objects(
        r"^service password-encryption"
    ):
        findings.append(
            "[CIS-MEDIUM] CIS Control 10: Password encryption not configured — enable 'service password-encryption' or AES encryption"
        )

    # CIS 11 — Unrestricted ICMP from any source
    if parse.find_objects(r"access-list.*permit icmp any any"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 11: Unrestricted ICMP (any/any) permitted — restrict ICMP to necessary types and sources"
        )

    return findings


def check_pci_compliance(parse):
    """PCI-DSS Requirement checks for Cisco ASA."""
    findings = []

    # PCI Req 1.3 — No any/any rules (direct routes to cardholder data prohibited)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) found — direct routes to cardholder data prohibited"
        )

    # PCI Req 10.2 — All permit rules must log (audit trail)
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text.strip()}"
            )

    # PCI Req 1.2 — Explicit deny all must exist
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    # PCI Req 2.2.3 — Insecure protocols (Telnet) must be disabled
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[PCI-HIGH] PCI Req 2.2.3: Telnet management access configured — Telnet is an insecure protocol prohibited by PCI-DSS"
        )

    # PCI Req 2.2 — SNMPv1/v2c must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[PCI-HIGH] PCI Req 2.2: SNMPv1/v2c community string in use: {r.text.strip()} — PCI-DSS requires SNMPv3"
        )

    # PCI Req 10.5 — Syslog server must be configured (log protection)
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[PCI-HIGH] PCI Req 10.5: No remote syslog server configured — logs must be sent to a protected central log server"
        )

    # PCI Req 6.4 — NTP required for accurate audit timestamps
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 10.4: No NTP server configured — synchronized time is required for accurate audit log timestamps"
        )

    # PCI Req 2.2 — HTTP/ASDM server exposure
    if parse.find_objects(r"^http server enable") and not parse.find_objects(
        r"^http\s+\d"
    ):
        findings.append(
            "[PCI-MEDIUM] PCI Req 2.2: HTTP/ASDM server enabled with no host restriction — restrict to authorized management hosts"
        )

    # PCI Req 1.1 — Unrestricted ICMP
    if parse.find_objects(r"access-list.*permit icmp any any"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 1.1: Unrestricted ICMP (any/any) permitted — restrict to necessary types to limit network exposure"
        )

    return findings


def check_nist_compliance(parse):
    """NIST SP 800-41 / NIST 800-53 checks for Cisco ASA."""
    findings = []

    # NIST AC-6 — Least privilege: no any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any permit rule(s) violate least privilege principle"
        )

    # NIST AU-2 — Audit events: logging required on permit rules
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text.strip()}"
            )

    # NIST SC-7 — Boundary protection: deny-all must exist
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found"
        )

    # NIST SC-8 — Transmission confidentiality: no Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[NIST-HIGH] NIST SC-8: Telnet configured — NIST SC-8 requires encrypted management channels; use SSH"
        )

    # NIST AU-9 — Log protection: remote syslog required
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[NIST-HIGH] NIST AU-9: No remote syslog server configured — logs must be protected from local modification or loss"
        )

    # NIST IA-3 — Device authentication: SNMPv3 required
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[NIST-HIGH] NIST IA-3: SNMPv1/v2c community string in use — NIST requires authenticated SNMPv3: {r.text.strip()}"
        )

    # NIST CM-7 — Least functionality: SSH version lock
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[NIST-HIGH] NIST CM-7: SSHv1 is enabled — disable to enforce least functionality"
        )
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append(
            "[NIST-MEDIUM] NIST CM-7: SSH version not locked to version 2 — enforce SSHv2 to reduce attack surface"
        )

    # NIST AU-8 — Time stamps: NTP required
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[NIST-MEDIUM] NIST AU-8: No NTP server configured — accurate time synchronization is required for reliable audit timestamps"
        )

    # NIST AC-17 — Remote access: HTTP/ASDM exposure
    if parse.find_objects(r"^http server enable") and not parse.find_objects(
        r"^http\s+\d"
    ):
        findings.append(
            "[NIST-MEDIUM] NIST AC-17: HTTP/ASDM management server unrestricted — limit remote access to authorized management hosts"
        )

    return findings


# ══════════════════════════════════════════════════════════ CISCO FTD ══


def check_cis_compliance_ftd(parse):
    """CIS checks for Cisco FTD (LINA CLI config)."""
    findings = []

    # CIS 1 — Explicit deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[CIS-HIGH] CIS Control 1: No default deny-all ACL rule found")

    # CIS 2 — No any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[CIS-HIGH] CIS Control 2: {len(any_any)} any/any permit rule(s) violate least privilege"
        )

    # CIS 3 — All permit rules must log
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Permit rule missing logging: {rule.text.strip()}"
            )

    # CIS 4 — Threat detection must be enabled
    if not parse.find_objects(r"^threat-detection"):
        findings.append(
            "[CIS-HIGH] CIS Control 4: Threat detection not configured — enable threat-detection basic-threat"
        )

    # CIS 5 — Intrusion policy (IPS/Snort) must be referenced
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(
        r"snort"
    ):
        findings.append(
            "[CIS-HIGH] CIS Control 5: No intrusion prevention policy reference found — assign an IPS policy in FMC"
        )

    # CIS 6 — SSH version 2 only
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[CIS-HIGH] CIS Control 6: SSHv1 is enabled — enforce SSHv2 only"
        )
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 6: SSH version not locked to version 2"
        )

    # CIS 7 — SNMPv1/v2c must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[CIS-HIGH] CIS Control 7: SNMPv1/v2c community string configured — migrate to SNMPv3: {r.text.strip()}"
        )

    # CIS 8 — No Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[CIS-HIGH] CIS Control 8: Telnet management access configured — disable and use SSH"
        )

    # CIS 9 — NTP configured
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 9: No NTP server configured — accurate timestamps required for FTD event correlation"
        )

    # CIS 10 — Remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 10: No remote syslog server configured"
        )

    return findings


def check_pci_compliance_ftd(parse):
    """PCI-DSS checks for Cisco FTD."""
    findings = []

    # PCI 1.3 — No any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) — direct routes to cardholder data prohibited"
        )

    # PCI 10.2 — Logging on permit rules
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text.strip()}"
            )

    # PCI 1.2 — Explicit deny all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    # PCI 2.2.3 — Telnet prohibited
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[PCI-HIGH] PCI Req 2.2.3: Telnet management configured — prohibited by PCI-DSS"
        )

    # PCI 10.5 — Remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[PCI-HIGH] PCI Req 10.5: No remote syslog server — logs must be sent to a protected central server"
        )

    # PCI 2.2 — SNMP
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[PCI-HIGH] PCI Req 2.2: SNMPv1/v2c in use: {r.text.strip()} — PCI-DSS requires SNMPv3"
        )

    # PCI 6.4 — IPS must be deployed
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(
        r"snort"
    ):
        findings.append(
            "[PCI-HIGH] PCI Req 6.6: No intrusion prevention policy found — IPS is required to detect and block web-based attacks"
        )

    # PCI 10.4 — NTP for audit timestamps
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 10.4: No NTP server configured — synchronized time required for audit log integrity"
        )

    return findings


def check_nist_compliance_ftd(parse):
    """NIST SP 800-41 / NIST 800-53 checks for Cisco FTD."""
    findings = []

    # NIST AC-6 — Least privilege
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any rule(s) violate least privilege"
        )

    # NIST AU-2 — Audit logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text.strip()}"
            )

    # NIST SC-7 — Boundary protection
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found"
        )

    # NIST SC-8 — No Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[NIST-HIGH] NIST SC-8: Telnet configured — use encrypted SSH management per NIST SC-8"
        )

    # NIST SI-3 — IPS/malware protection
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(
        r"snort"
    ):
        findings.append(
            "[NIST-HIGH] NIST SI-3: No intrusion prevention policy found — NIST SI-3 requires malicious code protection"
        )

    # NIST AU-9 — Log protection via remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[NIST-HIGH] NIST AU-9: No remote syslog server — audit records must be protected from local loss or tampering"
        )

    # NIST IA-3 — SNMPv3 for device authentication
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[NIST-HIGH] NIST IA-3: SNMPv1/v2c in use — NIST requires authenticated SNMPv3: {r.text.strip()}"
        )

    # NIST AU-8 — NTP
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[NIST-MEDIUM] NIST AU-8: No NTP server — accurate timestamps required for audit records"
        )

    return findings


# ════════════════════════════════════════════════════════ PALO ALTO ══


def check_cis_compliance_pa(rules):
    """CIS Palo Alto Networks Firewall Benchmark checks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        apps = [a.text for a in rule.findall(".//application/member")]
        profile_setting = rule.find(".//profile-setting")

        # CIS 1 — No any/any permit
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{name}' violates least privilege — any/any permit"
            )

        # CIS 2 — All permit rules must log
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{name}' missing logging"
            )

        # CIS 3 — Security profiles must be attached to allow rules
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[CIS-MEDIUM] CIS Control 3: Rule '{name}' has no security profile attached — "
                    "attach an AV, IPS, and URL filtering profile to inspect allowed traffic"
                )

        # CIS 4 — Application 'any' in allow rules
        if action == "allow" and "any" in apps:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 4: Rule '{name}' permits any application — "
                "specify allowed applications to enforce application-based policy"
            )

    # CIS 5 — Deny all must exist
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 5: No default deny-all rule found")

    # CIS 6 — Unnamed rules
    unnamed = [
        r
        for r in rules
        if not r.get("name") or r.get("name", "").lower() in ("unnamed", "")
    ]
    if unnamed:
        findings.append(
            f"[CIS-MEDIUM] CIS Control 6: {len(unnamed)} unnamed rule(s) found — all rules must be named for audit clarity"
        )

    return findings


def check_pci_compliance_pa(rules):
    """PCI-DSS checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        profile_setting = rule.find(".//profile-setting")

        # PCI 1.3 — No any/any
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{name}' — direct routes to cardholder data prohibited"
            )

        # PCI 10.2 — Logging required
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{name}' missing audit logging"
            )

        # PCI 6.6 — Security profiles for application inspection
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[PCI-MEDIUM] PCI Req 6.6: Rule '{name}' has no security profile — "
                    "attach IPS/AV profiles to inspect traffic for cardholder data threats"
                )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_pa(rules):
    """NIST SP 800-41 / NIST 800-53 checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        apps = [a.text for a in rule.findall(".//application/member")]
        profile_setting = rule.find(".//profile-setting")

        # NIST AC-6 — Least privilege
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{name}' violates least privilege principle"
            )

        # NIST AU-2 — Audit logging
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{name}' missing audit logging"
            )

        # NIST SI-3 — Security profiles (malicious code protection)
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[NIST-MEDIUM] NIST SI-3: Rule '{name}' has no security profile — "
                    "attach AV/IPS profiles per NIST SI-3 malicious code protection requirement"
                )

        # NIST CM-7 — Application 'any' reduces least functionality
        if action == "allow" and "any" in apps:
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{name}' permits any application — "
                "specify applications to enforce least functionality"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append(
            "[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found"
        )

    return findings


# ══════════════════════════════════════════════════════════ FORTINET ══


def check_cis_compliance_forti(policies):
    """CIS Fortinet FortiGate Benchmark checks."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        service = p.get("service", [])
        av_profile = p.get("av-profile", "")
        ips_sensor = p.get("ips-sensor", "")
        webfilter_profile = p.get("webfilter-profile", "")

        # CIS 1 — No any/any permit
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{name}' violates least privilege — source/dest all"
            )

        # CIS 2 — All permit rules must log
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{name}' missing logging"
            )

        # CIS 3 — Service 'ALL' in permit rules
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Rule '{name}' permits all services — restrict to required services only"
            )

        # CIS 4 — AV profile attached to permit rules
        if action == "accept" and not av_profile:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 4: Rule '{name}' has no AV profile attached"
            )

        # CIS 5 — IPS sensor attached to permit rules
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 5: Rule '{name}' has no IPS sensor attached"
            )

        # CIS 6 — Web filter for internet-facing rules
        if action == "accept" and not webfilter_profile and "all" in dst:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 6: Rule '{name}' with unrestricted destination has no web filter profile"
            )

    # CIS 7 — Deny all must exist
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 7: No default deny-all rule found")

    return findings


def check_pci_compliance_forti(policies):
    """PCI-DSS checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        ips_sensor = p.get("ips-sensor", "")
        av_profile = p.get("av-profile", "")
        service = p.get("service", [])

        # PCI 1.3 — No any/any
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{name}' — direct routes to cardholder data prohibited"
            )

        # PCI 10.2 — Logging required
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{name}' missing audit logging"
            )

        # PCI 6.6 — IPS required for allowed traffic
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 6.6: Rule '{name}' has no IPS sensor — IPS required to detect attacks against cardholder data"
            )

        # PCI 5.1 — AV required for allowed traffic
        if action == "accept" and not av_profile:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 5.1: Rule '{name}' has no AV profile — AV protection required per PCI-DSS Req 5"
            )

        # PCI 1.1 — Service ALL prohibited
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 1.1: Rule '{name}' permits all services — define only required and documented services"
            )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_forti(policies):
    """NIST SP 800-41 / NIST 800-53 checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        ips_sensor = p.get("ips-sensor", "")
        av_profile = p.get("av-profile", "")
        service = p.get("service", [])

        # NIST AC-6 — Least privilege
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{name}' violates least privilege principle"
            )

        # NIST AU-2 — Audit logging
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{name}' missing audit logging"
            )

        # NIST SI-3 — Malicious code protection (AV)
        if action == "accept" and not av_profile:
            findings.append(
                f"[NIST-MEDIUM] NIST SI-3: Rule '{name}' has no AV profile — malicious code protection required"
            )

        # NIST SI-4 — Intrusion detection (IPS)
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[NIST-MEDIUM] NIST SI-4: Rule '{name}' has no IPS sensor — network monitoring and intrusion detection required"
            )

        # NIST CM-7 — Least functionality: no ALL services
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{name}' permits all services — restrict to required services only"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append(
            "[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found"
        )

    return findings


# ══════════════════════════════════════════════════════════ PFSENSE ══


def check_cis_compliance_pf(rules):
    """CIS pfSense Firewall Benchmark checks."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # CIS 1 — No any/any permit
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{r['descr']}' violates least privilege — any/any on {iface}"
            )

        # CIS 2 — All permit rules must log
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{r['descr']}' missing logging"
            )

        # CIS 3 — Protocol 'any' in permit rules
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Rule '{r['descr']}' permits any protocol — restrict to required protocols"
            )

    # CIS 4 — Deny all must exist
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 4: No default deny-all rule found")

    # CIS 5 — Block rules must exist (defense in depth)
    block_rules = [r for r in rules if r["type"] == "block"]
    if not block_rules:
        findings.append(
            "[CIS-MEDIUM] CIS Control 5: No explicit block rules found — rely on explicit deny rather than implicit default"
        )

    return findings


def check_pci_compliance_pf(rules):
    """PCI-DSS checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # PCI 1.3 — No any/any
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{r['descr']}' — direct routes to cardholder data prohibited (any/any on {iface})"
            )

        # PCI 10.2 — Logging required
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{r['descr']}' missing audit logging"
            )

        # PCI 1.1 — Protocol 'any' in permit rules
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[PCI-MEDIUM] PCI Req 1.1: Rule '{r['descr']}' permits any protocol — document and restrict all allowed services"
            )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_pf(rules):
    """NIST SP 800-41 / NIST 800-53 checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # NIST AC-6 — Least privilege
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{r['descr']}' violates least privilege (any/any on {iface})"
            )

        # NIST AU-2 — Audit logging
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{r['descr']}' missing audit logging"
            )

        # NIST CM-7 — Least functionality: no protocol 'any'
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{r['descr']}' permits any protocol — restrict to required protocols (least functionality)"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append(
            "[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found"
        )

    return findings


# ══════════════════════════════════════════════════════════ HIPAA COMPLIANCE ══


def check_hipaa_compliance(parse):
    """HIPAA Security Rule checks for Cisco ASA.

    Maps to 45 CFR Part 164, Subpart C (Security Standards).
    """
    findings = []

    # §164.312(a)(1) — Access control: no any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(a)(1): {len(any_any)} any/any permit rule(s) violate access control"
        )

    # §164.312(b) — Audit controls: all permit rules must log
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Permit rule missing audit logging: {rule.text.strip()}"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no explicit deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not addressed"
        )

    # §164.312(e)(1) — Transmission security: Telnet in use
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): Telnet transmits ePHI in cleartext — disable and enforce SSH"
        )

    # §164.312(e)(1) — Transmission security: SSHv1
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): SSHv1 in use — weak encryption threatens ePHI transmission security"
        )

    # §164.308(a)(5)(ii)(B) — Malware protection: HTTP server enabled
    if parse.find_objects(r"^http server enable"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): HTTP management server enabled — use HTTPS only to protect ePHI"
        )

    # §164.308(a)(4) — Information access management: SNMPv1/v2c
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(4): SNMPv1/v2c in use — cleartext SNMP can expose ePHI network data; migrate to SNMPv3"
        )

    # §164.312(a)(2)(i) — Unique user identification: no login banner
    if not parse.find_objects(r"^banner (login|motd)"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.312(a)(2)(i): No login banner — required for authorized-use notice and user accountability"
        )

    return findings


def check_hipaa_compliance_ftd(parse):
    """HIPAA Security Rule checks for Cisco FTD (LINA CLI)."""
    findings = []

    # §164.312(a)(1) — Access control: any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(a)(1): {len(any_any)} any/any permit rule(s) violate access control"
        )

    # §164.312(b) — Audit controls: logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Permit rule missing audit logging: {rule.text.strip()}"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not mitigated"
        )

    # §164.312(e)(1) — Transmission security: Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): Telnet configured — ePHI transmission in cleartext"
        )

    # §164.308(a)(5)(ii)(B) — Malware / threat detection
    if not parse.find_objects(r"^threat-detection basic-threat"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Threat detection not enabled — enable basic threat detection to protect ePHI systems"
        )

    # §164.308(a)(5)(ii)(B) — IPS / Snort inspection
    if not parse.find_objects(r"^access-control-policy"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): No access-control-policy — IPS/Snort inspection may not be active"
        )

    # §164.308(a)(4) — Information access management: SNMPv1/v2c
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(4): SNMPv1/v2c community string detected — migrate to SNMPv3 to protect ePHI network data"
        )

    return findings


def check_hipaa_compliance_pa(rules):
    """HIPAA Security Rule checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = rule.get("from", [])
        dst = rule.get("to", [])
        act = rule.get("action", "")
        log = rule.get("log-end", "no")

        # §164.312(a)(1) — Access control: any/any permit
        if act == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Rule '{name}' permits any-to-any — violates access control"
            )

        # §164.312(b) — Audit controls: log-end
        if act == "allow" and log != "yes":
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Rule '{name}' missing session-end logging — audit trail incomplete"
            )

        # §164.308(a)(5)(ii)(B) — Malware: security profiles
        profiles = rule.get("profile-setting", {})
        has_profiles = bool(profiles.get("profiles") or profiles.get("group"))
        if act == "allow" and not has_profiles:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Rule '{name}' has no security profile — AV/IPS protection for ePHI not applied"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no deny-all
    has_deny_all = any(
        r.get("action") == "deny"
        and "any" in r.get("from", [])
        and "any" in r.get("to", [])
        for r in rules
    )
    if not has_deny_all:
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not addressed"
        )

    return findings


def check_hipaa_compliance_forti(policies):
    """HIPAA Security Rule checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name = p.get("name", f"policy-{p.get('policyid', '?')}")
        srcaddr = p.get("srcaddr", [])
        dstaddr = p.get("dstaddr", [])
        action = p.get("action", "")
        logtr = p.get("logtraffic", "disable")
        av = p.get("av-profile", "")
        ips = p.get("ips-sensor", "")

        # §164.312(a)(1) — Access control: any/any permit
        if action == "accept" and "all" in srcaddr and "all" in dstaddr:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Policy '{name}' allows all-to-all — violates access control"
            )

        # §164.312(b) — Audit controls: logging
        if action == "accept" and logtr == "disable":
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Policy '{name}' has logging disabled — no audit trail for ePHI traffic"
            )

        # §164.308(a)(5)(ii)(B) — Malware: AV profile
        if action == "accept" and not av:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Policy '{name}' has no AV profile — malware protection for ePHI missing"
            )

        # §164.308(a)(5)(ii)(B) — IPS sensor
        if action == "accept" and not ips:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Policy '{name}' has no IPS sensor — intrusion protection for ePHI missing"
            )

        # §164.312(e)(1) — Transmission security: service ALL
        service = p.get("service", [])
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(e)(1): Policy '{name}' permits ALL services — restrict to required services to protect ePHI"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: disabled policies accumulate risk
    disabled = [p for p in policies if p.get("status") == "disable"]
    if disabled:
        findings.append(
            f"[HIPAA-MEDIUM] HIPAA §164.308(a)(1)(ii)(A): {len(disabled)} disabled policy/policies not reviewed — stale rules increase ePHI risk"
        )

    return findings


def check_hipaa_compliance_pf(rules):
    """HIPAA Security Rule checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")
        descr = r.get("descr", "unnamed")

        # §164.312(a)(1) — Access control: any/any pass
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Rule '{descr}' on {iface} allows any/any — violates access control"
            )

        # §164.312(b) — Audit controls: logging
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Rule '{descr}' on {iface} missing logging — audit trail incomplete"
            )

        # §164.312(e)(1) — Transmission security: protocol any
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(e)(1): Rule '{descr}' on {iface} permits any protocol — restrict to required protocols"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no explicit block-all
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary protection risk not addressed"
        )

    return findings


# ══════════════════════════════════════════════════════════ JUNIPER SRX ══
#
# Juniper compliance checks operate on a dict:
#   {"content": <raw config str>, "policies": <list of normalised policy dicts>}
# This lets checks inspect both system-level config and the policy rulebase.


def _juniper_any_any(policies):
    """Return policies with permit any-src any-dst any-app."""
    broad = {"any", "any-ipv4", "any-ipv6"}
    return [
        p
        for p in policies
        if p.get("action") == "permit"
        and not p.get("disabled")
        and all(s.lower() in broad for s in (p.get("src") or ["any"]))
        and all(d.lower() in broad for d in (p.get("dst") or ["any"]))
        and any(a.lower() in broad | {"junos-any"} for a in (p.get("app") or ["any"]))
    ]


def check_cis_compliance_juniper(data: dict) -> list:
    """CIS Juniper SRX Benchmark checks."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    # CIS 1 — Explicit deny-all at end of each zone-pair
    from .juniper import check_deny_all_juniper

    deny_findings = check_deny_all_juniper(policies)
    if deny_findings:
        findings.append(
            "[CIS-HIGH] CIS Control 1: One or more zone pairs lack an explicit deny-all catch-all policy"
        )

    # CIS 2 — No any/any/any permit rules
    any_any = _juniper_any_any(policies)
    if any_any:
        findings.append(
            f"[CIS-HIGH] CIS Control 2: {len(any_any)} policy/policies permit any-source any-destination any-application — violates least privilege"
        )

    # CIS 3 — All permit rules must log
    no_log = [
        p
        for p in policies
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log")
    ]
    for p in no_log:
        findings.append(
            f"[CIS-MEDIUM] CIS Control 3: Policy '{p['name']}' ({p['from_zone']}→{p['to_zone']}) has no session logging"
        )

    # CIS 4 — Telnet disabled
    if re.search(r"set system services telnet", content) or (
        "services {" in content and re.search(r"\btelnet;", content)
    ):
        findings.append(
            "[CIS-HIGH] CIS Control 4: Telnet management is enabled — disable and use SSH only"
        )

    # CIS 5 — SNMPv1/v2c community strings
    for comm in re.findall(r"set snmp community (\S+)", content):
        findings.append(
            f"[CIS-HIGH] CIS Control 5: SNMPv1/v2c community '{comm}' — migrate to SNMPv3"
        )

    # CIS 6 — NTP configured
    if not re.search(r"set system ntp", content) and "ntp {" not in content.lower():
        findings.append(
            "[CIS-MEDIUM] CIS Control 6: No NTP configured — accurate timestamps required for audit"
        )

    # CIS 7 — Remote syslog
    if (
        not re.search(r"set system syslog", content)
        and "syslog {" not in content.lower()
    ):
        findings.append(
            "[CIS-HIGH] CIS Control 7: No syslog configured — audit trail cannot be preserved remotely"
        )

    # CIS 8 — Root SSH login denied
    if re.search(r"set system services ssh root-login allow", content):
        findings.append(
            "[CIS-HIGH] CIS Control 8: SSH root login is permitted — enforce 'root-login deny'"
        )

    return findings


def check_pci_compliance_juniper(data: dict) -> list:
    """PCI-DSS v4.0 Juniper SRX checks."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    # Req 1.3 — No direct any/any through the firewall
    any_any = _juniper_any_any(policies)
    if any_any:
        findings.append(
            f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} policy/policies permit any-to-any traffic — CDE exposure risk"
        )

    # Req 1.3.2 — All permit rules must log for PCI traffic visibility
    no_log = [
        p
        for p in policies
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log")
    ]
    if no_log:
        findings.append(
            f"[PCI-HIGH] PCI Req 10.2: {len(no_log)} permit policy/policies lack session logging — required for PCI audit"
        )

    # Req 1.5 — Explicit deny at boundary
    from .juniper import check_deny_all_juniper

    if check_deny_all_juniper(policies):
        findings.append(
            "[PCI-HIGH] PCI Req 1.3.2: One or more zone pairs have no explicit deny-all — implicit deny is not auditable"
        )

    # Req 8 — No telnet / cleartext protocols
    if re.search(r"set system services telnet", content):
        findings.append(
            "[PCI-HIGH] PCI Req 8.2: Telnet enabled — transmits credentials in cleartext, violating PCI Req 8"
        )

    # Req 10.5 — Remote syslog
    if (
        not re.search(r"set system syslog", content)
        and "syslog {" not in content.lower()
    ):
        findings.append(
            "[PCI-HIGH] PCI Req 10.5: No remote syslog — audit logs must be sent to a centralised log server"
        )

    return findings


def check_nist_compliance_juniper(data: dict) -> list:
    """NIST SP 800-41 Juniper SRX checks."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    # SC-7(5) — Default deny posture
    from .juniper import check_deny_all_juniper

    if check_deny_all_juniper(policies):
        findings.append(
            "[NIST-HIGH] NIST SC-7(5): No explicit deny-all — policy must deny all traffic not explicitly permitted"
        )

    # CM-7 — Least functionality: no any/any/any permits
    any_any = _juniper_any_any(policies)
    if any_any:
        findings.append(
            f"[NIST-HIGH] NIST CM-7: {len(any_any)} policy/policies permit unrestricted traffic — disable unnecessary access"
        )

    # AU-2 — Logging on permit rules
    no_log = [
        p
        for p in policies
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log")
    ]
    if no_log:
        findings.append(
            f"[NIST-MEDIUM] NIST AU-2: {len(no_log)} permit policy/policies without session logging"
        )

    # AC-17 — Management only via encrypted protocols
    if re.search(r"set system services telnet", content):
        findings.append(
            "[NIST-HIGH] NIST AC-17: Telnet management enabled — remote access must use encrypted channels"
        )

    # AU-12 — NTP for log timestamp integrity
    if not re.search(r"set system ntp", content) and "ntp {" not in content.lower():
        findings.append(
            "[NIST-MEDIUM] NIST AU-12: No NTP — log timestamps cannot be trusted without synchronised time"
        )

    return findings


def check_hipaa_compliance_juniper(data: dict) -> list:
    """HIPAA Security Rule Juniper SRX checks."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    # §164.312(a)(1) — Access controls: no any/any permits near ePHI zones
    any_any = _juniper_any_any(policies)
    if any_any:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(a)(1): {len(any_any)} any-to-any permit policy/policies risk unrestricted ePHI access"
        )

    # §164.312(b) — Audit controls: logging on all permit rules
    no_log = [
        p
        for p in policies
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log")
    ]
    if no_log:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(b): {len(no_log)} permit policy/policies have no session logging — audit trail incomplete"
        )

    # §164.312(e)(1) — Transmission security: no cleartext management
    if re.search(r"set system services telnet", content):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): Telnet is enabled — ePHI-adjacent management traffic must be encrypted"
        )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no syslog = no audit trail
    if (
        not re.search(r"set system syslog", content)
        and "syslog {" not in content.lower()
    ):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(1)(ii)(A): No remote syslog — ePHI access logs not preserved off-device"
        )

    return findings


# ══════════════════════════════════════════════════════════════ SOC 2 ══
#
# SOC 2 Trust Services Criteria relevant to firewall policy:
#   CC6.1  — Logical access controls restrict traffic to authorised services
#   CC6.6  — No overly permissive rules (any-any) that bypass access controls
#   CC6.7  — Transmission controls: no cleartext management protocols
#   CC7.2  — Monitor infrastructure: logging on all sessions
#   CC8.1  — Change management: rules are documented (descriptions present)
#   A1.2   — Availability: protection from denial-of-service
#
# Findings are tagged [SOC2-HIGH] or [SOC2-MEDIUM].


# ── SOC 2 — Cisco ASA ─────────────────────────────────────────────────────────


def check_soc2_compliance(parse):
    """SOC 2 Trust Services Criteria checks for Cisco ASA."""
    findings = []

    # CC6.6 — No any/any permit rules
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[SOC2-HIGH] CC6.6: {len(any_any)} any/any permit rule(s) — no access restriction enforced"
        )

    # CC6.1 — Explicit deny-all required
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[SOC2-HIGH] CC6.1: No explicit deny-all rule — default-deny posture not documented"
        )

    # CC6.7 — No cleartext management (Telnet)
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[SOC2-HIGH] CC6.7: Telnet management enabled — credentials transmitted in cleartext"
        )

    # CC7.2 — All permit rules must log
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[SOC2-MEDIUM] CC7.2: Permit rule missing logging: {rule.text.strip()}"
            )

    # CC7.2 — Remote syslog for centralised audit trail
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[SOC2-HIGH] CC7.2: No remote syslog host — audit trail not preserved off-device"
        )

    # CC8.1 — All ACLs should have a remark (documentation)
    acl_names = {
        r.text.split()[1]
        for r in parse.find_objects(r"^access-list\s")
        if len(r.text.split()) >= 2
    }
    for acl in acl_names:
        if not parse.find_objects(rf"access-list {acl} remark"):
            findings.append(
                f"[SOC2-MEDIUM] CC8.1: ACL '{acl}' has no remark/description — change management requires documentation"
            )

    return findings


# ── SOC 2 — Cisco FTD ─────────────────────────────────────────────────────────


def check_soc2_compliance_ftd(parse):
    """SOC 2 Trust Services Criteria checks for Cisco FTD."""
    findings = []

    if parse.find_objects(r"access-list.*permit.*any any"):
        findings.append(
            "[SOC2-HIGH] CC6.6: Any/any permit rule(s) found — access restriction not enforced"
        )

    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[SOC2-HIGH] CC6.1: No explicit deny-all rule")

    if parse.find_objects(r"^telnet\s"):
        findings.append("[SOC2-HIGH] CC6.7: Telnet management access configured")

    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[SOC2-MEDIUM] CC7.2: Permit rule missing logging: {rule.text.strip()}"
            )

    if not parse.find_objects(r"^logging host"):
        findings.append("[SOC2-HIGH] CC7.2: No remote syslog host configured")

    return findings


# ── SOC 2 — Palo Alto ────────────────────────────────────────────────────────


def check_soc2_compliance_pa(rules):
    """SOC 2 Trust Services Criteria checks for Palo Alto PAN-OS."""
    findings = []

    permit_no_log = []
    any_any_rules = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        app = [a.text for a in rule.findall(".//application/member")]
        action = rule.findtext(".//action") or ""
        log_end = rule.findtext(".//log-end") or "yes"
        log_fwd = rule.findtext(".//log-setting") or ""
        disabled = rule.findtext(".//disabled") == "yes"

        if disabled:
            continue

        # CC6.6 — any/any/any permit
        if action == "allow" and "any" in src and "any" in dst and "any" in app:
            any_any_rules.append(name)

        # CC7.2 — logging
        if action == "allow" and log_end != "yes" and not log_fwd:
            permit_no_log.append(name)

        # CC8.1 — rule description
        desc = rule.findtext(".//description") or ""
        if action == "allow" and not desc.strip():
            findings.append(f"[SOC2-MEDIUM] CC8.1: Rule '{name}' has no description")

    if any_any_rules:
        findings.append(
            f"[SOC2-HIGH] CC6.6: {len(any_any_rules)} any/any/any permit rule(s) — access restriction not enforced"
        )
    for name in permit_no_log:
        findings.append(f"[SOC2-MEDIUM] CC7.2: Rule '{name}' has no session logging")

    return findings


# ── SOC 2 — Fortinet ─────────────────────────────────────────────────────────


def check_soc2_compliance_forti(policies):
    """SOC 2 Trust Services Criteria checks for Fortinet."""
    findings = []

    any_any = [
        p
        for p in policies
        if p.get("action") == "accept"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        and p.get("status") != "disable"
    ]
    if any_any:
        findings.append(
            f"[SOC2-HIGH] CC6.6: {len(any_any)} any/any permit policy/policies — access restriction not enforced"
        )

    no_log = [
        p
        for p in policies
        if p.get("action") == "accept"
        and p.get("status") != "disable"
        and p.get("logtraffic") not in ("all", "utm", "enable")
    ]
    for p in no_log:
        name = p.get("name") or f"ID {p.get('id')}"
        findings.append(f"[SOC2-MEDIUM] CC7.2: Policy '{name}' has no traffic logging")

    no_name = [
        p
        for p in policies
        if p.get("action") == "accept"
        and p.get("status") != "disable"
        and not p.get("name", "").strip()
    ]
    if no_name:
        findings.append(
            f"[SOC2-MEDIUM] CC8.1: {len(no_name)} unnamed permit policy/policies — change management requires documentation"
        )

    return findings


# ── SOC 2 — pfSense ──────────────────────────────────────────────────────────


def check_soc2_compliance_pf(rules):
    """SOC 2 Trust Services Criteria checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "?")
        descr = r.get("descr") or r.get("description") or ""
        src = r.get("source", "1")
        dst = r.get("destination", "1")

        if r.get("type") == "pass" and src == "1" and dst == "1":
            findings.append(
                f"[SOC2-HIGH] CC6.6: Pass rule on '{iface}' allows any-to-any traffic"
            )

        if r.get("type") == "pass" and not r.get("log"):
            findings.append(
                f"[SOC2-MEDIUM] CC7.2: Pass rule on '{iface}' ('{descr}') has no logging"
            )

        if r.get("type") == "pass" and not descr.strip():
            findings.append(
                f"[SOC2-MEDIUM] CC8.1: Pass rule on '{iface}' has no description"
            )

    return findings


# ── SOC 2 — Juniper SRX ──────────────────────────────────────────────────────


def check_soc2_compliance_juniper(data: dict) -> list:
    """SOC 2 Trust Services Criteria checks for Juniper SRX."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    broad = {"any", "any-ipv4", "any-ipv6"}

    # CC6.6 — any-any-any permits
    any_any = [
        p
        for p in policies
        if p.get("action") == "permit"
        and not p.get("disabled")
        and all(s.lower() in broad for s in (p.get("src") or ["any"]))
        and all(d.lower() in broad for d in (p.get("dst") or ["any"]))
    ]
    if any_any:
        findings.append(
            f"[SOC2-HIGH] CC6.6: {len(any_any)} policy/policies permit any-to-any — access restriction not enforced"
        )

    # CC6.1 — Deny-all per zone pair
    from .juniper import check_deny_all_juniper

    if check_deny_all_juniper(policies):
        findings.append(
            "[SOC2-HIGH] CC6.1: One or more zone pairs lack an explicit deny-all — default-deny not documented"
        )

    # CC6.7 — No Telnet
    if re.search(r"set system services telnet", content):
        findings.append(
            "[SOC2-HIGH] CC6.7: Telnet management enabled — credentials transmitted in cleartext"
        )

    # CC7.2 — Logging on permit policies
    no_log = [
        p
        for p in policies
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log")
    ]
    for p in no_log:
        findings.append(
            f"[SOC2-MEDIUM] CC7.2: Policy '{p['name']}' ({p['from_zone']}→{p['to_zone']}) has no session logging"
        )

    # CC7.2 — Remote syslog
    if (
        not re.search(r"set system syslog", content)
        and "syslog {" not in content.lower()
    ):
        findings.append(
            "[SOC2-HIGH] CC7.2: No syslog configured — audit trail not preserved remotely"
        )

    # CC8.1 — Policy descriptions (only for set-style configs where we can check)
    no_desc_count = sum(
        1 for p in policies if p.get("action") == "permit" and not p.get("disabled")
    )
    if no_desc_count:
        findings.append(
            f"[SOC2-MEDIUM] CC8.1: Verify all {no_desc_count} permit policy/policies have descriptions for change management"
        )

    return findings


# ══════════════════════════════════════════════════════════ DISA STIG ══
#
# DISA Security Technical Implementation Guides (STIGs) are prescriptive
# per-vendor checklists used by US DoD and federal contractors.
#
# Severity categories:
#   CAT I   — Critical: direct, immediate risk — findings tagged [STIG-CAT-I]
#   CAT II  — High: significant risk           — findings tagged [STIG-CAT-II]
#   CAT III — Medium: limited risk             — findings tagged [STIG-CAT-III]
#
# Official STIGs: Cisco ASA, Cisco FTD, Palo Alto PAN-OS, Fortinet FortiOS,
#                Juniper SRX.  pfSense has no official DISA STIG; those checks
#                are derived from general network device hardening guidance.


# ── DISA STIG — Cisco ASA ────────────────────────────────────────────────────


def check_stig_compliance(parse):
    """DISA STIG checks for Cisco ASA (based on ASA STIG V1R4+)."""
    findings = []

    # CAT I — Telnet management must not be used (ASA STIG V-239945)
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[STIG-CAT-I] V-239945: Telnet management is enabled — must be disabled, use SSH only"
        )

    # CAT I — No any/any permit (ASA STIG V-239952)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[STIG-CAT-I] V-239952: {len(any_any)} any/any permit rule(s) — traffic must be restricted to least privilege"
        )

    # CAT I — SNMPv1/v2c community strings (ASA STIG V-239962)
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[STIG-CAT-I] V-239962: SNMPv1/v2c community '{r.text.split()[2]}' must be replaced with SNMPv3"
        )

    # CAT II — SSH must be limited to version 2 (ASA STIG V-239946)
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[STIG-CAT-II] V-239946: SSHv1 is enabled — must enforce SSH protocol version 2 only"
        )
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append("[STIG-CAT-II] V-239946: SSH version not explicitly set to 2")

    # CAT II — NTP must be configured (ASA STIG V-239972)
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[STIG-CAT-II] V-239972: NTP not configured — timestamps required for audit log integrity"
        )

    # CAT II — Logging must be enabled and sent to a syslog server (ASA STIG V-239973)
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[STIG-CAT-II] V-239973: No remote syslog host — audit records must be sent off-device"
        )

    if not parse.find_objects(r"^logging enable"):
        findings.append("[STIG-CAT-II] V-239973: Logging not explicitly enabled")

    # CAT II — All permit rules must log (ASA STIG V-239975)
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[STIG-CAT-II] V-239975: Permit rule missing log keyword: {rule.text.strip()}"
            )

    # CAT II — HTTP management must be disabled or restricted (ASA STIG V-239948)
    if parse.find_objects(r"^http server enable"):
        if not parse.find_objects(r"^http\s+\d"):
            findings.append(
                "[STIG-CAT-II] V-239948: ASDM/HTTP enabled with no host restriction"
            )

    # CAT II — Explicit deny-all (ASA STIG V-239954)
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[STIG-CAT-II] V-239954: No explicit deny-all rule — implicit deny produces no audit log entry"
        )

    # CAT III — Login banner must be configured (ASA STIG V-239980)
    if not parse.find_objects(r"^banner (login|motd)"):
        findings.append("[STIG-CAT-III] V-239980: No login or MOTD banner configured")

    # CAT III — Console timeout (ASA STIG V-239983)
    if not parse.find_objects(r"^console timeout"):
        findings.append(
            "[STIG-CAT-III] V-239983: No console session timeout configured"
        )

    return findings


# ── DISA STIG — Cisco FTD ────────────────────────────────────────────────────


def check_stig_compliance_ftd(parse):
    """DISA STIG checks for Cisco FTD (based on FTD STIG V1R2+)."""
    findings = []

    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[STIG-CAT-I] FTD-STIG: Telnet management enabled — must use SSH"
        )

    if parse.find_objects(r"access-list.*permit.*any any"):
        findings.append(
            "[STIG-CAT-I] FTD-STIG: Any/any permit rule violates least-privilege requirement"
        )

    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            "[STIG-CAT-I] FTD-STIG: SNMPv1/v2c community string — must migrate to SNMPv3"
        )

    if parse.find_objects(r"^ssh version 1"):
        findings.append("[STIG-CAT-II] FTD-STIG: SSHv1 enabled — enforce SSHv2 only")

    if not parse.find_objects(r"^ntp server"):
        findings.append("[STIG-CAT-II] FTD-STIG: NTP not configured")

    if not parse.find_objects(r"^logging host"):
        findings.append("[STIG-CAT-II] FTD-STIG: No remote syslog host configured")

    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[STIG-CAT-II] FTD-STIG: Permit rule missing log keyword: {rule.text.strip()}"
            )

    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[STIG-CAT-II] FTD-STIG: No explicit deny-all rule")

    if not parse.find_objects(r"^banner (login|motd)"):
        findings.append("[STIG-CAT-III] FTD-STIG: No login or MOTD banner configured")

    return findings


# ── DISA STIG — Palo Alto PAN-OS ─────────────────────────────────────────────


def check_stig_compliance_pa(rules):
    """DISA STIG checks for Palo Alto PAN-OS (based on PAN-OS STIG V1R4+)."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        app = [a.text for a in rule.findall(".//application/member")]
        action = rule.findtext(".//action") or ""
        log_end = rule.findtext(".//log-end") or "yes"
        disabled = rule.findtext(".//disabled") == "yes"

        if disabled:
            continue

        # CAT I — any/any/any permit (PAN STIG V-228838)
        if action == "allow" and "any" in src and "any" in dst and "any" in app:
            findings.append(
                f"[STIG-CAT-I] V-228838: Rule '{name}' permits any/any/any — violates least privilege"
            )

        # CAT II — logging required on permit rules (PAN STIG V-228842)
        if action == "allow" and log_end != "yes":
            findings.append(
                f"[STIG-CAT-II] V-228842: Rule '{name}' — session-end logging not enabled"
            )

        # CAT III — rule description (PAN STIG V-228860)
        desc = rule.findtext(".//description") or ""
        if action == "allow" and not desc.strip():
            findings.append(
                f"[STIG-CAT-III] V-228860: Rule '{name}' has no description"
            )

    return findings


# ── DISA STIG — Fortinet FortiOS ─────────────────────────────────────────────


def check_stig_compliance_forti(policies):
    """DISA STIG checks for Fortinet FortiOS (based on FortiOS STIG V1R2+)."""
    findings = []

    for p in policies:
        if p.get("status") == "disable":
            continue
        name = p.get("name") or f"Policy ID {p.get('id')}"

        # CAT I — any/any accept (FortiOS STIG V-234161)
        if (
            p.get("action") == "accept"
            and "all" in p.get("srcaddr", [])
            and "all" in p.get("dstaddr", [])
        ):
            findings.append(
                f"[STIG-CAT-I] V-234161: Policy '{name}' accepts all source/destination — violates least privilege"
            )

        # CAT II — logging required (FortiOS STIG V-234171)
        if p.get("action") == "accept" and p.get("logtraffic") not in (
            "all",
            "utm",
            "enable",
        ):
            findings.append(
                f"[STIG-CAT-II] V-234171: Policy '{name}' — traffic logging not enabled"
            )

        # CAT III — policy name required (FortiOS STIG V-234180)
        if p.get("action") == "accept" and not p.get("name", "").strip():
            findings.append(
                "[STIG-CAT-III] V-234180: Unnamed policy found — all policies must be named for auditability"
            )

    return findings


# ── DISA STIG — pfSense (hardening guidance — no official STIG) ──────────────


def check_stig_compliance_pf(rules):
    """Network device hardening checks for pfSense (no official DISA STIG).

    Based on NIST SP 800-41 and general network device hardening guidelines.
    """
    findings = []
    for r in rules:
        iface = r.get("interface", "?")
        descr = r.get("descr") or r.get("description") or ""
        src = r.get("source", "1")
        dst = r.get("destination", "1")

        # CAT I equivalent — any/any pass
        if r.get("type") == "pass" and src == "1" and dst == "1":
            findings.append(
                f"[STIG-CAT-I] Hardening: Pass rule on '{iface}' allows any-to-any — least privilege not enforced"
            )

        # CAT II equivalent — no logging
        if r.get("type") == "pass" and not r.get("log"):
            findings.append(
                f"[STIG-CAT-II] Hardening: Pass rule on '{iface}' ('{descr}') has no logging"
            )

        # CAT III equivalent — no description
        if r.get("type") == "pass" and not descr.strip():
            findings.append(
                f"[STIG-CAT-III] Hardening: Pass rule on '{iface}' has no description"
            )

    return findings


# ── DISA STIG — Juniper SRX ──────────────────────────────────────────────────


def check_stig_compliance_juniper(data: dict) -> list:
    """DISA STIG checks for Juniper SRX (based on Juniper SRX STIG V1R2+)."""
    import re

    content = data.get("content", "")
    policies = data.get("policies", [])
    findings = []

    broad = {"any", "any-ipv4", "any-ipv6"}

    # CAT I — Telnet enabled (SRX STIG V-66003)
    if re.search(r"set system services telnet", content):
        findings.append(
            "[STIG-CAT-I] V-66003: Telnet management service is enabled — must be disabled"
        )

    # CAT I — SNMPv1/v2c community strings (SRX STIG V-66019)
    for comm in re.findall(r"set snmp community (\S+)", content):
        findings.append(
            f"[STIG-CAT-I] V-66019: SNMPv1/v2c community '{comm}' — must migrate to SNMPv3"
        )

    # CAT I — any/any/any permit (SRX STIG V-65981)
    any_any = [
        p
        for p in policies
        if p.get("action") == "permit"
        and not p.get("disabled")
        and all(s.lower() in broad for s in (p.get("src") or ["any"]))
        and all(d.lower() in broad for d in (p.get("dst") or ["any"]))
    ]
    if any_any:
        findings.append(
            f"[STIG-CAT-I] V-65981: {len(any_any)} policy/policies permit any-to-any — violates least privilege"
        )

    # CAT II — NTP (SRX STIG V-66021)
    if not re.search(r"set system ntp", content) and "ntp {" not in content.lower():
        findings.append(
            "[STIG-CAT-II] V-66021: NTP not configured — audit log timestamps unreliable"
        )

    # CAT II — Syslog (SRX STIG V-66023)
    if (
        not re.search(r"set system syslog", content)
        and "syslog {" not in content.lower()
    ):
        findings.append(
            "[STIG-CAT-II] V-66023: No remote syslog — audit records must be sent off-device"
        )

    # CAT II — Deny-all per zone pair (SRX STIG V-65983)
    from .juniper import check_deny_all_juniper

    if check_deny_all_juniper(policies):
        findings.append(
            "[STIG-CAT-II] V-65983: One or more zone pairs lack an explicit deny-all policy"
        )

    # CAT II — Session logging on permit policies (SRX STIG V-65985)
    for p in policies:
        if p.get("action") == "permit" and not p.get("disabled") and not p.get("log"):
            findings.append(
                f"[STIG-CAT-II] V-65985: Policy '{p['name']}' ({p['from_zone']}→{p['to_zone']}) — session logging not enabled"
            )

    # CAT II — SSH root login (SRX STIG V-66001)
    if re.search(r"set system services ssh root-login allow", content):
        findings.append(
            "[STIG-CAT-II] V-66001: SSH root login is permitted — must be denied"
        )

    # CAT III — Login banner (SRX STIG V-66025)
    if (
        not re.search(r"set system login message", content)
        and "login {" not in content.lower()
    ):
        findings.append("[STIG-CAT-III] V-66025: No login banner configured")

    return findings
