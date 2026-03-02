def check_cis_compliance(parse):
    findings = []

    # CIS ASA Benchmark checks

    # 1. Ensure default deny exists
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[CIS-HIGH] CIS Control: No default deny-all rule found")

    # 2. Ensure no any/any permit rules exist
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[CIS-HIGH] CIS Control: {len(any_any)} any/any permit rule(s) violate least privilege")

    # 3. Ensure all permit rules have logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[CIS-MEDIUM] CIS Control: Permit rule missing logging: {rule.text}")

    return findings


def check_pci_compliance(parse):
    findings = []

    # PCI-DSS Requirement 1 checks

    # 1. No any/any rules (PCI Req 1.3)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) found - direct routes to cardholder data prohibited")

    # 2. All permit rules must log (PCI Req 10.2)
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text}")

    # 3. Explicit deny all must exist (PCI Req 1.2)
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance(parse):
    findings = []

    # NIST SP 800-41 checks

    # 1. Least privilege - no any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any rule(s) violate least privilege principle")

    # 2. Audit trail - logging required
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text}")

    # 3. Boundary protection - deny all must exist
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings


def check_cis_compliance_pa(rules):
    findings = []

    # CIS 1 - No any/any permit
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(f"[CIS-HIGH] CIS Control: Rule '{name}' violates least privilege - any/any permit")

    # CIS 2 - All permit rules must log
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(f"[CIS-MEDIUM] CIS Control: Rule '{name}' missing logging")

    # CIS 3 - Deny all must exist
    has_deny_all = any(
        rule.findtext(".//action") == "deny" and
        "any" in [s.text for s in rule.findall(".//source/member")] and
        "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control: No default deny-all rule found")

    return findings


def check_pci_compliance_pa(rules):
    findings = []

    # PCI Req 1.3 - No any/any
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(f"[PCI-HIGH] PCI Req 1.3: Rule '{name}' - direct routes to cardholder data prohibited")

    # PCI Req 10.2 - Logging required
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(f"[PCI-MEDIUM] PCI Req 10.2: Rule '{name}' missing audit logging")

    # PCI Req 1.2 - Explicit deny all
    has_deny_all = any(
        rule.findtext(".//action") == "deny" and
        "any" in [s.text for s in rule.findall(".//source/member")] and
        "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_pa(rules):
    findings = []

    # NIST AC-6 - Least privilege
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(f"[NIST-HIGH] NIST AC-6: Rule '{name}' violates least privilege principle")

    # NIST AU-2 - Audit logging
    for rule in rules:
        name = rule.get("name", "unnamed")
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(f"[NIST-MEDIUM] NIST AU-2: Rule '{name}' missing audit logging")

    # NIST SC-7 - Boundary protection
    has_deny_all = any(
        rule.findtext(".//action") == "deny" and
        "any" in [s.text for s in rule.findall(".//source/member")] and
        "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings