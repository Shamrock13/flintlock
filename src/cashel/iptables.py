"""iptables / nftables parser and auditor.

Parses:
  iptables-save output  (``iptables-save``, ``ip6tables-save``)
  nft ruleset text      (``nft list ruleset``)
  nft ruleset JSON      (``nft -j list ruleset``)

Key differences from stateful firewall vendors:
  - Rules are evaluated top-to-bottom; first match wins.
  - Default chain POLICY (ACCEPT/DROP) is the implicit fallback.
  - Logging requires an explicit LOG target before the terminal target.
  - nftables uses priority-based hooks; policy is per-chain.
"""

from __future__ import annotations

import ipaddress
import json
import re

from .models.findings import make_finding

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
    9200: "Elasticsearch",
    11211: "Memcached",
}

_INTERNET_SRCS = {"0.0.0.0/0", "::/0", "any"}


def _f(severity, category, message, remediation=""):
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "remediation": remediation,
    }


def _iptables_f(
    severity,
    category,
    message,
    remediation="",
    *,
    id,
    title,
    evidence,
    affected_object,
    rule_name=None,
    confidence="medium",
    impact=None,
    verification=None,
    rollback=None,
    suggested_commands=None,
    metadata=None,
):
    return make_finding(
        severity,
        category,
        message,
        remediation,
        id=id,
        vendor="iptables",
        title=title,
        evidence=evidence,
        affected_object=affected_object,
        rule_name=rule_name or affected_object,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        suggested_commands=suggested_commands,
        metadata=metadata,
    )


def _iptables_rule_metadata(rule: dict, extra: dict | None = None) -> dict:
    metadata = {
        "chain": rule.get("chain", ""),
        "policy": "",
        "protocol": rule.get("protocol", ""),
        "source": rule.get("src", ""),
        "destination": rule.get("dst", ""),
        "ports": rule.get("dport", "") or rule.get("sport", ""),
        "source_port": rule.get("sport", ""),
        "destination_port": rule.get("dport", ""),
        "icmp_type": rule.get("icmp_type", ""),
        "target": rule.get("target", ""),
        "input_interface": rule.get("in_iface", ""),
        "output_interface": rule.get("out_iface", ""),
        "state": rule.get("state", ""),
        "raw_rule": rule.get("raw", ""),
    }
    if extra:
        metadata.update(extra)
    return metadata


def _iptables_policy_metadata(chain: str, policy: str) -> dict:
    return {
        "chain": chain,
        "policy": policy,
        "protocol": "",
        "source": "",
        "destination": "",
        "ports": "",
        "target": policy,
        "raw_rule": "",
    }


def _is_any_source(src: str) -> bool:
    if not src or src in _INTERNET_SRCS:
        return True
    try:
        net = ipaddress.ip_network(src, strict=False)
        return net.num_addresses > (1 << 24)  # larger than /8 → treat as "any"
    except ValueError:
        return False


def _port_in_sensitive(port_spec: str) -> list[tuple[int, str]]:
    """Return (port, service_name) pairs for any sensitive ports in the spec."""
    hits = []
    for part in port_spec.replace(",", " ").split():
        if ":" in part:
            try:
                lo, hi = (int(x) for x in part.split(":", 1))
                for p, svc in SENSITIVE_PORTS.items():
                    if lo <= p <= hi:
                        hits.append((p, svc))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if p in SENSITIVE_PORTS:
                    hits.append((p, SENSITIVE_PORTS[p]))
            except ValueError:
                pass
    return hits


# ══════════════════════════════════════════════════════════ IPTABLES ══


def _parse_iptables_rule(line: str) -> dict | None:
    """Parse a single ``-A CHAIN ...`` iptables-save rule line."""
    m = re.match(r"^-A\s+(\S+)\s+(.*)$", line.strip())
    if not m:
        return None
    chain = m.group(1)
    rest = m.group(2)

    def _extract(flags, default=""):
        for flag in flags:
            pm = re.search(rf"{re.escape(flag)}\s+(\S+)", rest)
            if pm:
                return pm.group(1)
        return default

    def _extract_multiport(flags):
        for flag in flags:
            pm = re.search(rf"{re.escape(flag)}\s+(\S+)", rest)
            if pm:
                return pm.group(1)
        return ""

    # target (-j)
    target_m = re.search(r"-j\s+(\S+)", rest)
    target = target_m.group(1) if target_m else ""

    # protocol
    proto = _extract(["-p", "--protocol"])

    # source / destination
    src = _extract(["-s", "--source"], "0.0.0.0/0")
    dst = _extract(["-d", "--destination"], "0.0.0.0/0")

    # destination port(s)
    dport = _extract_multiport(
        ["--dport", "--dports", "--destination-port", "--destination-ports"]
    )

    # source port(s)
    sport = _extract_multiport(
        ["--sport", "--sports", "--source-port", "--source-ports"]
    )

    # in/out interface
    in_iface = _extract(["-i", "--in-interface"])
    out_iface = _extract(["-o", "--out-interface"])

    # icmp type
    icmp_type = _extract(["--icmp-type", "--icmpv6-type"])

    # state / conntrack
    state_m = re.search(r"--state\s+(\S+)|--ctstate\s+(\S+)", rest)
    state = (state_m.group(1) or state_m.group(2)) if state_m else ""

    return {
        "chain": chain,
        "target": target,
        "protocol": proto,
        "src": src,
        "dst": dst,
        "dport": dport,
        "sport": sport,
        "in_iface": in_iface,
        "out_iface": out_iface,
        "icmp_type": icmp_type,
        "state": state,
        "raw": line.strip(),
    }


def parse_iptables(filepath: str) -> tuple[dict, str | None]:
    """Parse an iptables-save file.

    Returns (data_dict, error_or_None).

    data_dict keys:
      ``tables``   — dict of table_name → {"policy": {chain: pol}, "rules": [rule_dict, ...]}
      ``is_ipv6``  — True if ip6tables-save format detected
    """
    try:
        with open(filepath) as fh:
            content = fh.read()
    except OSError as exc:
        return {}, f"Failed to read iptables file: {exc}"

    if not re.search(r"^\*\w+|^-A\s+\w+", content, re.MULTILINE):
        return (
            {},
            "Unrecognized format: expected iptables-save output (lines starting with '*' or '-A').",
        )

    is_ipv6 = bool(re.search(r"ip6tables|ip6", content, re.IGNORECASE))

    tables: dict = {}
    current_table = "filter"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current_table = line[1:]
            tables.setdefault(current_table, {"policy": {}, "rules": []})
        elif line.startswith(":"):
            # :CHAIN POLICY [packets:bytes]
            parts = line[1:].split()
            if len(parts) >= 2:
                chain, policy = parts[0], parts[1]
                tables.setdefault(current_table, {"policy": {}, "rules": []})
                tables[current_table]["policy"][chain] = policy
        elif line.startswith("-A"):
            rule = _parse_iptables_rule(line)
            if rule:
                tables.setdefault(current_table, {"policy": {}, "rules": []})
                tables[current_table]["rules"].append(rule)

    return {"tables": tables, "is_ipv6": is_ipv6}, None


# ── iptables checks ───────────────────────────────────────────────────────────


def check_default_policy_iptables(data: dict) -> list[dict]:
    """Flag INPUT or FORWARD chains with a default ACCEPT policy."""
    findings = []
    filter_tbl = data.get("tables", {}).get("filter", {})
    policy = filter_tbl.get("policy", {})
    for chain in ("INPUT", "FORWARD"):
        pol = policy.get(chain, "").upper()
        if pol == "ACCEPT":
            findings.append(
                _iptables_f(
                    "HIGH",
                    "hygiene",
                    f"[HIGH] iptables filter chain '{chain}' has default policy ACCEPT — all unmatched traffic is permitted.",
                    f"Set a default DROP policy: 'iptables -P {chain} DROP'. "
                    "Explicit ACCEPT rules should be used only for required traffic.",
                    id="CASHEL-IPTABLES-HYGIENE-001",
                    title="iptables filter chain has default ACCEPT policy",
                    evidence=f"chain={chain}; policy={pol}",
                    affected_object=chain,
                    confidence="high",
                    impact="Unmatched traffic is permitted by default instead of requiring explicit allow rules.",
                    verification=f"Run 'iptables -S {chain}' and confirm the chain policy is DROP.",
                    rollback=f"Restore the previous default policy with 'iptables -P {chain} ACCEPT' if emergency access is disrupted.",
                    suggested_commands=[f"iptables -P {chain} DROP"],
                    metadata=_iptables_policy_metadata(chain, pol),
                )
            )
    return findings


def check_any_any_accept_iptables(data: dict) -> list[dict]:
    """Flag unrestricted ACCEPT rules on the INPUT chain."""
    findings = []
    filter_tbl = data.get("tables", {}).get("filter", {})
    policy = filter_tbl.get("policy", {})
    rules = filter_tbl.get("rules", [])
    for r in rules:
        if (
            r["chain"] == "INPUT"
            and r["target"] == "ACCEPT"
            and not r["dport"]
            and not r["sport"]
            and _is_any_source(r["src"])
            and r["protocol"] in ("", "all")
        ):
            # skip loopback and established/related
            if r["in_iface"] == "lo":
                continue
            if r["state"] and any(
                s in r["state"].upper() for s in ("ESTABLISHED", "RELATED")
            ):
                continue
            findings.append(
                _iptables_f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] iptables INPUT rule allows ALL traffic from any source: {r['raw']}",
                    "Remove or replace broad ACCEPT rules with specific protocol/port/source restrictions. "
                    "Use 'iptables -A INPUT -s <trusted-cidr> -p <proto> --dport <port> -j ACCEPT'.",
                    id="CASHEL-IPTABLES-EXPOSURE-001",
                    title="iptables INPUT rule allows all traffic",
                    evidence=r["raw"],
                    affected_object="INPUT",
                    confidence="high",
                    impact="A broad INPUT ACCEPT rule can expose all local services to untrusted sources.",
                    verification="Run 'iptables -S INPUT' and confirm broad ACCEPT rules are removed or scoped.",
                    rollback="Restore the previous INPUT rule from configuration backup if approved traffic is interrupted.",
                    suggested_commands=[
                        f"iptables -D INPUT {r['raw'].replace('-A INPUT ', '', 1)}",
                        "iptables -A INPUT -s <trusted-cidr> -p <proto> --dport <port> -j ACCEPT",
                    ],
                    metadata=_iptables_rule_metadata(
                        r, {"policy": policy.get(r["chain"], "")}
                    ),
                )
            )
    return findings


def check_internet_ingress_iptables(data: dict) -> list[dict]:
    """Flag ACCEPT rules on INPUT that expose sensitive ports to 0.0.0.0/0."""
    findings = []
    filter_tbl = data.get("tables", {}).get("filter", {})
    policy = filter_tbl.get("policy", {})
    rules = filter_tbl.get("rules", [])
    for r in rules:
        if r["chain"] != "INPUT" or r["target"] != "ACCEPT":
            continue
        if not _is_any_source(r["src"]):
            continue
        if r["in_iface"] == "lo":
            continue
        if r["state"] and any(
            s in r["state"].upper() for s in ("ESTABLISHED", "RELATED")
        ):
            continue
        dport = r.get("dport", "")
        if dport:
            for port, svc in _port_in_sensitive(dport):
                findings.append(
                    _iptables_f(
                        "HIGH",
                        "exposure",
                        f"[HIGH] iptables: {svc} (TCP/{port}) open to 0.0.0.0/0: {r['raw']}",
                        f"Restrict '{svc}' access to known source CIDRs: "
                        f"'iptables -A INPUT -s <trusted-cidr> -p tcp --dport {port} -j ACCEPT'. "
                        "Remove or restrict the broad rule.",
                        id="CASHEL-IPTABLES-EXPOSURE-002",
                        title=f"iptables exposes {svc} to the internet",
                        evidence=r["raw"],
                        affected_object="INPUT",
                        confidence="high",
                        impact=f"{svc} is reachable from any source and may expose administrative or sensitive services.",
                        verification=f"Run 'iptables -S INPUT' and confirm TCP/{port} is restricted to approved CIDRs.",
                        rollback="Restore the previous INPUT rule from configuration backup if approved access is interrupted.",
                        suggested_commands=[
                            f"iptables -D INPUT {r['raw'].replace('-A INPUT ', '', 1)}",
                            f"iptables -A INPUT -s <trusted-cidr> -p tcp --dport {port} -j ACCEPT",
                        ],
                        metadata=_iptables_rule_metadata(
                            r,
                            {
                                "policy": policy.get(r["chain"], ""),
                                "service": svc,
                                "port": port,
                                "ports": r.get("dport", ""),
                            },
                        ),
                    )
                )
    return findings


def check_forward_chain_iptables(data: dict) -> list[dict]:
    """Flag permissive ACCEPT rules on the FORWARD chain."""
    findings = []
    filter_tbl = data.get("tables", {}).get("filter", {})
    policy = filter_tbl.get("policy", {})
    rules = filter_tbl.get("rules", [])
    for r in rules:
        if (
            r["chain"] == "FORWARD"
            and r["target"] == "ACCEPT"
            and not r["dport"]
            and _is_any_source(r["src"])
            and r["protocol"] in ("", "all")
        ):
            if r["state"] and any(
                s in r["state"].upper() for s in ("ESTABLISHED", "RELATED")
            ):
                continue
            findings.append(
                _iptables_f(
                    "MEDIUM",
                    "exposure",
                    f"[MEDIUM] iptables: FORWARD chain has unrestricted ACCEPT — host may be routing traffic: {r['raw']}",
                    "Restrict FORWARD rules to specific source/destination pairs. "
                    "If the host is not a router, set 'iptables -P FORWARD DROP' and remove FORWARD ACCEPT rules.",
                    id="CASHEL-IPTABLES-EXPOSURE-003",
                    title="iptables FORWARD chain has unrestricted ACCEPT",
                    evidence=r["raw"],
                    affected_object="FORWARD",
                    confidence="medium",
                    impact="The host may route traffic between interfaces without explicit source and destination controls.",
                    verification="Run 'iptables -S FORWARD' and confirm forwarding is denied by default or scoped to approved paths.",
                    rollback="Restore the previous FORWARD rule from configuration backup if approved routed traffic is interrupted.",
                    suggested_commands=[
                        f"iptables -D FORWARD {r['raw'].replace('-A FORWARD ', '', 1)}",
                        "iptables -P FORWARD DROP",
                    ],
                    metadata=_iptables_rule_metadata(
                        r, {"policy": policy.get(r["chain"], "")}
                    ),
                )
            )
    return findings


def check_missing_logging_iptables(data: dict) -> list[dict]:
    """Flag INPUT chains with ACCEPT rules but no LOG rule before them."""
    filter_tbl = data.get("tables", {}).get("filter", {})
    rules = filter_tbl.get("rules", [])
    input_rules = [r for r in rules if r["chain"] == "INPUT"]
    has_log = any(r["target"] == "LOG" for r in input_rules)
    if not has_log and any(r["target"] == "ACCEPT" for r in input_rules):
        return [
            _iptables_f(
                "MEDIUM",
                "logging",
                "[MEDIUM] iptables: No LOG target found in INPUT chain — accepted traffic is not logged.",
                "Add LOG rules before ACCEPT targets: "
                "'iptables -A INPUT -j LOG --log-prefix \"[ACCEPT] \" --log-level 4'. "
                "Without logging, permitted traffic cannot be audited.",
                id="CASHEL-IPTABLES-LOGGING-001",
                title="iptables INPUT chain is missing logging",
                evidence="No LOG target found before INPUT ACCEPT rules.",
                affected_object="INPUT",
                confidence="medium",
                impact="Accepted traffic may be absent from host firewall logs and audit trails.",
                verification="Run 'iptables -S INPUT' and confirm LOG rules exist before accepted traffic paths.",
                rollback="Remove the added LOG rule if log volume causes operational issues.",
                suggested_commands=[
                    'iptables -A INPUT -j LOG --log-prefix "[INPUT] " --log-level 4'
                ],
                metadata={
                    "chain": "INPUT",
                    "policy": filter_tbl.get("policy", {}).get("INPUT", ""),
                    "protocol": "",
                    "source": "",
                    "destination": "",
                    "ports": "",
                    "target": "LOG",
                    "raw_rule": "",
                    "accept_rule_count": sum(
                        1 for r in input_rules if r["target"] == "ACCEPT"
                    ),
                },
            )
        ]
    return []


def check_icmp_unrestricted_iptables(data: dict) -> list[dict]:
    """Flag unrestricted ICMP ACCEPT on INPUT without rate-limiting."""
    findings = []
    filter_tbl = data.get("tables", {}).get("filter", {})
    policy = filter_tbl.get("policy", {})
    rules = filter_tbl.get("rules", [])
    for r in rules:
        if (
            r["chain"] == "INPUT"
            and r["target"] == "ACCEPT"
            and r["protocol"] in ("icmp", "icmpv6", "ipv6-icmp")
            and _is_any_source(r["src"])
        ):
            has_limit = re.search(r"-m\s+limit|--limit\b", r["raw"])
            if not has_limit:
                findings.append(
                    _iptables_f(
                        "MEDIUM",
                        "exposure",
                        f"[MEDIUM] iptables: Unrestricted ICMP ACCEPT from 0.0.0.0/0 with no rate-limit: {r['raw']}",
                        "Add rate-limiting: 'iptables -A INPUT -p icmp --icmp-type echo-request "
                        "-m limit --limit 10/sec -j ACCEPT'. "
                        "Unrestricted ICMP can be abused for reconnaissance or flood attacks.",
                        id="CASHEL-IPTABLES-EXPOSURE-004",
                        title="iptables allows unrestricted ICMP",
                        evidence=r["raw"],
                        affected_object="INPUT",
                        confidence="medium",
                        impact="Unrestricted ICMP can support reconnaissance or contribute to flood traffic.",
                        verification="Run 'iptables -S INPUT' and confirm ICMP accepts are rate-limited or source-scoped.",
                        rollback="Restore the previous ICMP rule from configuration backup if troubleshooting traffic is interrupted.",
                        suggested_commands=[
                            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT",
                            "iptables -A INPUT -p icmp -j DROP",
                        ],
                        metadata=_iptables_rule_metadata(
                            r, {"policy": policy.get(r["chain"], "")}
                        ),
                    )
                )
    return findings


def audit_iptables(filepath: str) -> tuple[list[dict], dict]:
    """Run all checks on an iptables-save file.

    Returns (findings_list, data_dict).
    """
    data, error = parse_iptables(filepath)
    if error:
        return [
            _iptables_f(
                "HIGH",
                "parse",
                f"[HIGH] {error}",
                "",
                id="CASHEL-IPTABLES-PARSE-001",
                title="iptables ruleset could not be parsed",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the file exists and contains iptables-save output, then re-run the audit.",
                metadata={"filepath": filepath},
            )
        ], {}

    findings: list[dict] = []
    findings += check_default_policy_iptables(data)
    findings += check_any_any_accept_iptables(data)
    findings += check_internet_ingress_iptables(data)
    findings += check_forward_chain_iptables(data)
    findings += check_missing_logging_iptables(data)
    findings += check_icmp_unrestricted_iptables(data)
    return findings, data


# ══════════════════════════════════════════════════════════ NFTABLES ══


def _parse_nftables_json(content: str) -> tuple[list[dict], str | None]:
    """Parse ``nft -j list ruleset`` JSON output into a flat chain/rule list."""
    try:
        blob = json.loads(content)
    except json.JSONDecodeError as exc:
        return [], f"Failed to parse nftables JSON: {exc}"

    entries = blob if isinstance(blob, list) else blob.get("nftables", [])
    chains: list[dict] = []
    rules: list[dict] = []

    for item in entries:
        if "chain" in item:
            c = item["chain"]
            chains.append(
                {
                    "family": c.get("family", ""),
                    "table": c.get("table", ""),
                    "name": c.get("name", ""),
                    "hook": c.get("hook", ""),
                    "policy": c.get("policy", ""),
                    "type": c.get("type", ""),
                }
            )
        if "rule" in item:
            r = item["rule"]
            rules.append(
                {
                    "family": r.get("family", ""),
                    "table": r.get("table", ""),
                    "chain": r.get("chain", ""),
                    "expr": r.get("expr", []),
                    "raw": str(r.get("expr", "")),
                }
            )
    return [{"chains": chains, "rules": rules}], None


def _parse_nftables_text(content: str) -> list[dict]:
    """Parse ``nft list ruleset`` text output into a flat chain/rule list."""
    tables: list[dict] = []
    current_table: dict = {}
    current_chain: dict = {}
    brace_depth = 0

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("table "):
            m = re.match(r"table\s+(\w+)\s+(\w+)", stripped)
            if m:
                current_table = {
                    "family": m.group(1),
                    "name": m.group(2),
                    "chains": {},
                }
                tables.append(current_table)
            brace_depth = 0

        elif stripped.startswith("chain "):
            m = re.match(r"chain\s+(\w+)", stripped)
            if m and current_table:
                current_chain = {
                    "name": m.group(1),
                    "hook": "",
                    "policy": "",
                    "type": "",
                    "rules": [],
                }
                current_table["chains"][m.group(1)] = current_chain

        elif "type" in stripped and "hook" in stripped and current_chain:
            # type filter hook input priority 0; policy drop;
            tm = re.search(r"type\s+(\w+)", stripped)
            hm = re.search(r"hook\s+(\w+)", stripped)
            pm = re.search(r"policy\s+(\w+)", stripped)
            if tm:
                current_chain["type"] = tm.group(1)
            if hm:
                current_chain["hook"] = hm.group(1)
            if pm:
                current_chain["policy"] = pm.group(1).rstrip(";")

        elif stripped == "}":
            brace_depth = max(0, brace_depth - 1)

        elif current_chain and stripped not in ("{", "}"):
            # record rule lines as-is
            if not stripped.startswith("type "):
                current_chain["rules"].append(stripped)

        if "{" in stripped:
            brace_depth += 1

    return tables


def parse_nftables(filepath: str) -> tuple[list, str | None]:
    """Parse an nftables ruleset file (text or JSON).

    Returns (tables_list, error_or_None).
    """
    try:
        with open(filepath) as fh:
            content = fh.read()
    except OSError as exc:
        return [], f"Failed to read nftables file: {exc}"

    stripped = content.strip()
    if not stripped:
        return [], "Empty nftables ruleset file."

    # Try JSON first
    if stripped.startswith("{") or stripped.startswith("["):
        tables, err = _parse_nftables_json(stripped)
        if not err:
            return tables, None

    # Fallback to text format
    if not re.search(r"\btable\b|\bchain\b", content):
        return [], (
            "Unrecognized format: expected 'nft list ruleset' text output "
            "or 'nft -j list ruleset' JSON."
        )
    return _parse_nftables_text(content), None


# ── nftables checks ───────────────────────────────────────────────────────────


def _nft_is_json_format(tables: list) -> bool:
    """Detect whether tables came from JSON parse (single-item list with 'chains' key)."""
    return bool(
        tables
        and isinstance(tables[0], dict)
        and "chains" in tables[0]
        and isinstance(tables[0]["chains"], list)
    )


def check_default_policy_nftables(tables: list) -> list[dict]:
    """Flag input/forward chains with policy 'accept' instead of 'drop'."""
    findings = []
    if _nft_is_json_format(tables):
        for chain in tables[0].get("chains", []):
            if (
                chain.get("hook") in ("input", "forward")
                and chain.get("policy", "").lower() == "accept"
            ):
                findings.append(
                    _f(
                        "HIGH",
                        "hygiene",
                        f"[HIGH] nftables: chain '{chain['name']}' (hook={chain['hook']}) "
                        f"has default policy 'accept' — all unmatched traffic is permitted.",
                        f"Set 'policy drop' on the {chain['hook']} chain. "
                        "Use explicit 'accept' statements only for required traffic.",
                    )
                )
        return findings

    for tbl in tables:
        for cname, chain in tbl.get("chains", {}).items():
            if (
                chain.get("hook") in ("input", "forward")
                and chain.get("policy", "").lower() == "accept"
            ):
                findings.append(
                    _f(
                        "HIGH",
                        "hygiene",
                        f"[HIGH] nftables table '{tbl['name']}': chain '{cname}' "
                        f"(hook={chain['hook']}) has default policy 'accept'.",
                        f"Change to 'policy drop;' inside the '{cname}' chain. "
                        "Only explicitly needed traffic should be accepted.",
                    )
                )
    return findings


def _nft_rule_sensitive_ports(rule_text: str) -> list[tuple[int, str]]:
    """Extract any sensitive ports referenced in an nftables rule text."""
    hits = []
    port_m = re.findall(r"\b(\d+)\b", rule_text)
    for p_str in port_m:
        p = int(p_str)
        if p in SENSITIVE_PORTS:
            hits.append((p, SENSITIVE_PORTS[p]))
    # range  22-1024
    range_m = re.findall(r"\b(\d+)-(\d+)\b", rule_text)
    for lo_s, hi_s in range_m:
        lo, hi = int(lo_s), int(hi_s)
        for p, svc in SENSITIVE_PORTS.items():
            if lo <= p <= hi:
                hits.append((p, svc))
    return list({k: v for k, v in hits}.items())  # deduplicate by port


def check_internet_ingress_nftables(tables: list) -> list[dict]:
    """Flag nftables input-chain accept rules that expose sensitive ports."""
    findings: list[dict] = []
    if _nft_is_json_format(tables):
        # JSON format: limited rule info available — skip deep port analysis
        return findings

    for tbl in tables:
        for cname, chain in tbl.get("chains", {}).items():
            if chain.get("hook") != "input":
                continue
            for rule in chain.get("rules", []):
                rl = rule.lower()
                if "accept" not in rl:
                    continue
                # Only flag if no source restriction is apparent
                has_src = bool(re.search(r"ip\s+saddr|ip6\s+saddr|saddr", rl))
                if has_src:
                    continue
                hits = _nft_rule_sensitive_ports(rule)
                for port, svc in hits:
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] nftables table '{tbl['name']}' chain '{cname}': "
                            f"{svc} (TCP/{port}) accepted with no source restriction: {rule}",
                            f"Add a source restriction: 'ip saddr <trusted-cidr> tcp dport {port} accept'. "
                            "Unrestricted access to sensitive ports exposes the host to the internet.",
                        )
                    )
    return findings


def check_any_any_accept_nftables(tables: list) -> list[dict]:
    """Flag rules that accept all traffic unconditionally in the input chain."""
    findings: list[dict] = []
    if _nft_is_json_format(tables):
        return findings

    for tbl in tables:
        for cname, chain in tbl.get("chains", {}).items():
            if chain.get("hook") != "input":
                continue
            for rule in chain.get("rules", []):
                rl = rule.strip().lower()
                # bare "accept" or "counter accept" with no match expressions
                if re.match(r"^(counter\s+)?accept\s*$", rl):
                    findings.append(
                        _f(
                            "HIGH",
                            "exposure",
                            f"[HIGH] nftables table '{tbl['name']}' chain '{cname}': "
                            f"unconditional 'accept' — all traffic is permitted: {rule}",
                            "Replace the bare 'accept' with specific match conditions. "
                            "Every accept statement should include protocol, port, and source restrictions.",
                        )
                    )
    return findings


def check_missing_logging_nftables(tables: list) -> list[dict]:
    """Flag input chains with accept rules but no log statements."""
    findings: list[dict] = []
    if _nft_is_json_format(tables):
        return findings

    for tbl in tables:
        for cname, chain in tbl.get("chains", {}).items():
            if chain.get("hook") != "input":
                continue
            rules = chain.get("rules", [])
            has_log = any("log" in r.lower() for r in rules)
            has_accept = any("accept" in r.lower() for r in rules)
            if has_accept and not has_log:
                findings.append(
                    _f(
                        "MEDIUM",
                        "logging",
                        f"[MEDIUM] nftables table '{tbl['name']}' chain '{cname}': "
                        "no 'log' statement found — accepted traffic is not logged.",
                        "Add log statements before accept rules: "
                        "'log prefix \"[ACCEPT] \" level info'. "
                        "Without logging, accepted traffic cannot be audited.",
                    )
                )
    return findings


def check_icmp_unrestricted_nftables(tables: list) -> list[dict]:
    """Flag unrestricted ICMP accept without rate-limiting in input chain."""
    findings: list[dict] = []
    if _nft_is_json_format(tables):
        return findings

    for tbl in tables:
        for cname, chain in tbl.get("chains", {}).items():
            if chain.get("hook") != "input":
                continue
            for rule in chain.get("rules", []):
                rl = rule.lower()
                if (
                    "icmp" in rl
                    and "accept" in rl
                    and "limit" not in rl
                    and not re.search(r"saddr", rl)
                ):
                    findings.append(
                        _f(
                            "MEDIUM",
                            "exposure",
                            f"[MEDIUM] nftables table '{tbl['name']}' chain '{cname}': "
                            f"ICMP accepted without rate-limiting or source restriction: {rule}",
                            "Add rate-limiting: 'icmp type echo-request limit rate 10/second accept'. "
                            "Unrestricted ICMP can facilitate reconnaissance and flood attacks.",
                        )
                    )
    return findings


def audit_nftables(filepath: str) -> tuple[list[dict], list]:
    """Run all checks on an nftables ruleset file.

    Returns (findings_list, tables_list).
    """
    tables, error = parse_nftables(filepath)
    if error:
        return [_f("HIGH", "parse", f"[HIGH] {error}")], []

    findings: list[dict] = []
    findings += check_default_policy_nftables(tables)
    findings += check_any_any_accept_nftables(tables)
    findings += check_internet_ingress_nftables(tables)
    findings += check_missing_logging_nftables(tables)
    findings += check_icmp_unrestricted_nftables(tables)
    return findings, tables
