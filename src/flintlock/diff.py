"""Rule diff engine — compare two firewall configs of the same vendor."""
import re
from ciscoconfparse import CiscoConfParse
from .paloalto import parse_paloalto
from .fortinet import parse_fortinet
from .pfsense import parse_pfsense


# ── ASA ──────────────────────────────────────────────────────────────────────

def _sig_asa(text):
    """Normalise a Cisco access-list line for comparison (strip log variants)."""
    t = text.strip().lower()
    t = re.sub(r'\s+log\b.*', '', t)
    return re.sub(r'\s+', ' ', t).strip()


def diff_asa(path_a, path_b):
    pa = CiscoConfParse(path_a, ignore_blank_lines=False)
    pb = CiscoConfParse(path_b, ignore_blank_lines=False)
    rules_a = {_sig_asa(r.text): r.text for r in pa.find_objects(r"access-list")}
    rules_b = {_sig_asa(r.text): r.text for r in pb.find_objects(r"access-list")}
    added     = [rules_b[s] for s in rules_b if s not in rules_a]
    removed   = [rules_a[s] for s in rules_a if s not in rules_b]
    unchanged = [rules_a[s] for s in rules_a if s in rules_b]
    return {"added": added, "removed": removed, "unchanged": unchanged}


# ── Fortinet ─────────────────────────────────────────────────────────────────

def _sig_forti(policy):
    return (
        tuple(sorted(policy.get("srcaddr", []))),
        tuple(sorted(policy.get("dstaddr", []))),
        tuple(sorted(policy.get("service", []))),
        policy.get("action", ""),
    )


def _fmt_forti(p):
    name = p.get("name") or f"Policy {p.get('id')}"
    src  = ",".join(p.get("srcaddr", []))
    dst  = ",".join(p.get("dstaddr", []))
    return f"{name}: {src} → {dst} ({p.get('action', '')})"


def diff_fortinet(path_a, path_b):
    pols_a, _ = parse_fortinet(path_a)
    pols_b, _ = parse_fortinet(path_b)
    sig_a = {_sig_forti(p): p for p in (pols_a or [])}
    sig_b = {_sig_forti(p): p for p in (pols_b or [])}
    added     = [_fmt_forti(sig_b[s]) for s in sig_b if s not in sig_a]
    removed   = [_fmt_forti(sig_a[s]) for s in sig_a if s not in sig_b]
    unchanged = [_fmt_forti(sig_a[s]) for s in sig_a if s in sig_b]
    return {"added": added, "removed": removed, "unchanged": unchanged}


# ── Palo Alto ─────────────────────────────────────────────────────────────────

def _sig_pa(rule):
    return (
        tuple(sorted(s.text for s in rule.findall(".//source/member"))),
        tuple(sorted(d.text for d in rule.findall(".//destination/member"))),
        tuple(sorted(a.text for a in rule.findall(".//application/member"))),
        tuple(sorted(s.text for s in rule.findall(".//service/member"))),
        rule.findtext(".//action"),
    )


def _fmt_pa(rule):
    name   = rule.get("name", "unnamed")
    src    = ",".join(s.text for s in rule.findall(".//source/member"))
    dst    = ",".join(d.text for d in rule.findall(".//destination/member"))
    action = rule.findtext(".//action") or ""
    return f"{name}: {src} → {dst} ({action})"


def diff_paloalto(path_a, path_b):
    rules_a, _ = parse_paloalto(path_a)
    rules_b, _ = parse_paloalto(path_b)
    sig_a = {_sig_pa(r): r for r in (rules_a or [])}
    sig_b = {_sig_pa(r): r for r in (rules_b or [])}
    added     = [_fmt_pa(sig_b[s]) for s in sig_b if s not in sig_a]
    removed   = [_fmt_pa(sig_a[s]) for s in sig_a if s not in sig_b]
    unchanged = [_fmt_pa(sig_a[s]) for s in sig_a if s in sig_b]
    return {"added": added, "removed": removed, "unchanged": unchanged}


# ── pfSense ───────────────────────────────────────────────────────────────────

def _sig_pf(rule):
    return (rule["type"], rule["source"], rule["destination"], rule["protocol"])


def _fmt_pf(r):
    return f"{r['descr']}: {r['source']} → {r['destination']} ({r['type']}/{r['protocol']})"


def diff_pfsense(path_a, path_b):
    rules_a, _ = parse_pfsense(path_a)
    rules_b, _ = parse_pfsense(path_b)
    sig_a = {_sig_pf(r): r for r in (rules_a or [])}
    sig_b = {_sig_pf(r): r for r in (rules_b or [])}
    added     = [_fmt_pf(sig_b[s]) for s in sig_b if s not in sig_a]
    removed   = [_fmt_pf(sig_a[s]) for s in sig_a if s not in sig_b]
    unchanged = [_fmt_pf(sig_a[s]) for s in sig_a if s in sig_b]
    return {"added": added, "removed": removed, "unchanged": unchanged}


# ── Main entrypoint ───────────────────────────────────────────────────────────

def diff_configs(vendor, path_a, path_b):
    """Compare two configs of the same vendor. Returns {added, removed, unchanged}."""
    if vendor == "asa":
        return diff_asa(path_a, path_b)
    if vendor == "fortinet":
        return diff_fortinet(path_a, path_b)
    if vendor == "paloalto":
        return diff_paloalto(path_a, path_b)
    if vendor == "pfsense":
        return diff_pfsense(path_a, path_b)
    raise ValueError(f"Unsupported vendor for diff: {vendor}")
