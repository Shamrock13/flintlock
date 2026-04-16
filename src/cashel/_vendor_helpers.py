"""Vendor detection and validation helpers — pure functions, no Flask dependency."""

from __future__ import annotations

import json
import re
from defusedxml import ElementTree as ET

VENDOR_DISPLAY = {
    "asa": "Cisco",
    "ftd": "Cisco",
    "cisco": "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense": "pfSense",
    "aws": "AWS Security Group",
    "azure": "Azure NSG",
    "gcp": "GCP VPC Firewall",
    "iptables": "iptables",
    "juniper": "Juniper SRX",
    "nftables": "nftables",
}

ALL_VENDORS = set(VENDOR_DISPLAY)


def detect_vendor(content: str, filename: str) -> str | None:
    """Infer firewall vendor from file content and filename."""
    filename_lower = filename.lower()
    content_lower = content.lower()
    stripped = content.strip()

    # JSON-based: AWS, Azure, or GCP
    if (
        stripped.startswith("{")
        or stripped.startswith("[")
        or filename_lower.endswith(".json")
    ):
        try:
            data = json.loads(content[:8192])  # partial parse for detection
            if isinstance(data, dict):
                if (
                    "SecurityGroups" in data
                    or "GroupId" in data
                    or "IpPermissions" in data
                ):
                    return "aws"
                if "securityRules" in data or "defaultSecurityRules" in data:
                    return "azure"
                if isinstance(data.get("value"), list):
                    # Could be az network nsg list output
                    if data["value"] and "securityRules" in data["value"][0]:
                        return "azure"
                if (
                    "items" in data
                    and isinstance(data["items"], list)
                    and data["items"]
                ):
                    first = data["items"][0]
                    if (
                        "direction" in first
                        and "IPProtocol" not in first
                        and ("allowed" in first or "denied" in first)
                    ):
                        return "gcp"
                if "direction" in data and ("allowed" in data or "denied" in data):
                    return "gcp"
            elif isinstance(data, list) and data:
                first = data[0]
                if "GroupId" in first or "IpPermissions" in first:
                    return "aws"
                if "securityRules" in first or "defaultSecurityRules" in first:
                    return "azure"
                if "direction" in first and ("allowed" in first or "denied" in first):
                    return "gcp"
        except Exception:
            pass

    # XML-based: pfSense or Palo Alto
    if stripped.startswith("<") or filename_lower.endswith(".xml"):
        if "<pfsense>" in content_lower or (
            "<filter>" in content_lower and "<rule>" in content_lower
        ):
            return "pfsense"
        if any(
            k in content_lower
            for k in ("<devices>", "<vsys>", "<security>", "<rulebase>")
        ):
            return "paloalto"

    # Text-based: Fortinet
    if "config firewall policy" in content_lower or (
        "set srcintf" in content_lower and "set dstintf" in content_lower
    ):
        return "fortinet"

    # Text-based: Cisco FTD (check before ASA — FTD has ASA-style ACLs too)
    if any(
        k in content_lower
        for k in (
            "access-control-policy",
            "firepower threat defense",
            "firepower-module",
            "intrusion-policy",
        )
    ):
        return "ftd"

    # Text-based: Juniper SRX ("set" style or hierarchical brace style)
    if re.search(r"set security policies from-zone", content) or (
        "from-zone" in content_lower
        and "to-zone" in content_lower
        and ("security {" in content or "security{" in content)
    ):
        return "juniper"

    # Text-based: nftables ("nft list ruleset" output)
    if re.search(r"\btable\s+\w+\s+\w+\s*\{|\bchain\s+\w+\s*\{", content):
        return "nftables"

    # JSON nftables ("nft -j list ruleset")
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(content[:8192])
            nft_entries = data if isinstance(data, list) else data.get("nftables", [])
            if isinstance(nft_entries, list) and any(
                "chain" in e or "rule" in e for e in nft_entries
            ):
                return "nftables"
        except Exception:
            pass

    # Text-based: iptables-save
    if re.search(r"^\*\w+$|^-A\s+\w+", content, re.MULTILINE):
        return "iptables"

    # Text-based: Cisco ASA
    if "access-list" in content_lower and any(
        k in content_lower for k in ("permit", "deny")
    ):
        return "asa"

    return None


def validate_vendor_format(
    content: str, filename: str, vendor: str
) -> tuple[bool, str]:
    """Return (is_valid, error_message). Ensures the file actually matches the vendor format."""
    content_lower = content.lower()
    is_xml = content.strip().startswith("<") or filename.lower().endswith(".xml")
    is_json = content.strip().startswith(("{", "[")) or filename.lower().endswith(
        ".json"
    )

    if vendor == "ftd":
        if is_xml or is_json:
            return (
                False,
                "Cisco FTD LINA configs are text-based, but this file appears to be XML or JSON.",
            )
        # FTD configs may or may not have access-list; require at least some Cisco CLI content
        if not any(
            k in content_lower
            for k in (
                "access-list",
                "access-control-policy",
                "threat-detection",
                "intrusion-policy",
                "interface",
                "firepower",
            )
        ):
            return (
                False,
                "No recognizable Cisco FTD configuration markers found. Check vendor selection.",
            )

    elif vendor == "asa":
        if is_xml or is_json:
            return (
                False,
                "Cisco configs are text-based, but this file appears to be XML or JSON.",
            )
        # If the file actually looks like FTD, upgrade silently
        from .ftd import is_ftd_config

        if is_ftd_config(content):
            return True, ""  # will be re-routed to ftd in run_audit
        if "access-list" not in content_lower:
            return (
                False,
                "No Cisco access-list statements found. Check vendor selection.",
            )

    elif vendor == "paloalto":
        if not is_xml:
            return False, "Palo Alto configs are XML-based, but this file is not XML."
        if not any(
            m in content_lower
            for m in ("<devices>", "<vsys>", "<security>", "<rulebase>")
        ):
            return (
                False,
                "This XML does not contain Palo Alto Networks configuration markers.",
            )

    elif vendor == "fortinet":
        if is_xml or is_json:
            return (
                False,
                "Fortinet configs are text-based, but this file appears to be XML or JSON.",
            )
        if not any(
            m in content_lower
            for m in ("config firewall policy", "set srcintf", "set dstintf")
        ):
            return (
                False,
                "No Fortinet firewall policy statements found. Check vendor selection.",
            )

    elif vendor == "pfsense":
        if not is_xml:
            return False, "pfSense configs are XML-based, but this file is not XML."
        if "<pfsense>" not in content_lower:
            return False, "pfSense root element <pfsense> not found in this XML file."

    elif vendor == "aws":
        if not is_json:
            return (
                False,
                "AWS Security Group exports are JSON. Please upload a .json file.",
            )

    elif vendor == "azure":
        if not is_json:
            return False, "Azure NSG exports are JSON. Please upload a .json file."

    elif vendor == "juniper":
        if is_xml or is_json:
            return (
                False,
                "Juniper SRX configs are text-based, but this file appears to be XML or JSON.",
            )
        if not any(
            m in content_lower
            for m in (
                "set security",
                "from-zone",
                "to-zone",
                "security-zone",
                "security {",
            )
        ):
            return (
                False,
                "No Juniper SRX security configuration markers found. Check vendor selection.",
            )

    elif vendor == "gcp":
        if not is_json:
            return (
                False,
                "GCP VPC firewall exports are JSON. Please upload a .json file.",
            )
        try:
            parsed = json.loads(content[:8192])
            items = (
                parsed if isinstance(parsed, list) else parsed.get("items", [parsed])
            )
            if not items or not isinstance(items[0], dict):
                raise ValueError("empty")
            first = items[0]
            if "direction" not in first or (
                "allowed" not in first and "denied" not in first
            ):
                return False, (
                    "This JSON does not contain GCP VPC firewall rule markers "
                    "('direction', 'allowed'/'denied'). Check vendor selection."
                )
        except Exception:
            return False, "Could not parse this file as a GCP VPC firewall JSON export."

    elif vendor == "iptables":
        if is_xml:
            return False, "iptables-save files are text-based, not XML."
        if not re.search(r"^\*\w+$|^-A\s+\w+", content, re.MULTILINE):
            return False, (
                "No iptables-save markers found (expected '*filter' or '-A INPUT ...'). "
                "Export with 'iptables-save > rules.txt'."
            )

    elif vendor == "nftables":
        # Accept either nft text or JSON
        is_nft_text = bool(
            re.search(r"\btable\s+\w+\s+\w+\s*\{|\bchain\s+\w+\s*\{", content)
        )
        is_nft_json = False
        if is_json:
            try:
                data = json.loads(content[:8192])
                nft_entries = (
                    data if isinstance(data, list) else data.get("nftables", [])
                )
                is_nft_json = isinstance(nft_entries, list) and any(
                    "chain" in e or "rule" in e for e in nft_entries
                )
            except Exception:
                pass
        if not is_nft_text and not is_nft_json:
            return False, (
                "No nftables markers found. "
                "Export with 'nft list ruleset' or 'nft -j list ruleset'."
            )

    else:
        return False, f"Unknown vendor: {vendor}"

    return True, ""


def extract_hostname(vendor: str, content: str) -> str | None:
    """Try to extract the device hostname from a config file."""
    try:
        if vendor in ("asa", "ftd"):
            m = re.search(r"^hostname\s+(\S+)", content, re.MULTILINE)
            return m.group(1) if m else None

        if vendor == "paloalto":
            root = ET.fromstring(content)
            el = root.find(".//devices/entry/deviceconfig/system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "fortinet":
            block = re.search(r"config system global(.*?)end", content, re.DOTALL)
            if block:
                m = re.search(r'set hostname\s+"?([^"\n]+)"?', block.group(1))
                return m.group(1).strip().strip('"') if m else None
            return None

        if vendor == "pfsense":
            root = ET.fromstring(content)
            el = root.find("system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "aws":
            data = json.loads(content)
            groups = (
                data if isinstance(data, list) else data.get("SecurityGroups", [data])
            )
            if groups:
                for t in groups[0].get("Tags", []):
                    if t.get("Key") == "Name":
                        return t["Value"]
                return groups[0].get("GroupName")

        if vendor == "azure":
            data = json.loads(content)
            items = data.get("value", [data]) if isinstance(data, dict) else data
            if items:
                return items[0].get("name")

    except Exception:
        pass
    return None
