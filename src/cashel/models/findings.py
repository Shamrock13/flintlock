"""Normalized finding helpers.

The application still passes findings around as dictionaries.  This module
gives producers a richer common shape without forcing UI, export, archive, or
remediation consumers to accept dataclass instances yet.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NormalizedFinding:
    id: str
    vendor: str
    severity: str
    category: str
    title: str
    message: str
    remediation: str
    evidence: str | None = None
    affected_object: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    confidence: str = "medium"
    impact: str | None = None
    verification: str | None = None
    rollback: str | None = None
    compliance_refs: list[str] = field(default_factory=list)
    suggested_commands: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def finding_to_dict(finding: NormalizedFinding | dict[str, Any]) -> dict[str, Any]:
    """Return a backward-compatible finding dictionary."""
    if isinstance(finding, NormalizedFinding):
        data = asdict(finding)
    else:
        data = dict(finding)

    data.setdefault("severity", "")
    data.setdefault("category", "")
    data.setdefault("message", "")
    data.setdefault("remediation", "")
    data.setdefault("id", "")
    data.setdefault("vendor", "unknown")
    data.setdefault("title", data.get("message") or "Finding")
    data.setdefault("evidence", None)
    data.setdefault("affected_object", None)
    data.setdefault("rule_id", None)
    data.setdefault("rule_name", None)
    data.setdefault("confidence", "medium")
    data.setdefault("impact", None)
    data.setdefault("verification", None)
    data.setdefault("rollback", None)
    data.setdefault("compliance_refs", [])
    data.setdefault("suggested_commands", [])
    data.setdefault("metadata", {})
    return data


def normalize_finding(raw: Any, vendor: str | None = None) -> dict[str, Any]:
    """Normalize old string/dict findings into the additive finding shape."""
    if isinstance(raw, NormalizedFinding):
        data = finding_to_dict(raw)
    elif isinstance(raw, dict):
        data = finding_to_dict(raw)
    else:
        message = str(raw)
        severity = (
            "CRITICAL"
            if "[CRITICAL]" in message
            else "HIGH"
            if "[HIGH]" in message
            else "MEDIUM"
            if "[MEDIUM]" in message
            else ""
        )
        data = finding_to_dict(
            {
                "severity": severity,
                "category": "",
                "message": message,
                "remediation": "",
            }
        )

    if vendor is not None:
        data["vendor"] = vendor
    return data


def make_finding(
    severity: str,
    category: str,
    message: str,
    remediation: str = "",
    *,
    id: str | None = None,
    vendor: str = "unknown",
    title: str | None = None,
    evidence: str | None = None,
    affected_object: str | None = None,
    rule_id: str | None = None,
    rule_name: str | None = None,
    confidence: str = "medium",
    impact: str | None = None,
    verification: str | None = None,
    rollback: str | None = None,
    compliance_refs: list[str] | None = None,
    suggested_commands: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an enriched finding while preserving legacy dictionary keys."""
    finding = NormalizedFinding(
        id=id or "",
        vendor=vendor,
        severity=severity,
        category=category,
        title=title or message,
        message=message,
        remediation=remediation,
        evidence=evidence,
        affected_object=affected_object,
        rule_id=rule_id,
        rule_name=rule_name,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        compliance_refs=compliance_refs or [],
        suggested_commands=suggested_commands or [],
        metadata=metadata or {},
    )
    return finding_to_dict(finding)
