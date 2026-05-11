# Finding Model

Cashel currently accepts several finding shapes because older audit, compliance, archive, export, and UI paths still need to work while newer vendor checks migrate toward evidence-backed findings.

The contract for this phase is additive compatibility: keep legacy findings working, prefer enriched fields where available, and avoid a broad refactor until the remaining vendor work is ready.

## Current Accepted Formats

### Plain string findings

Plain strings still appear in older archive rows and many compliance mapping checks:

```text
[HIGH] No explicit deny-all rule found
```

Consumers must continue to accept strings. Export/report helpers infer severity from bracketed prefixes such as `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, and `[LOW]` when possible. Plain strings do not carry remediation, evidence, object scope, or stable IDs.

### Legacy dict findings

Legacy dicts are the minimum structured shape:

```json
{
  "severity": "HIGH",
  "category": "exposure",
  "message": "[HIGH] Permit any any rule found",
  "remediation": "Restrict the rule to specific sources and destinations."
}
```

These fields remain backward-compatible app boundary fields. Existing routes, archives, UI rendering, reports, remediation, and exports should not require more than this shape unless a specific feature needs enriched details.

### Enriched finding dicts

Newer vendor checks should emit enriched dicts through `make_finding(...)` in `src/cashel/models/findings.py` when practical:

```json
{
  "id": "CASHEL-ASA-EXPOSURE-001",
  "vendor": "asa",
  "severity": "HIGH",
  "category": "exposure",
  "title": "ASA ACL permits any source to any destination",
  "message": "[HIGH] ACL rule permits ip any any",
  "remediation": "Replace the broad ACL with scoped source, destination, and service objects.",
  "evidence": "access-list OUTSIDE_IN permit ip any any",
  "affected_object": "OUTSIDE_IN",
  "rule_id": "OUTSIDE_IN:10",
  "rule_name": "OUTSIDE_IN",
  "confidence": "high",
  "verification": "Re-run the audit and confirm the any-any finding is gone.",
  "rollback": "Restore the previous ACL line from backup.",
  "compliance_refs": ["PCI-DSS 1.2"],
  "suggested_commands": ["no access-list OUTSIDE_IN permit ip any any"],
  "metadata": {"acl": "OUTSIDE_IN", "line": 10}
}
```

Enriched findings are still plain dictionaries at app boundaries. Do not require dataclass instances in routes, archive rows, templates, exports, or remediation plans yet.

## Preferred Fields

Preferred enriched fields:

| Field | Expectation |
|---|---|
| `id` | Stable finding ID, preferably `CASHEL-<VENDOR>-<CATEGORY>-NNN`. |
| `vendor` | Lowercase vendor key such as `asa`, `fortinet`, or `paloalto`. |
| `severity` | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | Stable category such as `exposure`, `protocol`, `logging`, `hygiene`, `redundancy`, or `compliance`. |
| `title` | Short human-readable finding title without relying on severity prefixes. |
| `message` | Backward-compatible display message. |
| `remediation` | Human-readable remediation guidance. |

Optional enriched fields:

- `evidence`
- `affected_object`
- `rule_id`
- `rule_name`
- `confidence`
- `verification`
- `rollback`
- `compliance_refs`
- `suggested_commands`
- `impact`
- `metadata`

## Future Stable Finding Requirements

Future stable findings should include:

- stable `id`
- lowercase `vendor`
- normalized `severity`
- stable `category`
- clear `title`
- backward-compatible `message`
- actionable `remediation`
- at least one scope field, preferably `affected_object` or `rule_name`
- evidence whenever the parser can identify a source rule, object, line, or setting

`NormalizedRule` is still planned. Until it exists, vendor-specific scope and parser details should live in `metadata` without breaking existing consumers.

## Consumer Expectations

JSON export preserves findings as-is, including enriched fields.

CSV export emits backward-compatible core columns plus enriched columns for `id`, `vendor`, `title`, `evidence`, `affected_object`, `rule_name`, and `confidence`.

SARIF export uses `id` as the `ruleId` when present and falls back to a category-derived rule ID for legacy dicts and strings.

Remediation plans currently use dict findings that include `remediation`. Plain strings are skipped by remediation generation. When enriched fields are present, remediation steps should prefer `title`, preserve `id`, `evidence`, `affected_object`, `rule_name`, `verification`, `rollback`, and use `suggested_commands` before generating fallback commands.

Report and UI rendering must keep legacy string fallback behavior while displaying enriched fields when present.

## Migration Path

1. Keep returning strings from legacy compliance checks until those mappings are refactored.
2. Preserve legacy dict findings wherever vendor code already depends on them.
3. For new or touched vendor checks, use `make_finding(...)` and fill evidence/scope fields when parser data is available.
4. Use `normalize_finding(...)` only at compatibility boundaries where older strings or dicts need a richer additive shape.
5. Use `validate_finding_shape(...)` in tests for enriched findings, but do not apply it as a hard runtime gate.
6. Move compliance mapping toward stable finding IDs and evidence-backed controls after vendor findings are consistently enriched.
