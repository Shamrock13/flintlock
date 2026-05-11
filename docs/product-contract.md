# Cashel Product Contract

Cashel's contract is simple: produce trusted, evidence-backed, reproducible firewall audit findings that engineers can verify and remediate. Vendor breadth is secondary to correctness, explainability, and operational safety.

Branch guidance: [Branch strategy](branch-strategy.md).

## Current Priority Order

1. Product truth / docs cleanup
2. License decision/removal
3. SSO/OIDC model
4. Security hardening docs
5. Performance/scaling guardrails
6. NormalizedRule / NormalizedFinding model completion
7. Stable finding IDs everywhere
8. Evidence-backed vendor migration
9. Scope-aware analysis
10. Fortinet/Palo Alto/ASA depth
11. Policy-as-code / CI gates
12. MSP-grade reporting

## Feature Matrix

| Area | Status | Product contract |
|---|---|---|
| Single-file audit | Implemented | Deterministic parser-backed audit of one uploaded config. |
| Bulk audit | Implemented | Multiple uploaded configs audited independently; needs stronger bounds for large deployments. |
| Live SSH audit | Implemented | Pulls running configs from supported platforms; one-time credentials are not stored. |
| Scheduled SSH audit | Partial | Recurring audits exist with encrypted saved credentials; needs concurrency, timeout, and scheduler leadership hardening. |
| Audit history | Implemented | Stores audit summaries, findings, tags, activity, and report references. |
| Activity/auth logging | Implemented | Records operational events; retention policy is deployment responsibility today. |
| Modern audit PDFs | Implemented | HTML/CSS templates rendered through Playwright/Chromium. |
| Remediation PDFs | Implemented | Structured remediation output with evidence fields where findings provide them. |
| Evidence bundles | Implemented | ZIP exports with report artifacts and machine-readable outputs. |
| JSON export | Implemented | Preserves enriched finding dictionaries. |
| CSV export | Implemented | Includes normalized columns where available. |
| SARIF export | Implemented | Uses stable finding IDs when present; legacy findings remain supported. |
| NormalizedFinding model | Partial | Model exists and newer checks use it; legacy string findings still appear. |
| NormalizedRule model | Planned | Needed for scope-aware policy analysis and policy-as-code gates. |
| Stable finding IDs | Partial | Present for many enriched findings; not universal. |
| Evidence-backed vendor findings | Partial | Strongest in ASA and improving in Fortinet/Palo Alto; not complete everywhere. |
| Cisco ASA/FTD depth | Partial | Primary near-term platform. ASA has object/object-group expansion and enriched findings; FTD needs continued depth. |
| Fortinet depth | Partial | Enriched findings and object expansion exist; needs more complete service/address behavior. |
| Palo Alto depth | Partial | XML parsing, object/service/application expansion, and enriched findings exist; needs deeper scope semantics. |
| Juniper/pfSense depth | Partial | Useful audit coverage exists; not the current top depth priority. |
| Cloud firewall depth | Experimental | AWS/Azure/GCP are useful static checks but not the current depth priority. |
| Scope-aware shadowing | Partial | Existing shadow checks catch useful cases but are not fully context-aware. |
| Compliance checks | Deprecated | Current implementation is license-gated in some flows and should be reworked toward data-driven mappings. |
| License-gated compliance | Deprecated | Do not build new product direction around paid compliance gating. |
| OIDC SSO | Planned | First-class target. Local auth remains bootstrap/fallback. |
| SAML SSO | Planned | Future roadmap after OIDC. |
| Policy-as-code / CI gates | Planned | Depends on stable IDs and normalized findings/rules. |
| MSP-grade reporting | Planned | Needs better tenant/client presentation, retention controls, and evidence review workflows. |

## Vendor Maturity

| Vendor family | Status | Notes |
|---|---|---|
| Cisco ASA / FTD | Mature / enriched | ASA has the strongest normalized/evidence-backed coverage. Continue ASA/FTD depth before adding new vendors. |
| Fortinet FortiGate | Mature / enriched | Good parser direction with address/service expansion; continue hardening object semantics. |
| Palo Alto Networks | Mature / enriched | Good XML/parser direction with object/service/application expansion; continue scope-aware analysis. |
| Juniper SRX | Partial / legacy-compatible | Useful checks and some enrichment, but not uniform. |
| pfSense | Partial / legacy-compatible | Useful checks and alias expansion, but not uniform. |
| iptables / nftables | Partial / legacy-compatible | Useful host-firewall checks. |
| Azure NSG | Partial / legacy-compatible | Priority-based checks exist. |
| AWS Security Groups | Experimental / basic audit only | Basic static checks. |
| GCP VPC Firewall | Experimental / basic audit only | Basic static checks. |

## Compliance Direction

Current compliance behavior is not the long-term contract. It is partially implemented and may be license-gated depending on route and deployment state.

Future compliance should be data-driven:

- Controls map to stable finding IDs.
- Controls define required evidence fields.
- Exports include evidence, affected object/rule, remediation, verification, and status.
- Framework labels do not imply full certification readiness.
- Control mappings can be tested independently from parser logic.

## SSO Direction

OIDC should be the first SSO target. The intended providers are Microsoft Entra ID, Google Workspace, Okta, Authentik, and Keycloak. SAML is deferred.

Planned role mapping:

| IdP claim/group | Cashel role |
|---|---|
| `CASHEL_OIDC_ADMIN_GROUPS` | `admin` |
| `CASHEL_OIDC_AUDITOR_GROUPS` | `auditor` |
| `CASHEL_OIDC_VIEWER_GROUPS` | `viewer` |

Local auth should remain available for bootstrap/fallback, but production deployments should prefer SSO once implemented.
