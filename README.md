# Cashel

![CI](https://github.com/Shamrock13/cashel/actions/workflows/ci.yml/badge.svg)

**Cashel** is a self-hosted firewall audit and remediation platform for network engineers, MSPs, and security teams. It audits uploaded firewall configurations and live SSH pulls, preserves evidence for each finding where the parser supports it, and produces remediation-oriented reports and exports that can be reviewed, repeated, and defended.

The product direction is depth over breadth: trusted, evidence-backed, reproducible findings for the platforms engineers operate every day. Near-term work should prioritize Fortinet, Palo Alto Networks, and Cisco ASA/FTD correctness, SSO readiness, security hardening, operational clarity, and policy-as-code workflows before adding more vendors.

**Demo:** [demo.cashel.app](https://demo.cashel.app)

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Cashel-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Current State

Implemented today:

- Web UI and CLI audit workflows
- Single-file and bulk config audits
- Live SSH audits for supported network firewall platforms
- Scheduled SSH audits with saved encrypted credentials
- Audit history, activity logging, score trends, archived comparisons, and saved report views
- Modern audit, remediation, and evidence-bundle PDFs rendered with Playwright/Chromium
- JSON, CSV, SARIF, PDF, and evidence-bundle exports
- Structured remediation output that prefers enriched finding fields before falling back to legacy messages
- Normalized finding dictionaries for many newer checks, while preserving legacy string finding compatibility
- ASA object/object-group expansion and enriched ASA findings
- Fortinet, Palo Alto, Juniper, and pfSense parser improvements with varying maturity by check family
- CI validation for Ruff, formatting, mypy, pytest, dependency sync, XML parser safety, Docker build, and secret scanning

Partially implemented:

- Stable finding IDs across all vendors and checks
- Evidence-backed findings for every vendor-specific rule
- Scope-aware shadow analysis across nested groups, services, ports, zones, NAT context, and vendor-specific abstractions
- Data-driven compliance/control mappings
- Policy-as-code and CI gate outputs
- MSP-grade reporting workflows

Planned:

- OIDC SSO as a first-class authentication mode
- License-gating removal or replacement with a clearer non-paid feature model
- NormalizedRule and NormalizedFinding model completion
- Deeper Fortinet, Palo Alto, and Cisco ASA/FTD object expansion
- Bounded background execution for large PDFs, bulk audits, and scheduled audit queues

Deprecated / under review:

- The current license-gated compliance implementation
- Legacy paid compliance messaging
- Treating all supported vendors as equal maturity

---

## Supported Vendor Maturity

Cashel intentionally does not claim equal depth for every parser. Current maturity should be read as audit maturity, not a promise that every check is fully normalized or evidence-backed.

| Maturity | Vendors | Current reality |
|---|---|---|
| Mature / enriched | Cisco ASA / FTD, Fortinet FortiGate, Palo Alto Networks | Primary investment area. These have the strongest evidence-backed finding and object-expansion direction, with ASA currently the most normalized. |
| Partial / legacy-compatible | Juniper SRX, pfSense, iptables / nftables, Azure NSG | Useful checks exist, and legacy outputs are preserved. Some findings are enriched, but coverage is not yet uniformly normalized. |
| Experimental / basic audit only | AWS Security Groups, GCP VPC Firewall | Basic static audit coverage. These are not the near-term depth priority. |

> Cisco note: Cashel exposes Cisco ASA and FTD under a single Cisco option in the UI. The platform can auto-detect ASA vs. FTD from config content and apply relevant checks.

Full list of current checks: [docs/checks.md](docs/checks.md)

---

## Known Limitations

- Findings are not yet normalized everywhere. Legacy string findings remain supported and may appear in API/UI/export flows.
- Shadow detection is useful but not fully scope-aware across every vendor abstraction, nested object group, service group, NAT rule, zone context, and CIDR interaction.
- Compliance checks currently remain license-gated in code for some workflows. This behavior is under review and should not be treated as the long-term product model.
- SSO/OIDC is documented as the target model but is not implemented yet.
- SQLite is appropriate for lightweight self-hosted deployments, but it is not a horizontally scalable database.
- Multi-worker deployments can duplicate scheduler execution unless external locking or a single scheduler process is used.
- PDF generation can be CPU and memory intensive because it starts Chromium.
- Bulk audits run in request/response paths today and should be bounded for large deployments.
- Uploaded configs, generated reports, evidence bundles, and scheduled SSH credentials are sensitive and must be protected like production network documentation.
- Demo mode is for public/demo use only and should not be treated as a secure production mode.

---

## Roadmap Priority

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

Cashel should avoid adding new vendors until the top vendor parsers produce consistently evidence-backed, reproducible results.

See [docs/product-contract.md](docs/product-contract.md) for the status matrix and product contract.

---

## Authentication and SSO

Current behavior:

- Local users and API keys are implemented.
- First-run setup creates a local admin.
- Local auth can be disabled in settings for simple self-hosted use.
- RBAC-style roles exist for admin, auditor, and viewer access patterns.

Target direction:

- Local auth should become the fallback/bootstrap mode.
- OIDC should be the first SSO implementation.
- SAML is a future roadmap item, not the first SSO target.
- Supported OIDC deployments should include Microsoft Entra ID, Google Workspace, Okta, Authentik, and Keycloak.
- Role mapping should derive Cashel roles from IdP claims/groups: `admin`, `auditor`, and `viewer`.

Planned OIDC environment design:

```bash
CASHEL_AUTH_MODE=local|oidc
CASHEL_OIDC_ISSUER=https://idp.example.com/
CASHEL_OIDC_CLIENT_ID=cashel
CASHEL_OIDC_CLIENT_SECRET=replace-me
CASHEL_OIDC_REDIRECT_URI=https://cashel.example.com/auth/oidc/callback
CASHEL_OIDC_ALLOWED_DOMAINS=example.com,example.org
CASHEL_OIDC_ADMIN_GROUPS=NetSec Admins,Cashel Admins
CASHEL_OIDC_AUDITOR_GROUPS=Network Engineers,MSP Auditors
CASHEL_OIDC_VIEWER_GROUPS=Security Viewers
```

Deployment requirements for OIDC:

- Serve Cashel behind HTTPS.
- Set `CASHEL_SECURE_COOKIES=true`.
- Configure the IdP callback URL exactly, including scheme and path.
- Preserve `Host`, `X-Forwarded-Proto`, and client IP headers at the reverse proxy.
- Keep local bootstrap/fallback access documented and restricted.
- Store OIDC client secrets outside the repo and outside image layers.

More detail: [docs/security-model.md](docs/security-model.md) and [docs/deployment-hardening.md](docs/deployment-hardening.md).

---

## Security Model

Cashel handles sensitive network data:

- Uploaded firewall configs
- Live SSH connection details
- Scheduled SSH credentials
- Audit findings that reveal topology and control weaknesses
- Generated PDFs, evidence bundles, CSV, JSON, and SARIF exports
- Webhook/syslog destinations and secrets

Minimum production requirements:

- Set `CASHEL_SECRET` to a strong random value.
- Set and persist `CASHEL_KEY_FILE`; do not regenerate it after encrypting secrets.
- Put SQLite, reports, uploads, and key material on persistent storage.
- Serve behind a TLS-terminating reverse proxy.
- Enable secure cookies when served over HTTPS.
- Limit upload sizes and report retention.
- Review webhook allowlists and outbound egress policy.
- Back up SQLite and key material together.

Security docs:

- [Security model](docs/security-model.md)
- [Deployment hardening](docs/deployment-hardening.md)
- [Secrets](docs/secrets.md)

---

## Performance and Scaling Notes

Cashel is currently best suited to lightweight self-hosted deployments, MSP engineer workbenches, and small team installations.

Operational considerations:

- PDF generation is CPU/memory heavy because it uses Chromium.
- Bulk audits should be bounded by upload count, file size, and request timeout.
- Scope-aware shadow analysis can become expensive without caching/memoization.
- Scheduled SSH audits need concurrency limits, timeouts, retries, and backoff.
- SQLite has write-concurrency limits.
- Multi-worker deployments should run one scheduler or use leader election/locking.
- Reports and evidence bundles should have a retention policy.

Recommended starting points:

| Setting | Starting recommendation |
|---|---|
| Max upload size | 25 MB per file unless you have tested larger policies |
| Audit timeout | 60-120 seconds per request |
| PDF timeout | `CASHEL_PDF_TIMEOUT_MS=30000` to `60000` |
| Scheduled audit concurrency | 1-3 concurrent SSH audits |
| Worker count | 1 for small hosts; scale only after scheduler behavior is controlled |
| Report retention | 30-90 days, shorter for highly sensitive environments |
| Storage | Persistent volume for DB, reports, uploads, and keys |
| Backups | SQLite plus `CASHEL_KEY_FILE` together |

More detail: [docs/performance.md](docs/performance.md) and [docs/operations.md](docs/operations.md).

---

## Licensing Direction

Cashel is MIT licensed. The current code still contains a legacy license mechanism that gates compliance checks in some workflows. That implementation is deprecated and under review.

Current behavior:

- Hygiene audits run without a license.
- Compliance checks may be skipped unless a local license key is present.
- Demo mode bypasses licensing for hosted demo behavior.
- The active code still exposes license activation/deactivation routes and UI copy.

Preferred direction:

- Remove paid compliance gating unless a strong reason remains.
- Treat compliance as a data-quality and evidence-mapping problem, not a paid unlock.
- Make compliance controls data-driven and mapped to stable finding IDs.
- Include evidence, affected object/rule, remediation, verification, and status in compliance exports.
- Remove stale purchase links and paid-feature claims from product docs and UI.

Tracking docs: [docs/product-contract.md](docs/product-contract.md)

---

## Compliance Direction

Compliance support is useful only when it is evidence-backed and auditable.

Current behavior:

- Supported framework labels include CIS, DISA STIG, HIPAA, NIST, PCI-DSS, and SOC2.
- Current checks map some findings to framework-style labels.
- Some workflows still require the legacy license state before compliance checks run.

Future behavior:

- Control mappings should be stored as data, not hard-coded scattered logic.
- Controls should map to stable finding IDs and normalized finding fields.
- Compliance exports should include evidence, affected object/rule, remediation, verification, and implementation status.
- Compliance should not overstate coverage. A framework label should identify mapped checks, not full certification readiness.

---

## Installation

### Docker Compose

Requirements: Docker Desktop, OrbStack, or another Docker-compatible runtime.

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
docker compose up --build
```

Open `http://localhost:8080`.

Recommended `.env` values for persistent self-hosted use:

```bash
CASHEL_SECRET=replace-with-a-long-random-secret
CASHEL_KEY_FILE=/data/cashel.key
CASHEL_DB=/data/cashel.db
UPLOAD_FOLDER=/data/uploads
REPORTS_FOLDER=/data/reports
PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
CASHEL_SECURE_COOKIES=true
```

The Docker build installs Playwright Chromium for PDF generation. First builds can take longer while the browser is downloaded.

### Local Python

Requirements: Python 3.9+.

```bash
git clone https://github.com/Shamrock13/cashel.git
cd cashel
pip install -r requirements.txt
python -m playwright install chromium
```

Run the web UI:

```bash
PYTHONPATH=src python -m flask --app src/cashel/web.py run
```

Run the CLI:

```bash
PYTHONPATH=src python -m cashel.main --file examples/cisco_asa.txt --vendor cisco
```

CLI reference: [docs/cli.md](docs/cli.md)

---

## Web UI Areas

| Area | Purpose |
|---|---|
| Audit | Single-file and bulk upload audits with findings and exports |
| Compare | Diff two configs of the same vendor |
| Live Connect | Pull and audit running configs over SSH |
| History | Browse saved audits, compare previous runs, and view trends |
| Schedules | Manage recurring SSH audits and alert behavior |
| Settings | Configure auth, email, security settings, syslog, webhooks, compliance access, and app preferences |

---

## Example Config Files

| File | Vendor |
|---|---|
| `examples/cisco_asa.txt` | Cisco ASA |
| `examples/cisco_ftd.txt` | Cisco FTD |
| `examples/fortinet_fortigate.txt` | Fortinet FortiGate |
| `examples/palo_alto.xml` | Palo Alto Networks |
| `examples/pfsense.xml` | pfSense |
| `examples/juniper_srx.txt` | Juniper SRX |
| `examples/iptables.txt` | iptables |
| `examples/nftables.txt` | nftables |
| `examples/aws_security_groups.json` | AWS Security Groups |
| `examples/azure_nsg.json` | Azure NSG |
| `examples/gcp_vpc_firewall.json` | GCP VPC Firewall |

---

## Development

```bash
python3 -m ruff format src/ tests/
python3 -m ruff check src/ tests/
python3 -m mypy src/cashel/ --ignore-missing-imports
python3 -m pytest tests/ -q
git diff --check
```

Current version in `pyproject.toml`: **2.0.0**.

---

## License

Cashel is released under the MIT License.

---

## Author

Built by a network security engineer for network security engineers.
