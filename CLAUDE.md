**CLAUDE.md**

# Cashel — Claude Code Guide

Cashel is a firewall configuration auditing tool with a CLI and Flask web UI. It parses configs from 11 firewall vendors, scores them, and checks compliance against frameworks like SOC2, DISA STIG, PCI-DSS, HIPAA, CIS, and NIST SP 800-41.

## Project Structure

```
src/cashel/             # Main package
  main.py               # CLI entry point (typer)
  web.py                # Flask web UI
  audit_engine.py       # Core scoring and findings logic (includes ASA audit helpers)
  compliance.py         # All compliance framework checks (paid feature)
  reporter.py           # PDF report generation (fpdf2)
  export.py             # JSON / CSV / SARIF export
  diff.py               # Config diff / comparison
  rule_quality.py       # Shadow and duplicate rule detection
  notify.py             # Slack / Teams / Email alerts
  syslog_handler.py     # Syslog forwarding
  ssh_connector.py      # Paramiko SSH connections
  scheduler_runner.py   # APScheduler recurring audits
  schedule_store.py     # Persists scheduled audit config
  activity_log.py       # Audit history
  archive.py            # Historical audit storage
  settings.py           # User settings management
  license.py            # License key validation (compliance gate)
  # Vendor parsers — Cisco is the vendor; ASA and FTD are different appliances:
  audit_engine.py       # Also contains _audit_asa() for Cisco ASA appliances
  ftd.py                # Cisco FTD (Firepower Threat Defense) appliances
  iptables.py           # iptables-save and nftables
  juniper.py            # Juniper SRX (set-style and hierarchical)
  paloalto.py           # Palo Alto (XML)
  fortinet.py           # Fortinet FortiGate
  pfsense.py            # pfSense (XML)
  aws.py                # AWS Security Groups (JSON)
  azure.py              # Azure NSG (JSON)
  gcp.py                # GCP VPC Firewall (JSON)
tests/                  # Test suite — run as plain Python scripts
```

## Running Tests

Tests use the standard library `unittest` and are run directly (no pytest required):

```bash
# Run a single test file
python3 tests/test_iptables.py
python3 tests/test_juniper.py
python3 tests/test_gcp.py
python3 tests/test_export.py
python3 tests/test_notify.py
python3 tests/test_rule_quality.py
python3 tests/test_soc2_stig.py

# Run all tests at once (if pytest is installed)
python -m pytest tests/ -v
```

Each test file inserts `src/` into `sys.path` at the top — no install required.

## Test Fixtures

Vendor config fixtures live in `tests/`:
- `test_asa.txt` — Cisco ASA ACL config
- `test_forti.txt` — Fortinet FortiGate policy config
- `test_pa.xml` — Palo Alto XML config
- `test_pfsense.xml` — pfSense XML config

## Vendor Naming Convention

**Cisco** is the vendor. The ASA (Adaptive Security Appliance) and FTD (Firepower Threat Defense) are
different Cisco appliances, but they share LINA CLI syntax. In the vendor dispatch code they use the
`"asa"` and `"ftd"` vendor keys respectively. Tests for both live in `tests/test_cisco.py`.

## Test Coverage Gaps

All primary vendor modules now have test files. Remaining gap:

| Module | Status |
|---|---|
| `compliance.py` | Partially covered — `test_soc2_stig.py` covers SOC2/STIG; CIS/NIST/PCI/HIPAA checks need expansion |

## Roadmap Status

### Done
- [x] API key authentication with session management
- [x] Fernet encryption for stored credentials
- [x] CSRF protection (Flask-WTF)
- [x] Multi-factor SSH authentication (PEM key support)
- [x] REST API for CI/CD pipeline integration
- [x] Rate limiting (Flask-Limiter)
- [x] Content Security Policy (CSP) header with nonce
- [x] Input size limits (50MB total, 5MB per file)
- [x] Health endpoint (GET /health)

### Pending
- [ ] Local username/password auth (see Auth Expansion Plan in PLAN.md)
- [ ] LDAP / Active Directory auth
- [ ] OIDC auth (Okta, Azure AD, Google)
- [ ] TACACS+ auth
- [ ] web.py decomposition into blueprints
- [ ] GitHub Actions CI pipeline
- [ ] Docker image hardening (non-root user, pinned digest)
- [ ] Structured logging (replace print() with logging module)

## Architecture Notes

- **Compliance features are gated** by a license key checked in `license.py`. The `keygen.py` utility (gitignored) generates keys via SHA256 hash.
- **Vendor parsers** follow a consistent pattern: `parse_<vendor>()` → returns a list of rule dicts, then `audit_<vendor>()` → calls individual `check_*()` functions and returns findings.
- **Findings** are dicts with keys: `id`, `title`, `severity` (`critical`/`high`/`medium`/`low`/`info`), `description`, `remediation`, `category`.
- **`audit_engine.py`** computes the 0–100 security score from findings and is vendor-agnostic.
- **`web.py`** is large (~1,600 lines). Flask routes handle file upload, SSH, scheduling, diff, export, and settings.
- **XML parsing** always uses `defusedxml` (never `xml.etree`) for XXE protection.

## Code Style

- Python 3.8+ compatible
- Linting: `ruff` (see commit history for fixes)
- No type annotations required, but keep existing ones consistent
- Avoid `xml.etree` — always use `defusedxml.ElementTree`

## Installation (Development)

```bash
pip install -e .
# or
pip install -r requirements.txt
```

Both `requirements.txt` and `pyproject.toml` are the source of truth for dependencies and should be kept in sync. The pre-merge validation Stop hook checks for drift between them.
```

---

