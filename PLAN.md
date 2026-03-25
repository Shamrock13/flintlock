**PLAN.md**


# Cashel — Project Plan

Internal working document. Not the public roadmap (see README.md).

---

## Active: README Roadmap Items

These map 1-to-1 with the `[ ]` items in README.md and will be checked off there when done.

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | API key authentication with session management | **Done** | Web UI login + API key for CLI/programmatic access |
| 2 | Fernet encryption for stored credentials | **Done** | schedule_store.py + settings.py; crypto.py module; base64 migration fallback |
| 3 | CSRF protection (Flask-WTF) | **Done** | CSRFProtect on all routes; JS fetch interceptor adds X-CSRFToken header |
| 4 | Multi-factor SSH authentication (key-based) | **Done** | PEM/passphrase support in ssh_connector.py |
| 5 | REST API for CI/CD pipeline integration | **Done** | JSON API wrapping existing audit_engine |

---

## Engineering / Internal Work

These are **not** public roadmap items and should not appear in README.md.

### Testing & CI
- [ ] **Scheduled CI (GitHub Actions)** — on PR: ruff + mypy + pytest; on merge/main: full suite + secret scan; nightly: pip-audit
- [ ] **pip-audit nightly job** — automate dependency CVE scanning; alert on new critical/high vulns
- [ ] **Integration tests** — Docker Compose test environment with mock SSH server (paramiko stub or sshesame); test full audit flow end-to-end
- [ ] **APScheduler tests** — use `freezegun` to test scheduled job firing, cron intervals, and missed-run behavior without wall-clock waiting
- [ ] **Compliance test expansion** — `test_soc2_stig.py` only covers SOC2/STIG; need CIS, NIST, PCI-DSS, HIPAA checks in `compliance.py`
- [ ] **Address pytest warnings** — 3 test functions in `test_rule_quality.py` return values instead of asserting (PytestReturnNotNoneWarning)

### Code Quality
- [ ] **main.py refactor** — summary block duplicated 4× (one per vendor); doesn't use `audit_engine.run_vendor_audit`; vendors added to `audit_engine` but not wired in CLI
- [ ] **web.py decomposition** — ~1,600 lines; split into blueprints (audit, ssh, schedule, history, settings, export)
- [ ] **mypy strictness** — currently `--no-strict-optional`; tighten incrementally as annotations are added
- [ ] **Python 3.8 compat** — `pyproject.toml` says `>=3.8` but code uses `list[dict]` annotations (3.9+); either drop 3.8 support or use `from __future__ import annotations`

### Security
- [x] **Rate limiting** — Flask-Limiter, memory:// storage, 30/min on audit/diff, 10/min on connect
- [x] **Content Security Policy (CSP) header** — nonce-based, injected via g.csp_nonce before_request
- [x] **Input size limits** — MAX_CONTENT_LENGTH=50MB, per-file 5MB check in routes
- [ ] **SSRF review** — webhook allowlist covers Slack/Teams/Discord; verify no other outbound HTTP calls are user-influenced

### Infrastructure
- [ ] **Docker image hardening** — run as non-root user in Dockerfile; pin base image digest
- [x] **Health endpoint** — GET /health — version, uptime, scheduler status, public
- [ ] **Structured logging** — replace `print()` calls in vendor parsers with Python `logging` module; enables log-level control and SIEM routing

---

## Decisions Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-03-22 | All new features developed in `claude/` branches before merge to main | Keeps main stable; reviewed before merge |
| 2026-03-22 | Test files run as plain Python scripts (no pytest dependency at runtime) | Zero extra deps for contributors; pytest still works for CI |
| 2026-03-22 | defusedxml required everywhere XML is parsed | XXE protection; enforced by xml.etree safety check in Stop hook |
| 2026-03-22 | Pre-merge validation runs 6 checks: ruff, mypy, xml-safety, dep-sync, CLI contracts, pytest | Catches linting, type, security, and functional regressions before push |
| 2026-03-24 | Project renamed from Flintlock to Cashel | Rebranding; package path changed from src/flintlock/ to src/cashel/ |
| 2026-03-24 | Default Fernet key path changed from /data/cashel.key to ~/.config/cashel/cashel.key | /data requires root on macOS; Docker/prod should set CASHEL_KEY_FILE explicitly |
| 2026-03-24 | Auth expansion planned in 4 phases: local → LDAP → OIDC → TACACS+ | Ordered by implementation complexity and enterprise adoption frequency |

---

## Auth Expansion Plan

Full multi-provider authentication to replace the current single API-key model.

### Phase 1 — Local username/password (next up)
- Store users in `~/.config/cashel/users.json` (bcrypt-hashed passwords)
- Add `POST /auth/users` (create), `DELETE /auth/users/<username>`, `GET /auth/users` (list)
- Login form gains a username field alongside password
- Roles: `admin` (full access) and `viewer` (read-only: audit, history, diff, export)
- Migrate: existing API-key sessions remain valid alongside new local auth

### Phase 2 — LDAP/Active Directory
- New dependency: `flask-ldap3-login` or raw `ldap3`
- Settings pane: LDAP server, base DN, bind DN/password, group-to-role mapping
- Bind→search→bind flow; TLS/STARTTLS required
- Group mapping: configure AD groups → Cashel admin/viewer roles

### Phase 3 — OIDC (Okta, Azure AD, Google Workspace)
- New dependency: `authlib` (OAuth2/OIDC client)
- Settings: OIDC discovery URL, client_id, client_secret, role claim
- Callback route: `GET /auth/oidc/callback`
- Token stored in session; refresh handled transparently
- Supports Okta, Azure AD, Google Workspace, Keycloak out of the box

### Phase 4 — TACACS+
- New dependency: `tacacs-plus` (or socket-level implementation)
- Settings: TACACS+ server host/port, shared secret, service/protocol
- Auth-only flow (no accounting required for MVP)
- Fallback: if TACACS+ unreachable, fall through to local auth

### Implementation Notes
- Auth provider selection stored in settings: `auth_provider: "local" | "ldap" | "oidc" | "tacacs"`
- API key auth (X-API-Key header) always works in parallel for CI/CD regardless of provider
- New blueprint: `src/cashel/blueprints/auth.py` (all /auth/* routes)
- Session handling unchanged — all providers issue the same Flask session cookie
- Provider switching: warn user that sessions will be invalidated
