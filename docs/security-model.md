# Security Model

Cashel is self-hosted software that processes sensitive firewall and network-control-plane data. Treat the application, database, reports, uploads, and exports as sensitive infrastructure records.

## Sensitive Data

Cashel may handle:

- Uploaded firewall configurations
- Live SSH hostnames, usernames, passwords, and private keys
- Scheduled SSH credentials
- Audit findings that expose topology, policy gaps, and security weaknesses
- Generated PDFs, evidence bundles, CSV, JSON, and SARIF files
- API keys, local user records, and auth events
- Webhook URLs, HMAC secrets, SMTP credentials, and syslog targets

## Authentication and Authorization

Current behavior:

- Local users are created during first-run setup.
- Local sessions and API keys are supported.
- Roles are admin, auditor, and viewer style access patterns.
- Local auth can be disabled for simple deployments.

Target behavior:

- `CASHEL_AUTH_MODE=local|oidc`
- Local auth remains bootstrap/fallback.
- OIDC is the first SSO target.
- SAML is future roadmap.
- Role mapping comes from IdP claims/groups:
  - `CASHEL_OIDC_ADMIN_GROUPS`
  - `CASHEL_OIDC_AUDITOR_GROUPS`
  - `CASHEL_OIDC_VIEWER_GROUPS`

OIDC deployment requirements:

- HTTPS is required.
- Set `CASHEL_SECURE_COOKIES=true`.
- Configure exact callback URL: `CASHEL_OIDC_REDIRECT_URI`.
- Preserve proxy headers, especially `Host` and `X-Forwarded-Proto`.
- Restrict local fallback accounts and document break-glass access.

## Secrets

`CASHEL_SECRET` signs Flask sessions and CSRF tokens. It must be long, random, and stable across restarts. If it changes, active sessions are invalidated.

`CASHEL_KEY_FILE` stores the Fernet key used for encrypted secrets such as scheduled SSH passwords and API-key material. It must persist across restarts and be backed up with the SQLite database. If it is lost, encrypted stored secrets cannot be decrypted.

Never commit:

- `CASHEL_SECRET`
- `CASHEL_KEY_FILE`
- SQLite databases
- Uploaded configs
- Generated reports
- License files
- Webhook, SMTP, or OIDC secrets

## Uploaded Configs and Reports

Firewall configs and generated artifacts can contain:

- Internal IP ranges
- Hostnames
- Interface names
- VPN peers
- Access-control policy
- Security gaps
- Change history and evidence

Use persistent storage with restricted filesystem permissions. Apply retention policies for uploads, reports, evidence bundles, and audit history.

## Live SSH and Scheduled Credentials

Live SSH one-time credentials should not be stored. Scheduled SSH credentials are stored encrypted and depend on `CASHEL_KEY_FILE`.

Recommendations:

- Prefer least-privilege read-only device accounts.
- Use strict SSH host-key policy in production.
- Set command timeouts.
- Limit scheduled audit concurrency.
- Rotate credentials and remove old schedules.
- Back up DB and key file together.

## CSRF, Cookies, and Rate Limiting

Cashel uses Flask-WTF CSRF protections for browser workflows and rate limiting on sensitive routes. Production deployments should:

- Serve only over HTTPS.
- Set `CASHEL_SECURE_COOKIES=true`.
- Keep `CASHEL_SECRET` stable and private.
- Forward real client IPs from the reverse proxy.
- Avoid exposing the app directly without TLS.

## XML Parsing Safety

XML inputs use safe parsing patterns and CI checks prevent use of unsafe `xml.etree` imports under `src/cashel`. Keep using `defusedxml` for untrusted XML configs.

## Webhooks and Syslog

Outbound integrations can leak sensitive audit metadata. Webhook SSRF controls and allowlists reduce risk, but egress should also be controlled at the network layer.

Recommendations:

- Allowlist only known webhook hostnames.
- Use HMAC secrets for generic webhooks.
- Avoid sending full findings to broad external channels unless approved.
- Treat syslog destinations as sensitive egress.
- Monitor webhook delivery failures and unexpected destinations.

## Playwright/PDF Runtime

PDF rendering starts Chromium through Playwright. This is useful but heavier than plain JSON/CSV export.

Recommendations:

- Keep Playwright browsers installed in a known read-only path for containers.
- Set `CASHEL_PDF_TIMEOUT_MS`.
- Avoid unbounded concurrent PDF generation.
- Treat PDF files as sensitive artifacts.
- Keep browser dependencies patched through regular image rebuilds.

## Demo Mode

Demo mode is intended for hosted demos only. It may bypass licensing and disable persistent write operations. Do not use demo mode as a production security boundary.

## Audit and Retention Expectations

Cashel records audits, auth events, activity logs, schedule runs, and failures. Operators should define:

- How long audit history is retained
- How reports and bundles are deleted
- How SQLite backups are protected
- Who can export evidence
- Who can delete archived data

