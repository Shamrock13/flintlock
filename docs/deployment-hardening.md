# Deployment Hardening

This guide summarizes production hardening expectations for self-hosted Cashel deployments.

## Baseline

- Run behind a TLS-terminating reverse proxy.
- Do not expose Gunicorn directly to the internet.
- Set `CASHEL_SECRET` to a strong stable secret.
- Set and persist `CASHEL_KEY_FILE`.
- Use persistent storage for SQLite, reports, uploads, and key material.
- Set `CASHEL_SECURE_COOKIES=true` when served over HTTPS.
- Keep `WEB_CONCURRENCY=1` unless scheduler leadership is controlled.

## Reverse Proxy

Forward:

- `Host`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Real-IP`

Recommended proxy controls:

- HTTPS only
- HSTS at the proxy
- Request body limit aligned with max upload policy
- Read timeout long enough for bounded audits and PDFs
- Access logs with sensitive-query redaction where possible

## OIDC/SSO Readiness

Planned environment variables:

```bash
CASHEL_AUTH_MODE=local|oidc
CASHEL_OIDC_ISSUER=https://idp.example.com/
CASHEL_OIDC_CLIENT_ID=cashel
CASHEL_OIDC_CLIENT_SECRET=replace-me
CASHEL_OIDC_REDIRECT_URI=https://cashel.example.com/auth/oidc/callback
CASHEL_OIDC_ALLOWED_DOMAINS=example.com
CASHEL_OIDC_ADMIN_GROUPS=Cashel Admins
CASHEL_OIDC_AUDITOR_GROUPS=Network Engineers
CASHEL_OIDC_VIEWER_GROUPS=Security Viewers
```

Provider targets:

- Microsoft Entra ID
- Google Workspace
- Okta
- Authentik
- Keycloak

SAML is future roadmap. Keep local auth for bootstrap/fallback, and restrict fallback admin credentials.

## Containers

Recommended environment:

```bash
CASHEL_SECRET=<strong-random-secret>
CASHEL_KEY_FILE=/data/cashel.key
CASHEL_DB=/data/cashel.db
UPLOAD_FOLDER=/data/uploads
REPORTS_FOLDER=/data/reports
PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
CASHEL_SECURE_COOKIES=true
WEB_CONCURRENCY=1
```

Mount persistent storage at `/data`. Back up `/data/cashel.db` and `/data/cashel.key` together.

## File and Report Retention

Suggested defaults:

- Upload temp files: delete immediately after processing where possible.
- Reports and evidence bundles: 30-90 days unless client requirements say otherwise.
- Activity and auth logs: 90-180 days for small deployments.
- Backups: encrypted at rest and tested for restore.

## Network Egress

Restrict outbound access for:

- Webhooks
- Slack/Teams
- SMTP
- Syslog
- OIDC discovery/token/userinfo endpoints after SSO is implemented

Use allowlists and monitor unexpected destinations.

## Scheduler Hardening

Until leader election or scheduler locking exists:

- Run a single scheduler process.
- Avoid multiple Gunicorn workers that each start schedulers.
- Use explicit SSH timeouts.
- Limit concurrent scheduled audits.
- Add retries with backoff instead of tight retry loops.

## Demo Mode

`CASHEL_DEMO_MODE=true` is for hosted demos. Do not use it for production.

