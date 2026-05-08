# Operations

This runbook covers day-to-day operations for a self-hosted Cashel deployment.

## Startup

Required before production use:

- `CASHEL_SECRET` set
- `CASHEL_KEY_FILE` present and persistent
- SQLite path on persistent storage
- Upload/report directories writable
- TLS reverse proxy configured
- Secure cookies enabled over HTTPS

Health endpoint:

```bash
curl -f http://localhost:5000/health
```

## Backups

Back up together:

- SQLite database
- `CASHEL_KEY_FILE`
- Reports/evidence bundles if they are compliance records

Test restore regularly. A restored database without the matching key file may not be able to decrypt stored scheduled credentials.

## Upgrades

Recommended process:

1. Stop new scheduled jobs.
2. Back up DB and key file.
3. Pull/build the new image.
4. Start one instance.
5. Check `/health`.
6. Run a small known-good audit.
7. Re-enable scheduled jobs.

## Retention

Define explicit retention for:

- Audit history
- Activity/auth logs
- Uploaded configs
- Generated reports
- Evidence bundles
- Webhook delivery records

For sensitive customer/MSP environments, shorter report retention plus external controlled evidence storage may be preferable.

## Scheduler Operations

Until scheduler leader election/locking exists:

- Run a single scheduler process.
- Keep `WEB_CONCURRENCY=1` unless you are certain only one worker runs the scheduler.
- Set device command timeouts.
- Use bounded retries and backoff.
- Monitor repeated authentication failures.

## Incident Response

If secrets may be exposed:

1. Rotate local passwords/API keys.
2. Rotate webhook and SMTP secrets.
3. Rotate OIDC client secret after SSO exists.
4. Decide whether `CASHEL_SECRET` must be rotated and accept session invalidation.
5. Do not rotate `CASHEL_KEY_FILE` without a decrypt/re-encrypt migration.

If reports or configs leak:

1. Treat them as sensitive network architecture disclosure.
2. Identify affected devices/customers.
3. Review generated evidence bundles and exports.
4. Rotate device credentials if configs include secrets.
5. Remove artifacts from storage and backups according to policy.

## Monitoring

Monitor:

- Failed logins and invalid API-key events
- Audit failures
- Scheduled run failures
- PDF generation failures/timeouts
- Webhook/syslog delivery failures
- Disk usage for reports and uploads
- SQLite backup success

