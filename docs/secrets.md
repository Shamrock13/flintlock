# Secrets

Cashel has a small number of secrets that determine whether sessions and encrypted stored credentials survive restarts.

## Required Production Secrets

| Secret | Purpose | Requirement |
|---|---|---|
| `CASHEL_SECRET` | Flask session and CSRF signing | Long random value, stable across restarts |
| `CASHEL_KEY_FILE` | Fernet key for encrypted stored secrets | Persistent file, backed up with SQLite |
| OIDC client secret | Future SSO token exchange | Store in environment/secret manager, not repo |
| SMTP password | Email alerts | Stored encrypted when saved through Cashel |
| Webhook HMAC secrets | Generic webhook signing | Stored encrypted where supported |
| Scheduled SSH passwords | Recurring device pulls | Stored encrypted with `CASHEL_KEY_FILE` |

## Generating Secrets

```bash
openssl rand -hex 32
```

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Write the Fernet key to the configured `CASHEL_KEY_FILE` path once. Do not regenerate it unless you intentionally want to invalidate encrypted stored secrets.

## Backup Rule

Back up these together:

- SQLite database
- `CASHEL_KEY_FILE`
- Reports if you need historical evidence artifacts

If the database is restored without the matching Fernet key, scheduled SSH credentials and other encrypted values may be unrecoverable.

## Rotation

`CASHEL_SECRET` rotation invalidates sessions. Rotate during a maintenance window.

`CASHEL_KEY_FILE` rotation requires a migration plan that decrypts existing values with the old key and re-encrypts with the new key. Do not replace the file blindly.

## What Not To Commit

Never commit:

- `.env`
- SQLite files
- key files
- license files
- uploaded configs
- generated PDFs
- evidence bundles
- webhook URLs or secrets
- OIDC secrets
- real firewall configs

## Legacy License State

`LICENSE_PATH` is a legacy compliance-gating artifact. It may still affect current compliance behavior, but it is deprecated and under review. Do not build new deployment workflows around a paid license file.

