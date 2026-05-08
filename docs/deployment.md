# Cashel — Production Deployment Guide

This guide covers deploying Cashel behind a TLS-terminating reverse proxy. The app is a standard WSGI service running under Gunicorn — any proxy that can forward HTTP/1.1 will work.

> **Homelab users:** `docker compose up` works out of the box with no proxy, no RBAC, and no TLS. Everything below is additive — none of it is mandatory.

---

## Contents

- [Prerequisites](#prerequisites)
- [Environment variables](#environment-variables)
- [Docker Compose with nginx (primary)](#docker-compose-with-nginx)
- [Render Docker deployment](#render-docker-deployment)
- [Docker Compose with Caddy (alternative)](#docker-compose-with-caddy)
- [First-run admin setup](#first-run-admin-setup)
- [Persistent volumes](#persistent-volumes)
- [Upgrade procedure](#upgrade-procedure)
- [Health check](#health-check)
- [Hardening checklist](#hardening-checklist)

---

## Prerequisites

- Docker ≥ 24 and Docker Compose v2 (`docker compose`)
- A domain name with DNS pointed at your server (for TLS)
- Ports 80 and 443 open on the host firewall

Cashel generates audit reports, remediation reports, and evidence bundle covers
from HTML/CSS using Playwright Chromium. The official Docker image installs
Chromium's headless shell during build into `/ms-playwright`, which is readable
by the non-root runtime user. First builds can take longer while the browser is
downloaded. For non-Docker deployments, install Python dependencies and then run:

```bash
python -m playwright install chromium
```

Set `CASHEL_PDF_PAGE_FORMAT` to override the default `Letter` page size, or
`CASHEL_PDF_TIMEOUT_MS` to tune the render timeout.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CASHEL_SECRET` | **Yes** | — | Flask `SECRET_KEY`. Generate with `openssl rand -hex 32`. Sessions survive restarts only when this is set. |
| `CASHEL_KEY_FILE` | **Yes** | `~/.config/cashel/cashel.key` | Path to the Fernet encryption key used to encrypt stored SSH passwords and API keys. Must persist across restarts. |
| `CASHEL_DB` | No | `/data/cashel.db` | SQLite database path. |
| `UPLOAD_FOLDER` | No | `/tmp/cashel_uploads` | Temporary uploaded config storage. Use `/data/uploads` in Docker/Render so the path is writable. |
| `REPORTS_FOLDER` | No | `/tmp/cashel_reports` | Generated report storage. Use `/data/reports` in Docker/Render. |
| `LICENSE_PATH` | No | platform config path | Legacy compliance access file path. This gate is deprecated and under review; use `/data/.cashel_license` only if you must preserve current compatibility behavior. |
| `PLAYWRIGHT_BROWSERS_PATH` | No | Playwright default | Browser install path. Docker images set this to `/ms-playwright` for non-root PDF rendering. |
| `CASHEL_SECURE_COOKIES` | No | `false` | Set to `true` when serving over HTTPS. Marks session cookie with `Secure` flag. |
| `WEB_CONCURRENCY` | No | `1` | Gunicorn worker count. Keep at `1` on single-CPU hosts to avoid OOM. |
| `PORT` | No | `5000` | Internal port Gunicorn binds to (do not expose directly). |

Generate required secrets:

```bash
# Flask session key
openssl rand -hex 32

# Fernet encryption key (base64-encoded 32-byte key)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Docker Compose with nginx

This is the recommended production setup. nginx handles TLS, and Cashel runs on an internal network not exposed to the internet.

### Directory layout

```
cashel-prod/
  docker-compose.yml
  nginx/
    nginx.conf
  data/           # SQLite DB (created on first run, must persist)
  keys/           # Fernet key file (must persist)
```

### `docker-compose.yml`

```yaml
services:
  cashel:
    image: ghcr.io/shamrock13/cashel:latest
    restart: unless-stopped
    environment:
      CASHEL_SECRET: "${CASHEL_SECRET}"
      CASHEL_KEY_FILE: /keys/cashel.key
      CASHEL_DB: /data/cashel.db
      CASHEL_SECURE_COOKIES: "true"
      WEB_CONCURRENCY: "1"
    volumes:
      - ./data:/data
      - ./keys:/keys
    networks:
      - internal
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  nginx:
    image: nginx:1.27-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro   # certbot-managed certs
    networks:
      - internal
    depends_on:
      - cashel

networks:
  internal:
    driver: bridge
```

### `nginx/nginx.conf`

```nginx
events {}

http {
    # Redirect HTTP → HTTPS
    server {
        listen 80;
        server_name cashel.example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        server_name cashel.example.com;

        ssl_certificate     /etc/letsencrypt/live/cashel.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/cashel.example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        # Pass real client IP to Cashel (needed for rate limiting and audit logs)
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header Host            $host;

        location / {
            proxy_pass         http://cashel:5000;
            proxy_http_version 1.1;
            proxy_read_timeout 120s;
            client_max_body_size 50M;
        }
    }
}
```

Obtain a certificate with Certbot before starting nginx:

```bash
certbot certonly --standalone -d cashel.example.com
```

### Start

```bash
# Set secrets in the shell (or use a .env file)
export CASHEL_SECRET="$(openssl rand -hex 32)"

# Create the Fernet key on first deploy only — never regenerate it afterwards
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" \
  > keys/cashel.key

docker compose up -d
```

---

## Render Docker deployment

For Render Docker services, add a persistent disk mounted at `/data`. Without a
persistent `/data` mount, the setup page, audit history, schedules, legacy
compliance access state, reports, uploads, and encryption key can reset when
Render replaces the container.

Recommended Render environment:

```bash
CASHEL_SECRET=<strong-random-secret>
PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
UPLOAD_FOLDER=/data/uploads
REPORTS_FOLDER=/data/reports
LICENSE_PATH=/data/.cashel_license  # legacy compatibility only
CASHEL_KEY_FILE=/data/cashel.key
CASHEL_DB=/data/cashel.db
WEB_CONCURRENCY=1
```

The Docker build installs Playwright Chromium headless shell with system
dependencies. The first build can be slow because the browser is downloaded
during image creation, but runtime PDF generation should use the shared
`/ms-playwright` browser path as the non-root `cashel` user.

---

## Docker Compose with Caddy

Caddy handles TLS automatically via ACME/Let's Encrypt — no manual certificate management.

```yaml
services:
  cashel:
    image: ghcr.io/shamrock13/cashel:latest
    restart: unless-stopped
    environment:
      CASHEL_SECRET: "${CASHEL_SECRET}"
      CASHEL_KEY_FILE: /keys/cashel.key
      CASHEL_DB: /data/cashel.db
      CASHEL_SECURE_COOKIES: "true"
    volumes:
      - ./data:/data
      - ./keys:/keys
    networks:
      - internal

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - internal
    depends_on:
      - cashel

networks:
  internal:
    driver: bridge

volumes:
  caddy_data:
  caddy_config:
```

**`Caddyfile`:**

```
cashel.example.com {
    reverse_proxy cashel:5000 {
        header_up X-Forwarded-For {remote_host}
    }
}
```

Caddy fetches and renews the certificate automatically on first request.

---

## First-Run Admin Setup

On first boot with an empty database, Cashel redirects all requests to `/setup`. Open a browser and navigate to your domain — you'll be prompted to create the first admin account.

After setup, auth is enabled automatically. Store the admin credentials somewhere safe — there is no password recovery route (you can reset via the admin users API if you have another admin account).

---

## Persistent Volumes

Two paths **must** survive container restarts and re-deploys:

| Path | Contents | Risk if lost |
|---|---|---|
| `/data/cashel.db` | All audits, history, users, schedules, settings | **All data lost** |
| `/keys/cashel.key` (or `CASHEL_KEY_FILE`) | Fernet encryption key | Encrypted SSH passwords and API keys become unreadable |

Back up both. The database is a single SQLite file — a simple `cp` or `rsync` is sufficient.

```bash
# Quick backup
cp data/cashel.db "backups/cashel_$(date +%Y%m%d).db"
```

---

## Upgrade Procedure

1. Pull the new image:
   ```bash
   docker compose pull cashel
   ```
2. Restart the container (SQLite schema migrations run automatically on startup):
   ```bash
   docker compose up -d cashel
   ```
3. Verify health:
   ```bash
   curl https://cashel.example.com/health
   ```

No manual database migrations are required. The schema uses `CREATE TABLE IF NOT EXISTS` — new tables and columns are added automatically on startup.

---

## Health Check

`GET /health` is always public (no authentication required).

```json
{
  "ok": true,
  "version": "1.4.0",
  "uptime_seconds": 3600,
  "scheduler_running": true,
  "last_audit_at": "2026-04-10T14:32:00Z"
}
```

Use this endpoint for container health checks, load balancer probes, and uptime monitoring.

---

## Hardening Checklist

- [ ] `CASHEL_SECRET` is set and not the default
- [ ] `CASHEL_KEY_FILE` points to a persistent, backed-up location
- [ ] `CASHEL_SECURE_COOKIES=true` when behind HTTPS
- [ ] TLS 1.2+ only on the proxy (TLS 1.3 preferred)
- [ ] `/data` volume is backed up regularly
- [ ] Fernet key (`cashel.key`) is backed up separately from the database
- [ ] Admin account uses a strong password (≥ 12 characters, enforced)
- [ ] `WEB_CONCURRENCY=1` on single-CPU hosts (prevents OOM under Gunicorn)
- [ ] Port 5000 is not exposed directly — proxy handles all inbound traffic
- [ ] HSTS header enabled at the proxy layer (`Strict-Transport-Security: max-age=31536000`)
