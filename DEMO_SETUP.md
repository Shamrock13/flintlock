# Cashel Demo — Setup & Deployment Guide

Internal reference. Not for public distribution.

---

## Overview

The demo is a separate **private GitHub repo** (`cashel-demo`) that contains
a copy of the public Cashel source plus demo-specific additions:

- `CASHEL_DEMO_MODE=true` env flag — bypasses license, disables all writes
- `src/cashel/demo_samples/` — four bundled sample configs (ASA, PA, FortiGate, AWS)
- Sample config picker UI baked into `index.html`
- `api/index.py` — Vercel WSGI entrypoint
- `vercel.json` — Vercel routing and build config
- `.github/workflows/demo-deploy.yml` — optional CI to trigger Vercel redeploy on push

---

## 1. Private Repo Setup

The private `cashel-demo` repo on GitHub is the source of truth for the demo.
It is a clone of the public repo with demo additions pushed on top.

To sync future upstream changes from the public repo into the demo:

```bash
# From your local cashel-demo checkout
git fetch upstream
git merge upstream/main
git push origin main   # Vercel auto-deploys on push
```

Where `upstream` points to `https://github.com/Shamrock13/cashel.git`.

---

## 2. Vercel Setup

### Connect the private repo

1. Go to [vercel.com](https://vercel.com) → Add New Project
2. Import `Shamrock13/cashel-demo` (private repo — Vercel has GitHub access)
3. Framework Preset: **Other**
4. Root Directory: leave as `/` (default)
5. Do NOT override build command or output directory — `vercel.json` handles it

### Set environment variables

In Vercel → Project → Settings → Environment Variables, add:

| Name | Value | Environment |
|---|---|---|
| `CASHEL_SECRET` | Any long random string (e.g. `openssl rand -hex 32`) | Production |
| `CASHEL_DEMO_MODE` | `true` | Production |
| `CASHEL_SECURE_COOKIES` | `true` | Production |

`CASHEL_DEMO_MODE` is already set in `vercel.json` but setting it here too
makes it explicit and visible in the dashboard.

### Deploy

Vercel auto-deploys on every push to `main`. For the first deploy, either
push a commit or click "Deploy" in the Vercel dashboard.

Your demo will be live at `cashel-demo.vercel.app` (or your custom domain).

---

## 3. Point Cloudflare at Vercel (when ready)

1. In Vercel → Project → Settings → Domains → Add your subdomain (e.g. `demo.cashel.app`)
2. Vercel will give you a CNAME value to add in Cloudflare
3. In Cloudflare DNS, add:
   - Type: `CNAME`
   - Name: `demo`
   - Target: `cname.vercel-dns.com`
   - Proxy: **Enabled** (orange cloud)
4. Vercel provisions TLS automatically

---

## 4. What CASHEL_DEMO_MODE does

When `CASHEL_DEMO_MODE=true`:

| Behaviour | Normal | Demo |
|---|---|---|
| License check | Reads `~/.cashel_license` | Always returns `True` |
| Auth required | Configurable | Disabled (no login page) |
| Audit archive | Written to disk | Skipped |
| Activity log | Written to disk | Skipped |
| Settings save | Written to disk | Returns 403 |
| SSH connect | Available | Available (still works) |
| `/demo/configs` | 404 | Returns sample config list |
| `/demo/load/<id>` | 404 | Streams sample config file |

---

## 5. Adding or updating sample configs

Sample configs live in `src/cashel/demo_samples/`. They are served by
`/demo/load/<id>` and described in the `_DEMO_CONFIGS` dict in `web.py`.

To add a new one:
1. Drop the file into `src/cashel/demo_samples/`
2. Add an entry to `_DEMO_CONFIGS` in `web.py`
3. Push to `main` — Vercel redeploys automatically

---

## 6. Local testing

```bash
# Install Vercel CLI if needed
npm i -g vercel

# Run locally with Vercel's dev server (respects vercel.json)
vercel dev

# Or just run Flask directly
CASHEL_DEMO_MODE=true CASHEL_SECRET=dev-secret python -m flask \
  --app src/cashel/web.py run --debug
```
