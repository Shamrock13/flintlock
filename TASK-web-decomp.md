# TASK: web.py Blueprint Decomposition

**Status:** 🔵 Active
**Branch:** `cld/web-decomp` (cut from `staging`)
**Assigned to:** Builder
**Architect sign-off required before merge:** Yes

---

## Context

`web.py` is ~2,000 lines and must be decomposed into Flask blueprints before the auth expansion (Phase 1 local auth) begins. Adding a new auth blueprint, new middleware, and new settings routes against a 2,000-line monolith creates unacceptable merge complexity.

This task is a **pure structural refactor** — zero behavior change. Every route responds identically after completion.

---

## Target Structure

```
src/cashel/
  web.py                   # App factory only (~150 lines)
                           # Config, limiter, csrf, middleware wiring, blueprint registration, main()
  _vendor_helpers.py       # detect_vendor(), validate_vendor_format(), extract_hostname()
                           # Pure functions — no Flask dependency
  _helpers.py              # _err() and any other shared non-route helpers
  blueprints/
    __init__.py            # Empty or minimal
    auth.py                # /login GET, /login POST, /logout
    audit.py               # /audit, /bulk_audit, /diff, /connect
    history.py             # /archive/*, /activity/*
    schedules.py           # /schedules/*
    settings_bp.py         # /settings/*, /license/*  (named settings_bp — not settings.py, which already exists)
    reports.py             # /reports/*
    api_v1.py              # /api/v1/*  (existing api_bp renamed/moved)
```

---

## Route → Blueprint Mapping

| Current route(s) | Blueprint file | Notes |
|---|---|---|
| `/login` GET/POST, `/logout` | `auth.py` | Seed location for future LDAP/OIDC callbacks |
| `/audit`, `/bulk_audit`, `/diff`, `/connect` | `audit.py` | Imports from `_vendor_helpers.py` |
| `/archive/*`, `/activity/*` | `history.py` | |
| `/schedules/*` | `schedules.py` | |
| `/settings`, `/settings/*`, `/license/*` | `settings_bp.py` | |
| `/reports/*` | `reports.py` | |
| `/api/v1/*` | `api_v1.py` | Already a Blueprint internally; mostly a file move |
| `/`, `/health` | `web.py` (keep inline) | Too small to warrant a blueprint |

---

## Shared State Strategy

- `limiter` and `csrf` are defined in `web.py`; each blueprint imports them:
  ```python
  from cashel.web import limiter, csrf
  ```
- `get_settings()` is already a standalone import from `settings.py` — no change.
- `_require_auth` stays in `web.py` as an `app.before_request` hook — fires globally across all blueprints without re-registration.
- `DEMO_MODE` constant imported from `license.py` in each blueprint that needs it.
- `_err()` helper moves to `_helpers.py`, imported by any blueprint that uses it.

---

## Migration Order (Lowest Risk First)

Execute these steps in order. Run `pytest tests/ -v` after each step before proceeding.

1. **Extract `_vendor_helpers.py`**
   - Move: `detect_vendor()`, `validate_vendor_format()`, `extract_hostname()`
   - These are pure functions with no Flask dependency — easiest to verify in isolation
   - Update all imports in `web.py` and anywhere else they're referenced

2. **Extract `_helpers.py`**
   - Move: `_err()` and any other shared non-route utility functions
   - Update all callers in `web.py`

3. **`blueprints/reports.py`**
   - Read-only routes, no auth complexity — good warm-up
   - Register blueprint in `web.py` app factory

4. **`blueprints/history.py`**
   - Routes: `/archive/*`, `/activity/*`
   - Imports: `archive.py`, `activity_log.py`

5. **`blueprints/schedules.py`**
   - Routes: `/schedules/*`
   - Imports: `schedule_store.py`, `scheduler_runner.py`

6. **`blueprints/settings_bp.py`**
   - Routes: `/settings`, `/settings/*`, `/license/*`
   - Imports: `settings.py`, `crypto.py`, `license.py`
   - Note: file named `settings_bp.py` to avoid shadowing `settings.py` module

7. **`blueprints/api_v1.py`**
   - Already a Blueprint internally; this is mostly a file move + import update
   - CSRF-exempt flag must be preserved

8. **`blueprints/audit.py`**
   - Largest chunk; depends on `_vendor_helpers.py` being extracted first (step 1)
   - Routes: `/audit`, `/bulk_audit`, `/diff`, `/connect`

9. **`blueprints/auth.py`**
   - Last — becomes the future home for Phase 1 local auth routes
   - Routes: `/login` GET/POST, `/logout`

10. **Slim `web.py` to app factory**
    - After all blueprints extracted, `web.py` should contain only:
      - Flask app creation and config
      - `limiter`, `csrf` initialization
      - `_require_auth` before_request hook
      - Blueprint registration
      - `main()` entry point
      - `/` and `/health` routes (inline, too small for a blueprint)

---

## Flags (Escalate to Architect if Unsure)

- **Circular imports**: If any blueprint needs something from `web.py` beyond `limiter`/`csrf`, flag it — don't paper over it with a workaround.
- **`g` and `session` usage**: These are Flask request-context globals. They're safe to use in blueprints without import — just `from flask import g, session`. Verify each usage after move.
- **`@app.route` vs `@blueprint.route`**: Every route decorator must be updated. A missed `@app.route` will silently not register under the blueprint's URL prefix (there is no prefix — blueprints here use empty `url_prefix=""`).
- **`url_for()` calls in templates**: After extracting blueprints, `url_for("login")` becomes `url_for("auth.login")`. Update all `url_for()` calls in templates and JS after `auth.py` is extracted.
- **`_AUTH_EXEMPT_ENDPOINTS` set in `_require_auth`**: Uses endpoint names. After blueprints, endpoint names become `blueprint_name.function_name` (e.g., `"auth.login"`). Update this set when extracting `auth.py`.

---

## Acceptance Criteria (Definition of Done)

- [ ] All existing routes respond identically — same URLs, same response shapes, same status codes
- [ ] `web.py` is below 200 lines
- [ ] `blueprints/` directory exists with all 7 blueprint files
- [ ] `_vendor_helpers.py` and `_helpers.py` exist and are imported correctly
- [ ] `pytest tests/ -v` passes with no changes to any test file
- [ ] `ruff check src/ tests/` passes clean
- [ ] No `url_for()` calls reference stale endpoint names
- [ ] `SESSION-CHECKPOINT.md` updated at completion

---

## Branch and PR

```bash
# Cut branch
git checkout -b cld/web-decomp origin/staging

# After each step, verify tests pass before continuing
python -m pytest tests/ -v

# When done
git push origin cld/web-decomp
# PR → staging (not main)
```
