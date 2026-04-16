# TASK: Multi-User Auth Phase 1 — Local Username/Password

**Status:** 🔵 Active
**Branch:** `cld/auth-phase1` (cut from `staging`)
**Assigned to:** Builder
**Architect sign-off required before merge:** Yes

---

## Context

Cashel currently uses a single shared API key for all access. This task replaces that with a proper multi-user system: local username/password login for the browser, per-user API keys for programmatic/CI access, and three roles (admin, auditor, viewer).

The `blueprints/auth.py` file already exists as the seed — all new auth routes go there.
The `db.py` module already exists — add the `users` table to the schema there.
Settings (`settings.py`) stays as JSON — user credentials live in SQLite only.

---

## Role Permissions

| Capability | Admin | Auditor | Viewer |
|---|---|---|---|
| Run audits (file, SSH, bulk) | ✅ | ✅ | ❌ |
| View audit history / activity | ✅ | ✅ | ✅ |
| Diff / compare configs | ✅ | ✅ | ✅ |
| Export (JSON, CSV, SARIF, PDF) | ✅ | ✅ | ✅ |
| Manage schedules | ✅ | ✅ | ❌ |
| View schedules | ✅ | ✅ | ✅ |
| Manage settings | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| Generate/revoke own API key | ✅ | ✅ | ✅ |

---

## Database: `users` Table

Add to `db.py` `init_db()` schema:

```sql
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,           -- uuid4().hex[:12]
    username     TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,             -- werkzeug generate_password_hash()
    role         TEXT NOT NULL DEFAULT 'viewer',  -- admin | auditor | viewer
    api_key_enc  TEXT NOT NULL DEFAULT '',   -- Fernet-encrypted per-user API key
    created_at   TEXT NOT NULL
);
```

Also add a unique index:
```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
```

---

## New Module: `user_store.py`

Create `src/cashel/user_store.py`. This module owns all user CRUD and credential operations. Nothing in `blueprints/auth.py` touches the DB directly — it calls `user_store`.

```python
# Public API

def has_users() -> bool
    # Returns True if any row exists in users table

def create_user(username: str, password: str, role: str = "viewer") -> dict
    # Validates: username 3–64 chars alphanumeric+underscore+hyphen
    # Validates: password >= 12 chars
    # Validates: role in {"admin", "auditor", "viewer"}
    # Hashes password with werkzeug.security.generate_password_hash()
    # Raises UserValidationError on bad input
    # Returns user dict (no password_hash, no api_key_enc)

def get_user_by_username(username: str) -> dict | None
    # Case-insensitive lookup; returns user dict or None

def get_user_by_api_key(plaintext_key: str) -> dict | None
    # Decrypts all api_key_enc values and compares with secrets.compare_digest()
    # Returns user dict (with role) or None
    # Note: use indexed lookup pattern — decrypt on read, not store plaintext

def check_password(username: str, plaintext: str) -> dict | None
    # Looks up user, calls check_password_hash(); returns user dict or None

def list_users() -> list
    # Returns list of user dicts (no password_hash, no api_key_enc)
    # Includes: id, username, role, has_api_key (bool), created_at

def delete_user(user_id: str) -> bool
    # Cannot delete the last admin — raises UserValidationError

def change_password(user_id: str, new_password: str) -> None
    # Validates length >= 12; re-hashes and updates

def generate_api_key(user_id: str) -> str
    # Generates secrets.token_urlsafe(32), prefixes "csh_"
    # Encrypts with crypto.encrypt(), stores as api_key_enc
    # Returns plaintext key (shown once — caller must display to user)

def revoke_api_key(user_id: str) -> None
    # Sets api_key_enc = '' for user

class UserValidationError(ValueError):
    pass
```

---

## `_helpers.py` Changes

Replace the current single-key `_require_auth_impl` with multi-user awareness.

**Update `_require_auth_impl`:**

```python
_AUTH_EXEMPT_ENDPOINTS = {
    "auth.login", "auth.login_post", "auth.logout",
    "auth.setup", "auth.setup_post",
    "health", "static"
}

def _require_auth_impl(demo_mode: bool):
    if demo_mode:
        g.auth_method = "demo"
        g.current_user = None
        return

    settings = get_settings()

    # First-run: no users exist → redirect to /setup
    if request.endpoint not in _AUTH_EXEMPT_ENDPOINTS:
        from .user_store import has_users
        if not has_users():
            return redirect(url_for("auth.setup"))

    if not settings.get("auth_enabled"):
        return

    if request.endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return

    # API key auth (X-API-Key header or ?api_key= param) — CI/CLI
    api_key_header = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key_header:
        from .user_store import get_user_by_api_key
        user = get_user_by_api_key(api_key_header)
        if user:
            g.auth_method = "api_key"
            g.current_user = user
            return
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "data": None, "error": "Invalid API key."}), 401
        return jsonify({"error": "Invalid API key."}), 401

    # Session auth (browser)
    if session.get("authenticated") and session.get("user_id"):
        lifetime = settings.get("session_lifetime_minutes", 480)
        if time.time() - session.get("last_seen", 0) < lifetime * 60:
            session["last_seen"] = time.time()
            g.auth_method = "session"
            # Lazy-load user into g for role checks
            from .user_store import get_user_by_id
            g.current_user = get_user_by_id(session["user_id"])
            return
        session.clear()

    # Not authenticated
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "data": None, "error": "Authentication required."}), 401
    next_url = request.url if request.method == "GET" else None
    return redirect(url_for("auth.login", next=next_url))
```

**Add `_require_role` helper** (used as decorator in blueprints):

```python
def _require_role(*allowed_roles):
    """Decorator: abort 403 if g.current_user's role is not in allowed_roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user and user.get("role") not in allowed_roles:
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Insufficient permissions."}), 403
                return jsonify({"error": "Insufficient permissions."}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
```

Also add `get_user_by_id` to `user_store.py`:
```python
def get_user_by_id(user_id: str) -> dict | None
```

---

## `blueprints/auth.py` Changes

Replace the stub with full auth routes:

```
GET  /login          → login()         — show login form (redirect to index if already authed)
POST /login          → login_post()    — validate username+password; lockout after 5 failures
POST /logout         → logout()        — clear session

GET  /setup          → setup()         — first-run wizard (redirect to login if users exist)
POST /setup          → setup_post()    — create first admin user + enable auth + auto-login

GET  /auth/users     → list_users_route()     — admin only
POST /auth/users     → create_user_route()    — admin only
DELETE /auth/users/<user_id>  → delete_user_route()  — admin only; cannot delete self or last admin

POST /auth/change-password    → change_password_route()  — any authenticated user (own password)
POST /auth/generate-api-key   → generate_api_key_route() — any authenticated user (own key)
POST /auth/revoke-api-key     → revoke_api_key_route()   — any authenticated user (own key)
```

**Login lockout:** 5 failed attempts → 5-minute lockout per username. Track in-memory with a module-level dict `{username: (attempts, lockout_until)}`. Resets on successful login. (No DB storage needed — resets on restart, acceptable for this deployment model.)

**`login_post` logic:**
```python
key = f"{username.lower()}"
attempts, lockout_until = _lockout.get(key, (0, 0))
if lockout_until and time.time() < lockout_until:
    remaining = int(lockout_until - time.time())
    return render_template("login.html", error=f"Account locked. Try again in {remaining}s."), 429

user = check_password(username, password)
if user:
    _lockout.pop(key, None)
    session.clear()
    session["authenticated"] = True
    session["user_id"] = user["id"]
    session["last_seen"] = time.time()
    ...redirect...
else:
    attempts += 1
    lockout_until = time.time() + 300 if attempts >= 5 else 0
    _lockout[key] = (attempts, lockout_until)
    return render_template("login.html", error="Invalid username or password."), 401
```

**`setup_post` logic:**
- Validate username (3+ chars), password (12+ chars), confirm match
- `create_user(username, password, role="admin")`
- `save_settings({**get_settings(), "auth_enabled": True})`
- Auto-login (set session), redirect to index

---

## `templates/login.html` Changes

Replace the single `api_key` field with:
```html
<input type="text" name="username" autocomplete="username" autofocus required placeholder="Username" />
<input type="password" name="password" autocomplete="current-password" required placeholder="Password" />
```

Remove the `csh_…` placeholder and API key hint text.

---

## New Template: `templates/setup.html`

Same card layout as `login.html`. Fields: username, password, confirm password.
Show `errors` list if validation fails.
Include CSRF token.
Note: "Create your admin account. Store your credentials safely."

---

## `templates/index.html` Changes

### Auth Settings pane — replace API key section with:

**Users table** (admin only — hide for auditor/viewer via Jinja2 `{% if current_user.role == 'admin' %}`):
- Table columns: Username, Role, API Key, Created, Actions
- Actions: Delete button (disabled for self and last admin)
- "Add User" form inline below table: username, password, role selector (admin/auditor/viewer)

**Per-user API key section** (visible to all roles — shows current user's key):
- "Generate API Key" button → POST `/auth/generate-api-key` → shows key once with copy button
- "Revoke API Key" button → POST `/auth/revoke-api-key`
- Status line: "API key active" / "No API key set"

**Change Password section** (visible to all roles):
- Current password, new password, confirm new password
- POST to `/auth/change-password`

Pass `current_user` to the template from the index route in `web.py`:
```python
return render_template("index.html", ..., current_user=getattr(g, "current_user", None))
```

---

## Role Enforcement in Blueprints

Apply `@_require_role(...)` decorators to restricted routes. Import from `_helpers.py`.

Key routes to gate:

| Blueprint | Route | Allowed roles |
|---|---|---|
| `audit.py` | `/audit`, `/bulk_audit`, `/connect` | admin, auditor |
| `schedules.py` | POST/PUT/DELETE `/schedules/*` | admin, auditor |
| `settings_bp.py` | POST `/settings`, `/settings/*` | admin |
| `auth.py` | GET/POST/DELETE `/auth/users*` | admin |

Read-only routes (GET history, GET schedules, reports, export) remain open to all authenticated users.

---

## `settings.py` / API key migration

Remove `api_key_enc` and `api_key` from `settings.py` DEFAULTS and `get_settings()` return. Per-user API keys now live in the `users` table. The `save_api_key()` function can be removed.

Update `_helpers.py` `_require_auth_impl` to use `get_user_by_api_key()` (already done above).

Also remove the "Generate API Key" button from the old settings section — replaced by per-user key management in the Auth pane.

---

## `web.py` Changes

Update the `index()` route to pass `current_user`:
```python
return render_template("index.html", ..., current_user=getattr(g, "current_user", None))
```

---

## Testing: `tests/test_auth.py` (new)

Follow the same pattern as `test_db.py` — use `_tmp_db` decorator for isolation.

**`user_store.py` unit tests:**
- `test_has_users_false_when_empty`
- `test_create_user_success`
- `test_create_user_duplicate_username_raises`
- `test_create_user_short_password_raises`
- `test_create_user_short_username_raises`
- `test_create_user_invalid_role_raises`
- `test_check_password_correct`
- `test_check_password_wrong_password`
- `test_check_password_wrong_username`
- `test_list_users_excludes_hashes`
- `test_delete_user_success`
- `test_delete_last_admin_raises`
- `test_change_password_success`
- `test_change_password_too_short_raises`
- `test_generate_api_key_returns_plaintext`
- `test_get_user_by_api_key_correct`
- `test_get_user_by_api_key_wrong_key`
- `test_revoke_api_key_clears_key`

**Web integration tests** (test_client, `WTF_CSRF_ENABLED=False`, `_tmp_db`):
- `test_setup_get_200_when_no_users`
- `test_setup_post_creates_admin_and_enables_auth`
- `test_setup_redirects_to_login_when_users_exist`
- `test_login_success_sets_session`
- `test_login_wrong_password_401`
- `test_login_generic_error_message`  — must not reveal "wrong password" vs "wrong user"
- `test_login_lockout_after_five_failures`
- `test_api_key_auth_grants_access`
- `test_viewer_cannot_run_audit`
- `test_auditor_can_run_audit`
- `test_admin_can_manage_users`
- `test_viewer_cannot_manage_users`
- `test_change_password_success`
- `test_generate_api_key_returns_key`

---

## Migration Order (Lowest Risk First)

Run `python -m pytest tests/ -v` after each step.

1. **Add `users` table to `db.py`** schema (in `init_db()`)
2. **Create `user_store.py`** with all functions
3. **Update `_helpers.py`** — new `_require_auth_impl`, add `_require_role`
4. **Update `blueprints/auth.py`** — full route set
5. **Create `templates/setup.html`**
6. **Update `templates/login.html`** — username + password fields
7. **Apply `@_require_role` to restricted routes** in audit, schedules, settings_bp blueprints
8. **Update `templates/index.html`** — users table, per-user API key, change-password
9. **Update `web.py`** — pass `current_user` to index template
10. **Remove `api_key_enc`** from `settings.py` DEFAULTS and `save_api_key()`
11. **Write `tests/test_auth.py`**

---

## Acceptance Criteria (Definition of Done)

- [ ] `users` table in SQLite with correct schema
- [ ] `user_store.py` implemented with all public functions
- [ ] `/setup` first-run wizard works (no users → redirect to setup)
- [ ] `/login` accepts username + password; lockout after 5 failures
- [ ] `/logout` clears session
- [ ] Per-user API key generation/revocation working
- [ ] `_require_role` enforced on all restricted routes
- [ ] Admin user management UI (add, delete, list users) in Settings pane
- [ ] Change-password working for all roles
- [ ] Viewer cannot run audits or manage schedules
- [ ] Auditor cannot manage settings or users
- [ ] API key header auth (`X-API-Key`) working for all users
- [ ] Old shared `api_key_enc` removed from settings
- [ ] All 202 existing tests pass with no changes to existing test files
- [ ] `tests/test_auth.py` written and passing
- [ ] `ruff check src/ tests/` clean
- [ ] `SESSION-CHECKPOINT.md` updated at completion

---

## Branch and PR

```bash
git checkout -b cld/auth-phase1 origin/staging
# ... implement ...
python -m pytest tests/ -v
ruff check src/ tests/
git push origin cld/auth-phase1
# PR → staging (not main)
```
