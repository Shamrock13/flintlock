# TASK: RBAC UI Fixes + Header Redesign

**Status:** 🔵 Active
**Branch:** `cld/rbac-ui` (cut from `staging`)
**Assigned to:** Builder
**Architect sign-off required before merge:** Yes

---

## Context

Staging validation revealed that Auditor and Viewer roles can see settings they cannot change, creating confusion. Research against Tenable/Qualys/Rapid7/NIST standards produced a definitive permission matrix. This task implements those corrections across the backend routes, Jinja2 templates, and header redesign.

Zero new dependencies. All changes are to existing files.

---

## Definitive Permission Matrix

| Capability | Admin | Auditor | Viewer |
|---|:---:|:---:|:---:|
| Run file/SSH/bulk audit | ✅ | ✅ | ❌ |
| View audit history + findings | ✅ | ✅ | ✅ |
| Save audit to archive | ✅ | ✅ | ❌ |
| **Delete audit history entry** | ✅ | **❌** | ❌ |
| Compare two audits (diff) | ✅ | ✅ | ✅ |
| Generate remediation plan | ✅ | ✅ | ❌ |
| View remediation plan (already saved) | ✅ | ✅ | ✅ |
| Export JSON/CSV/SARIF/PDF | ✅ | ✅ | ✅ |
| View schedules | ✅ | ✅ | ✅ |
| Create/edit/delete schedules | ✅ | ✅ | ❌ |
| **View full activity log** | ✅ | **❌** | **❌** |
| View Settings page (any part) | ✅ | ❌ | ❌ |
| All Settings write operations | ✅ | ❌ | ❌ |
| Activate/deactivate license | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| Generate/revoke own API key | ✅ | ✅ | ✅ |
| Change own password | ✅ | ✅ | ✅ |

---

## Backend Route Changes

### `blueprints/history.py`

**Change 1:** `DELETE /archive/<entry_id>` — change from `@_require_role("admin", "auditor")` to `@_require_role("admin")`

**Change 2:** `GET /activity` — add `@_require_role("admin")` (currently no role guard)

**Change 3:** `POST /archive/save` — add `@_require_role("admin", "auditor")` (currently no role guard)

**Change 4:** `GET /archive/<entry_id>/remediation-plan` — add `@_require_role("admin", "auditor")` for generation; GET of JSON format (view) can stay open to all — simplest approach is require admin+auditor for all formats since "view" of a plan requires having generated it.

### `blueprints/settings_bp.py`

Already has `@_require_role("admin")` on all write routes and GET /settings. No changes needed.

### No other backend changes needed.

---

## Frontend (templates/index.html) Changes

All role checks use the Jinja2 `current_user` variable already passed from `web.py`. When `current_user` is None (auth disabled or demo mode), show everything — no change to existing behavior for those modes.

### 1. Settings nav item — hide entirely for non-admin

Find the Settings nav button and wrap in role check:

```html
{% if not current_user or current_user.role == 'admin' %}
<button class="settings-nav-item" data-pane="general">General</button>
... (all settings nav items)
{% endif %}
```

More specifically, hide the entire settings tab trigger button in the main nav:

```html
{% if not current_user or current_user.role == 'admin' %}
<button class="tab-btn" data-tab="settings">Settings</button>
{% endif %}
```

Also hide the Settings tab content panel for non-admin (belt-and-suspenders, since the tab button is hidden):

Wrap the settings tab pane in:
```html
{% if not current_user or current_user.role == 'admin' %}
... settings pane content ...
{% endif %}
```

**Important:** The "My Account" section (change password + API key) must remain visible to ALL roles. Move it OUT of the admin settings pane into the header user menu OR keep it as a standalone always-visible section. Simplest approach: keep change-password and API key management in the Auth pane, but show ONLY those two sections for non-admin users. The SMTP, syslog, SSH policy, webhook allowlist, error detail, and user management sections are hidden for non-admin.

Implementation: in the Auth pane, keep the change-password and API key sections outside of the `{% if current_user.role == 'admin' %}` guard that wraps user management.

### 2. Audit tab — hide upload/run controls for Viewer

Find the upload form / run audit button area. Wrap in:

```html
{% if not current_user or current_user.role in ('admin', 'auditor') %}
... upload form, run audit button, bulk audit section, connect SSH section ...
{% endif %}
```

Viewer sees the Audit tab but only sees a message: show a simple placeholder inside the guarded block:
```html
{% else %}
<p class="role-notice">Audit execution requires Auditor or Admin role. You can view results in the History tab.</p>
{% endif %}
```

### 3. History tab — archive delete button

Change the delete button on audit history entries from always-shown to role-conditional:

```html
{% if not current_user or current_user.role == 'admin' %}
<button class="btn-delete-entry" data-id="${entry.id}">Delete</button>
{% else %}
<button class="btn-delete-entry" disabled title="Deletion requires Admin role" style="opacity:0.4;cursor:not-allowed">Delete</button>
{% endif %}
```

Note: The delete button in the history tab is rendered by JavaScript (dynamic list), not Jinja2. So instead of Jinja2, inject the role into a JS variable and conditionally render:

In the template (inside a `<script nonce="...">` block):
```javascript
const userRole = {{ (current_user.role if current_user else 'admin') | tojson }};
```

Then in the JS that renders history entries, use:
```javascript
const canDelete = (userRole === 'admin');
const deleteBtn = canDelete
  ? `<button class="btn-delete-entry" data-id="${entry.id}">Delete</button>`
  : `<button disabled title="Deletion requires Admin role" style="opacity:0.4;cursor:not-allowed">Delete</button>`;
```

Apply the same pattern to the activity log clear/delete buttons.

### 4. Schedules tab — hide create/edit/delete for Viewer

Wrap schedule create form and edit/delete buttons:
```javascript
const canManageSchedules = (userRole === 'admin' || userRole === 'auditor');
```

Show/hide create-schedule button and edit/delete actions based on `canManageSchedules`.

### 5. Activity log tab — hide entirely for non-admin

```html
{% if not current_user or current_user.role == 'admin' %}
<button class="tab-btn" data-tab="activity">Activity</button>
{% endif %}
```

And wrap the activity tab pane content similarly.

---

## Header Redesign

### Goal
Clean, minimal. Remove emoji. Use "Logout" as the button label. Username shown in a smaller muted style. No icon/avatar.

### Current HTML (to replace)
```html
{% if current_user and not demo_mode %}
<span class="header-user" title="Signed in as {{ current_user.username }} ({{ current_user.role }})">&#128100; {{ current_user.username }}</span>
<form method="post" action="/logout" style="display:inline">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit" class="btn-logout" title="Sign out">Sign out</button>
</form>
{% endif %}
```

### New HTML
```html
{% if current_user and not demo_mode %}
<span class="header-username">{{ current_user.username }}</span>
<form method="post" action="/logout" style="display:inline;margin:0">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit" class="btn-logout">Logout</button>
</form>
{% endif %}
```

### New/Updated CSS (in `static/style.css`)

Replace existing `.header-user` and `.btn-logout` styles:

```css
/* ===== Header user / logout ===== */
.header-username {
  color: rgba(255,255,255,0.55);
  font-size: 0.78rem;
  letter-spacing: 0.01em;
  white-space: nowrap;
}

.btn-logout {
  background: transparent;
  border: 1px solid rgba(255,255,255,0.25);
  border-radius: 5px;
  color: rgba(255,255,255,0.75);
  cursor: pointer;
  font-size: 0.78rem;
  padding: 0.22rem 0.65rem;
  transition: border-color 0.15s, color 0.15s;
  white-space: nowrap;
}

.btn-logout:hover {
  border-color: rgba(255,255,255,0.55);
  color: #fff;
}
```

---

## Migration Order (Lowest Risk First)

Run `python -m pytest tests/ -v` after each step.

1. **Backend route fixes** (history.py) — GET /activity admin-only, DELETE /archive admin-only, POST /archive/save guard
2. **JS role variable** — inject `userRole` into index.html script block
3. **History delete button** — conditional render via JS `userRole`
4. **Activity log tab** — hide tab button and pane for non-admin
5. **Settings tab** — hide tab button for non-admin; show only account sections (password + API key) for non-admin inside the settings pane
6. **Audit tab** — hide upload/run controls for viewer; show role notice
7. **Schedules tab** — hide create/edit/delete for viewer
8. **Header HTML** — replace with clean version
9. **Header CSS** — update `.header-username` and `.btn-logout` styles

---

## Acceptance Criteria (Definition of Done)

- [ ] Viewer cannot see Settings tab in navigation
- [ ] Viewer cannot see Activity tab in navigation
- [ ] Viewer sees Audit tab but no upload/run controls — sees role notice instead
- [ ] Viewer sees History tab with disabled (not hidden) delete buttons with tooltip
- [ ] Viewer sees Schedules tab (read-only) with no create/edit/delete controls
- [ ] Viewer sees change-password and API key sections (in Auth pane or standalone)
- [ ] Auditor cannot delete audit history entries (button disabled with tooltip)
- [ ] Auditor cannot see Activity tab
- [ ] Auditor CAN run audits, manage schedules, export, view history
- [ ] `GET /activity` returns 403 for auditor and viewer
- [ ] `DELETE /archive/<id>` returns 403 for auditor
- [ ] Header shows clean username (muted) + "Logout" button, no emoji
- [ ] All 234 existing tests pass unchanged
- [ ] `ruff check src/ tests/` clean
- [ ] `SESSION-CHECKPOINT.md` updated at completion

---

## Branch and PR

```bash
git checkout -b cld/rbac-ui origin/staging
python -m pytest tests/ -v  # confirm 234 pass from baseline
# ... implement steps 1-9 ...
python -m pytest tests/ -v  # confirm still 234+ pass
ruff check src/ tests/
git push origin cld/rbac-ui
# PR → staging
```
