# Threshold-Based Alerting — Design Spec

**Date:** 2026-04-11
**Issue:** #46
**Status:** Approved — pending implementation plan

---

## Overview

Add a threshold-based alerting system that fires a consolidated notification when an audit result breaches configured thresholds. Alerts deduplicate: they fire once when a condition is first crossed and re-arm only after the condition clears. Thresholds are configured globally with optional per-schedule overrides. Alert channels are configured independently from schedule notification settings.

---

## Data Model

### `alert_thresholds` table

Stores individual threshold rules. Global rules have `schedule_id = NULL`. Per-schedule overrides have a `schedule_id` foreign key pointing to the schedule that owns the override.

```sql
CREATE TABLE IF NOT EXISTS alert_thresholds (
    id TEXT PRIMARY KEY,
    schedule_id TEXT,                    -- NULL = global default
    metric TEXT NOT NULL,                -- see Metrics section
    operator TEXT NOT NULL,              -- "lt" | "gte"
    threshold_value REAL NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_thresholds_schedule ON alert_thresholds(schedule_id);
```

**Effective thresholds** for a given audit are computed by merging: per-schedule overrides take precedence over global defaults on a per-metric basis.

### `alert_state` table

Tracks dedup/re-arm state. One row per schedule (or `__manual__` for API/manual audits).

```sql
CREATE TABLE IF NOT EXISTS alert_state (
    schedule_id TEXT PRIMARY KEY,        -- schedule UUID or "__manual__"
    in_breach INTEGER NOT NULL DEFAULT 0,
    breach_started_at TEXT,
    breach_audit_id TEXT,
    breached_metrics TEXT NOT NULL DEFAULT '[]'  -- JSON array
);
```

- `in_breach = 1`: a breach alert has been sent; subsequent audits that still breach are suppressed
- When an audit passes all thresholds: `in_breach` reset to 0, re-arming for the next breach
- A new breach after re-arm fires a fresh alert

### Alert channel config (settings table)

New keys added to the existing encrypted `settings` table:

| Key | Type | Description |
|-----|------|-------------|
| `alert_slack_webhook` | string (encrypted) | Slack webhook URL for breach alerts |
| `alert_teams_webhook` | string (encrypted) | Teams webhook URL for breach alerts |
| `alert_email_recipients` | string | Comma-separated email addresses |

These are distinct from per-schedule `notify_slack_webhook` / `notify_teams_webhook` — alert channels are for threshold breach events only.

---

## Supported Metrics

| Metric key | Description | Typical operator |
|------------|-------------|-----------------|
| `score` | Overall audit score (0–100) | `lt` (alert if score drops below N) |
| `critical` | Critical finding count | `gte` (alert if ≥ N critical findings) |
| `high` | High finding count | `gte` |
| `medium` | Medium finding count | `gte` |
| `low` | Low finding count | `gte` |
| `total` | Total finding count | `gte` |
| `pci` | PCI-DSS compliance % (0–100) | `lt` (alert if < 100) |
| `cis` | CIS compliance % | `lt` |
| `nist` | NIST compliance % | `lt` |
| `hipaa` | HIPAA compliance % | `lt` |
| `soc2` | SOC2 compliance % | `lt` |
| `stig` | STIG compliance % | `lt` |

Each framework is individually configurable — a user can alert on PCI non-compliance without alerting on HIPAA.

---

## Module Architecture

### `src/cashel/alert_engine.py` (new)

Core logic module, following the `activity_log.py` / `auth_audit.py` pattern.

```python
@dataclass
class AlertResult:
    breached: bool
    suppressed: bool        # True if in_breach already and no new metrics
    breached_metrics: list[dict]
    cleared: bool           # True if was in_breach and now clean

def check_thresholds(audit_summary: dict, schedule_id: str | None = None) -> AlertResult
def get_effective_thresholds(schedule_id: str | None = None) -> list[dict]
def save_threshold(threshold: dict) -> None
def delete_threshold(threshold_id: str) -> None
def get_alert_channels() -> dict
def save_alert_channels(channels: dict) -> None
```

**`check_thresholds` logic:**

1. Load effective thresholds (globals merged with per-schedule overrides)
2. Evaluate each enabled threshold against `audit_summary`
3. Collect all breached metrics into a list
4. Look up `alert_state` row for `schedule_id` (or `__manual__`)
5. **If currently in breach (`in_breach=1`):**
   - Check if any *new* metrics are breaching that weren't in the original `breached_metrics`
   - If no new metrics: return `AlertResult(suppressed=True)` — do nothing
   - If new metrics: update `breached_metrics`, fire consolidated alert for new metrics only
6. **If not in breach:**
   - If metrics breached: update `alert_state` to `in_breach=1`, fire consolidated alert
   - If no breach: ensure `alert_state` is reset/cleared (re-arm)
7. **Clear condition:** if `in_breach=1` and zero thresholds breached: reset `alert_state` to `in_breach=0`

### `src/cashel/scheduler_runner.py` (modified)

One call added after each scheduled audit completes:

```python
from .alert_engine import check_thresholds
# after audit_summary is available:
check_thresholds(summary, schedule_id=schedule["id"])
```

Failure is caught and logged to `activity_log` — never propagates to crash the scheduler thread.

### `src/cashel/blueprints/settings_bp.py` (modified)

New routes:

| Method | Path | Access | Description |
|--------|------|--------|-------------|
| `GET` | `/settings/alert-thresholds` | Admin | List all thresholds (global + per-schedule) |
| `POST` | `/settings/alert-thresholds` | Admin | Create or update a threshold rule |
| `DELETE` | `/settings/alert-thresholds/<id>` | Admin | Delete a threshold rule |
| `GET` | `/settings/alert-channels` | Admin | Get alert channel config (masked) |
| `POST` | `/settings/alert-channels` | Admin | Save alert channel config |

### `src/cashel/db.py` (modified)

Add `alert_thresholds` and `alert_state` tables to `init_db()`.

---

## Consolidated Alert Format

When a breach fires, a single message is sent to all configured alert channels summarizing all violated thresholds:

**Subject:** `[Cashel Alert] Audit threshold breach — <hostname>`

**Body:**
```
Audit threshold breach detected for: <hostname>
Audit ID: <id> | Score: <score>/100 | Timestamp: <ts>

Breached thresholds:
  ✗ Score: 58 (threshold: ≥ 70)
  ✗ High findings: 4 (threshold: < 1)
  ✗ PCI compliance: 87% (threshold: 100%)

View full audit: <omitted if CASHEL_BASE_URL not configured>
```

Slack/Teams messages use the same structure with appropriate block formatting.

---

## UI: Settings Page

New "Alert Thresholds" section in the Settings page (Admin only):

1. **Alert Channels** — Slack webhook, Teams webhook, email recipients (same input style as existing notify fields)
2. **Global Thresholds** — table of metric / operator / value / enabled toggle, with Add/Delete controls
3. **Per-Schedule Overrides** — dropdown to select a schedule, then same threshold table for that schedule's overrides

---

## Error Handling

- Alert channel missing/unconfigured: skip that channel silently, log to `activity_log`
- `notify.py` dispatch failure (network error, bad webhook): catch exception, log, continue — never crashes scheduler
- `audit_summary` missing a metric key (e.g., compliance not computed): treat as no-breach for that metric, log a warning
- Manual/API audits: use sentinel `schedule_id = "__manual__"` in `alert_state`

---

## Out of Scope

- Alert history/log UI (can be added later — `activity_log` will capture breach events)
- Per-user alert subscriptions
- Alert escalation (repeat after N hours if unacknowledged)
- Webhook event bus (Phase 2 item #6 — separate feature)
