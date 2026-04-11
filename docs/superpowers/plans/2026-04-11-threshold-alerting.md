# Threshold-Based Alerting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a threshold-based alerting system that fires a single consolidated notification when an audit breaches configured thresholds, with global defaults, per-schedule overrides, and dedup/re-arm logic.

**Architecture:** New `alert_engine.py` module handles all threshold logic (evaluation, state, dispatch). Two new SQLite tables (`alert_thresholds`, `alert_state`) store rules and dedup state. `scheduler_runner.py` calls `check_thresholds()` after each audit. Alert channels (Slack, Teams, email) are configured independently in `settings_bp.py`. The Settings UI gets a new "Alert Thresholds" pane.

**Tech Stack:** Python/Flask, SQLite (via existing `db.py` pattern), existing `notify.py` for dispatch, Jinja2 + vanilla JS for UI.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `src/cashel/alert_engine.py` | **Create** | Core threshold logic: evaluate, dedup, dispatch |
| `src/cashel/db.py` | **Modify** | Add `alert_thresholds` + `alert_state` tables to `init_db()` |
| `src/cashel/scheduler_runner.py` | **Modify** | Call `check_thresholds()` after each successful audit |
| `src/cashel/blueprints/settings_bp.py` | **Modify** | Add 5 new routes for threshold/channel CRUD |
| `src/cashel/templates/index.html` | **Modify** | Add "Alert Thresholds" settings pane + JS |
| `tests/test_alert_engine.py` | **Create** | Unit tests for threshold evaluation and dedup logic |

---

## Task 1: Database schema — add alert tables

**Files:**
- Modify: `src/cashel/db.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_alert_engine.py` with a schema test:

```python
"""Tests for alert_engine.py — threshold evaluation and dedup logic."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.db as db_mod


def _tmp_db(fn):
    """Decorator: run test against an isolated temp database."""
    def wrapper(*args, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        orig_path = db_mod.DB_PATH
        orig_conn = getattr(db_mod._local, "conn", None)
        try:
            db_mod.DB_PATH = tmp
            db_mod._local.conn = None
            db_mod.init_db()
            return fn(*args, **kwargs)
        finally:
            conn = getattr(db_mod._local, "conn", None)
            if conn:
                conn.close()
            db_mod.DB_PATH = orig_path
            db_mod._local.conn = orig_conn
            try:
                os.unlink(tmp)
            except OSError:
                pass
    wrapper.__name__ = fn.__name__
    return wrapper


class TestAlertSchema(unittest.TestCase):
    @_tmp_db
    def test_alert_thresholds_table_exists(self):
        conn = db_mod.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alert_thresholds'"
        ).fetchone()
        self.assertIsNotNone(row)

    @_tmp_db
    def test_alert_state_table_exists(self):
        conn = db_mod.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alert_state'"
        ).fetchone()
        self.assertIsNotNone(row)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_alert_engine.py::TestAlertSchema -v
```

Expected: FAIL — tables don't exist yet.

- [ ] **Step 3: Add tables to `init_db()` in `src/cashel/db.py`**

Inside `init_db()`, add to the `executescript` block (after the `idx_auth_events_ts` line, before the closing `"""`):

```python
        CREATE TABLE IF NOT EXISTS alert_thresholds (
            id              TEXT PRIMARY KEY,
            schedule_id     TEXT,
            metric          TEXT NOT NULL,
            operator        TEXT NOT NULL,
            threshold_value REAL NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alert_thresholds_schedule
            ON alert_thresholds(schedule_id);

        CREATE TABLE IF NOT EXISTS alert_state (
            schedule_id         TEXT PRIMARY KEY,
            in_breach           INTEGER NOT NULL DEFAULT 0,
            breach_started_at   TEXT,
            breach_audit_id     TEXT,
            breached_metrics    TEXT NOT NULL DEFAULT '[]'
        );
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_alert_engine.py::TestAlertSchema -v
```

Expected: PASS — both tables exist.

- [ ] **Step 5: Commit**

```bash
git add src/cashel/db.py tests/test_alert_engine.py
git commit -m "feat: add alert_thresholds and alert_state tables (#46)"
```

---

## Task 2: `alert_engine.py` — threshold CRUD and evaluation

**Files:**
- Create: `src/cashel/alert_engine.py`
- Modify: `tests/test_alert_engine.py`

- [ ] **Step 1: Add CRUD and evaluation tests to `tests/test_alert_engine.py`**

Append the following classes to `tests/test_alert_engine.py`:

```python
from cashel import alert_engine


class TestThresholdCRUD(unittest.TestCase):
    @_tmp_db
    def test_save_and_get_global_threshold(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        thresholds = alert_engine.get_effective_thresholds(schedule_id=None)
        self.assertEqual(len(thresholds), 1)
        t = thresholds[0]
        self.assertEqual(t["metric"], "score")
        self.assertEqual(t["operator"], "lt")
        self.assertAlmostEqual(t["threshold_value"], 70.0)
        self.assertIsNone(t["schedule_id"])

    @_tmp_db
    def test_per_schedule_override_takes_precedence(self):
        # Global: alert if score < 70
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        # Override: alert if score < 80
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 80.0,
            "enabled": True, "schedule_id": "sched-abc",
        })
        effective = alert_engine.get_effective_thresholds(schedule_id="sched-abc")
        score_thresholds = [t for t in effective if t["metric"] == "score"]
        self.assertEqual(len(score_thresholds), 1)
        self.assertAlmostEqual(score_thresholds[0]["threshold_value"], 80.0)

    @_tmp_db
    def test_global_used_when_no_override(self):
        alert_engine.save_threshold({
            "metric": "high", "operator": "gte", "threshold_value": 1.0,
            "enabled": True, "schedule_id": None,
        })
        effective = alert_engine.get_effective_thresholds(schedule_id="sched-xyz")
        self.assertEqual(len(effective), 1)
        self.assertEqual(effective[0]["metric"], "high")

    @_tmp_db
    def test_delete_threshold(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        thresholds = alert_engine.get_effective_thresholds()
        tid = thresholds[0]["id"]
        alert_engine.delete_threshold(tid)
        self.assertEqual(alert_engine.get_effective_thresholds(), [])

    @_tmp_db
    def test_disabled_threshold_not_evaluated(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": False, "schedule_id": None,
        })
        summary = {"score": 50, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id=None)
        self.assertFalse(result.breached)


class TestThresholdEvaluation(unittest.TestCase):
    @_tmp_db
    def test_lt_operator_breaches_when_below(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 65, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(len(result.breached_metrics), 1)
        self.assertEqual(result.breached_metrics[0]["metric"], "score")

    @_tmp_db
    def test_lt_operator_no_breach_when_above(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 85, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertFalse(result.breached)

    @_tmp_db
    def test_gte_operator_breaches_when_at_or_above(self):
        alert_engine.save_threshold({
            "metric": "high", "operator": "gte", "threshold_value": 1.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 90, "high": 1, "medium": 0, "low": 0, "total": 1}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)

    @_tmp_db
    def test_compliance_metric_breach(self):
        alert_engine.save_threshold({
            "metric": "pci", "operator": "lt", "threshold_value": 100.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {
            "score": 90, "high": 0, "medium": 0, "low": 0, "total": 0,
            "compliance": {"pci": {"score": 87}},
        }
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(result.breached_metrics[0]["metric"], "pci")

    @_tmp_db
    def test_missing_metric_key_no_breach(self):
        """Metric not in summary should not trigger a breach."""
        alert_engine.save_threshold({
            "metric": "pci", "operator": "lt", "threshold_value": 100.0,
            "enabled": True, "schedule_id": None,
        })
        # summary has no 'compliance' key
        summary = {"score": 90, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertFalse(result.breached)

    @_tmp_db
    def test_multiple_thresholds_consolidated(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        alert_engine.save_threshold({
            "metric": "high", "operator": "gte", "threshold_value": 1.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 55, "high": 3, "medium": 0, "low": 0, "total": 3}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(len(result.breached_metrics), 2)


class TestAlertDedup(unittest.TestCase):
    @_tmp_db
    def test_second_breach_suppressed(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0}
        # First call — breaches
        r1 = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(r1.breached)
        self.assertFalse(r1.suppressed)
        # Second call — same condition, should be suppressed
        r2 = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertFalse(r2.breached)
        self.assertTrue(r2.suppressed)

    @_tmp_db
    def test_clears_and_rearms_when_condition_resolves(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        bad_summary  = {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0}
        good_summary = {"score": 85, "high": 0, "medium": 0, "low": 0, "total": 0}
        # Breach
        r1 = alert_engine.check_thresholds(bad_summary, schedule_id="s1")
        self.assertTrue(r1.breached)
        # Condition clears
        r2 = alert_engine.check_thresholds(good_summary, schedule_id="s1")
        self.assertTrue(r2.cleared)
        self.assertFalse(r2.breached)
        # New breach fires again
        r3 = alert_engine.check_thresholds(bad_summary, schedule_id="s1")
        self.assertTrue(r3.breached)
        self.assertFalse(r3.suppressed)

    @_tmp_db
    def test_new_metric_fires_during_existing_breach(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        alert_engine.save_threshold({
            "metric": "high", "operator": "gte", "threshold_value": 1.0,
            "enabled": True, "schedule_id": None,
        })
        # First breach: score only
        r1 = alert_engine.check_thresholds(
            {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0},
            schedule_id="s1",
        )
        self.assertTrue(r1.breached)
        # Second call: score still breached + high now breached too
        r2 = alert_engine.check_thresholds(
            {"score": 55, "high": 2, "medium": 0, "low": 0, "total": 2},
            schedule_id="s1",
        )
        self.assertTrue(r2.breached)
        self.assertFalse(r2.suppressed)
        new_metrics = [m["metric"] for m in r2.breached_metrics]
        self.assertIn("high", new_metrics)

    @_tmp_db
    def test_manual_audit_uses_sentinel(self):
        alert_engine.save_threshold({
            "metric": "score", "operator": "lt", "threshold_value": 70.0,
            "enabled": True, "schedule_id": None,
        })
        summary = {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0}
        r1 = alert_engine.check_thresholds(summary, schedule_id=None)
        r2 = alert_engine.check_thresholds(summary, schedule_id=None)
        self.assertTrue(r1.breached)
        self.assertTrue(r2.suppressed)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_alert_engine.py -v
```

Expected: FAIL — `alert_engine` module doesn't exist yet.

- [ ] **Step 3: Create `src/cashel/alert_engine.py`**

```python
"""Threshold-based alerting engine.

Evaluates audit summaries against configured thresholds, manages dedup/re-arm
state, and fires consolidated breach notifications via notify.py.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from .db import get_conn

logger = logging.getLogger(__name__)

# Valid metric keys and their source paths in the audit summary dict.
# Severity counts are top-level keys; compliance metrics live under summary["compliance"][fw]["score"].
_SEVERITY_METRICS = {"critical", "high", "medium", "low", "total"}
_COMPLIANCE_METRICS = {"pci", "cis", "nist", "hipaa", "soc2", "stig"}
VALID_METRICS = _SEVERITY_METRICS | _COMPLIANCE_METRICS | {"score"}
VALID_OPERATORS = {"lt", "gte"}

# Sentinel for manual/API-triggered audits (not from a schedule).
_MANUAL_SENTINEL = "__manual__"


@dataclass
class AlertResult:
    breached: bool = False
    suppressed: bool = False       # True when already in_breach with no new metrics
    breached_metrics: list[dict] = field(default_factory=list)
    cleared: bool = False          # True when was in_breach and condition is now clean


# ── Threshold CRUD ─────────────────────────────────────────────────────────────


def save_threshold(threshold: dict) -> dict:
    """Insert or update a threshold rule. Returns the saved threshold with id."""
    tid = threshold.get("id") or uuid.uuid4().hex[:12]
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO alert_thresholds (id, schedule_id, metric, operator, threshold_value, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            schedule_id     = excluded.schedule_id,
            metric          = excluded.metric,
            operator        = excluded.operator,
            threshold_value = excluded.threshold_value,
            enabled         = excluded.enabled
        """,
        (
            tid,
            threshold.get("schedule_id"),
            threshold["metric"],
            threshold["operator"],
            float(threshold["threshold_value"]),
            1 if threshold.get("enabled", True) else 0,
            now,
        ),
    )
    conn.commit()
    return {**threshold, "id": tid, "created_at": now}


def delete_threshold(threshold_id: str) -> bool:
    """Delete a threshold by id. Returns True if deleted."""
    conn = get_conn()
    cur = conn.execute("DELETE FROM alert_thresholds WHERE id = ?", (threshold_id,))
    conn.commit()
    return cur.rowcount > 0


def list_thresholds() -> list[dict]:
    """Return all threshold rules (global and per-schedule)."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alert_thresholds ORDER BY created_at ASC"
    ).fetchall()
    return [_threshold_row(r) for r in rows]


def get_effective_thresholds(schedule_id: str | None = None) -> list[dict]:
    """Return effective thresholds for a schedule.

    Per-schedule overrides take precedence over global defaults on a per-metric
    basis. A schedule override fully replaces the global for that metric.
    """
    conn = get_conn()
    # Load globals (schedule_id IS NULL)
    globals_ = {
        r["metric"]: _threshold_row(r)
        for r in conn.execute(
            "SELECT * FROM alert_thresholds WHERE schedule_id IS NULL AND enabled = 1"
        ).fetchall()
    }
    if schedule_id:
        # Load per-schedule overrides and merge over globals
        overrides = {
            r["metric"]: _threshold_row(r)
            for r in conn.execute(
                "SELECT * FROM alert_thresholds WHERE schedule_id = ? AND enabled = 1",
                (schedule_id,),
            ).fetchall()
        }
        merged = {**globals_, **overrides}
    else:
        merged = globals_
    return list(merged.values())


# ── Alert channel config ───────────────────────────────────────────────────────


def get_alert_channels() -> dict:
    """Return alert channel config from settings (decrypted)."""
    from .settings import get_settings
    from .crypto import decrypt

    s = get_settings()
    slack = ""
    teams = ""
    if s.get("alert_slack_webhook_enc"):
        try:
            slack = decrypt(s["alert_slack_webhook_enc"])
        except Exception:
            pass
    if s.get("alert_teams_webhook_enc"):
        try:
            teams = decrypt(s["alert_teams_webhook_enc"])
        except Exception:
            pass
    return {
        "alert_slack_webhook": slack,
        "alert_teams_webhook": teams,
        "alert_email_recipients": s.get("alert_email_recipients", ""),
    }


def save_alert_channels(channels: dict) -> None:
    """Persist alert channel config to settings."""
    from .settings import get_settings, save_settings
    from .crypto import encrypt

    current = get_settings()
    if channels.get("alert_slack_webhook"):
        current["alert_slack_webhook_enc"] = encrypt(channels["alert_slack_webhook"])
    if channels.get("alert_teams_webhook"):
        current["alert_teams_webhook_enc"] = encrypt(channels["alert_teams_webhook"])
    if "alert_email_recipients" in channels:
        current["alert_email_recipients"] = channels["alert_email_recipients"]
    _save_raw_settings(current)


def _save_raw_settings(data: dict) -> None:
    """Write arbitrary keys to settings.json without going through save_settings validation."""
    import json, os
    from .settings import SETTINGS_FILE

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    try:
        with open(SETTINGS_FILE) as f:
            existing = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing = {}
    existing.update(data)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# ── Core evaluation ────────────────────────────────────────────────────────────


def check_thresholds(
    audit_summary: dict,
    schedule_id: str | None = None,
    audit_id: str | None = None,
    hostname: str | None = None,
) -> AlertResult:
    """Evaluate audit_summary against thresholds.  Fire alert if new breach.

    Never raises — all errors are caught and logged.
    """
    try:
        return _check_thresholds_impl(audit_summary, schedule_id, audit_id, hostname)
    except Exception as exc:  # noqa: BLE001
        logger.error("check_thresholds failed unexpectedly: %s", exc)
        return AlertResult()


def _check_thresholds_impl(
    audit_summary: dict,
    schedule_id: str | None,
    audit_id: str | None,
    hostname: str | None,
) -> AlertResult:
    state_key = schedule_id or _MANUAL_SENTINEL
    thresholds = get_effective_thresholds(schedule_id)

    if not thresholds:
        return AlertResult()

    # Evaluate each threshold
    newly_breached: list[dict] = []
    for t in thresholds:
        value = _extract_metric(audit_summary, t["metric"])
        if value is None:
            logger.debug("Metric %s not found in summary — skipping", t["metric"])
            continue
        if _operator_matches(value, t["operator"], t["threshold_value"]):
            newly_breached.append({
                "metric": t["metric"],
                "operator": t["operator"],
                "threshold_value": t["threshold_value"],
                "actual_value": value,
            })

    # Load current state
    state = _get_state(state_key)
    in_breach = bool(state.get("in_breach"))
    prev_metrics = set(state.get("breached_metrics_list", []))
    current_metrics = {m["metric"] for m in newly_breached}

    result = AlertResult()

    if not newly_breached:
        if in_breach:
            # Condition cleared — re-arm
            _clear_state(state_key)
            result.cleared = True
            logger.info("Alert cleared for schedule=%s", state_key)
        return result

    # There are breached thresholds
    new_only = [m for m in newly_breached if m["metric"] not in prev_metrics]

    if in_breach and not new_only:
        # Already notified, no new metrics
        result.suppressed = True
        return result

    # Fire alert — either first breach or new metrics added
    result.breached = True
    result.breached_metrics = new_only if in_breach else newly_breached

    _set_state(state_key, audit_id, current_metrics | prev_metrics)

    # Dispatch
    _dispatch_alert(result.breached_metrics, audit_summary, audit_id, hostname)

    return result


def _extract_metric(summary: dict, metric: str) -> float | None:
    """Extract a numeric value from the audit summary for the given metric key."""
    if metric == "score":
        v = summary.get("score")
        return float(v) if v is not None else None
    if metric in _SEVERITY_METRICS:
        v = summary.get(metric)
        return float(v) if v is not None else None
    if metric in _COMPLIANCE_METRICS:
        compliance = summary.get("compliance") or {}
        fw_data = compliance.get(metric) or {}
        v = fw_data.get("score")
        return float(v) if v is not None else None
    return None


def _operator_matches(value: float, operator: str, threshold: float) -> bool:
    if operator == "lt":
        return value < threshold
    if operator == "gte":
        return value >= threshold
    return False


# ── State management ───────────────────────────────────────────────────────────


def _get_state(state_key: str) -> dict:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM alert_state WHERE schedule_id = ?", (state_key,)
    ).fetchone()
    if not row:
        return {"in_breach": 0, "breached_metrics_list": []}
    d = dict(row)
    d["breached_metrics_list"] = json.loads(d.get("breached_metrics") or "[]")
    return d


def _set_state(state_key: str, audit_id: str | None, all_metrics: set[str]) -> None:
    conn = get_conn()
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        """
        INSERT INTO alert_state (schedule_id, in_breach, breach_started_at, breach_audit_id, breached_metrics)
        VALUES (?, 1, ?, ?, ?)
        ON CONFLICT(schedule_id) DO UPDATE SET
            in_breach         = 1,
            breach_audit_id   = excluded.breach_audit_id,
            breached_metrics  = excluded.breached_metrics
        """,
        (state_key, now, audit_id or "", json.dumps(sorted(all_metrics))),
    )
    conn.commit()


def _clear_state(state_key: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE alert_state SET in_breach = 0, breached_metrics = '[]' WHERE schedule_id = ?",
        (state_key,),
    )
    conn.commit()


# ── Dispatch ───────────────────────────────────────────────────────────────────


def _dispatch_alert(
    breached_metrics: list[dict],
    summary: dict,
    audit_id: str | None,
    hostname: str | None,
) -> None:
    """Send consolidated breach alert to all configured channels."""
    from .activity_log import log_activity
    from .settings import get_settings
    from .notify import send_slack, send_teams, send_email, validate_webhook_url

    channels = get_alert_channels()
    settings = get_settings()
    extra_domains = [
        d.strip() for d in settings.get("webhook_allowlist", "").split(",") if d.strip()
    ]

    subject = _build_subject(hostname, summary)
    body = _build_body(breached_metrics, summary, audit_id, hostname)

    # Reuse notify.py send functions with a synthetic "schedule" dict
    # so the existing email/slack/teams helpers work without modification.
    synthetic_schedule = {
        "id": "__alert__",
        "vendor": "",
        "host": hostname or "unknown",
        "tag": "",
    }

    if channels.get("alert_slack_webhook"):
        _send_alert_slack(
            channels["alert_slack_webhook"],
            breached_metrics,
            summary,
            hostname,
            extra_domains,
        )

    if channels.get("alert_teams_webhook"):
        _send_alert_teams(
            channels["alert_teams_webhook"],
            breached_metrics,
            summary,
            hostname,
            extra_domains,
        )

    for recipient in _parse_recipients(channels.get("alert_email_recipients", "")):
        _send_alert_email(recipient, subject, body, settings)

    log_activity(
        "threshold_breach",
        hostname or "unknown",
        success=True,
        details={
            "breached_metrics": [m["metric"] for m in breached_metrics],
            "audit_id": audit_id or "",
        },
    )


def _build_subject(hostname: str | None, summary: dict) -> str:
    host = hostname or "unknown"
    score = summary.get("score", "?")
    return f"[Cashel Alert] Audit threshold breach — {host} (score: {score})"


def _build_body(
    breached_metrics: list[dict],
    summary: dict,
    audit_id: str | None,
    hostname: str | None,
) -> str:
    import os
    host = hostname or "unknown"
    score = summary.get("score", "?")
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"Audit threshold breach detected for: {host}",
        f"Audit ID: {audit_id or 'n/a'} | Score: {score}/100 | {ts}",
        "",
        "Breached thresholds:",
    ]
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        lines.append(
            f"  \u2717 {m['metric'].upper()}: {m['actual_value']} "
            f"(threshold: {op_str} {m['threshold_value']})"
        )
    base_url = os.environ.get("CASHEL_BASE_URL", "").rstrip("/")
    if base_url and audit_id:
        lines += ["", f"View full audit: {base_url}/history"]
    lines += ["", "\u2014 Cashel Firewall Auditor"]
    return "\n".join(lines)


def _parse_recipients(recipients_str: str) -> list[str]:
    return [r.strip() for r in recipients_str.split(",") if r.strip()]


def _send_alert_slack(
    webhook_url: str,
    breached_metrics: list[dict],
    summary: dict,
    hostname: str | None,
    extra_domains: list[str],
) -> None:
    import json as _json
    import urllib.request, urllib.error
    from .notify import validate_webhook_url

    valid, reason = validate_webhook_url(webhook_url, extra_domains)
    if not valid:
        logger.warning("Alert Slack webhook blocked: %s", reason)
        return

    host = hostname or "unknown"
    score = summary.get("score", "?")
    lines = [f":warning: *Cashel threshold breach* — {host} (score: {score}/100)", ""]
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        lines.append(
            f"• *{m['metric'].upper()}*: {m['actual_value']} "
            f"(threshold: {op_str} {m['threshold_value']})"
        )
    payload = _json.dumps({"text": "\n".join(lines)}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert Slack dispatch failed: %s", exc)


def _send_alert_teams(
    webhook_url: str,
    breached_metrics: list[dict],
    summary: dict,
    hostname: str | None,
    extra_domains: list[str],
) -> None:
    import json as _json
    import urllib.request, urllib.error
    from .notify import validate_webhook_url

    valid, reason = validate_webhook_url(webhook_url, extra_domains)
    if not valid:
        logger.warning("Alert Teams webhook blocked: %s", reason)
        return

    host = hostname or "unknown"
    score = summary.get("score", "?")
    facts = []
    for m in breached_metrics:
        op_str = "<" if m["operator"] == "lt" else ">="
        facts.append({
            "name": m["metric"].upper(),
            "value": f"{m['actual_value']} (threshold: {op_str} {m['threshold_value']})",
        })
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "CC2200",
        "summary": f"Cashel threshold breach — {host}",
        "sections": [{
            "activityTitle": "**Cashel Firewall Auditor — Threshold Breach**",
            "activitySubtitle": f"{host} | Score: {score}/100",
            "facts": facts,
        }],
    }
    payload = _json.dumps(card).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert Teams dispatch failed: %s", exc)


def _send_alert_email(
    recipient: str,
    subject: str,
    body: str,
    smtp_cfg: dict,
) -> None:
    import smtplib, ssl
    from email.mime.text import MIMEText

    smtp_host = (smtp_cfg.get("smtp_host") or "").strip()
    if not smtp_host:
        logger.warning("Alert email skipped: smtp_host not configured.")
        return

    smtp_port = int(smtp_cfg.get("smtp_port") or 587)
    smtp_user = (smtp_cfg.get("smtp_user") or "").strip()
    smtp_password = smtp_cfg.get("smtp_password") or ""
    smtp_from = (smtp_cfg.get("smtp_from") or smtp_user or "cashel@localhost").strip()
    use_tls = bool(smtp_cfg.get("smtp_tls", True))

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = recipient

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [recipient], msg.as_string())
        logger.info("Alert email sent to %s", recipient)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert email failed to %s: %s", recipient, exc)


# ── Internal helpers ───────────────────────────────────────────────────────────


def _threshold_row(row) -> dict:
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    d["threshold_value"] = float(d["threshold_value"])
    return d
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_alert_engine.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Run full test suite to confirm no regressions**

```bash
pytest tests/ -v
```

Expected: All existing tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add src/cashel/alert_engine.py tests/test_alert_engine.py
git commit -m "feat: alert_engine — threshold evaluation, dedup, and dispatch (#46)"
```

---

## Task 3: Wire `check_thresholds` into `scheduler_runner.py`

**Files:**
- Modify: `src/cashel/scheduler_runner.py`

- [ ] **Step 1: Locate the post-audit block in `_run_scheduled_audit`**

In `src/cashel/scheduler_runner.py`, find the block after `save_audit(...)` and before the `notify_on_finding` check (around line 143). The insertion point is after `record_run(schedule_id, "ok")`.

- [ ] **Step 2: Add the import and call**

Add to the imports at the top of `_run_scheduled_audit` (the function-local imports block at line 22):

```python
    from .alert_engine import check_thresholds
```

After `record_run(schedule_id, "ok")` (line 143), add:

```python
        try:
            check_thresholds(
                summary,
                schedule_id=schedule_id,
                audit_id=None,
                hostname=host,
            )
        except Exception as _ae:  # noqa: BLE001
            logger.warning("check_thresholds failed for schedule %s: %s", schedule_id, _ae)
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/ -v
```

Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/cashel/scheduler_runner.py
git commit -m "feat: call check_thresholds after each scheduled audit (#46)"
```

---

## Task 4: API routes in `settings_bp.py`

**Files:**
- Modify: `src/cashel/blueprints/settings_bp.py`

- [ ] **Step 1: Add 5 new routes**

Append to the end of `src/cashel/blueprints/settings_bp.py`:

```python
# ── Alert Thresholds ──────────────────────────────────────────────────────────

from cashel.alert_engine import (  # noqa: E402
    list_thresholds,
    save_threshold as _save_threshold,
    delete_threshold as _delete_threshold,
    get_alert_channels,
    save_alert_channels as _save_alert_channels,
)


@settings_bp.route("/settings/alert-thresholds", methods=["GET"])
@_require_role("admin")
def alert_thresholds_get():
    return jsonify(list_thresholds())


@settings_bp.route("/settings/alert-thresholds", methods=["POST"])
@_require_role("admin")
def alert_thresholds_save():
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    metric = data.get("metric", "")
    operator = data.get("operator", "")
    from cashel.alert_engine import VALID_METRICS, VALID_OPERATORS
    if metric not in VALID_METRICS:
        return jsonify({"error": f"Invalid metric: {metric}"}), 400
    if operator not in VALID_OPERATORS:
        return jsonify({"error": f"Invalid operator: {operator}"}), 400
    try:
        threshold_value = float(data["threshold_value"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "threshold_value must be a number"}), 400
    saved = _save_threshold({
        "id": data.get("id"),
        "schedule_id": data.get("schedule_id") or None,
        "metric": metric,
        "operator": operator,
        "threshold_value": threshold_value,
        "enabled": bool(data.get("enabled", True)),
    })
    return jsonify(saved), 201


@settings_bp.route("/settings/alert-thresholds/<threshold_id>", methods=["DELETE"])
@_require_role("admin")
def alert_thresholds_delete(threshold_id):
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    deleted = _delete_threshold(threshold_id)
    if not deleted:
        return jsonify({"error": "Threshold not found"}), 404
    return jsonify({"ok": True})


@settings_bp.route("/settings/alert-channels", methods=["GET"])
@_require_role("admin")
def alert_channels_get():
    channels = get_alert_channels()
    # Mask webhook URLs — return only whether they are set
    return jsonify({
        "alert_slack_webhook_set": bool(channels.get("alert_slack_webhook")),
        "alert_teams_webhook_set": bool(channels.get("alert_teams_webhook")),
        "alert_email_recipients": channels.get("alert_email_recipients", ""),
    })


@settings_bp.route("/settings/alert-channels", methods=["POST"])
@_require_role("admin")
def alert_channels_save():
    if DEMO_MODE:
        return jsonify({"error": "Not available in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    _save_alert_channels({
        "alert_slack_webhook": data.get("alert_slack_webhook", ""),
        "alert_teams_webhook": data.get("alert_teams_webhook", ""),
        "alert_email_recipients": data.get("alert_email_recipients", ""),
    })
    return jsonify({"ok": True})
```

- [ ] **Step 2: Run tests**

```bash
pytest tests/ -v
```

Expected: All tests PASS.

- [ ] **Step 3: Run linter**

```bash
ruff check src/cashel/blueprints/settings_bp.py
ruff format --check src/cashel/blueprints/settings_bp.py
```

Expected: No errors. If format issues, run `ruff format src/cashel/blueprints/settings_bp.py`.

- [ ] **Step 4: Commit**

```bash
git add src/cashel/blueprints/settings_bp.py
git commit -m "feat: alert threshold and channel CRUD routes (#46)"
```

---

## Task 5: Settings UI — Alert Thresholds pane

**Files:**
- Modify: `src/cashel/templates/index.html`

This task adds a new sidebar nav item and pane to the Settings section, plus the JS to manage it. The pane is admin-only and appears between Syslog and the footer.

- [ ] **Step 1: Add the sidebar nav item**

In `src/cashel/templates/index.html`, find this block (around line 850):

```html
          <button class="settings-nav-item" data-pane="syslog">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="1" y="1.5" width="14" height="5" rx="1.5"/><rect x="1" y="9.5" width="14" height="5" rx="1.5"/><circle cx="4" cy="4" r="0.8" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="0.8" fill="currentColor" stroke="none"/><line x1="7" y1="4" x2="12" y2="4"/><line x1="7" y1="12" x2="12" y2="12"/></svg>
            Syslog
          </button>
```

Add a new nav item immediately after it (before the `{% endif %}{# /admin-only security+syslog panes #}` comment — which is actually further down — just add after the Syslog button):

```html
          <button class="settings-nav-item" data-pane="alerts">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 1.5a4.5 4.5 0 0 1 4.5 4.5c0 2 .8 3.2 1.5 4H2c.7-.8 1.5-2 1.5-4A4.5 4.5 0 0 1 8 1.5z"/><path d="M6.5 14a1.5 1.5 0 0 0 3 0"/></svg>
            Alert Thresholds
          </button>
```

- [ ] **Step 2: Add the Alert Thresholds pane HTML**

Find `</div><!-- /.settings-content -->` (around line 1199) and insert the new pane immediately before the closing `{% endif %}{# /admin-only security+syslog panes #}` line (line 1189). Insert after the closing `</div>` of the syslog pane (after line 1188):

```html
          <!-- Alert Thresholds pane -->
          <div class="settings-pane" id="spane-alerts">
            <div class="settings-pane-header">
              <h2 class="settings-pane-title">Alert Thresholds</h2>
              <p class="settings-pane-desc">Fire a consolidated notification when an audit result crosses a configured threshold. Alerts fire once on first breach and re-arm after the condition clears.</p>
            </div>

            <div class="settings-group">
              <h3 class="settings-group-title">Alert Channels</h3>
              <p class="settings-row-desc" style="margin-bottom:0.75rem">Separate from per-schedule notifications — these channels receive threshold breach alerts only.</p>
              <div class="form-grid">
                <div class="form-group">
                  <label for="alert-slack-webhook">Slack Webhook URL</label>
                  <input type="password" id="alert-slack-webhook" placeholder="https://hooks.slack.com/services/…" autocomplete="off" />
                  <span class="form-hint" id="alert-slack-set-hint" style="display:none">&#10003; Webhook configured (enter new URL to replace)</span>
                </div>
                <div class="form-group">
                  <label for="alert-teams-webhook">Teams Webhook URL</label>
                  <input type="password" id="alert-teams-webhook" placeholder="https://webhook.office.com/…" autocomplete="off" />
                  <span class="form-hint" id="alert-teams-set-hint" style="display:none">&#10003; Webhook configured (enter new URL to replace)</span>
                </div>
                <div class="form-group" style="grid-column:1/-1">
                  <label for="alert-email-recipients">Email Recipients</label>
                  <input type="text" id="alert-email-recipients" placeholder="ops@example.com, security@example.com" autocomplete="off" />
                  <span class="form-hint">Comma-separated. Uses the SMTP settings from the Email pane.</span>
                </div>
              </div>
              <button class="btn-secondary" id="saveAlertChannelsBtn" style="margin-top:0.75rem">Save Channels</button>
              <span class="settings-saved-msg hidden" id="alertChannelsSavedMsg">&#10003; Saved</span>
            </div>

            <div class="settings-group" style="margin-top:1.5rem">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem">
                <h3 class="settings-group-title" style="margin:0">Global Thresholds</h3>
                <button class="btn-secondary" id="addGlobalThresholdBtn">+ Add Threshold</button>
              </div>
              <p class="settings-row-desc">Applied to all audits. Per-schedule overrides (below) take precedence on a per-metric basis.</p>
              <div id="globalThresholdsTable">
                <p class="muted" id="noGlobalThresholds">No global thresholds configured.</p>
              </div>
            </div>

            <div class="settings-group" style="margin-top:1.5rem">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem">
                <h3 class="settings-group-title" style="margin:0">Per-Schedule Overrides</h3>
              </div>
              <p class="settings-row-desc">Select a schedule to view or add overrides. An override replaces the global threshold for that metric on that schedule only.</p>
              <div class="form-group" style="max-width:300px;margin-bottom:1rem">
                <label for="alertScheduleSelect">Schedule</label>
                <select id="alertScheduleSelect">
                  <option value="">— Select a schedule —</option>
                </select>
              </div>
              <div id="scheduleThresholdsTable" style="display:none">
                <div style="display:flex;justify-content:flex-end;margin-bottom:0.5rem">
                  <button class="btn-secondary" id="addScheduleThresholdBtn">+ Add Override</button>
                </div>
                <div id="scheduleThresholdsList">
                  <p class="muted" id="noScheduleThresholds">No overrides for this schedule.</p>
                </div>
              </div>
            </div>
          </div>
```

- [ ] **Step 3: Add the threshold row form template (hidden)**

Immediately after the new pane `</div>`, before `{% endif %}{# /admin-only... #}`, add a hidden template for adding thresholds:

```html
          <!-- Hidden threshold add form (reused for global and per-schedule) -->
          <div id="addThresholdModal" class="modal-overlay hidden" role="dialog" aria-modal="true">
            <div class="modal-box" style="max-width:420px">
              <div class="modal-header">
                <h3 class="modal-title" id="addThresholdModalTitle">Add Threshold</h3>
                <button class="modal-close" id="addThresholdModalClose">&times;</button>
              </div>
              <div class="modal-body">
                <input type="hidden" id="addThresholdScheduleId" value="" />
                <div class="form-group">
                  <label for="addThresholdMetric">Metric</label>
                  <select id="addThresholdMetric">
                    <optgroup label="Overall">
                      <option value="score">Score (0–100)</option>
                    </optgroup>
                    <optgroup label="Finding Counts">
                      <option value="high">High findings</option>
                      <option value="medium">Medium findings</option>
                      <option value="low">Low findings</option>
                      <option value="total">Total findings</option>
                    </optgroup>
                    <optgroup label="Compliance (%)">
                      <option value="pci">PCI-DSS</option>
                      <option value="cis">CIS</option>
                      <option value="nist">NIST</option>
                      <option value="hipaa">HIPAA</option>
                      <option value="soc2">SOC2</option>
                      <option value="stig">STIG</option>
                    </optgroup>
                  </select>
                </div>
                <div class="form-group">
                  <label for="addThresholdOperator">Condition</label>
                  <select id="addThresholdOperator">
                    <option value="lt">Below (&lt;)</option>
                    <option value="gte">At or above (&ge;)</option>
                  </select>
                </div>
                <div class="form-group">
                  <label for="addThresholdValue">Value</label>
                  <input type="number" id="addThresholdValue" min="0" max="10000" step="0.1" placeholder="e.g. 70" />
                </div>
                <div style="display:flex;gap:0.5rem;margin-top:1rem">
                  <button class="btn-primary" id="saveThresholdBtn">Save</button>
                  <button class="btn-secondary" id="cancelThresholdBtn">Cancel</button>
                </div>
                <span class="alert-inline hidden" id="addThresholdError" style="display:block;margin-top:0.5rem"></span>
              </div>
            </div>
          </div>
```

- [ ] **Step 4: Add the JS for the Alert Thresholds pane**

Find the `// ═════════════════════════════════════════════════════════ SETTINGS ══` comment section end (after the `saveSettingsBtn` event listener, around line 2799). Add the following JS block immediately after:

```javascript
  // ═══════════════════════════════════════════════ ALERT THRESHOLDS ══

  const METRIC_LABELS = {
    score: "Score", high: "High findings", medium: "Medium findings",
    low: "Low findings", total: "Total findings",
    pci: "PCI-DSS (%)", cis: "CIS (%)", nist: "NIST (%)",
    hipaa: "HIPAA (%)", soc2: "SOC2 (%)", stig: "STIG (%)",
  };
  const OP_LABELS = { lt: "<", gte: "≥" };
  let _allThresholds = [];
  let _activeThresholdScheduleId = null;

  async function loadAlertChannels() {
    try {
      const res = await fetch("/settings/alert-channels");
      if (!res.ok) return;
      const data = await res.json();
      const slackHint = document.getElementById("alert-slack-set-hint");
      const teamsHint = document.getElementById("alert-teams-set-hint");
      if (slackHint) slackHint.style.display = data.alert_slack_webhook_set ? "" : "none";
      if (teamsHint) teamsHint.style.display = data.alert_teams_webhook_set ? "" : "none";
      const emailEl = document.getElementById("alert-email-recipients");
      if (emailEl) emailEl.value = data.alert_email_recipients || "";
    } catch (_) {}
  }

  async function loadAlertThresholds() {
    try {
      const res = await fetch("/settings/alert-thresholds");
      if (!res.ok) return;
      _allThresholds = await res.json();
      renderGlobalThresholds();
      renderScheduleThresholds(_activeThresholdScheduleId);
    } catch (_) {}
  }

  function renderGlobalThresholds() {
    const container = document.getElementById("globalThresholdsTable");
    const noMsg = document.getElementById("noGlobalThresholds");
    if (!container) return;
    const globals = _allThresholds.filter(t => !t.schedule_id);
    if (!globals.length) {
      if (noMsg) noMsg.style.display = "";
      container.querySelectorAll("table").forEach(el => el.remove());
      return;
    }
    if (noMsg) noMsg.style.display = "none";
    container.querySelectorAll("table").forEach(el => el.remove());
    container.appendChild(_buildThresholdTable(globals));
  }

  function renderScheduleThresholds(scheduleId) {
    const container = document.getElementById("scheduleThresholdsList");
    const noMsg = document.getElementById("noScheduleThresholds");
    if (!container) return;
    if (!scheduleId) return;
    const overrides = _allThresholds.filter(t => t.schedule_id === scheduleId);
    if (!overrides.length) {
      if (noMsg) noMsg.style.display = "";
      container.querySelectorAll("table").forEach(el => el.remove());
      return;
    }
    if (noMsg) noMsg.style.display = "none";
    container.querySelectorAll("table").forEach(el => el.remove());
    container.appendChild(_buildThresholdTable(overrides));
  }

  function _buildThresholdTable(thresholds) {
    const table = document.createElement("table");
    table.className = "data-table";
    table.innerHTML = `<thead><tr><th>Metric</th><th>Condition</th><th>Value</th><th></th></tr></thead>`;
    const tbody = document.createElement("tbody");
    for (const t of thresholds) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${METRIC_LABELS[t.metric] || t.metric}</td>
        <td>${OP_LABELS[t.operator] || t.operator}</td>
        <td>${t.threshold_value}</td>
        <td><button class="btn-danger-sm" data-tid="${t.id}">Delete</button></td>
      `;
      tr.querySelector("[data-tid]").addEventListener("click", async () => {
        await deleteAlertThreshold(t.id);
      });
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    return table;
  }

  async function deleteAlertThreshold(id) {
    try {
      const csrf = document.querySelector("meta[name='csrf-token']")?.content || "";
      const res = await fetch(`/settings/alert-thresholds/${id}`, {
        method: "DELETE",
        headers: { "X-CSRFToken": csrf },
      });
      if (res.ok) await loadAlertThresholds();
    } catch (_) {}
  }

  async function saveAlertThreshold(metric, operator, value, scheduleId) {
    const csrf = document.querySelector("meta[name='csrf-token']")?.content || "";
    try {
      const res = await fetch("/settings/alert-thresholds", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
        body: JSON.stringify({
          metric, operator,
          threshold_value: parseFloat(value),
          enabled: true,
          schedule_id: scheduleId || null,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        return err.error || "Failed to save threshold";
      }
      await loadAlertThresholds();
      return null;
    } catch (_) { return "Request failed"; }
  }

  // Add threshold modal
  let _addThresholdForSchedule = null;
  function openAddThresholdModal(scheduleId) {
    _addThresholdForSchedule = scheduleId || null;
    const modal = document.getElementById("addThresholdModal");
    const title = document.getElementById("addThresholdModalTitle");
    if (title) title.textContent = scheduleId ? "Add Schedule Override" : "Add Global Threshold";
    const errEl = document.getElementById("addThresholdError");
    if (errEl) { errEl.textContent = ""; errEl.classList.add("hidden"); }
    if (modal) modal.classList.remove("hidden");
  }

  document.getElementById("addGlobalThresholdBtn")?.addEventListener("click", () => openAddThresholdModal(null));
  document.getElementById("addScheduleThresholdBtn")?.addEventListener("click", () => openAddThresholdModal(_activeThresholdScheduleId));
  document.getElementById("addThresholdModalClose")?.addEventListener("click", () => {
    document.getElementById("addThresholdModal")?.classList.add("hidden");
  });
  document.getElementById("cancelThresholdBtn")?.addEventListener("click", () => {
    document.getElementById("addThresholdModal")?.classList.add("hidden");
  });

  document.getElementById("saveThresholdBtn")?.addEventListener("click", async () => {
    const metric   = document.getElementById("addThresholdMetric").value;
    const operator = document.getElementById("addThresholdOperator").value;
    const value    = document.getElementById("addThresholdValue").value;
    const errEl    = document.getElementById("addThresholdError");
    if (!value || isNaN(parseFloat(value))) {
      if (errEl) { errEl.textContent = "Please enter a numeric value."; errEl.classList.remove("hidden"); }
      return;
    }
    const err = await saveAlertThreshold(metric, operator, value, _addThresholdForSchedule);
    if (err) {
      if (errEl) { errEl.textContent = err; errEl.classList.remove("hidden"); }
    } else {
      document.getElementById("addThresholdModal")?.classList.add("hidden");
    }
  });

  document.getElementById("saveAlertChannelsBtn")?.addEventListener("click", async () => {
    const csrf = document.querySelector("meta[name='csrf-token']")?.content || "";
    const data = {
      alert_slack_webhook:   document.getElementById("alert-slack-webhook")?.value.trim() || "",
      alert_teams_webhook:   document.getElementById("alert-teams-webhook")?.value.trim() || "",
      alert_email_recipients: document.getElementById("alert-email-recipients")?.value.trim() || "",
    };
    try {
      const res = await fetch("/settings/alert-channels", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
        body: JSON.stringify(data),
      });
      if (res.ok) {
        await loadAlertChannels();
        const msg = document.getElementById("alertChannelsSavedMsg");
        if (msg) { msg.classList.remove("hidden"); setTimeout(() => msg.classList.add("hidden"), 2500); }
      }
    } catch (_) {}
  });

  // Load schedule list into dropdown
  async function loadAlertScheduleSelect() {
    try {
      const res = await fetch("/schedules");
      if (!res.ok) return;
      const schedules = await res.json();
      const sel = document.getElementById("alertScheduleSelect");
      if (!sel) return;
      sel.innerHTML = '<option value="">— Select a schedule —</option>';
      for (const s of schedules) {
        const opt = document.createElement("option");
        opt.value = s.id;
        opt.textContent = s.name || `${s.vendor}@${s.host}`;
        sel.appendChild(opt);
      }
    } catch (_) {}
  }

  document.getElementById("alertScheduleSelect")?.addEventListener("change", function () {
    _activeThresholdScheduleId = this.value || null;
    const table = document.getElementById("scheduleThresholdsTable");
    if (table) table.style.display = _activeThresholdScheduleId ? "" : "none";
    if (_activeThresholdScheduleId) renderScheduleThresholds(_activeThresholdScheduleId);
  });

  // Load when alerts pane is activated
  document.querySelectorAll(".settings-nav-item[data-pane='alerts']").forEach(btn => {
    btn.addEventListener("click", () => {
      loadAlertChannels();
      loadAlertThresholds();
      loadAlertScheduleSelect();
    });
  });
```

- [ ] **Step 5: Run linter and verify no syntax issues**

```bash
ruff check src/cashel/ --include "*.py"
```

Expected: No errors.

- [ ] **Step 6: Run tests**

```bash
pytest tests/ -v
```

Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/cashel/templates/index.html
git commit -m "feat: Alert Thresholds settings pane with channels and CRUD UI (#46)"
```

---

## Task 6: Lint, format, type-check, and final test run

**Files:** All modified files.

- [ ] **Step 1: Run ruff lint**

```bash
ruff check src/ tests/
```

Expected: No errors. Fix any flagged issues.

- [ ] **Step 2: Run ruff format check**

```bash
ruff format --check src/ tests/
```

Expected: No files would be reformatted. If any, run `ruff format src/ tests/` and commit.

- [ ] **Step 3: Run mypy**

```bash
mypy src/cashel/ --ignore-missing-imports
```

Expected: No errors (or only pre-existing ones — do not regress).

- [ ] **Step 4: Run full test suite**

```bash
pytest tests/ -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit any lint/format fixes**

```bash
git add -u
git commit -m "style: ruff format and lint fixes for threshold alerting"
```

Only create this commit if there were actual changes. Skip if clean.

---

## Task 7: Open PR to staging

- [ ] **Step 1: Verify branch is clean**

```bash
git status
git log --oneline origin/staging..HEAD
```

Expected: All commits from Tasks 1–6 are present, working tree is clean.

- [ ] **Step 2: Push and open PR**

```bash
git push -u origin HEAD
gh pr create \
  --base staging \
  --title "feat: threshold-based alerting (#46)" \
  --body "$(cat <<'EOF'
## Summary
- New `alert_engine.py` module: threshold evaluation, dedup/re-arm state, consolidated dispatch
- Two new SQLite tables: `alert_thresholds`, `alert_state`
- `scheduler_runner.py` calls `check_thresholds()` after each audit
- 5 new routes in `settings_bp.py` for threshold and channel CRUD
- Alert Thresholds pane in Settings UI (global defaults + per-schedule overrides)

## Test plan
- [ ] `pytest tests/test_alert_engine.py -v` — all new tests pass
- [ ] `pytest tests/ -v` — no regressions
- [ ] Manually configure a score threshold < current score, run an audit, verify Slack/email fires
- [ ] Verify second audit with same breach is suppressed (no duplicate alert)
- [ ] Verify breach clears when score improves, and re-fires on next breach

Closes #46

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Post-merge: close issue

After the PR merges to staging and passes CI, merge staging → main, then close issue #46:

```bash
gh issue close 46 --comment "Implemented in PR — threshold alerting shipped in this release."
```
