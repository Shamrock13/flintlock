"""Tests for alert_engine.py — threshold evaluation and dedup logic."""

import functools
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.db as db_mod


def _tmp_db(fn):
    """Decorator: run test against an isolated temp database."""

    @functools.wraps(fn)
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


from cashel import alert_engine  # noqa: E402


class TestThresholdCRUD(unittest.TestCase):
    @_tmp_db
    def test_save_and_get_global_threshold(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
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
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        # Override: alert if score < 80
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 80.0,
                "enabled": True,
                "schedule_id": "sched-abc",
            }
        )
        effective = alert_engine.get_effective_thresholds(schedule_id="sched-abc")
        score_thresholds = [t for t in effective if t["metric"] == "score"]
        self.assertEqual(len(score_thresholds), 1)
        self.assertAlmostEqual(score_thresholds[0]["threshold_value"], 80.0)

    @_tmp_db
    def test_global_used_when_no_override(self):
        alert_engine.save_threshold(
            {
                "metric": "high",
                "operator": "gte",
                "threshold_value": 1.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        effective = alert_engine.get_effective_thresholds(schedule_id="sched-xyz")
        self.assertEqual(len(effective), 1)
        self.assertEqual(effective[0]["metric"], "high")

    @_tmp_db
    def test_delete_threshold(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        thresholds = alert_engine.get_effective_thresholds()
        tid = thresholds[0]["id"]
        alert_engine.delete_threshold(tid)
        self.assertEqual(alert_engine.get_effective_thresholds(), [])

    @_tmp_db
    def test_disabled_threshold_not_evaluated(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": False,
                "schedule_id": None,
            }
        )
        summary = {"score": 50, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id=None)
        self.assertFalse(result.breached)


class TestThresholdEvaluation(unittest.TestCase):
    @_tmp_db
    def test_lt_operator_breaches_when_below(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {"score": 65, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(len(result.breached_metrics), 1)
        self.assertEqual(result.breached_metrics[0]["metric"], "score")

    @_tmp_db
    def test_lt_operator_no_breach_when_above(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {"score": 85, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertFalse(result.breached)

    @_tmp_db
    def test_gte_operator_breaches_when_at_or_above(self):
        alert_engine.save_threshold(
            {
                "metric": "high",
                "operator": "gte",
                "threshold_value": 1.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {"score": 90, "high": 1, "medium": 0, "low": 0, "total": 1}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)

    @_tmp_db
    def test_compliance_metric_breach(self):
        alert_engine.save_threshold(
            {
                "metric": "pci",
                "operator": "lt",
                "threshold_value": 100.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {
            "score": 90,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
            "compliance": {"pci": {"score": 87}},
        }
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(result.breached_metrics[0]["metric"], "pci")

    @_tmp_db
    def test_missing_metric_key_no_breach(self):
        """Metric not in summary should not trigger a breach."""
        alert_engine.save_threshold(
            {
                "metric": "pci",
                "operator": "lt",
                "threshold_value": 100.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        # summary has no 'compliance' key
        summary = {"score": 90, "high": 0, "medium": 0, "low": 0, "total": 0}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertFalse(result.breached)

    @_tmp_db
    def test_multiple_thresholds_consolidated(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        alert_engine.save_threshold(
            {
                "metric": "high",
                "operator": "gte",
                "threshold_value": 1.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {"score": 55, "high": 3, "medium": 0, "low": 0, "total": 3}
        result = alert_engine.check_thresholds(summary, schedule_id="s1")
        self.assertTrue(result.breached)
        self.assertEqual(len(result.breached_metrics), 2)


class TestAlertDedup(unittest.TestCase):
    @_tmp_db
    def test_second_breach_suppressed(self):
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
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
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        bad_summary = {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0}
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
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        alert_engine.save_threshold(
            {
                "metric": "high",
                "operator": "gte",
                "threshold_value": 1.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
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
        alert_engine.save_threshold(
            {
                "metric": "score",
                "operator": "lt",
                "threshold_value": 70.0,
                "enabled": True,
                "schedule_id": None,
            }
        )
        summary = {"score": 55, "high": 0, "medium": 0, "low": 0, "total": 0}
        r1 = alert_engine.check_thresholds(summary, schedule_id=None)
        r2 = alert_engine.check_thresholds(summary, schedule_id=None)
        self.assertTrue(r1.breached)
        self.assertTrue(r2.suppressed)


if __name__ == "__main__":
    unittest.main()
