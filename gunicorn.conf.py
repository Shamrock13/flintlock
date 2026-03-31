"""Gunicorn configuration for Cashel.

Start the APScheduler background scheduler in only one worker to avoid
duplicate job execution.  The scheduler is started in `post_fork` for
the first worker (worker with the lowest PID) so that threads are
created after forking and survive correctly.
"""

import os

# ── Server ────────────────────────────────────────────────────────────────────
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
timeout = 120
preload_app = False  # each worker imports the app independently

# ── Scheduler ─────────────────────────────────────────────────────────────────
_scheduler_started = False


def post_fork(server, worker):
    """Start the APScheduler in the first worker only."""
    global _scheduler_started
    if not _scheduler_started:
        _scheduler_started = True
        worker._cashel_scheduler = True
    else:
        # Prevent non-scheduler workers from running the scheduler
        os.environ["CASHEL_SKIP_SCHEDULER"] = "1"
