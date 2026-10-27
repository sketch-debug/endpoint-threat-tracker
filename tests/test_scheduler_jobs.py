"""Scheduler wiring smoke test: every periodic job is registered with sane
settings, and every real job callable runs clean once on a fresh DB.

Audit gap this closes: build_scheduler's job ids/intervals and the callable
wiring behind them were never exercised by a test - a renamed job id or a
bad wiring choice would merge green and only misbehave on the server.
"""
from __future__ import annotations

from app import alerts as alerts_mod
from app import auth, detect, health as health_mod, recheck as recheck_mod
from app import retention as retention_mod
from app.ingest import Ingestor
from app.main import build_scheduler


def _noop() -> None:
    return None


def _scheduler(settings):
    return build_scheduler(
        settings, ingest_fn=_noop, recheck_fn=_noop, sessions_fn=_noop,
        alert_flush_fn=_noop, retention_fn=_noop, heartbeat_fn=_noop)


class TestSchedulerWiring:
    def test_registers_every_periodic_job(self, settings):
        sched = _scheduler(settings)
        try:
            sched.start(paused=True)
            jobs = {j.id: j for j in sched.get_jobs()}
        finally:
            sched.shutdown(wait=False)
        assert set(jobs) == {"ingest", "recheck", "sessions",
                             "alert_flush", "retention", "heartbeat"}
        # a backlog must collapse into one run, never replay back-to-back
        assert all(j.max_instances == 1 for j in jobs.values())
        assert all(j.coalesce for j in jobs.values())
        assert jobs["ingest"].trigger.interval.total_seconds() == \
            max(5, settings.poll_seconds)
        assert jobs["retention"].trigger.interval.total_seconds() == 24 * 3600
        assert jobs["recheck"].trigger.interval.total_seconds() == 3600


class TestJobFunctionsRunOnce:
    def test_each_job_callable_runs_clean_on_a_fresh_db(
            self, settings, db, indicators):
        # exactly the callables the app lifespan wires, invoked once each
        # the way the scheduler would invoke them
        auth.purge_expired(db)
        assert retention_mod.run_retention(db, settings) is not None
        assert health_mod.run_heartbeat(db, settings) is not None
        alerts_mod.flush_pending_alerts(db, settings)
        recheck_mod.run_recheck_sweep(db, settings)
        ing = Ingestor(db, settings, indicators, detector=None)
        det = detect.Detector(db, settings, indicators)
        stats = detect.run_cycle(ing, det)
        assert isinstance(stats, dict)
