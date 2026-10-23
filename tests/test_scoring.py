"""Scoring model tests: weights, thresholds, severity bands, escalation."""
from __future__ import annotations

import itertools

from app import scoring
from app.config import Settings
from app.db import Database
from app.normalize import now_iso

_seq = itertools.count(1)


def _add_signal(db: Database, pc: str, rule_id: str, category: str,
                weight: int, ts: str | None = None) -> None:
    db.execute(
        "INSERT INTO signals(ts, pc, rule_id, category, weight, title, detail, "
        "correlation, dedup_key) VALUES(?,?,?,?,?,?,?,?,?)",
        (ts or now_iso(), pc, rule_id, category, weight, f"{rule_id} on {pc}", "",
         "[]", f"{pc}|{rule_id}|{next(_seq)}"))


class TestScorePc:
    def test_no_signals_returns_none(self, db: Database, settings: Settings):
        assert scoring.score_pc(db, settings, "NOBODY") is None

    def test_distinct_rules_sum_repeats_do_not_stack(self, db: Database, settings: Settings):
        w = settings.rule_weights["dns_mining_pool"]  # 15
        for _ in range(5):
            _add_signal(db, "PC-A", "dns_mining_pool", "miner", w)
        result = scoring.score_pc(db, settings, "PC-A")
        assert result["score"] == w, "repeats of one rule must not stack"

    def test_below_threshold_is_not_an_alert(self, db: Database, settings: Settings):
        _add_signal(db, "PC-B", "acct_offhours_login", "account",
                    settings.rule_weights["acct_offhours_login"])  # 5 < 40
        result = scoring.score_pc(db, settings, "PC-B")
        assert result["alert"] is False
        assert result["severity"] is None

    def test_severity_bands(self, db: Database, settings: Settings):
        # 30 + 35 = 65 -> medium band
        _add_signal(db, "PC-C", "proc_bad_hash", "execution", 30)
        _add_signal(db, "PC-C", "defender_detection", "execution", 35)
        result = scoring.score_pc(db, settings, "PC-C")
        assert result["alert"] is True
        assert result["severity"] in ("medium", "high")  # execution x1 -> medium band

    def test_escalation_three_categories_to_high(self, db: Database, settings: Settings):
        # 45 + 25 + 20 = 90 score is already high; use lower weights to prove
        # the escalation: 40 (ransom_note) + 20 + 20 = 80 -> high band anyway.
        # Instead: 3 categories with total 60 -> medium band, escalation -> high.
        _add_signal(db, "PC-D", "acct_failed_burst", "account", 25)
        _add_signal(db, "PC-D", "pers_run_key", "persistence", 20)
        _add_signal(db, "PC-D", "evade_defender_rtp", "evasion", 15)
        result = scoring.score_pc(db, settings, "PC-D")
        assert result["score"] == 60
        assert len(result["categories"]) == 3
        assert result["severity"] == "high", "3 categories must escalate to high"

    def test_window_anchored_to_latest_signal(self, db: Database, settings: Settings):
        _add_signal(db, "PC-E", "proc_bad_hash", "execution", 30,
                    ts="2026-01-01T00:00:00Z")
        _add_signal(db, "PC-E", "defender_detection", "execution", 35,
                    ts="2026-06-01T00:00:00Z")  # months later: old signal out of window
        result = scoring.score_pc(db, settings, "PC-E")
        assert result["score"] == 35, "signals outside the window must not count"


class TestSeverityRank:
    def test_order(self):
        assert scoring.severity_rank("critical") > scoring.severity_rank("high")
        assert scoring.severity_rank("bogus") == 0


class TestSummarizeSignal:
    def test_handles_dict_and_row(self, settings: Settings):
        text = scoring.summarize_signal(settings, {"title": "T", "detail": "D"})
        assert text == "T - D"
        assert scoring.summarize_signal(settings, {"title": "T"}) == "T"

    def test_truncates_long_text(self, settings: Settings):
        long = {"title": "x" * 1000, "detail": "y" * 1000}
        assert len(scoring.summarize_signal(settings, long)) <= 400
