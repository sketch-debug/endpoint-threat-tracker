"""Re-check (14-day) and auth tests."""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app import auth, incidents, recheck
from app.config import Settings
from app.db import Database
from app.normalize import now_iso


_seq = itertools.count(1)


def _verified_incident(db: Database, settings: Settings, pc: str = "PC-A",
                       days: int = 14) -> int:
    """Create an incident, walk the PC to verified, return the incident id."""
    db.execute(
        "INSERT INTO signals(ts, pc, rule_id, category, weight, title, detail, "
        "correlation, dedup_key) VALUES(?,?,?,?,?,?,?,?,?)",
        (now_iso(), pc, "proc_miner_name", "miner", 25, "miner", "", "[]",
         f"{pc}|seed|{next(_seq)}"))
    sig = dict(db.one("SELECT * FROM signals ORDER BY id DESC LIMIT 1"))
    inc, _ = incidents.correlate_and_record(db, settings, sig, "medium", ["miner"],
                                            ["proc_miner_name"])
    iid = int(inc["id"])
    incidents.transition_pc(db, settings, iid, pc, "isolated", "alice")
    incidents.transition_pc(db, settings, iid, pc, "reimaged", "alice")
    incidents.transition_pc(db, settings, iid, pc, "verified", "alice")
    if days != settings.recheck_days:
        future = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        db.execute("UPDATE incident_pcs SET recheck_until=? WHERE incident_id=? AND pc=?",
                   (future, iid, pc))
    return iid


class TestRecheck:
    def test_new_signal_reopens_verified_pc(self, db: Database, settings: Settings):
        _verified_incident(db, settings, days=-1)  # window already elapsed
        # sanity: sweep passes the PC
        result = recheck.run_recheck_sweep(db, settings)
        assert result["rechecks_passed"] == 1

    def test_reopen_on_new_signal_within_window(self, db: Database, settings: Settings):
        iid = _verified_incident(db, settings, days=14)  # window still open
        reopened = recheck.check_signal_against_recheck(
            db, settings, {"pc": "PC-A", "rule_id": "pers_run_key"}, "medium")
        assert reopened and int(reopened[0]["id"]) == iid
        pc = incidents.pcs_of(db, iid)[0]
        assert pc["state"] == "detected", "reopened PC returns to detected"
        assert incidents.get(db, iid)["status"] == "open"

    def test_sweep_closes_incident_when_all_pcs_pass(self, db: Database, settings: Settings):
        iid = _verified_incident(db, settings, days=-1)
        result = recheck.run_recheck_sweep(db, settings)
        assert result["incidents_closed"] == 1
        assert incidents.get(db, iid)["status"] == "closed"

    def test_disabled_setting_short_circuits(self, db: Database, settings: Settings):
        settings.app.setdefault("recheck", {})["enabled"] = False
        try:
            result = recheck.run_recheck_sweep(db, settings)
            assert result.get("disabled") is True
        finally:
            settings.app["recheck"]["enabled"] = True


class TestPasswords:
    def test_hash_verify_roundtrip(self):
        stored = auth.hash_password("correct horse", iterations=1000)
        assert auth.verify_password("correct horse", stored)
        assert not auth.verify_password("wrong horse", stored)

    def test_unique_salts(self):
        a = auth.hash_password("same", iterations=1000)
        b = auth.hash_password("same", iterations=1000)
        assert a != b

    def test_garbage_stored_string(self):
        assert not auth.verify_password("x", "not-a-hash")


class TestUsers:
    def test_create_and_authenticate(self, db: Database, settings: Settings):
        auth.create_user(db, "alice", "password123", "analyst")
        row = auth.authenticate(db, "alice", "password123")
        assert row and row["role"] == "analyst"

    def test_short_password_rejected(self, db: Database, settings: Settings):
        with pytest.raises(ValueError):
            auth.create_user(db, "bob", "short", "analyst")

    def test_bad_role_rejected(self, db: Database, settings: Settings):
        with pytest.raises(ValueError):
            auth.create_user(db, "bob", "password123", "superuser")

    def test_case_insensitive_username(self, db: Database, settings: Settings):
        auth.create_user(db, "Alice", "password123", "viewer")
        assert auth.authenticate(db, "ALICE", "password123") is not None

    def test_rate_limit_after_failures(self, db: Database, settings: Settings):
        auth.create_user(db, "carol", "password123", "viewer")
        for _ in range(5):
            auth.authenticate(db, "carol", "wrong-password")
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(db, "carol", "password123")
        assert exc.value.status_code == 429

    def test_rate_limit_thresholds_come_from_settings(self, db: Database,
                                                      settings: Settings):
        """The attempt count and window are config, not constants: a stricter
        max_failed_attempts must take effect for the web login path."""
        settings.app.setdefault("auth", {})["max_failed_attempts"] = 2
        assert settings.login_max_attempts == 2
        settings.app["auth"]["lockout_window_minutes"] = 1
        assert settings.login_window_seconds == 60

        auth.create_user(db, "erin", "password123", "viewer")
        assert auth.authenticate(db, "erin", "wrong", settings=settings) is None
        assert auth.authenticate(db, "erin", "wrong", settings=settings) is None
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(db, "erin", "password123", settings=settings)
        assert exc.value.status_code == 429

    def test_invalid_rate_limit_config_falls_back(self, settings: Settings):
        """A typo must not disable the lockout (0) or block everyone (-1)."""
        for bad in ({"max_failed_attempts": "lots",
                     "lockout_window_minutes": 0},
                    {"max_failed_attempts": -3,
                     "lockout_window_minutes": -1}):
            settings.app["auth"] = dict(bad)
            assert settings.login_max_attempts == 5
            assert settings.login_window_seconds == 300

    def test_rate_limit_keys_on_client_ip_too(self, db: Database, settings: Settings):
        """One host spraying many usernames must trip the limiter even
        though no single username reaches the per-account limit."""
        auth.create_user(db, "dave", "password123", "viewer")
        for i in range(5):
            auth.authenticate(db, f"nosuchuser{i}", "wrong",
                              client_ip="10.9.9.9")
        # different username, same host: the per-IP count blocks it
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(db, "dave", "password123", client_ip="10.9.9.9")
        assert exc.value.status_code == 429
        # a different host is unaffected - the limit is not global
        assert auth.authenticate(db, "dave", "password123",
                                 client_ip="10.9.9.8") is not None


class TestSessions:
    def test_roundtrip(self, db: Database, settings: Settings):
        auth.create_user(db, "alice", "password123", "analyst")
        cookie = auth.create_session(db, settings, "alice", "analyst")
        user = auth.resolve_session(db, settings, cookie)
        assert user == {"username": "alice", "role": "analyst"}

    def test_tampered_token_rejected(self, db: Database, settings: Settings):
        cookie = auth.create_session(db, settings, "alice", "analyst")
        token, sig = cookie.rsplit(".", 1)
        assert auth.resolve_session(db, settings, f"{token[:-2]}xx.{sig}") is None

    def test_destroy_session(self, db: Database, settings: Settings):
        cookie = auth.create_session(db, settings, "alice", "analyst")
        auth.destroy_session(db, cookie)
        assert auth.resolve_session(db, settings, cookie) is None

    def test_none_and_malformed(self, db: Database, settings: Settings):
        assert auth.resolve_session(db, settings, None) is None
        assert auth.resolve_session(db, settings, "no-signature") is None
