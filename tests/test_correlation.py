"""Incident correlation tests: create/join/merge, type suggestion/override."""
from __future__ import annotations

import itertools

from app import incidents
from app.config import Settings
from app.db import Database
from app.normalize import now_iso

_seq = itertools.count(1)


def _sig(db: Database, pc: str, rule_id: str, category: str,
         correlation: list | None = None) -> dict:
    cur = db.execute(
        "INSERT INTO signals(ts, pc, rule_id, category, weight, title, detail, "
        "correlation, dedup_key) VALUES(?,?,?,?,?,?,?,?,?)",
        (now_iso(), pc, rule_id, category, 10, f"{rule_id} on {pc}", "",
         str(correlation or []).replace("'", '"'),
         f"{pc}|{rule_id}|{next(_seq)}"))
    row = db.one("SELECT * FROM signals WHERE id=?", (cur,))
    return dict(row)


class TestSuggestType:
    def test_miner_from_categories(self, settings: Settings):
        assert incidents.suggest_type(settings, {"miner"}, set()) == "miner"

    def test_ransomware_beats_unknown(self, settings: Settings):
        assert incidents.suggest_type(settings, {"ransomware", "execution"},
                                      {"ransom_note"}) == "ransomware"

    def test_counts_weight_rules_double(self, settings: Settings):
        counts = {"cat:ransomware": 1, "rule:ransom_note": 3}
        assert incidents.suggest_type(settings, {"ransomware"},
                                      {"ransom_note"}, counts) == "ransomware"

    def test_no_match_is_unknown(self, settings: Settings):
        assert incidents.suggest_type(settings, {"execution"}, {"proc_unsigned"}) == "unknown"


class TestCorrelate:
    def test_first_signal_opens_incident(self, db: Database, settings: Settings):
        sig = _sig(db, "PC-A", "dns_mining_pool", "miner", [["domain", "pool.x"]])
        inc, transitions = incidents.correlate_and_record(
            db, settings, sig, "high", ["miner"], ["dns_mining_pool"])
        assert transitions == ["opened"]
        assert inc["type"] == "miner"
        assert inc["pcs"] == ["PC-A"]

    def test_same_pc_joins_existing_incident(self, db: Database, settings: Settings):
        sig1 = _sig(db, "PC-A", "dns_mining_pool", "miner", [["domain", "pool.x"]])
        incidents.correlate_and_record(db, settings, sig1, "high", ["miner"],
                                       ["dns_mining_pool"])
        sig2 = _sig(db, "PC-A", "pers_run_key", "persistence")
        inc, transitions = incidents.correlate_and_record(
            db, settings, sig2, "high", ["miner", "persistence"],
            ["dns_mining_pool", "pers_run_key"])
        assert "opened" not in transitions
        assert incidents.list_incidents(db) and len(incidents.list_incidents(db)) == 1

    def test_signal_bridging_two_incidents_merges_them(self, db: Database,
                                                       settings: Settings):
        # incident 1: miner on PC-A keyed by domain; incident 2: RAT on PC-B keyed by tool
        sig1 = _sig(db, "PC-A", "dns_mining_pool", "miner", [["domain", "pool.x"]])
        inc1, _ = incidents.correlate_and_record(db, settings, sig1, "high", ["miner"],
                                                 ["dns_mining_pool"])
        sig2 = _sig(db, "PC-B", "net_unapproved_rat", "network", [["tool", "anydesk.exe"]])
        inc2, _ = incidents.correlate_and_record(db, settings, sig2, "high", ["network"],
                                                 ["net_unapproved_rat"])
        assert int(inc1["id"]) != int(inc2["id"])
        # a new signal carries BOTH keys -> the two open incidents must merge
        sig3 = _sig(db, "PC-C", "dns_mining_pool", "miner",
                    [["domain", "pool.x"], ["tool", "anydesk.exe"]])
        inc, transitions = incidents.correlate_and_record(
            db, settings, sig3, "high", ["miner", "network"],
            ["dns_mining_pool", "net_unapproved_rat"])
        assert "incident_merged" in transitions
        assert sorted(inc["pcs"]) == ["PC-A", "PC-B", "PC-C"]
        assert len(incidents.list_incidents(db)) == 1

    def test_severity_only_rises(self, db: Database, settings: Settings):
        sig1 = _sig(db, "PC-A", "dns_mining_pool", "miner", [["domain", "pool.x"]])
        inc, _ = incidents.correlate_and_record(db, settings, sig1, "high", ["miner"],
                                                ["dns_mining_pool"])
        sig2 = _sig(db, "PC-A", "pers_run_key", "persistence")
        inc2, tr = incidents.correlate_and_record(db, settings, sig2, "low",
                                                  ["miner", "persistence"],
                                                  ["dns_mining_pool", "pers_run_key"])
        assert "severity_raised" not in tr
        assert inc2["severity"] == inc["severity"]

    def test_closed_incident_not_joined(self, db: Database, settings: Settings):
        sig1 = _sig(db, "PC-A", "dns_mining_pool", "miner", [["domain", "pool.x"]])
        inc, _ = incidents.correlate_and_record(db, settings, sig1, "high", ["miner"],
                                                ["dns_mining_pool"])
        incidents.close_incident(db, settings, int(inc["id"]), "alice", "done")
        sig2 = _sig(db, "PC-A", "pers_run_key", "persistence", [["domain", "pool.x"]])
        inc2, transitions = incidents.correlate_and_record(
            db, settings, sig2, "high", ["persistence"], ["pers_run_key"])
        assert "opened" in transitions
        assert int(inc2["id"]) != int(inc["id"])


class TestWorkflow:
    def _incident(self, db: Database, settings: Settings) -> dict:
        sig = _sig(db, "PC-A", "proc_miner_name", "miner", [["proc", "xmrig.exe"]])
        inc, _ = incidents.correlate_and_record(db, settings, sig, "medium", ["miner"],
                                                ["proc_miner_name"])
        return inc

    def test_state_machine_order(self, db: Database, settings: Settings):
        inc = self._incident(db, settings)
        iid = int(inc["id"])
        inc = incidents.transition_pc(db, settings, iid, "PC-A", "isolated", "alice")
        inc = incidents.transition_pc(db, settings, iid, "PC-A", "reimaged", "alice")
        inc = incidents.transition_pc(db, settings, iid, "PC-A", "verified", "alice")
        pc = incidents.pcs_of(db, iid)[0]
        assert pc["state"] == "verified"
        assert pc["recheck_until"], "verified PC must get a re-check deadline"

    def test_invalid_state_rejected(self, db: Database, settings: Settings):
        import pytest
        inc = self._incident(db, settings)
        with pytest.raises(ValueError):
            incidents.transition_pc(db, settings, int(inc["id"]), "PC-A",
                                    "obliterated", "alice")

    def test_unknown_pc_rejected(self, db: Database, settings: Settings):
        import pytest
        inc = self._incident(db, settings)
        with pytest.raises(LookupError):
            incidents.transition_pc(db, settings, int(inc["id"]), "PC-ZZZ",
                                    "isolated", "alice")

    def test_analyst_type_override_sticks(self, db: Database, settings: Settings):
        inc = self._incident(db, settings)
        iid = int(inc["id"])
        changed = incidents.set_type(db, settings, iid, "unknown", "alice")
        assert changed["type"] == "unknown"
        assert changed["type_source"] == "analyst"
        # a later auto refresh must not override the analyst choice
        refreshed, did_change = incidents._refresh_type(db, settings, iid)
        assert did_change is False
        assert refreshed["type"] == "unknown"

    def test_timeline_records_transitions(self, db: Database, settings: Settings):
        inc = self._incident(db, settings)
        incidents.transition_pc(db, settings, int(inc["id"]), "PC-A", "isolated", "alice")
        actions = [e["action"] for e in incidents.timeline(db, int(inc["id"]))]
        assert "opened" in actions
        assert "pc_workflow" in actions

    def test_checklist_seeded_from_type(self, db: Database, settings: Settings):
        inc = self._incident(db, settings)
        items = incidents.checklist_state(db, int(inc["id"]))
        assert items, "checklist must be seeded on incident creation"
        assert all(int(i["done"]) == 0 for i in items)
