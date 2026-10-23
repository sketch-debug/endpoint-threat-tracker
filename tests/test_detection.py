"""Detection tests: rules fire on the right records, dedup is idempotent."""
from __future__ import annotations

import itertools
import json

from app import detect
from app.config import Settings
from app.db import Database
from app.indicators import Indicators
from app.normalize import now_iso

_seq = itertools.count(1)


def _obs(db: Database, record_type: str, payload: dict, ts: str | None = None) -> None:
    payload = dict(payload)
    payload.setdefault("record_type", record_type)
    payload.setdefault("ts", ts or now_iso())
    payload.setdefault("pc", "PC-TEST")
    db.execute(
        "INSERT INTO observations(record_type, pc, ts, dedup_key, payload) VALUES(?,?,?,?,?)",
        (record_type, payload["pc"], payload["ts"],
         f"{record_type}|{next(_seq)}",
         json.dumps(payload, sort_keys=True)))


def _detector(db: Database, settings: Settings, indicators: Indicators):
    return detect.Detector(db, settings, indicators)


class TestMinerRules:
    def test_dns_mining_pool(self, db, settings, indicators):
        pool = next(iter(indicators.pool_domains))
        _obs(db, "dns_query", {"client_ip": "192.168.10.21",
                               "domain": f"eu1.{pool}"})
        det = _detector(db, settings, indicators)
        result = det.run({"PC-TEST"})
        assert result["signals"] >= 1
        row = db.one("SELECT * FROM signals WHERE rule_id='dns_mining_pool'")
        assert row and row["category"] == "miner"
        assert row["weight"] == settings.rule_weights["dns_mining_pool"]

    def test_mining_port_needs_long_duration(self, db, settings, indicators):
        _obs(db, "connection", {"client_ip": "192.168.10.21", "dst_ip": "10.0.0.9",
                                "port": 4444, "duration": "12"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='conn_mining_port'") is None

    def test_mining_port_long_flow_fires(self, db, settings, indicators):
        _obs(db, "connection", {"client_ip": "192.168.10.21", "dst_ip": "10.0.0.9",
                                "port": 4444, "duration": "900"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='conn_mining_port'") is not None

    def test_miner_process_name(self, db, settings, indicators):
        _obs(db, "process_inventory", {"name": "xmrig.exe",
                                       "path": r"C:\ProgramData\xmrig.exe"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='proc_miner_name'") is not None


class TestExecutionRules:
    def test_temp_unsigned_combo_emits_single_signal(self, db, settings, indicators):
        _obs(db, "process_inventory", {"name": "sneaky.exe",
                                       "path": r"C:\Users\bob\AppData\Local\Temp\sneaky.exe",
                                       "signature_status": "unsigned"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        rows = db.query("SELECT rule_id FROM signals WHERE pc='PC-TEST'")
        assert [r["rule_id"] for r in rows] == ["exec_temp_unsigned"]

    def test_offhours_high_cpu_only_offhours(self, db, settings, indicators):
        # build a timestamp at 03:00 LOCAL time (off-hours 22:00-06:00 default)
        from datetime import datetime
        from app.normalize import ts_str
        local_3am = datetime.now().astimezone().replace(hour=3, minute=0, second=0,
                                                        microsecond=0)
        _obs(db, "process_inventory", {"name": "xmr.exe", "cpu_percent": "97",
                                       "path": "C:\\x\\x.exe"},
             ts=ts_str(local_3am))
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='cpu_high_offhours'") is not None

    def test_office_spawn(self, db, settings, indicators):
        _obs(db, "event_4688", {
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "command_line": "powershell -enc SQBFAFgA"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='exec_office_spawn'") is not None

    def test_defender_detection_with_bad_hash(self, db, settings, indicators):
        bad = next(iter(indicators.bad_hashes))
        _obs(db, "defender_detection", {"threat_name": "Trojan:Win32/X",
                                        "process_name": "a.exe",
                                        "resources": f"file:_C:\\a.exe_-{bad}"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='defender_detection'") is not None
        assert db.one("SELECT 1 FROM signals WHERE rule_id='proc_bad_hash'") is not None


class TestEvasionRules:
    def test_5007_filtered_without_evasion_words(self, db, settings, indicators):
        _obs(db, "event_5007", {"path": "Threats\\Default",
                                "old_value": "a", "new_value": "b"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='evade_defender_exclusion'") is None

    def test_5007_exclusion_fires(self, db, settings, indicators):
        _obs(db, "event_5007", {"path": r"Real-Time Protection\Exclusions\Paths",
                                "old_value": "", "new_value": r"C:\Users\Public\Libs"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='evade_defender_exclusion'") is not None

    def test_log_cleared(self, db, settings, indicators):
        _obs(db, "event_1102", {"provider": "Microsoft-Windows-Eventlog"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='evade_log_cleared'") is not None


class TestAccountRules:
    def test_failed_login_burst(self, db, settings, indicators):
        for i in range(6):
            _obs(db, "event_4625", {"target_user": "jenkins_svc",
                                    "source_ip": "10.99.0.55", "logon_type": "3"},
                 ts=f"2026-10-14T02:0{i}:00Z")
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='acct_failed_burst'") is not None

    def test_scattered_failures_no_burst(self, db, settings, indicators):
        for day in range(1, 7):
            _obs(db, "event_4625", {"target_user": "u", "source_ip": "10.99.0.55"},
                 ts=f"2026-10-0{day}T02:00:00Z")
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='acct_failed_burst'") is None


class TestRansomwareRules:
    def test_ransom_extension_and_note(self, db, settings, indicators):
        _obs(db, "file_activity", {"file_path": r"C:\Users\bob\doc.pdf.locked",
                                   "action": "rename"})
        _obs(db, "file_activity", {"file_path": r"C:\Users\bob\how_to_decrypt.txt",
                                   "action": "create"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='ransom_extension'") is not None
        assert db.one("SELECT 1 FROM signals WHERE rule_id='ransom_note'") is not None

    def test_shadow_copy_tamper(self, db, settings, indicators):
        _obs(db, "event_4688", {"process_name": r"C:\Windows\System32\vssadmin.exe",
                                "command_line": "vssadmin delete shadows /all /quiet",
                                "parent_process": r"C:\Windows\System32\cmd.exe"})
        det = _detector(db, settings, indicators)
        det.run({"PC-TEST"})
        assert db.one("SELECT 1 FROM signals WHERE rule_id='ransom_shadow_copy'") is not None


class TestIdempotency:
    def test_rerun_creates_no_duplicates(self, db, settings, indicators):
        pool = next(iter(indicators.pool_domains))
        _obs(db, "dns_query", {"client_ip": "192.168.10.21", "domain": pool})
        det = _detector(db, settings, indicators)
        first = det.run({"PC-TEST"})
        second = det.run({"PC-TEST"})
        assert first["signals"] >= 1
        assert second["signals"] == 0, "re-running detection must be a no-op"
