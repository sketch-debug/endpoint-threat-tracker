"""Regression tests for the four ways smoke_test.ps1 could print PASS without
proving anything:

1. steps 7-9 waited for ``COUNT(*) > 0``, which a database left behind by an
   earlier run satisfies before this run's files are parsed;
2. step 6 only required the inbox root to drain, so a run in which every file
   was quarantined still passed;
3. reuse was decided by ``GET /login = 200``, so any process bound to the
   port - including a stale build - could carry the whole run;
4. the .venv preflight read empty stdout as "nothing missing", so a check that
   itself failed reported all packages installed.

The script cannot be executed by pytest (it needs a serving app and a real
database), so its logic is pinned two ways: by reading the script text where
the change is purely structural, and by running the pipeline the script drives
for the part that depends on real ingest/detection behaviour - the canary file
that gives steps 7-9 something to wait for on a reused database.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CANARY_MARKER = "$canaryCsv = @'\n"


def _script() -> str:
    return (ROOT / "smoke_test.ps1").read_text(encoding="utf-8").replace("\r\n", "\n")


def _dep_block() -> str:
    """Everything from the requirements check to its PASS report."""
    text = _script()
    start = text.index("$reqFile = Join-Path $root 'requirements.txt'")
    end = text.index("Report 'virtual environment up to date' $true")
    return text[start:end]


def _dep_snippet() -> str:
    text = _script()
    return text.split("$depCheck = @'", 1)[1].split("'@", 1)[0]


def _canary_template() -> str:
    text = _script()
    start = text.index(CANARY_MARKER) + len(CANARY_MARKER)
    end = text.index("\n'@", start)
    return text[start:end]


class TestBaselinesAndGrowth:
    """Finding 1: every downstream wait must measure growth, not existence."""

    def test_baselines_are_read_before_the_files_are_dropped(self):
        text = _script()
        drop = text.index("generate_fake_data.py")
        for name in ("$filesBefore", "$ingestedBefore", "$quarantinedBefore",
                     "$sigBase", "$incBase", "$linkedBase", "$alertBase"):
            assert text.index(name) < drop, f"{name} is read after the drop"

    def test_no_wait_stops_at_a_mere_nonzero_count(self):
        text = _script()
        assert "-le 0" not in text, "a wait that stops at > 0 passes on stale rows"
        assert "function Wait-DbGrowth" in text
        assert "while ((Get-Date) -lt $deadline -and $n -le $base)" in text

    def test_steps_7_and_9_wait_above_their_baseline(self):
        text = _script()
        assert ("Wait-DbGrowth 'detection fires' 'SELECT COUNT(*) FROM signals' $sigBase"
                in text)
        assert "Wait-DbGrowth 'alert attempted'" in text
        assert "$alertBase" in text

    def test_alert_wait_ignores_rows_without_an_incident(self):
        # heartbeat/indicator alerts carry incident_id NULL and would otherwise
        # stand in for an attempt made by this run's incident
        assert ("SELECT COUNT(*) FROM alerts_log WHERE incident_id IS NOT NULL"
                in _script())

    def test_incident_wait_accepts_a_join_into_an_existing_incident(self):
        # correlation joins a new signal into an already-open incident for the
        # same PC instead of always creating a row, so a bare incident-row
        # delta would fail a healthy rerun
        text = _script()
        assert "$linkedBase" in text
        assert "($incidents -gt $incBase) -or ($linked -gt $linkedBase)" in text


class TestStepSixMeasuresChange:
    """Finding 2: a run in which everything was quarantined must fail."""

    def test_pass_requires_growth_without_new_quarantine(self):
        text = _script()
        assert "$rootLeft -eq 0 -and" in text
        assert "$quarantinedNow -le $quarantinedBefore" in text
        assert "$ingestedNow -gt $ingestedBefore" in text

    def test_the_old_root_only_condition_is_gone(self):
        text = _script()
        assert "$rootLeft -eq 0 -and $filesNow -gt 0" not in text
        assert "files table $filesBefore" not in text

    def test_a_failed_baseline_read_aborts_the_run(self):
        text = _script()
        assert "-contains -1" in text
        assert "Abort 'sample files parsed'" in text


class TestReuseChecksTheServingBuild:
    """Finding 3: /login=200 cannot distinguish our build from a stale one."""

    def test_health_version_is_read_before_app_starts_is_reported(self):
        text = _script()
        health = text.index('curl.exe -s --max-time 10 "$base/health"')
        report = text.index("Report 'app starts'")
        assert health < report, "reuse must be verified before the step reports"

    def test_health_read_survives_a_degraded_503(self):
        # /health answers 503 whenever the instance reports a problem (stale
        # data is enough), and Invoke-RestMethod raises on the status code
        # before the body - which carries `version` - can be read: a current
        # build with stale data was reported as "not a current build".
        text = _script()
        assert 'Invoke-RestMethod "$base/health"' not in text
        assert "ConvertFrom-Json" in text

    def test_version_comes_from_this_checkout(self):
        text = _script()
        assert "Join-Path $root 'VERSION'" in text
        assert "$servedVersion -ne $wantVersion" in text

    def test_a_mismatch_aborts_instead_of_continuing(self):
        text = _script()
        mismatch = text.index("$servedVersion -ne $wantVersion")
        abort = text.index("Abort 'app starts'", mismatch)
        after = text.index("Report 'app starts'", abort)
        # the run stops here instead of carrying on to steps 2-11
        assert abort < after
        helper = text.index("function Abort(")
        body = text[helper:text.index("function Get-DbCount")]
        assert "exit 1" in body
        assert "Stop-Process" in body, "aborting leaks the app this run started"


class TestDependencyCheckFailsClosed:
    """Finding 4: an empty stdout meant "nothing missing"."""

    def test_snippet_reports_an_unreadable_requirements_file(self, tmp_path):
        out = subprocess.run(
            [sys.executable, "-c", _dep_snippet(), str(tmp_path / "nope.txt")],
            capture_output=True, text=True, timeout=60)
        assert out.returncode != 0, "an unreadable requirements.txt must not pass"
        assert "CHECK-FAILED" in out.stdout

    def test_snippet_still_uses_single_quotes_only(self):
        # Windows PowerShell mangles embedded double quotes in a -c argument
        assert '"' not in _dep_snippet()

    def test_exit_code_and_stderr_are_kept(self):
        block = _dep_block()
        assert "$LASTEXITCODE" in block, "the check's exit code is never inspected"
        assert "2>$null" not in block, "stderr is discarded, so crashes look empty"
        assert "Test-Path $reqFile" in block, "a missing requirements.txt passes today"

    def test_failure_names_the_fix(self):
        block = _dep_block()
        assert "missing from .venv" in block
        assert "run install.bat" in block
        assert "pip install -r requirements.txt" in block


class TestCanaryGivesTheWaitsSomethingToWaitFor:
    """Finding 1, proved against the real pipeline: on a database that already
    holds incidents and alerts, the canary drop still produces growth in every
    table steps 7-9 watch - and a fully quarantined batch produces none."""

    @staticmethod
    def _ingestor(db, settings, indicators):
        from app import detect
        from app.ingest import Ingestor
        det = detect.Detector(db, settings, indicators)
        return detect, Ingestor(db, settings, indicators, detector=det), det

    @staticmethod
    def _body(run_id: str) -> str:
        # The template embeds a NOW-derived timestamp (second precision) and
        # ingest dedupes by sha256. Recomputing this for the "byte-identical
        # rerun" below produced different bytes whenever the two calls
        # straddled a wall-clock second, so the rerun ingested a *new* file
        # instead of deduplicating and this test failed intermittently.
        # Compute once per run_id and reuse: the rerun must see the exact
        # content the first run dropped.
        cache = TestCanaryGivesTheWaitsSomethingToWaitFor._body_cache
        if run_id not in cache:
            ts = (datetime.now(timezone.utc) - timedelta(hours=1)) \
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            cache[run_id] = (_canary_template()
                             .replace("__TS__", ts)
                             .replace("__PC__", f"SMOKE-{run_id}")
                             .replace("__NOTE__", f"README_RESTORE_{run_id}.txt"))
        return cache[run_id]

    _body_cache: dict[str, str] = {}

    @staticmethod
    def _drop(settings, run_id: str) -> None:
        (settings.inbox_dir / f"file_activity_{run_id}.csv").write_text(
            TestCanaryGivesTheWaitsSomethingToWaitFor._body(run_id),
            encoding="utf-8")

    @staticmethod
    def _counts(db) -> dict:
        def n(sql: str) -> int:
            row = db.one(sql)
            return int(row["n"]) if row else 0
        return {
            "files": n("SELECT COUNT(*) AS n FROM files"),
            "ingested": n("SELECT COUNT(*) AS n FROM files WHERE status='ingested'"),
            "errors": n("SELECT COUNT(*) AS n FROM files WHERE status='error'"),
            "signals": n("SELECT COUNT(*) AS n FROM signals"),
            "incidents": n("SELECT COUNT(*) AS n FROM incidents"),
            "linked": n("SELECT COUNT(*) AS n FROM signals "
                        "WHERE incident_id IS NOT NULL"),
            "alerts": n("SELECT COUNT(*) AS n FROM alerts_log "
                        "WHERE incident_id IS NOT NULL"),
        }

    def test_canary_creates_the_fresh_rows_on_a_rerun(self, db, settings, indicators):
        detect_mod, ing, det = self._ingestor(db, settings, indicators)

        # --- first run: the canary must build the whole chain ---------------
        self._drop(settings, "first01")
        first = detect_mod.run_cycle(ing, det)
        assert first["ingested"] == 1, first
        before = self._counts(db)
        assert before["signals"] >= 1, "detection did not fire on the canary"
        assert before["incidents"] == 1, "the canary PC did not open an incident"
        assert before["alerts"] >= 1, "opening the incident recorded no alert"

        # --- second run: the database is now "dirty" ------------------------
        # This is the state steps 7-9 used to satisfy with rows from run one.
        self._drop(settings, "second02")
        second = detect_mod.run_cycle(ing, det)
        assert second["ingested"] == 1, second
        after = self._counts(db)

        assert after["signals"] > before["signals"], "signals wait would starve"
        assert after["incidents"] > before["incidents"], "incident wait would starve"
        assert after["linked"] > before["linked"], "linked-signal wait would starve"
        assert after["alerts"] > before["alerts"], "alert wait would starve"
        assert after["errors"] == before["errors"], "canary was quarantined"

    def test_a_fully_quarantined_batch_does_not_look_ingested(
            self, db, settings, indicators):
        detect_mod, ing, det = self._ingestor(db, settings, indicators)
        self._drop(settings, "baseline1")
        detect_mod.run_cycle(ing, det)
        before = self._counts(db)

        # every file of this batch is rejected: the inbox root still drains
        (settings.inbox_dir / "payload.exe").write_text("MZ...", encoding="utf-8")
        (settings.inbox_dir / "dns_generic_junk.csv").write_text(
            "not,a,valid,dns,file\n1,2,3,4\n", encoding="utf-8")
        stats = detect_mod.run_cycle(ing, det)
        after = self._counts(db)

        root_left = len([p for p in settings.inbox_dir.iterdir() if p.is_file()])
        assert root_left == 0, "test needs the root to drain for the old check"
        assert after["errors"] > before["errors"]
        assert after["ingested"] == before["ingested"]
        assert stats["errors"] >= 2 and stats["ingested"] == 0


class TestOldLogicWouldHavePassedFalsely:
    """Seed a database the way an earlier run leaves it, then evaluate the
    predicates smoke_test.ps1 USED to apply against this run's result: both
    still report PASS while the pipeline has produced nothing new.

    The two conditions are transcribed from the pre-fix script:
      step 6:   $rootLeft -eq 0 -and $filesNow -gt 0
      steps 7-9: wait until COUNT(*) -gt 0
    """

    @staticmethod
    def _seeded(db, settings, indicators, run_id: str):
        harness = TestCanaryGivesTheWaitsSomethingToWaitFor
        detect_mod, ing, det = harness._ingestor(db, settings, indicators)
        harness._drop(settings, run_id)
        stats = detect_mod.run_cycle(ing, det)
        assert stats["ingested"] == 1, stats
        return harness, detect_mod, ing, det

    @staticmethod
    def _root_left(settings) -> int:
        return len([p for p in settings.inbox_dir.iterdir() if p.is_file()])

    def test_stage_waits_would_have_passed_on_rows_from_an_earlier_run(
            self, db, settings, indicators):
        harness, detect_mod, ing, det = self._seeded(
            db, settings, indicators, "firstrun")
        seeded = harness._counts(db)
        assert seeded["signals"] > 0, "the earlier run left no signal rows"
        assert seeded["incidents"] > 0 and seeded["alerts"] > 0

        # this run drops byte-identical content - what a rerun of the
        # generator with its fixed default seed puts in the inbox - so ingest
        # dedupes it and records nothing new
        body = harness._body("firstrun")
        path = settings.inbox_dir / "file_activity_firstrun.csv"
        path.write_text(body, encoding="utf-8")
        rerun_stats = detect_mod.run_cycle(ing, det)
        assert rerun_stats["duplicates"] == 1 and rerun_stats["ingested"] == 0, \
            rerun_stats
        rerun = harness._counts(db)
        assert rerun == seeded, "the rerun must add nothing for this test to hold"

        for stage in ("signals", "incidents", "alerts"):
            old_ok = rerun[stage] > 0          # old: Wait-DbCount stops at > 0
            new_ok = rerun[stage] > seeded[stage]   # now: must exceed the baseline
            assert old_ok, f"{stage}: the old wait reports PASS instantly"
            assert not new_ok, f"{stage}: the growth wait must report FAIL"

    def test_step_6_would_have_passed_when_every_file_was_quarantined(
            self, db, settings, indicators):
        harness, detect_mod, ing, det = self._seeded(
            db, settings, indicators, "prerun01")
        seeded = harness._counts(db)
        assert seeded["files"] > 0 and seeded["ingested"] > 0

        # this run: every file rejected, yet all three paths still move the
        # file out of the inbox root and quarantine writes a ledger row
        (settings.inbox_dir / "payload.exe").write_text("MZ...", encoding="utf-8")
        (settings.inbox_dir / "dns_generic_junk.csv").write_text(
            "not,a,valid,dns,file\n1,2,3,4\n", encoding="utf-8")
        stats = detect_mod.run_cycle(ing, det)
        now = harness._counts(db)
        root_left = self._root_left(settings)

        old_ok = root_left == 0 and now["files"] > 0        # old step 6 condition
        new_ok = (root_left == 0
                  and now["errors"] <= seeded["errors"]
                  and now["ingested"] > seeded["ingested"])

        assert stats["ingested"] == 0 and stats["errors"] >= 2, stats
        assert root_left == 0
        assert now["files"] > seeded["files"], "quarantine must write a ledger row"
        assert now["errors"] > seeded["errors"]
        assert now["ingested"] == seeded["ingested"]
        assert old_ok, "the old condition reports PASS on a fully quarantined run"
        assert not new_ok, "the new condition must report FAIL"


class TestReportAndConfigChecks:
    """Two more ways a step could pass without proving what it claims: step 10
    accepted any HTML page (the login page a bounced session lands on included),
    and every count was taken from a hardcoded data\tracker.db even though the
    app resolves its database from config/app_config.yaml."""

    def test_db_path_is_read_from_the_config_the_app_uses(self):
        text = _script()
        assert r"(?m)^\s*db_path:\s*(.+?)\s*$" in text
        # resolved before the first count is taken, and the hardcoded path
        # survives only as the fallback when the key is absent
        assert text.index("db_path:") < text.index("$filesBefore")
        assert text.count("Join-Path $root 'data\\tracker.db'") == 1

    def test_report_check_needs_the_incidents_own_content(self):
        text = _script()
        # the old check: any HTML body at all
        assert "-match '<html'" not in text
        assert "<h1>Incident report:" in text
        assert "SELECT id, incident_key FROM incidents" in text

    def test_report_check_fails_when_bounced_to_the_login_page(self):
        text = _script()
        assert "$landed -eq $wantPath" in text, \
            "a redirected session must not count as a rendered report"
        assert "$hasKey" in text and "$hasHeading" in text
