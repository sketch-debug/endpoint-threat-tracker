"""CI must prove the first-run path, not just that the installer exits 0.

The documented journey is install -> smoke_test.bat -> dashboard, but CI only
ever ran the installer and an HTTP probe: the 11 smoke steps (ingest,
detection, incident, alert, report, the three role logins) never executed on a
PR, so a regression anywhere past first byte could merge green.

Two things are pinned here: that the workflow actually invokes smoke_test.bat
in the installer job after the dashboard probe, and that the .bat wrapper
propagates the PowerShell exit code - without that, a failing smoke run would
still leave the job green.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ci() -> str:
    return (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8").replace("\r\n", "\n")


def _installer_job() -> str:
    """The `installer:` job block, without its offline sibling."""
    text = _ci()
    start = text.index("\n  installer:")
    end = text.index("\n  installer-offline:", start)
    return text[start:end]


class TestTheWorkflowRunsTheSmokeTest:
    def test_the_installer_job_invokes_smoke_test_bat(self):
        assert ".\\smoke_test.bat" in _installer_job(), (
            "no PR check runs the smoke test - only install and an HTTP probe")

    def test_it_runs_through_the_cmd_wrapper(self):
        # cmd, not pwsh: the .bat is what the README hands to the admin
        job = _installer_job()
        idx = job.index(".\\smoke_test.bat")
        step = job.rfind("      - name:", 0, idx)
        assert "shell: cmd" in job[step:idx]

    def test_the_dashboard_probe_comes_first(self):
        # that step writes the feed stamp and stops its instance, which is
        # what frees port 8043 for the smoke run
        job = _installer_job()
        assert (job.index("Start the dashboard and check HTTP")
                < job.index(".\\smoke_test.bat"))


class TestTheBatWrapperCanFailTheBuild:
    def test_it_runs_the_powershell_script(self):
        bat = (ROOT / "smoke_test.bat").read_text(
            encoding="utf-8").replace("\r\n", "\n")
        assert "smoke_test.ps1" in bat

    def test_it_forwards_the_exit_code(self):
        # smoke_test.ps1 exits 1 when a step fails; if the wrapper swallowed
        # it, every CI run would report success regardless
        bat = (ROOT / "smoke_test.bat").read_text(
            encoding="utf-8").replace("\r\n", "\n")
        assert "exit /b %errorlevel%" in bat
