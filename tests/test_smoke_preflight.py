"""Regression tests for the smoke test's stale-.venv preflight.

Observed failure (recorded as limitation 9 in RELIABILITY_REPORT.md): a
.venv older than requirements.txt let smoke_test start python, which then
died with a raw `ModuleNotFoundError` traceback in logs\\smoke-server.err.log
and the run reported "FAIL app starts - process exited with code". The script
must now check requirements.txt against the venv FIRST and exit with a clear
instruction instead.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _script() -> str:
    return (ROOT / "smoke_test.ps1").read_text(encoding="utf-8").replace("\r\n", "\n")


class TestStaleVenvPreflight:
    def test_preflight_exists_and_names_the_fix(self):
        text = _script()
        assert "importlib.metadata" in text, "no requirements.txt preflight found"
        assert "missing from .venv" in text
        assert "run install.bat" in text
        assert "pip install -r requirements.txt" in text

    def test_preflight_runs_before_the_app_starts(self):
        text = _script()
        dep_idx = text.index("importlib.metadata")
        start_idx = text.index("step 1: app starts")
        fail_idx = text.index("SMOKE: 0/1 steps passed", dep_idx)
        assert dep_idx < start_idx, "preflight must run before launching the app"
        # the stale-venv branch exits immediately, not after partial results
        assert dep_idx < fail_idx < start_idx

    def test_preflight_snippet_avoids_double_quotes(self):
        # Windows PowerShell mangles embedded double quotes in a -c argument
        # (the same bug that forced Backup-Database.ps1 onto temp files).
        text = _script()
        start = text.index("$depCheck = @'")
        end = text.index("'@", start)
        snippet = text[start:end]
        assert '"' not in snippet, "the -c snippet must use single quotes only"


class TestDependencyCheckerLogic:
    """Run the same checker against real and fabricated requirement sets."""

    @staticmethod
    def _check(tmp_path: Path, requirements_text: str) -> str:
        import subprocess
        import sys

        req = tmp_path / "requirements.txt"
        req.write_text(requirements_text, encoding="utf-8")
        # extract the exact snippet smoke_test.ps1 embeds
        text = (ROOT / "smoke_test.ps1").read_text(encoding="utf-8")
        snippet = text.split("$depCheck = @'", 1)[1].split("'@", 1)[0]
        out = subprocess.run([sys.executable, "-c", snippet, str(req)],
                             capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()

    def test_reports_a_missing_package(self, tmp_path):
        missing = self._check(tmp_path, "fastapi==0.115.6\nno-such-package-xyz==9.9\n")
        assert "no-such-package-xyz" in missing
        assert "fastapi" not in missing

    def test_real_requirements_are_satisfied_by_this_environment(self, tmp_path):
        # the environment running the suite satisfies requirements.txt (CI and
        # a fresh install both do), so nothing should be reported missing
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert self._check(tmp_path, req) == ""

    def test_comments_and_blank_lines_are_ignored(self, tmp_path):
        assert self._check(tmp_path, "\n# fastapi==0.115.6\n\n") == ""
