"""P18 regression: start.bat must fail with a readable message, not a raw error.

The clean-machine pass found start.bat printing a bare "'python' is not
recognized..." (and later an opaque traceback) when a prerequisite was
missing. The script now checks each step and prints what to do; these tests
pin the guards so a future edit cannot silently drop them.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _start_bat() -> str:
    # cmd batch files are CRLF; normalise so assertions read the same everywhere
    return (ROOT / "start.bat").read_text(encoding="utf-8").replace("\r\n", "\n")


class TestStartBatGuards:
    def test_missing_python_is_caught_with_a_friendly_message(self):
        text = _start_bat()
        assert "where python >nul 2>&1" in text, "no PATH check for python"
        assert "Python was not found on PATH" in text
        # the friendly branch must abort before anything is created
        guard = text.split("Python was not found on PATH", 1)[0]
        after = text.split("Python was not found on PATH", 1)[1]
        assert "where python" in guard
        assert "exit /b 1" in after.split("python -m venv", 1)[0], (
            "the missing-python branch must exit before creating the venv")

    def test_venv_creation_failure_aborts_cleanly(self):
        text = _start_bat()
        assert "could not create the virtual environment" in text
        venv_idx = text.index("python -m venv .venv")
        fail_idx = text.index("could not create the virtual environment")
        exit_idx = text.index("exit /b 1", fail_idx)
        assert venv_idx < fail_idx < exit_idx

    def test_dependency_install_failure_explains_the_offline_fallback(self):
        text = _start_bat()
        assert "dependency install failed" in text
        assert "--no-index --find-links packages" in text, (
            "the offline install command must be shown to the admin")

    def test_incomplete_venv_is_reported_before_launch(self):
        text = _start_bat()
        assert ".venv\\Scripts\\python.exe" in text
        assert "missing or incomplete" in text

    def test_app_crash_prints_where_to_look(self):
        text = _start_bat()
        assert "the tracker exited with an error" in text
        assert "tracker.log" in text

    def test_default_env_creation_warns_about_the_default_secrets(self):
        # start.bat run before install.bat silently copies .env.example, which
        # ships SECRET_KEY=change-me... and admin1234. The copy must not happen
        # without saying what it just created.
        text = _start_bat()
        assert "copy .env.example .env" in text
        branch = text.split("if not exist .env (", 1)[1].split("\n)", 1)[0]
        assert "WARNING" in branch, "no warning when .env defaults are created"
        assert "SECRET_KEY" in branch
        assert "admin1234" in branch
        assert "install.bat" in branch, "must point at the real installer"
