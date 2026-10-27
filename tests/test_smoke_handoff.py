"""Regression: the smoke test must hand off to the dashboard it just proved.

The script printed a bare "SMOKE: 11/11 steps passed" and stopped the instance
it had started, so the first-run path dead-ended one step short of the working
dashboard: nothing said to run start.bat, where to browse, or which password
applies (install.ps1 writes a generated one, not admin1234).
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _smoke() -> str:
    return (ROOT / "smoke_test.ps1").read_text(encoding="utf-8").replace("\r\n", "\n")


class TestDashboardHandoff:
    def test_success_output_points_at_the_dashboard_url_and_login(self):
        text = _smoke()
        assert "Next: open the dashboard" in text, "no handoff after the summary"
        assert "http://127.0.0.1:{0}/' -f $port" in text, (
            "the handoff must print the configured port, not a literal")
        assert "TRACKER_ADMIN_PASSWORD" in text, "no login pointer"

    def test_handoff_reports_whether_the_instance_is_still_running(self):
        text = _smoke()
        tail = text[text.index("Next: open the dashboard"):]
        # two honest cases: we stopped our own instance (say how to start one),
        # or we reused an already-running one (say it is still up)
        assert "$startedByUs" in tail
        assert "start.bat" in tail
        assert "still running" in tail

    def test_handoff_is_reachable_only_after_a_clean_run(self):
        text = _smoke()
        fail_idx = text.index("if ($failed.Count -gt 0)")
        next_idx = text.index("Next: open the dashboard")
        assert fail_idx < next_idx, "handoff must come after the failure branch"
        assert "exit 1" in text[fail_idx:next_idx], (
            "a failed run must exit before printing the dashboard handoff")
