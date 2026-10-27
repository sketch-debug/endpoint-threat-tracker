"""Shared fixtures: tmp-dir Settings, DB, real indicator files.

Tests use the REAL config/ files (weights, thresholds, indicator lists) so the
shipped configuration is itself under test; only data paths are redirected to tmp.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import Settings          # noqa: E402
from app.db import Database              # noqa: E402
from app.indicators import Indicators    # noqa: E402


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    st = Settings(base_dir=ROOT, path_overrides={
        "inbox_dir": str(tmp_path / "inbox"),
        "processed_dir": str(tmp_path / "processed"),
        "error_dir": str(tmp_path / "errors"),
        "db_path": str(tmp_path / "tracker.db"),
        "reports_dir": str(tmp_path / "reports"),
        "log_dir": str(tmp_path / "logs"),
    })
    # Tests write a file and scan immediately; disable the production
    # in-flight guard (stability_seconds) except in the test that sets it.
    st.app.setdefault("ingest", {})["stability_seconds"] = 0
    st.ensure_dirs()
    return st


@pytest.fixture()
def db(settings: Settings) -> Database:
    database = Database(settings.db_path)
    yield database
    database.close()


@pytest.fixture()
def indicators() -> Indicators:
    ind = Indicators(ROOT / "config")
    assert not ind.load_errors, f"shipped indicator files have bad patterns: {ind.load_errors}"
    return ind
