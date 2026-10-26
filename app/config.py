"""Configuration loading: YAML config files + .env environment overrides.

Everything path/port/threshold related lives in config files or .env, never
hard-coded in logic, so the tool can be moved from a home dev box to the
office server by editing config only.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR_NAME = "config"

_env_loaded = False


def load_dotenv(path: Path) -> None:
    """Parse a simple KEY=VALUE .env file into os.environ. Existing env wins."""
    global _env_loaded
    if _env_loaded or not path.is_file():
        _env_loaded = True
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
    _env_loaded = True


def read_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


class Settings:
    """Resolved view over config/app_config.yaml + config/scoring.yaml +
    config/incident_types.yaml + config/behavior_lists.yaml + .env."""

    def __init__(self, base_dir: Path | None = None, path_overrides: dict | None = None):
        self.base_dir = Path(base_dir) if base_dir else BASE_DIR
        self.config_dir = self.base_dir / CONFIG_DIR_NAME
        load_dotenv(self.base_dir / ".env")
        self.app = read_yaml(self.config_dir / "app_config.yaml")
        self.scoring_cfg = read_yaml(self.config_dir / "scoring.yaml")
        self.incident_types_cfg = read_yaml(self.config_dir / "incident_types.yaml")
        self.behavior = read_yaml(self.config_dir / "behavior_lists.yaml")
        self._path_overrides = dict(path_overrides or {})
        self.warnings: list[str] = []

    # ---- paths -----------------------------------------------------------
    def path(self, key: str) -> Path:
        if key in self._path_overrides:
            return Path(self._path_overrides[key])
        rel = self.app.get("paths", {}).get(key, key)
        p = Path(rel)
        return p if p.is_absolute() else (self.base_dir / p)

    @property
    def inbox_dir(self) -> Path:
        return self.path("inbox_dir")

    @property
    def processed_dir(self) -> Path:
        return self.path("processed_dir")

    @property
    def error_dir(self) -> Path:
        return self.path("error_dir")

    @property
    def db_path(self) -> Path:
        return self.path("db_path")

    @property
    def reports_dir(self) -> Path:
        return self.path("reports_dir")

    @property
    def log_dir(self) -> Path:
        return self.path("log_dir")

    def ensure_dirs(self) -> None:
        for d in (self.inbox_dir, self.processed_dir, self.error_dir,
                  self.db_path.parent, self.reports_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ---- server ----------------------------------------------------------
    @property
    def host(self) -> str:
        return str(self.app.get("server", {}).get("host", "127.0.0.1"))

    @property
    def port(self) -> int:
        return int(self.app.get("server", {}).get("port", 8043))

    # ---- ingest ----------------------------------------------------------
    @property
    def poll_seconds(self) -> int:
        return int(self.app.get("ingest", {}).get("poll_seconds", 30))

    @property
    def max_file_bytes(self) -> int:
        return int(self.app.get("ingest", {}).get("max_file_bytes", 50 * 1024 * 1024))

    @property
    def ingest_stability_seconds(self) -> float:
        """Files newer than this are considered still-being-written (in-flight)
        and are deferred to the next inbox scan."""
        return float(self.app.get("ingest", {}).get("stability_seconds", 5))

    @property
    def allowed_extensions(self) -> list[str]:
        exts = self.app.get("ingest", {}).get("allowed_extensions", [".csv", ".json", ".jsonl", ".txt", ".log"])
        return [e.lower() for e in exts]

    # ---- scoring / windows ---------------------------------------------
    @property
    def window_hours(self) -> int:
        return int(self.app.get("scoring_window_hours", 24))

    @property
    def recheck_days(self) -> int:
        return int(self.app.get("recheck", {}).get("days", 14))

    @property
    def recheck_enabled(self) -> bool:
        return bool(self.app.get("recheck", {}).get("enabled", True))

    @property
    def version(self) -> str:
        try:
            return (self.base_dir / "VERSION").read_text(encoding="utf-8").strip()
        except OSError:
            return "dev"

    @property
    def alert_channels(self) -> list[str]:
        if not self.app.get("alerts", {}).get("enabled", True):
            return []
        return list(self.app.get("alerts", {}).get("channels", ["log"]))

    @property
    def rule_weights(self) -> dict:
        return dict(self.scoring_cfg.get("rule_weights", {}))

    @property
    def thresholds(self) -> dict:
        return dict(self.scoring_cfg.get("thresholds", {}))

    @property
    def escalation(self) -> dict:
        return dict(self.scoring_cfg.get("escalation", {}))

    @property
    def severity_levels(self) -> list[str]:
        return list(self.scoring_cfg.get("severity_levels", ["low", "medium", "high", "critical"]))

    @property
    def types(self) -> dict:
        return dict(self.incident_types_cfg.get("types", {}))

    @property
    def retention_cfg(self) -> dict:
        return dict(self.app.get("retention", {}) or {})

    def off_hours_minutes(self) -> list[tuple[int, int]]:
        """Parse off_hours entries like '22:00-06:00' into (start, end) minutes."""
        ranges: list[tuple[int, int]] = []
        for item in self.app.get("off_hours", []) or []:
            try:
                start, end = str(item).split("-")
                sh, sm = start.strip().split(":")
                eh, em = end.strip().split(":")
                ranges.append((int(sh) * 60 + int(sm), int(eh) * 60 + int(em)))
            except (ValueError, AttributeError):
                self.warnings.append(f"Invalid off_hours entry: {item!r}")
        return ranges

    @property
    def technitium_columns(self) -> dict:
        return dict(self.app.get("technitium_columns", {}))

    @property
    def ip_map_file(self) -> Path:
        rel = self.app.get("ip_map_file", "config/ip_map.txt")
        p = Path(rel)
        return p if p.is_absolute() else (self.base_dir / p)

    # ---- behavior lists (office/browser/interpreter) ---------------------
    @property
    def office_apps(self) -> list[str]:
        return [str(x).lower() for x in self.behavior.get("office_apps", [])]

    @property
    def browsers(self) -> list[str]:
        return [str(x).lower() for x in self.behavior.get("browsers", [])]

    @property
    def interpreters(self) -> list[str]:
        return [str(x).lower() for x in self.behavior.get("script_interpreters", [])]

