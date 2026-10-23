"""Endpoint Threat Detection & Incident Tracker."""
from pathlib import Path


def read_version() -> str:
    try:
        return (Path(__file__).resolve().parent.parent / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


VERSION = read_version()
