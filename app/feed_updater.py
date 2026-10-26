"""Feed updater for threat intel indicator files.

Loads config/feeds.yaml mappings and fetches URLs into config/indicators/*.txt
with backup and audit logging. Normalizes entries to one per line.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

import yaml
import requests

from . import audit as audit_mod

DEFAULT_TIMEOUT = 30


def _read_feeds(cfg_dir: Path) -> dict:
    path = cfg_dir / "feeds.yaml"
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("feeds", {})


def _normalize_lines(text: str, mode: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if mode == "domains":
            # keep hostnames lowercased, strip trailing dot
            line = line.lower().strip().rstrip(".")
            # extract domain if URL
            if line.startswith("http://") or line.startswith("https://"):
                # crude extraction
                try:
                    from urllib.parse import urlparse
                    line = urlparse(line).hostname or line
                except Exception:
                    pass
                line = (line or "").lower().strip().rstrip(".")
        elif mode == "hashes":
            line = line.lower().strip()
        else:
            line = line.strip().lower()
        if line:
            lines.append(line)
    # dedupe preserving order
    seen = set()
    out = []
    for l in lines:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out


def _atomic_write(path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)


def update_all(settings, db=None, actor: str = "system") -> dict[str, Any]:
    cfg_dir = settings.config_dir
    feeds_cfg = _read_feeds(cfg_dir)
    ind_dir = cfg_dir / "indicators"
    ind_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    now = time.time()
    for target_file, meta in feeds_cfg.items():
        url = meta.get("url")
        mode = meta.get("mode", "text")
        if not url:
            results[target_file] = {"skipped": True, "reason": "no url"}
            continue
        try:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
            resp.raise_for_status()
            text = resp.text
            lines = _normalize_lines(text, mode)
            target_path = ind_dir / f"{target_file}.txt"
            if target_path.is_file():
                backup = target_path.with_name(target_path.name + ".bak")
                shutil.copy2(target_path, backup)
            _atomic_write(target_path, lines)
            if db:
                audit_mod.audit(db, actor, "feed_update", f"indicators/{target_file}.txt", f"updated {len(lines)} entries from {url}")
            results[target_file] = {"updated": True, "count": len(lines)}
        except Exception as exc:
            results[target_file] = {"updated": False, "error": str(exc)}
    # touch last run marker
    try:
        (settings.base_dir / "data").mkdir(parents=True, exist_ok=True)
        (settings.base_dir / "data" / "last_feed_update.txt").write_text(str(int(now)), encoding="utf-8")
    except Exception:
        pass
    return results
