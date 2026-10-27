"""Inbox watcher: validate, hash, dedupe, parse and store exported files.

This tool is READ-ONLY with respect to the environment: it only consumes
files that a human (or scheduled export script) drops into the inbox folder.
Files are moved to processed/ or errors/ afterwards; they are never modified
in place, and no other system is ever contacted.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path

from .audit import audit
from .config import Settings
from .db import Database
from .indicators import Indicators
from .normalize import now_iso
from .parsers import ParseError, dedup_key, parse_file

log = logging.getLogger("tracker.ingest")

INVENTORY_TYPES = ("process_inventory", "task_inventory", "persistence_inventory", "defender_status")
NETWORK_TYPES = ("dns_query", "connection")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Ingestor:
    """Scans the inbox once per call. Safe to call repeatedly and concurrently
    (serialized by the Database lock; the ledger prevents double work)."""

    def __init__(self, db: Database, settings: Settings, indicators: Indicators,
                 detector=None):
        self.db = db
        self.settings = settings
        self.indicators = indicators
        self.detector = detector  # object with .run(set[str]) -> dict
        self._ip_map: dict[str] = dict(indicators.ip_map)
        self._ip_map_loaded = False
        # files whose last quarantine move failed (disk full / permissions):
        # name -> unix time when processing may be retried, so a failing disk
        # cannot be re-hashed and re-audited on every 30 s scan (log/DB flood)
        self._move_backoff: dict[str, float] = {}
        self.move_backoff_seconds = 300.0

    # ---- IP -> hostname learning ----------------------------------------
    def _load_ip_map(self) -> None:
        if self._ip_map_loaded:
            return
        self._ip_map_loaded = True
        rows = self.db.query(
            "SELECT payload, pc FROM observations WHERE record_type IN "
            "('process_inventory','persistence_inventory','defender_status','file_activity','task_inventory')"
        )
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (ValueError, TypeError):
                continue
            ip = payload.get("ip")
            host = payload.get("hostname") or row["pc"]
            if ip and host:
                self._ip_map[str(ip)] = str(host)

    def resolve_pc(self, record: dict) -> str:
        host = record.get("hostname") or record.get("pc")
        if host:
            return str(host)
        ip = record.get("client_ip")
        if ip:
            return self._ip_map.get(str(ip), str(ip))
        return "unknown"

    # ---- file helpers ----------------------------------------------------
    def _move(self, path: Path, target_dir: Path) -> Path | None:
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            dst = target_dir / path.name
            if dst.exists():
                stem, suffix, n = path.stem, path.suffix, 1
                while (target_dir / f"{stem}_{n}{suffix}").exists():
                    n += 1
                dst = target_dir / f"{stem}_{n}{suffix}"
            shutil.move(str(path), str(dst))
            self._move_backoff.pop(path.name, None)
            return dst
        except OSError as exc:
            log.warning("could not move %s: %s (backing off %ss)",
                        path, exc, int(self.move_backoff_seconds))
            self._move_backoff[path.name] = time.time() + self.move_backoff_seconds
            return None

    def _record_file(self, sha: str, filename: str, size: int, status: str,
                     detail: str, record_type: str = "", count: int = 0) -> int:
        # Upsert keyed by content hash: a retry after a fix updates the old
        # error row instead of tripping the unique index. Return the real row id
        # (an upsert-on-conflict does not yield a fresh lastrowid).
        self.db.execute(
            "INSERT INTO files(sha256, filename, size_bytes, record_type, status, "
            "detail, record_count, ingested_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET filename=excluded.filename, "
            "record_type=excluded.record_type, status=excluded.status, "
            "detail=excluded.detail, record_count=excluded.record_count, "
            "ingested_at=excluded.ingested_at",
            (sha, filename, size, record_type, status, detail, count, now_iso()),
        )
        row = self.db.one("SELECT id FROM files WHERE sha256=?", (sha,))
        return int(row["id"]) if row else 0

    def _upsert_pc(self, hostname: str, ip: str, ts: str) -> None:
        self.db.execute(
            "INSERT INTO pcs(hostname, ip, first_seen, last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(hostname) DO UPDATE SET "
            "ip=CASE WHEN excluded.ip <> '' THEN excluded.ip ELSE pcs.ip END, "
            "last_seen=MAX(pcs.last_seen, excluded.last_seen)",
            (hostname, ip or "", ts, ts),
        )

    # ---- main scan -------------------------------------------------------
    def scan_once(self) -> dict:
        self.settings.ensure_dirs()
        stats = {"files": 0, "ingested": 0, "duplicates": 0, "errors": 0,
                 "deferred": 0,
                 "observations": 0, "signals": 0, "incidents_touched": 0}
        self._load_ip_map()

        try:
            entries = sorted(p for p in self.settings.inbox_dir.iterdir()
                             if p.is_file() and not p.name.startswith("."))
        except OSError as exc:
            log.error("cannot read inbox: %s", exc)
            return stats

        for path in entries:
            try:
                self._process_file(path, stats)
            except Exception:  # noqa: BLE001 - one bad file must not stop the watcher
                log.exception("unexpected error processing %s", path.name)
                stats["errors"] += 1
        return stats

    def _process_file(self, path: Path, stats: dict) -> None:
        # P9: after a failed quarantine move (disk full), leave the file
        # alone until the backoff expires instead of reprocessing every scan.
        retry_at = self._move_backoff.get(path.name)
        if retry_at is not None and time.time() < retry_at:
            stats["deferred"] += 1
            return
        stats["files"] += 1
        name = path.name
        try:
            st = path.stat()
        except OSError:
            return
        size = st.st_size

        # 1. validation: size + extension
        if size > self.settings.max_file_bytes:
            self._reject(path, size, f"file too large ({size} > {self.settings.max_file_bytes} bytes)", stats)
            return
        if path.suffix.lower() not in self.settings.allowed_extensions:
            self._reject(path, size, f"extension not allowed: {path.suffix}", stats)
            return

        # 2. in-flight guard: a file with a very fresh mtime is probably still
        # being written. Leave it in the inbox for the next cycle instead of
        # ingesting a partial file and moving it to processed/ forever.
        if time.time() - st.st_mtime < self.settings.ingest_stability_seconds:
            stats["deferred"] += 1
            log.debug("deferring in-flight file %s (mtime too fresh)", name)
            return

        # 2. ledger: skip content we already ingested
        try:
            sha = sha256_file(path)
        except OSError as exc:
            self._reject(path, size, f"cannot read file: {exc}", stats)
            return
        existing = self.db.one("SELECT status FROM files WHERE sha256=?", (sha,))
        if existing and existing["status"] != "error":
            stats["duplicates"] += 1
            audit(self.db, "system", "ingest_duplicate", name, f"sha256={sha[:12]}…")
            self._move(path, self.settings.processed_dir)
            return

        # 3. parse (safe parsing; ParseError -> error folder)
        try:
            records = parse_file(path, self.settings)
        except ParseError as exc:
            self._record_file(sha, name, size, "error", str(exc))
            audit(self.db, "system", "ingest_error", name, str(exc))
            self._reject(path, size, str(exc), stats, already_recorded=True)
            return
        except Exception as exc:  # noqa: BLE001 - a parser bug must not strand
            # the file in the inbox (retried and re-logged every cycle):
            # quarantine it with the error in the ledger instead.
            log.exception("parser crashed on %s", name)
            detail = f"parser crashed: {type(exc).__name__}: {exc}"
            self._record_file(sha, name, size, "error", detail)
            audit(self.db, "system", "ingest_error", name, detail)
            self._reject(path, size, detail, stats, already_recorded=True)
            return

        # 4. normalize PCs, store observations, run detection; one transaction.
        # On an unexpected failure nothing is committed, the file is parked in
        # errors/ (ledger row says 'error', so it can be retried after a fix),
        # and the next file still gets processed.
        affected: set[str] = set()
        stored = 0
        types: set[str] = set()
        try:
            with self.db.tx():
                file_id = self._record_file(sha, name, size, "ingested", "", "", len(records))
                for rec in records:
                    rec.pop("file_id", None)
                    pc = self.resolve_pc(rec)
                    rec["pc"] = pc
                    types.add(rec["record_type"])
                    obs_key = dedup_key(rec)
                    cur_id = self.db.execute(
                        "INSERT OR IGNORE INTO observations(file_id, record_type, pc, ts, dedup_key, payload) "
                        "VALUES(?,?,?,?,?,?)",
                        (file_id, rec["record_type"], pc, rec["ts"], obs_key,
                         json.dumps(rec, sort_keys=True, default=str)),
                    )
                    if cur_id:
                        stored += 1
                    affected.add(pc)
                    ip = rec.get("ip") or rec.get("client_ip")
                    if ip and pc and pc != "unknown":
                        self._ip_map[str(ip)] = pc
                        self._upsert_pc(pc, str(ip), rec["ts"])
                    elif pc and pc != "unknown":
                        self._upsert_pc(pc, "", rec["ts"])

                # 5. detection pipeline over affected PCs
                det = {"signals": 0, "incidents_touched": 0}
                if self.detector and affected:
                    det = self.detector.run(affected) or {}
        except Exception as exc:  # noqa: BLE001 - park the file, keep going
            log.exception("failed to ingest %s", name)
            self._record_file(sha, name, size, "error", f"ingest failed: {exc}")
            audit(self.db, "system", "ingest_error", name, f"ingest failed: {exc}")
            stats["errors"] += 1
            self._move(path, self.settings.error_dir)
            return

        stats["ingested"] += 1
        stats["observations"] += stored
        stats["signals"] += int(det.get("signals", 0))
        stats["incidents_touched"] += int(det.get("incidents_touched", 0))
        audit(self.db, "system", "ingest", name,
              f"records={len(records)} new_observations={stored} types={','.join(sorted(types))}")
        self.db.execute("UPDATE files SET record_type=?, record_count=? WHERE id=?",
                        (",".join(sorted(types)), stored, file_id))
        self._move(path, self.settings.processed_dir)

    def _reject(self, path: Path, size: int, reason: str, stats: dict,
                already_recorded: bool = False) -> None:
        stats["errors"] += 1
        if not already_recorded:
            try:
                sha = sha256_file(path)
            except OSError:
                sha = "-"
            if sha != "-":
                self._record_file(sha, path.name, size, "error", reason)
        audit(self.db, "system", "ingest_rejected", path.name, reason)
        self._move(path, self.settings.error_dir)
