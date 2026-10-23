"""SQLite access layer.

Single serialized connection guarded by a re-entrant lock: one background
watcher thread plus FastAPI request handlers. All queries are parameterized.
The schema is created idempotently and tracked in schema_meta so future
migrations can be applied in order.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pcs (
  hostname TEXT PRIMARY KEY,
  ip TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL UNIQUE,
  filename TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  record_type TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,               -- ingested | duplicate | error
  detail TEXT NOT NULL DEFAULT '',
  record_count INTEGER NOT NULL DEFAULT 0,
  ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
  record_type TEXT NOT NULL,
  pc TEXT,
  ts TEXT NOT NULL,
  dedup_key TEXT NOT NULL UNIQUE,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_pc_ts ON observations(pc, ts);
CREATE INDEX IF NOT EXISTS idx_obs_type_ts ON observations(record_type, ts);

CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  pc TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  category TEXT NOT NULL,
  weight INTEGER NOT NULL DEFAULT 0,
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
  correlation TEXT NOT NULL DEFAULT '[]',
  incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
  dedup_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_signals_pc_ts ON signals(pc, ts);
CREATE INDEX IF NOT EXISTS idx_signals_incident ON signals(incident_id);
CREATE INDEX IF NOT EXISTS idx_signals_rule ON signals(rule_id, ts);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_key TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,                 -- miner | ransomware | remote-access/backdoor | unknown
  type_source TEXT NOT NULL DEFAULT 'auto',
  severity TEXT NOT NULL DEFAULT 'low',
  status TEXT NOT NULL DEFAULT 'open', -- open | closed
  state_version INTEGER NOT NULL DEFAULT 0,
  title TEXT NOT NULL DEFAULT '',
  entry_point TEXT NOT NULL DEFAULT '',
  containment_actions TEXT NOT NULL DEFAULT '',
  reimaged INTEGER NOT NULL DEFAULT 0,
  priority TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT,
  closed_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_pcs (
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  pc TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'detected', -- detected | isolated | reimaged | verified
  owner TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL DEFAULT '',
  state_ts TEXT,
  verified_at TEXT,
  recheck_until TEXT,
  recheck_passed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (incident_id, pc)
);

CREATE TABLE IF NOT EXISTS incident_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  pc TEXT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'system',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  transition TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inc_events ON incident_events(incident_id, ts);

CREATE TABLE IF NOT EXISTS incident_keys (
  key_type TEXT NOT NULL,
  key_value TEXT NOT NULL,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (key_type, key_value, incident_id)
);
CREATE INDEX IF NOT EXISTS idx_inc_keys_incident ON incident_keys(incident_id);

CREATE TABLE IF NOT EXISTS checklist_state (
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  item TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  checked_by TEXT NOT NULL DEFAULT '',
  ts TEXT,
  PRIMARY KEY (incident_id, item)
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,                -- admin | analyst | viewer
  created_at TEXT NOT NULL,
  last_login TEXT,
  disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS alerts_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  incident_id INTEGER,
  kind TEXT NOT NULL,
  channel TEXT NOT NULL,
  dedup_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,              -- sent | logged | disabled | failed | skipped_unconfigured
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts_log(incident_id);
"""

SCHEMA_VERSION = "2"


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._tx_depth = 0
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('version', ?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()

    # ---- basic accessors -------------------------------------------------
    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchone()

    def execute(self, sql: str, params: tuple = ()) -> int:
        """Execute one statement. Returns the new rowid for successful INSERTs
        (0 when an INSERT OR IGNORE was ignored); callers ignore the value for
        UPDATE/DELETE."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            rowid = cur.lastrowid if cur.rowcount == 1 else 0
            if self._tx_depth == 0:
                self._conn.commit()
            return rowid or 0

    def executemany(self, sql: str, seq) -> None:
        with self._lock:
            self._conn.executemany(sql, seq)
            if self._tx_depth == 0:
                self._conn.commit()

    @contextmanager
    def tx(self):
        """Serialized transaction; nests safely (inner joins the outer tx)."""
        with self._lock:
            if self._tx_depth > 0:
                self._tx_depth += 1
                try:
                    yield
                finally:
                    self._tx_depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._tx_depth = 1
            try:
                yield
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                self._tx_depth = 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()
