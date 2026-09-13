from __future__ import annotations

import sqlite3
import threading
import time
from importlib import resources
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, source TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  config_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events(
  id TEXT PRIMARY KEY, raw_hash TEXT NOT NULL UNIQUE, source TEXT NOT NULL,
  device_id TEXT NOT NULL, occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
  event_type TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT,
  category TEXT NOT NULL, vendor_category TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL, attributes_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_src_time ON security_events(src_ip, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON security_events(source, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(occurred_at);
CREATE TABLE IF NOT EXISTS policy_decisions(
  id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES security_events(id),
  decision TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL, window_count INTEGER NOT NULL, location TEXT NOT NULL,
  created_at TEXT NOT NULL, UNIQUE(event_id, rule_id, rule_version)
);
CREATE TABLE IF NOT EXISTS blacklist_entries(
  id TEXT PRIMARY KEY, ip TEXT NOT NULL UNIQUE, desired_state TEXT NOT NULL,
  actual_state TEXT NOT NULL DEFAULT 'unknown', first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL, desired_expires_at TEXT NOT NULL,
  confirmed_expires_at TEXT, hit_count INTEGER NOT NULL DEFAULT 0,
  category TEXT NOT NULL, source TEXT NOT NULL, location TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1, last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_blacklist_state ON blacklist_entries(desired_state, actual_state);
CREATE TABLE IF NOT EXISTS review_cases(
  id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL, event_id TEXT NOT NULL,
  ip TEXT NOT NULL, category TEXT NOT NULL, source TEXT NOT NULL,
  status TEXT NOT NULL, count INTEGER NOT NULL, reason TEXT NOT NULL,
  assignee TEXT, resolution TEXT, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reviews_status ON review_cases(status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_review ON review_cases(dedup_key) WHERE status IN ('open','claimed');
CREATE TABLE IF NOT EXISTS action_outbox(
  id TEXT PRIMARY KEY, action_type TEXT NOT NULL, aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL, payload_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pending',
  priority INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 8, available_at TEXT NOT NULL,
  locked_by TEXT, locked_until TEXT, last_error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_ready ON action_outbox(status, available_at, priority);
CREATE TABLE IF NOT EXISTS collector_checkpoints(
  device_id TEXT PRIMARY KEY, file_path TEXT NOT NULL, inode TEXT NOT NULL,
  offset INTEGER NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS parse_failures(
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
  raw_hash TEXT NOT NULL, sample TEXT NOT NULL, error TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1, first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL, UNIQUE(device_id, raw_hash)
);
CREATE TABLE IF NOT EXISTS ip_geo_cache(
  ip TEXT PRIMARY KEY, country TEXT, region TEXT, city TEXT,
  status TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS whitelist_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vpn_sessions(
  id TEXT PRIMARY KEY, session_key TEXT NOT NULL UNIQUE, username TEXT NOT NULL,
  client_ip TEXT NOT NULL, virtual_ip TEXT, login_at TEXT NOT NULL,
  logout_at TEXT, status TEXT NOT NULL, location TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hosts(
  ip TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'unknown',
  consecutive_failures INTEGER NOT NULL DEFAULT 0, last_checked_at TEXT,
  last_changed_at TEXT, last_notified_at TEXT
);
CREATE TABLE IF NOT EXISTS host_checks(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, checked_at TEXT NOT NULL,
  online INTEGER NOT NULL, loss_rate REAL, latency_ms REAL, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_host_checks_time ON host_checks(ip, checked_at);
CREATE TABLE IF NOT EXISTS service_heartbeats(
  service TEXT PRIMARY KEY, instance_id TEXT NOT NULL, status TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_logs(
  id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL, channel TEXT NOT NULL,
  status TEXT NOT NULL, error TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT NOT NULL, reason TEXT,
  before_json TEXT, after_json TEXT, source_ip TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_stats(
  stat_date TEXT NOT NULL, source TEXT NOT NULL, category TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0, block_count INTEGER NOT NULL DEFAULT 0,
  review_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(stat_date, source, category)
);
"""


class ManagedConnection(sqlite3.Connection):
    """A sqlite connection whose context manager also releases the file handle."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Database:
    dialect = "sqlite"
    supports_multi_node = False

    def __init__(self, path: str | Path, busy_timeout_ms: int = 10000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None,
            factory=ManagedConnection,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        try:
            # journal_mode is persistent for a SQLite database.  Changing or
            # even negotiating it for every short-lived worker connection
            # serialises all writers, which caused the discovery worker to
            # restart under a busy Syslog load.  It is now ensured only by an
            # explicit initialization/migration operation.
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            # Dashboard reads repeatedly sort and aggregate recent windows.
            # Keep temporary work in memory and let SQLite use a bounded mmap
            # window; both settings are per connection and preserve WAL safety.
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=-32768")
            conn.execute("PRAGMA mmap_size=268435456")
        except Exception:
            conn.close()
            raise
        return conn

    def _ensure_wal(self) -> None:
        """Enable WAL during a controlled initialization, never hot-path I/O."""
        with self.connect() as conn:
            for attempt in range(10):
                try:
                    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                    if str(mode).lower() == "wal":
                        return
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == 9:
                        raise
                    time.sleep(0.05 * (2 ** attempt))
        raise RuntimeError("unable to enable SQLite WAL mode")

    def initialize(self, migrate: bool = True) -> None:
        """Create/upgrade the database.

        Service workers call this with ``migrate=False`` after the deployment
        migration has completed.  That avoids every worker issuing DDL and an
        immediate write transaction at startup while collectors are active.
        A new, empty database is always fully migrated.
        """
        with self.connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone() is not None
        if not exists:
            self._ensure_wal()
            with self.connect() as conn:
                conn.executescript(SCHEMA)
                conn.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, datetime('now'))")
            migrate = True
        if migrate:
            self._ensure_wal()
            self.migrate()

    def migrate(self) -> None:
        """Apply ordered migrations under a cross-process SQLite write lock."""
        migration_root = resources.files("monitor.migrations")
        migrations = sorted(
            (item for item in migration_root.iterdir() if item.name[:4].isdigit() and item.name.endswith(".sql")),
            key=lambda item: int(item.name[:4]),
        )
        with self.transaction(immediate=True, retries=8) as conn:
            for item in migrations:
                version = int(item.name[:4])
                if conn.execute("SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone():
                    continue
                sql = item.read_text(encoding="utf-8")
                for statement in self._sql_statements(sql):
                    conn.execute(statement)
                conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, datetime('now'))", (version,))

    @staticmethod
    def _sql_statements(script: str) -> list[str]:
        """Split packaged migration SQL without executescript's implicit transaction commit."""
        statements: list[str] = []
        buffer = ""
        for line in script.splitlines(keepends=True):
            buffer += line
            if sqlite3.complete_statement(buffer):
                if buffer.strip():
                    statements.append(buffer.strip())
                buffer = ""
        if buffer.strip():
            raise ValueError("incomplete SQL statement in migration")
        return statements

    @contextmanager
    def transaction(self, immediate: bool = False, retries: int = 4):
        conn = self.connect()
        try:
            for attempt in range(retries):
                try:
                    conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == retries - 1:
                        raise
                    time.sleep(0.05 * (2**attempt))
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
