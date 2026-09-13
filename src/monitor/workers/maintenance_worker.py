from __future__ import annotations

import time
import logging
import sqlite3
import json
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

from monitor.common.logging import configure_logging
from monitor.domain.models import utc_now
from monitor.services.event_service import EventService
from monitor.common.retention import effective_retention
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


RETENTION_TARGETS = {
    "parse_failures_days": ("parse_failures", "last_seen_at"),
    "host_checks_days": ("host_checks", "checked_at"),
    "vpn_sessions_days": ("vpn_sessions", "login_at"),
    "notification_logs_days": ("notification_logs", "created_at"),
    "audit_logs_days": ("audit_logs", "created_at"),
}


def _candidate_rows(db, sql, params):
    # A missing retention index must never turn a read scan into a writer lock.
    with db.connect() as conn:
        deadline = time.monotonic() + 10.0
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        return conn.execute(sql, params).fetchall()


@contextmanager
def _maintenance_write(db):
    with db.transaction(immediate=True) as conn:
        deadline = time.monotonic() + 1.0
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            yield conn
        finally:
            conn.set_progress_handler(None, 0)


def _delete_batch(db, table: str, column: str, cutoff: str, batch_size: int, max_batches: int = 20) -> int:
    """Delete old rows in short transactions; table names only come from the allowlist above."""
    deleted = 0
    cursor_key = 'retention_cursor:' + table
    with db.connect() as conn:
        row = conn.execute('SELECT value_json FROM runtime_settings WHERE name=?', (cursor_key,)).fetchone()
        cursor = int(json.loads(row[0])) if row else 0
    for _ in range(max_batches):
        condition = " AND status<>'active'" if table == 'vpn_sessions' else ''
        status_column = ',status' if table == 'vpn_sessions' else ''
        rows = _candidate_rows(db,
            f"SELECT rowid,{column}{status_column} FROM {table} WHERE rowid>? ORDER BY rowid LIMIT 500",
            (cursor,))
        limit = min(batch_size, 50)
        ids = []
        for row in rows:
            cursor = row[0]
            if row[1] is not None and row[1] < cutoff and (table != 'vpn_sessions' or row[2] != 'active'):
                ids.append(row[0])
                if len(ids) == limit: break
        if not rows: cursor = 0
        marks = ','.join('?' for _ in ids)
        with _maintenance_write(db) as conn:
            changed = conn.execute(
                f"DELETE FROM {table} WHERE rowid IN ({marks}) AND {column}<?{condition}",
                (*ids, cutoff),
            ).rowcount if ids else 0
            conn.execute('''INSERT INTO runtime_settings(name,value_json,updated_at) VALUES(?,?,?)
                ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at''',
                (cursor_key, json.dumps(cursor), utc_now().isoformat()))
        deleted += changed
        if not rows or (len(rows) < 500 and len(ids) < limit):
            # Wrap only after all rows in this segment were visited.
            if rows:
                with _maintenance_write(db) as conn:
                    conn.execute('UPDATE runtime_settings SET value_json=? WHERE name=?', ('0', cursor_key))
            return deleted
        # Maintenance is lower priority than live ingestion.  Yield between
        # batches so collectors can acquire SQLite's single writer lock.
        time.sleep(0.02)
    return deleted


def _delete_events(db, cutoff: str, batch_size: int, max_batches: int = 20) -> int:
    deleted = 0
    for _ in range(max_batches):
        ids = [row[0] for row in _candidate_rows(db,
            "SELECT id FROM security_events WHERE occurred_at<? LIMIT ?", (cutoff, min(batch_size, 10)))]
        if not ids:
            return deleted
        with _maintenance_write(db) as conn:
            marks = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM policy_decisions WHERE event_id IN ({marks})", ids)
            conn.execute(f"DELETE FROM soc_alerts WHERE event_id IN ({marks})", ids)
            conn.execute(f"DELETE FROM security_events WHERE id IN ({marks})", ids)
        deleted += len(ids)
        time.sleep(0.02)
    return deleted


def aggregate_day(db, stat_date: date, timeout_seconds: float = 30) -> int:
    start = datetime.combine(stat_date, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    # The production aggregation scan can take several seconds.  Keep it on a
    # read connection so it does not starve collectors waiting to persist live
    # events and VPN sessions.  Only the small replacement needs a write lock.
    with db.connect() as conn:
        deadline = time.monotonic() + max(0.01, timeout_seconds)
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        rows = conn.execute(
            """SELECT e.source,e.category,COUNT(DISTINCT e.id) event_count,
               COUNT(DISTINCT CASE WHEN d.decision='BLOCK' THEN e.id END) block_count,
               COUNT(DISTINCT CASE WHEN d.decision='MANUAL_REVIEW' THEN e.id END) review_count
               FROM security_events e LEFT JOIN policy_decisions d ON d.event_id=e.id
               WHERE e.occurred_at>=? AND e.occurred_at<? GROUP BY e.source,e.category""",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
    with db.transaction(immediate=True) as conn:
        conn.execute("DELETE FROM daily_stats WHERE stat_date=?", (stat_date.isoformat(),))
        conn.executemany(
            "INSERT INTO daily_stats(stat_date,source,category,event_count,block_count,review_count) VALUES(?,?,?,?,?,?)",
            [(stat_date.isoformat(), row["source"], row["category"], row["event_count"],
              row["block_count"], row["review_count"]) for row in rows],
        )
    return len(rows)


def run_once(settings, db) -> dict:
    now = utc_now()
    with db.connect() as conn:
        retention = effective_retention(settings, conn)
    batch_size = max(10, int(retention.get("batch_size", 1000)))
    details: dict[str, object] = {"expired": 0, "deleted": {}, "aggregated_rows": 0}

    with db.transaction(immediate=True) as conn:
        expired = conn.execute(
            "SELECT id,ip,version FROM blacklist_entries "
            "WHERE desired_state='blocked' AND desired_expires_at<=? LIMIT 100", (now.isoformat(),)
        ).fetchall()
        for row in expired:
            conn.execute("UPDATE blacklist_entries SET desired_state='pending_unblock',version=version+1 WHERE id=?", (row["id"],))
            EventService._enqueue(conn, "UNBLOCK", "blacklist", row["id"], {"ip": row["ip"]},
                                  f"unblock:{row['id']}:{int(row['version'])+1}", 90)
    details["expired"] = len(expired)

    aggregate_days = max(1, int(retention.get("aggregate_days", 2)))
    for days_ago in range(1, aggregate_days + 1):
        heartbeat(db, "maintenance-worker", "running", {"phase": "aggregation", "days_ago": days_ago})
        try:
            details["aggregated_rows"] += aggregate_day(
                db, now.date() - timedelta(days=days_ago),
                float(retention.get("aggregation_timeout_seconds", 30)),
            )
        except sqlite3.OperationalError as exc:
            details.setdefault("errors", []).append("aggregation: " + str(exc))

    deleted = details["deleted"]
    for setting, (table, column) in RETENTION_TARGETS.items():
        heartbeat(db, "maintenance-worker", "running", {"phase": "retention", "table": table})
        days = int(retention.get(setting, 30))
        try:
            deleted[table] = _delete_batch(db, table, column, (now - timedelta(days=days)).isoformat(), batch_size)
        except sqlite3.OperationalError as exc:
            details.setdefault('errors', []).append(table + ': ' + str(exc))
    event_days = int(retention.get("security_events_days", 180))
    try:
        deleted["security_events"] = _delete_events(
            db, (now - timedelta(days=event_days)).isoformat(), batch_size
        )
    except sqlite3.OperationalError as exc:
        details.setdefault('errors', []).append('security_events: ' + str(exc))
    for table in ('source_hourly_stats', 'ingestion_hourly_stats', 'source_alert_hourly_stats'):
        try:
            deleted[table] = _delete_batch(
                db, table, "hour", (now - timedelta(days=event_days)).isoformat()[:13], batch_size
            )
        except sqlite3.OperationalError as exc:
            details.setdefault('errors', []).append(table + ': ' + str(exc))
    with db.connect() as conn:
        checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
    details["wal_checkpoint"] = list(checkpoint)
    return details


def run():
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    interval = max(60, int(settings.section("retention").get("interval_seconds", 300)))
    while not stopping.is_set():
        try:
            details = run_once(settings, db)
            heartbeat(db, "maintenance-worker", "degraded" if details.get("errors") else "ok", details)
        except sqlite3.OperationalError as exc:
            logging.getLogger(__name__).warning("maintenance cycle deferred: %s", exc)
            heartbeat(db, "maintenance-worker", "degraded", {"last_error": str(exc)})
        stopping.wait(interval)


def main():
    configure_logging()
    run()


if __name__ == "__main__":
    main()
