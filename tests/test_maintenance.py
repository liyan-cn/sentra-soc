from datetime import timedelta
from pathlib import Path

from monitor.domain.models import utc_now
from monitor.infrastructure.database import Database
from monitor.workers.maintenance_worker import run_once


def test_candidate_scan_does_not_hold_writer_lock(tmp_path, monkeypatch):
    from monitor.workers import maintenance_worker as worker
    db = Database(tmp_path / 'concurrent.db'); db.initialize()
    with db.transaction() as conn:
        conn.execute("CREATE TABLE writer_probe(value INTEGER)")
        conn.execute("INSERT INTO parse_failures(device_id,raw_hash,sample,error,first_seen_at,last_seen_at) VALUES('d','old','x','x','2000','2000')")
    original = worker._candidate_rows
    def concurrent_writer(*args):
        with db.connect() as conn:
            conn.execute('PRAGMA busy_timeout=50')
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('INSERT INTO writer_probe VALUES(1)')
            conn.commit()
        return original(*args)
    monkeypatch.setattr(worker, '_candidate_rows', concurrent_writer)
    assert worker._delete_batch(db, 'parse_failures', 'last_seen_at', '2020', 10) == 1


def test_timed_out_maintenance_write_rolls_back_and_releases_lock(tmp_path, monkeypatch):
    import sqlite3
    import pytest
    from monitor.workers import maintenance_worker as worker
    db = Database(tmp_path / 'rollback.db'); db.initialize()
    with db.transaction() as conn: conn.execute('CREATE TABLE writer_probe(value INTEGER)')
    clock = iter([0, 2, 2, 2])
    monkeypatch.setattr(worker.time, 'monotonic', lambda: next(clock, 2))
    with pytest.raises(sqlite3.OperationalError, match='interrupted'):
        with worker._maintenance_write(db) as conn:
            conn.execute('INSERT INTO writer_probe VALUES(1)')
            conn.execute('WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n').fetchone()
    with db.transaction(immediate=True) as conn:
        assert conn.execute('SELECT count(*) FROM writer_probe').fetchone()[0] == 0



class Settings:
    config_path = Path(__file__)

    def section(self, name):
        if name == "retention":
            return {
                "security_events_days": 10, "parse_failures_days": 10,
                "host_checks_days": 10, "vpn_sessions_days": 10,
                "notification_logs_days": 10, "audit_logs_days": 10,
                "batch_size": 10, "aggregate_days": 2,
            }
        return {}


def test_maintenance_continues_retention_after_aggregation_timeout(tmp_path, monkeypatch):
    import sqlite3
    from monitor.workers import maintenance_worker
    db = Database(tmp_path / "timeout.db"); db.initialize()
    def interrupted(*args, **kwargs):
        raise sqlite3.OperationalError("interrupted")
    monkeypatch.setattr(maintenance_worker, "aggregate_day", interrupted)
    result = run_once(Settings(), db)
    assert len(result["errors"]) == 2
    assert "parse_failures" in result["deleted"]
    assert "wal_checkpoint" in result


def test_event_cleanup_timeout_keeps_other_results(tmp_path, monkeypatch):
    import sqlite3
    from monitor.workers import maintenance_worker as worker
    db = Database(tmp_path / 'events-timeout.db'); db.initialize()
    def interrupted(*args, **kwargs):
        raise sqlite3.OperationalError('interrupted')
    monkeypatch.setattr(worker, '_delete_events', interrupted)
    report = worker.run_once(Settings(), db)
    assert 'security_events: interrupted' in report['errors']
    assert 'source_hourly_stats' in report['deleted']
    assert 'wal_checkpoint' in report


def test_retention_has_a_per_cycle_batch_limit(tmp_path):
    from monitor.workers.maintenance_worker import _delete_batch
    db = Database(tmp_path / "bounded.db"); db.initialize()
    with db.transaction() as conn:
        conn.executemany("INSERT INTO parse_failures(device_id,raw_hash,sample,error,first_seen_at,last_seen_at) VALUES('d',?,'x','x','2000','2000')",
                         [(str(i),) for i in range(30)])
    assert _delete_batch(db, "parse_failures", "last_seen_at", "2020", 10, max_batches=2) == 20
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM parse_failures").fetchone()[0] == 10


def test_maintenance_aggregates_and_removes_old_events(tmp_path):
    db = Database(tmp_path / "maintenance.db")
    db.initialize()
    now = utc_now()
    yesterday = now - timedelta(days=1)
    old = now - timedelta(days=20)
    with db.transaction() as conn:
        for event_id, occurred in (("recent", yesterday), ("old", old)):
            conn.execute(
                """INSERT INTO security_events(id,raw_hash,source,device_id,occurred_at,received_at,
                   event_type,src_ip,category,severity) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (event_id, event_id, "WAF", "d1", occurred.isoformat(), occurred.isoformat(),
                 "attack", "203.0.113.1", "SQL", "high"),
            )
            conn.execute(
                """INSERT INTO policy_decisions(id,event_id,decision,rule_id,reason,window_count,location,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                ("decision-" + event_id, event_id, "BLOCK", "r1", "test", 1, "X", occurred.isoformat()),
            )
        conn.execute(
            """INSERT INTO parse_failures(device_id,raw_hash,sample,error,first_seen_at,last_seen_at)
               VALUES('d1','old','x','bad',?,?)""", (old.isoformat(), old.isoformat())
        )

    report = run_once(Settings(), db)

    assert report["deleted"]["security_events"] == 1
    assert report["deleted"]["parse_failures"] == 1
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1
        row = conn.execute("SELECT * FROM daily_stats WHERE stat_date=?", (yesterday.date().isoformat(),)).fetchone()
        assert row["event_count"] == 1
        assert row["block_count"] == 1
