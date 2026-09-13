from monitor.infrastructure.database import Database
from concurrent.futures import ThreadPoolExecutor


def test_schema_initializes(tmp_path):
    db = Database(tmp_path / "test.db")
    db.initialize()
    with db.connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"security_events", "blacklist_entries", "action_outbox", "review_cases",
            "workspaces", "soc_assets", "vulnerabilities", "baseline_findings",
            "soc_alerts", "threat_models", "operation_reports", "report_templates", "ai_analyses"} <= tables
    with db.connect() as conn:
        assert {row[0] for row in conn.execute("SELECT version FROM schema_migrations")} == set(range(1, 26))
        assert conn.execute("SELECT COUNT(*) FROM managed_playbooks WHERE id LIKE 'preset-%'").fetchone()[0] == 30


def test_concurrent_service_startup_applies_migrations_once(tmp_path):
    path = tmp_path / "concurrent.db"

    def initialize(_index):
        Database(path, busy_timeout_ms=5000).initialize()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(initialize, range(16)))

    db = Database(path)
    with db.connect() as conn:
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version")]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(action_outbox)")}
        assert versions == list(range(1, 26))
    assert "execution_mode" in columns


def test_migration_statement_splitter_rejects_incomplete_sql():
    assert Database._sql_statements("CREATE TABLE one(id INTEGER);\nCREATE INDEX idx ON one(id);") == [
        "CREATE TABLE one(id INTEGER);", "CREATE INDEX idx ON one(id);",
    ]
    try:
        Database._sql_statements("CREATE TABLE broken(")
    except ValueError as exc:
        assert "incomplete SQL" in str(exc)
    else:
        raise AssertionError("incomplete migration SQL must be rejected")


def test_security_event_is_materialized_as_mitre_alert(tmp_path):
    db = Database(tmp_path / "mitre.db"); db.initialize()
    with db.transaction(immediate=True) as conn:
        conn.execute("""INSERT INTO security_events(id,raw_hash,source,device_id,occurred_at,received_at,
                     event_type,src_ip,dst_ip,category,vendor_category,severity,attributes_json)
                     VALUES('evt-1','hash-1','WAF','waf-1','2026-08-07T01:00:00+00:00','2026-08-07T01:00:00+00:00',
                     'attack','203.0.113.8','192.0.2.1','SQL injection','SQL injection','high','{}')""")
        conn.execute("""INSERT INTO policy_decisions(id,event_id,decision,rule_id,reason,window_count,location,created_at)
                     VALUES('decision-1','evt-1','MANUAL_REVIEW','test','test',1,'UNKNOWN','2026-08-07T01:00:00+00:00')""")
    with db.connect() as conn:
        alert = conn.execute("SELECT mitre_tactic,mitre_technique FROM soc_alerts WHERE event_id='evt-1'").fetchone()
    assert tuple(alert) == ("Initial Access", "T1190")


def test_security_event_updates_hourly_source_rollup(tmp_path):
    db = Database(tmp_path / "rollup.db"); db.initialize()
    with db.transaction(immediate=True) as conn:
        for index in range(2):
            conn.execute("""INSERT INTO security_events(id,raw_hash,source,device_id,occurred_at,received_at,
                         event_type,src_ip,dst_ip,category,vendor_category,severity,attributes_json)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (f"rollup-{index}", f"rollup-hash-{index}", "H3C_SECURITY", "auto-192-0-2-21",
                          "2026-08-13T09:15:00+00:00", "2026-08-13T09:15:01+00:00", "attack",
                          f"203.0.113.{index + 1}", "192.0.2.1", "scan", "scan", "medium", "{}"))
        row = conn.execute("""SELECT event_count FROM source_hourly_stats
                            WHERE hour='2026-08-13T09' AND device_id='auto-192-0-2-21'""").fetchone()
    assert row[0] == 2


def test_soc_alert_updates_hourly_alert_source_rollup(tmp_path):
    db = Database(tmp_path / "alert-rollup.db"); db.initialize()
    with db.transaction(immediate=True) as conn:
        conn.execute("""INSERT INTO security_events(id,raw_hash,source,device_id,occurred_at,received_at,
                     event_type,src_ip,dst_ip,category,vendor_category,severity,attributes_json)
                     VALUES('evt-rollup','hash-rollup','TEST_WAF','device-1','2026-08-13T10:30:00+00:00',
                     '2026-08-13T10:30:01+00:00','attack','203.0.113.8','192.0.2.10','WEB_ATTACK',
                     'WEB_ATTACK','high','{}')""")
        conn.execute("""INSERT INTO soc_alerts(id,workspace_id,event_id,title,source,src_ip,dst_ip,
                     severity,status,occurred_at,updated_at)
                     VALUES('alert-rollup','default','evt-rollup','WEB_ATTACK','TEST_WAF','203.0.113.8',
                     '192.0.2.10','high','open','2026-08-13T10:30:00+00:00','2026-08-13T10:30:01+00:00')""")
        row = conn.execute("SELECT event_count,src_ip FROM source_alert_hourly_stats WHERE device_id='device-1'").fetchone()
    assert tuple(row) == (1, "203.0.113.8")
