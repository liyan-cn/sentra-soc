"""Release acceptance scenarios. Failures intentionally expose unmet requirements.

All writes use pytest temporary databases; no real firewall/notifier is used.
"""
from datetime import timedelta, timezone
from pathlib import Path
import os
import time

import pytest

from monitor.api.app import _limit_source_summaries
from monitor.domain.models import utc_now
from monitor.infrastructure.database import Database
from monitor.release_check import run_release_checks
from monitor.sources import FileTailSource
from monitor.workers.vpn_worker import process_line, reconcile_recent_activity


class Geo:
    def lookup(self, ip):
        return "test-location"


class Settings:
    config_path = Path(__file__).parents[1] / "config/base.yaml"
    def section(self, name):
        return {
            "policy": {"rules_file": "./config/rules.yaml"},
            "operations": {"min_free_disk_mb": 1},
            "health": {"required_services": ["host-worker"],
                       "heartbeat_max_age_seconds": 180,
                       "service_max_age_seconds": {"host-worker": 900}},
        }.get(name, {})


@pytest.fixture
def db(tmp_path):
    result = Database(tmp_path / "preflight.db")
    result.initialize()
    return result


def activity(at, username="alice"):
    stamp = at.astimezone(timezone(timedelta(hours=8))).strftime("%b %d %H:%M:%S")
    return (f"{stamp} FW %%01SECLOG/6/SESSION_SETUP(l):"
            "SourceIP=172.16.90.8,DestinationIP=192.0.2.1,"
            f"PolicyName=SSLVPN_access,UserName={username}.\n")


def test_replayed_vpn_activity_does_not_move_last_seen_backwards(db):
    latest = utc_now().replace(microsecond=0)
    process_line(db, Geo(), "vpn-test", activity(latest))
    process_line(db, Geo(), "vpn-test", activity(latest - timedelta(minutes=20)))
    with db.connect() as conn:
        actual = conn.execute("SELECT last_seen_at FROM vpn_sessions").fetchone()[0]
    assert actual == latest.isoformat(), "Old replay must not make a live user appear offline"


def test_vpn_username_with_dot_is_preserved(db):
    process_line(db, Geo(), "vpn-test", activity(utc_now(), "alice.smith"))
    with db.connect() as conn:
        assert conn.execute("SELECT username FROM vpn_sessions").fetchone()[0] == "alice.smith"


def test_partial_write_completes_as_one_record(db, tmp_path):
    log = tmp_path / "continued.log"
    log.write_bytes("开始".encode("utf-8"))
    source = FileTailSource(db, "test", str(log))
    assert source.poll() == []
    with log.open("ab") as stream:
        stream.write("结束\r\n".encode("utf-8"))
    rows = source.poll()
    assert [r.data for r in rows] == ["开始结束\n"]
    source.commit(rows[0].checkpoint)
    assert FileTailSource(db, "test", str(log)).poll() == []


def test_repeated_late_login_audit_preserves_activity(db):
    now = utc_now().replace(microsecond=0)
    stamp = (now-timedelta(minutes=2)).astimezone(timezone(timedelta(hours=8))).strftime("%b %d %H:%M:%S")
    line = f"{stamp} FW USERLOGINSUCC User Name=alice, Virtual IP=172.16.90.8, Client IP=203.0.113.8"
    process_line(db, Geo(), "vpn-test", activity(now))
    process_line(db, Geo(), "vpn-test", line)
    process_line(db, Geo(), "vpn-test", line)
    with db.connect() as conn:
        rows = conn.execute("SELECT last_seen_at FROM vpn_sessions WHERE status='active'").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == now.isoformat()


def test_new_activity_after_logout_can_reconnect(db):
    now = utc_now().replace(microsecond=0)
    stamp = (now-timedelta(minutes=1)).astimezone(timezone(timedelta(hours=8))).strftime("%b %d %H:%M:%S")
    process_line(db, Geo(), "vpn-test", f"{stamp} FW USERLOGOUT User Name=alice, Virtual IP=172.16.90.8, Client IP=203.0.113.8, Logout Reason=timeout)")
    process_line(db, Geo(), "vpn-test", activity(now))
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 1


def test_restart_reconciliation_respects_logout(db, tmp_path):
    now = utc_now().replace(microsecond=0)
    login_stamp = (now - timedelta(minutes=3)).astimezone(timezone(timedelta(hours=8))).strftime("%b %d %H:%M:%S")
    logout_stamp = (now - timedelta(minutes=1)).astimezone(timezone(timedelta(hours=8))).strftime("%b %d %H:%M:%S")
    login = f"{login_stamp} FW USERLOGINSUCC User Name=alice, Virtual IP=172.16.90.8, Client IP=203.0.113.8"
    logout = f"{logout_stamp} FW USERLOGOUT User Name=alice, Virtual IP=172.16.90.8, Client IP=203.0.113.8, Logout Reason=timeout)"
    process_line(db, Geo(), "vpn-test", login)
    process_line(db, Geo(), "vpn-test", logout)
    log = tmp_path / "vpn.log"
    log.write_text(activity(now - timedelta(minutes=2)) + logout + "\n", encoding="utf-8")
    reconcile_recent_activity(db, Geo(), "vpn-test", str(log), 600)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 0


def test_byte_catchup_never_emits_partial_log_line(db, tmp_path):
    log = tmp_path / "busy.log"
    log.write_bytes(b"seed\n")
    original = FileTailSource(db, "sensor", str(log))
    original.commit(original.poll(1)[0].checkpoint)
    with log.open("ab") as stream:
        stream.write(b"discard-this-long-line\nvalid\n")
    source = FileTailSource(db, "sensor", str(log), max_checkpoint_lag_bytes=10)
    assert [r.data for r in source.poll(10)] == ["valid\n"]


def test_partial_write_is_not_committed_before_newline(db, tmp_path):
    log = tmp_path / "partial.log"
    log.write_bytes(b"half-a-security-event")
    source = FileTailSource(db, "sensor", str(log))
    assert source.poll(10) == [], "Incomplete network log writes must wait for newline"


def test_stale_rotation_catchup_respects_byte_budget_immediately(db, tmp_path):
    old, latest = tmp_path / "old.log", tmp_path / "latest.log"
    old.write_bytes(b"seed\n")
    original = FileTailSource(db, "sensor", str(tmp_path / "*.log"))
    original.commit(original.poll(1)[0].checkpoint)
    old_time = time.time() - 7200
    os.utime(old, (old_time, old_time))
    latest.write_bytes(b"obsolete\n" * 100 + b"fresh\n")
    source = FileTailSource(db, "sensor", str(tmp_path / "*.log"),
                            max_checkpoint_lag_seconds=60, max_checkpoint_lag_bytes=6)
    assert [r.data for r in source.poll(1)] == ["fresh\n"]


def test_release_gate_uses_configured_worker_cadence(db):
    with db.transaction() as conn:
        conn.execute("INSERT INTO service_heartbeats(service,instance_id,status,updated_at) VALUES(?,?,?,?)",
                     ("host-worker", "test", "ok", (utc_now()-timedelta(seconds=300)).isoformat()))
    checks = run_release_checks(Settings(), db, [], require_backup=False)
    assert next(x for x in checks if x["name"] == "required-workers")["ok"]


@pytest.mark.parametrize("limit", [8, 20])
def test_discovered_sensor_survives_busy_source_limit(limit):
    sources = [{"device_id": f"legacy-{i}", "raw_events": 1000-i} for i in range(25)]
    sensor = {"device_id": "auto-192-0-2-21", "raw_events": 0, "lifecycle": "active"}
    selected = _limit_source_summaries(sources + [sensor], limit)
    assert sensor in selected
    assert len(selected) == limit


def test_stale_activity_is_not_recreated_on_restart(db, tmp_path):
    log = tmp_path / "old-vpn.log"
    log.write_text(activity(utc_now()-timedelta(hours=2)), encoding="utf-8")
    assert reconcile_recent_activity(db, Geo(), "vpn-test", str(log), 600) == 0
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions").fetchone()[0] == 0


def test_discovery_database_lock_keeps_record_for_retry(db, tmp_path, monkeypatch):
    import logging
    import sqlite3
    from monitor.workers import discovery_worker
    log = tmp_path / "h3c.log"
    log.write_text("Sep 10 19:00:00 H3C %%10FILTER/6/FILTER: SrcIPAddr(5)=203.0.113.8;DstIPAddr(5)=192.0.2.1;Event(5)=Deny;\n", encoding="utf-8")
    with db.transaction() as conn:
        conn.execute("""INSERT INTO discovered_devices(id,source_ip,status,parser,source,
                     log_glob,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)""",
                     ("h3c-test", "192.0.2.21", "observing", "h3c_security", "H3C_SECURITY",
                      str(log), utc_now().isoformat(), utc_now().isoformat()))
    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(discovery_worker.EventService, "submit", locked)
    monkeypatch.setattr(discovery_worker, "enrich_event", lambda *a: ("US", {}))
    monkeypatch.setattr(discovery_worker, "record_failure", lambda *a: True)
    discovery_worker.collect_once(Settings(), db, {}, {}, "test", Geo(), Geo(), logging.getLogger("test"))
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM collector_checkpoints").fetchone()[0] == 0, "A database lock must not acknowledge an unpersisted event"


def test_replay_does_not_count_permit_telemetry_as_parse_failure(tmp_path):
    from monitor.simulation import replay
    log = tmp_path / "permit.log"
    log.write_text("Sep 10 19:00:00 H3C %%10FILTER/6/FILTER: SrcIPAddr(5)=203.0.113.8;DstIPAddr(5)=192.0.2.1;Event(5)=Permit;\n", encoding="utf-8")
    result = replay({"defaults": {}}, "h3c_security", "test", log)
    assert result["parse_failures"] == 0
    assert result["side_effects"] is False


def test_batch_replay_10000_security_events_without_actions(db, tmp_path):
    from monitor.simulation import replay
    log = tmp_path / "load.log"
    log.write_text("Jul 13 10:20:30 2026 %%WAF/WEBATTACK source-ip:8.8.8.8;destination-ip:192.0.2.3;att_level1:SQL;\n" * 10000, encoding="utf-8")
    started = time.perf_counter()
    result = replay({"defaults": {"warn_threshold": 2, "block_threshold": 3}}, "dptech_waf", "test", log)
    elapsed = time.perf_counter()-started
    assert result["processed"] == 10000
    assert result["parse_failures"] == 0
    assert result["side_effects"] is False
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0] == 0
    print(f"replay: 10000 events in {elapsed:.3f}s; {10000/elapsed:.0f} events/s")


def test_api_300_sequential_dashboard_requests(db):
    from monitor.api.app import create_app
    class ApiSettings(Settings):
        admin_token = "local-preflight-test-token"
        def section(self, name):
            if name == "health":
                return {}
            if name == "api":
                return {"auth_rate_limit_per_minute": 10000}
            return super().section(name)
    client = create_app(ApiSettings(), db).test_client()
    headers = {"Authorization": "Bearer local-preflight-test-token"}
    for path in ("/api/v1/overview", "/api/v1/soc/brain", "/api/v1/display/overview"):
        assert client.get(path).status_code == 401
        timings = []
        for _ in range(100):
            started = time.perf_counter()
            response = client.get(path, headers=headers)
            timings.append((time.perf_counter()-started)*1000)
            assert response.status_code == 200
            assert response.headers["Cache-Control"] == "no-store"
        print(f"{path}: 100/100 OK; cold={timings[0]:.2f}ms, p95={sorted(timings)[94]:.2f}ms")
