from monitor.infrastructure.database import Database
from monitor.workers.vpn_worker import (
    build_sources, expire_activity_sessions, process_line, reconcile_recent_activity,
    reconcile_recent_audits, vpn_log_time,
)


class Geo:
    def lookup(self, _ip):
        return "中国/四川/成都"


def test_closed_or_stale_public_address_is_not_reused(tmp_path):
    db=Database(tmp_path/'no-stale-ip.db');db.initialize()
    process_line(db,Geo(),'vpn','Aug  4 20:01:02 FW USERLOGINSUCC User Name=alice, Virtual IP=172.16.90.8, Client IP=1.2.3.4')
    expire_activity_sessions(db,1)
    process_line(db,Geo(),'vpn','Aug  5 20:01:02 FW SESSION_SETUP SourceIP=172.16.90.8, PolicyName=SSLVPN,UserName=alice.')
    with db.connect() as conn:
        row=conn.execute("SELECT client_ip FROM vpn_sessions WHERE status='active'").fetchone()
    assert row['client_ip']==''


def test_legacy_category_is_watched_without_explicit_config(tmp_path):
    db=Database(tmp_path/'legacy.db');db.initialize()
    category=tmp_path/'%%01SSLVPN';category.mkdir()
    (category/'2026-09-12.log').write_text('login record\n')
    sources=build_sources(db,'vpn',{'log_glob':str(tmp_path/'*.log')})
    assert sources[0].source_id.endswith(':login-audit')
    assert sources[0].poll(1)[0].data=='login record\n'


def test_huawei_login_logout_and_duplicate_session(tmp_path):
    db = Database(tmp_path / "monitor.db")
    db.initialize()
    login = ("Aug  4 20:01:02 firewall USERLOGINSUCC User Name=alice, "
             "Virtual IP=172.16.90.8, Client IP=1.2.3.4")
    process_line(db, Geo(), "huawei-vpn", login)
    with db.connect() as conn:
        active = conn.execute("SELECT * FROM vpn_sessions WHERE status='active'").fetchall()
        assert len(active) == 1
        assert active[0]["username"] == "alice"

    second = ("Aug  4 20:02:02 firewall USERLOGINSUCC User Name=alice, "
              "Virtual IP=172.16.90.9, Client IP=5.6.7.8")
    process_line(db, Geo(), "huawei-vpn", second)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='closed'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM action_outbox WHERE action_type='NOTIFY'").fetchone()[0] == 1

    logout = ("Aug  4 20:03:02 firewall USERLOGOUT User Name=alice, "
              "Virtual IP=172.16.90.9, Client IP=5.6.7.8, Logout Reason=timeout)")
    process_line(db, Geo(), "huawei-vpn", logout)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 0


def test_ssl_vpn_activity_infers_online_session(tmp_path):
    db = Database(tmp_path / "monitor.db")
    db.initialize()
    activity = ("Jan  1 00:01:02 FW %%01SECLOG/6/SESSION_TEARDOWN(l):"
                "SourceIP=172.16.90.86,DestinationIP=192.168.1.1,"
                "PolicyName=SSLVPN_access,UserName=alice.")
    process_line(db, Geo(), "huawei-vpn", activity)
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM vpn_sessions WHERE status='active'").fetchone()
        assert row["username"] == "alice"
        assert row["virtual_ip"] == "172.16.90.86"
        assert row["session_origin"] == "activity"
        assert row["client_ip"] == ""
    assert expire_activity_sessions(db, 1) == 1


def test_ssl_vpn_activity_reuses_public_ip_from_login_audit(tmp_path):
    db = Database(tmp_path / "monitor.db")
    db.initialize()
    login = ("Aug  4 20:01:02 firewall USERLOGINSUCC User Name=alice, "
             "Virtual IP=172.16.90.86, Client IP=1.2.3.4")
    process_line(db, Geo(), "huawei-vpn", login)
    activity = ("Aug  4 20:02:02 FW %%01SECLOG/6/SESSION_SETUP(l):"
                "SourceIP=172.16.90.86,DestinationIP=192.168.1.1,"
                "PolicyName=SSLVPN_access,UserName=alice.")
    process_line(db, Geo(), "huawei-vpn", activity)
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM vpn_sessions WHERE status='active'").fetchall()
        assert len(rows) == 1
        assert rows[0]["client_ip"] == "1.2.3.4"
        assert rows[0]["location"] == "中国/四川/成都"


def test_late_login_audit_enriches_existing_live_activity(tmp_path):
    db = Database(tmp_path / "monitor.db")
    db.initialize()
    activity = ("Aug  4 20:02:02 FW %%01SECLOG/6/SESSION_SETUP(l):"
                "SourceIP=172.16.90.86,DestinationIP=192.168.1.1,"
                "PolicyName=SSLVPN_access,UserName=alice.")
    process_line(db, Geo(), "huawei-vpn", activity)
    login = ("Aug  4 20:01:02 firewall USERLOGINSUCC User Name=alice, "
             "Virtual IP=172.16.90.86, Client IP=1.2.3.4")
    process_line(db, Geo(), "huawei-vpn", login)

    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM vpn_sessions WHERE status='active'").fetchall()
        assert len(rows) == 1
        assert rows[0]["client_ip"] == "1.2.3.4"
        assert rows[0]["location"] == "中国/四川/成都"
        assert rows[0]["session_origin"] == "audit+activity"


def test_huawei_timestamp_is_interpreted_as_shanghai_time():
    parsed = vpn_log_time("Aug  4 20:01:02 firewall event")
    assert parsed.hour == 12
    assert parsed.tzinfo is not None


def test_stale_login_audit_session_also_expires(tmp_path):
    db = Database(tmp_path / "monitor.db")
    db.initialize()
    process_line(db, Geo(), "huawei-vpn", (
        "Aug  4 20:01:02 firewall USERLOGINSUCC User Name=alice, "
        "Virtual IP=172.16.90.8, Client IP=1.2.3.4"
    ))
    assert expire_activity_sessions(db, 1) == 1
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 0


def test_login_audit_uses_an_independent_latest_file_checkpoint(tmp_path):
    activity = tmp_path / "activity.log"
    audit_dir = tmp_path / "SSLVPN"
    audit_dir.mkdir()
    old_audit = audit_dir / "2026-08-01.log"
    current_audit = audit_dir / "2026-08-02.log"
    activity.write_text("old traffic\n", encoding="utf-8")
    old_audit.write_text("old login\n", encoding="utf-8")
    current_audit.write_text("current login\n", encoding="utf-8")
    db = Database(tmp_path / "sources.db"); db.initialize()

    sources = build_sources(db, "huawei-vpn", {
        "log_glob": str(activity),
        "login_audit_glob": str(audit_dir / "*.log"),
        "start_at_end": True,
    })

    assert len(sources) == 2
    assert sources[0].source_id.endswith(":login-audit")
    assert sources[0].poll(1)[0].data == "current login\n"
    assert sources[1].poll(1) == []


def test_recent_combined_log_audit_backfills_live_activity(tmp_path):
    db = Database(tmp_path / "combined.db"); db.initialize()
    process_line(db, Geo(), "huawei-vpn", (
        "Aug  4 20:02:02 FW %%01SECLOG/6/SESSION_SETUP(l):"
        "SourceIP=172.16.90.86,DestinationIP=192.168.1.1,"
        "PolicyName=SSLVPN_access,UserName=alice."
    ))
    hourly = tmp_path / "2026-08-04-20.log"
    hourly.write_text(
        "ordinary high-volume traffic\n"
        "Aug  4 20:01:02 firewall USERLOGINSUCC User Name=alice, "
        "Virtual IP=172.16.90.86, Client IP=1.2.3.4\n",
        encoding="utf-8",
    )

    assert reconcile_recent_audits(db, Geo(), "huawei-vpn", str(tmp_path / "*.log")) == 1
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM vpn_sessions WHERE status='active'").fetchone()
        assert row["client_ip"] == "1.2.3.4"
        assert row["session_origin"] == "audit+activity"


def test_recent_activity_rebuilds_online_presence(tmp_path):
    from datetime import datetime, timedelta, timezone
    db = Database(tmp_path / "presence.db"); db.initialize()
    shanghai = timezone(timedelta(hours=8))
    now = datetime.now(shanghai).strftime("%b %d %H:%M:%S")
    hourly = tmp_path / "current.log"
    hourly.write_text(
        f"{now} FW %%01SECLOG/6/SESSION_SETUP(l):SourceIP=172.16.90.86,"
        "DestinationIP=192.168.1.1,PolicyName=SSLVPN_access,UserName=alice.\n",
        encoding="utf-8",
    )
    assert reconcile_recent_activity(db, Geo(), "huawei-vpn", str(hourly), 600) == 1
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0] == 1
