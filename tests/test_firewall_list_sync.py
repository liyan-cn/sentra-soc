from monitor.infrastructure.database import Database
from monitor.infrastructure.firewall import HuaweiFirewallClient
from monitor.workers.firewall_sync_worker import sync_once


SAMPLE = """
 IP/port/protocol                         Reason          Insert Time            Age Time  HitTimes      Description
 123.160.223.74 / any (src) / any         Manual          2026-08-04 22:34:23    Permanent 51            TOPSEC_WAF_____
 103.233.10.2 / any (src) / any           Manual          2026-08-04 22:34:23    Permanent 0
 195.170.172.215 / any (dst) / any        Manual          2026-08-04 22:34:23    60        0             temporary rule
"""


def test_huawei_list_parser_preserves_direction_age_hits_and_description():
    rows = HuaweiFirewallClient.parse_list_output(SAMPLE, "blacklist")
    assert rows[0]["direction"] == "src"
    assert rows[0]["permanent"] is True
    assert rows[0]["hit_count"] == 51
    assert rows[0]["description"] == "TOPSEC_WAF_____"
    assert rows[1]["description"] == ""
    assert rows[2]["direction"] == "dst"
    assert rows[2]["age_time"] == "60"
    assert rows[2]["expires_at"].startswith("2026-08-04T23:34:23")


def test_huawei_list_parser_accepts_device_crlf_output():
    rows = HuaweiFirewallClient.parse_list_output(SAMPLE.replace("\n", "\r\n"), "blacklist")
    assert [(row["direction"], row["ip"]) for row in rows] == [
        ("src", "123.160.223.74"), ("src", "103.233.10.2"), ("dst", "195.170.172.215")
    ]


def test_sync_once_mirrors_and_removes_stale_firewall_rows(tmp_path):
    class FakeFirewall:
        def __init__(self):
            self.rows = HuaweiFirewallClient.parse_list_output(SAMPLE, "blacklist")

        def list_items(self, list_type):
            return list(self.rows) if list_type == "blacklist" else []

    db = Database(tmp_path / "mirror.db"); db.initialize()
    firewall = FakeFirewall()
    assert sync_once(db, firewall) == {"blacklist": 3, "whitelist": 0}
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM firewall_list_entries").fetchone()[0] == 3
    firewall.rows = firewall.rows[:1]
    sync_once(db, firewall)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM firewall_list_entries").fetchone()[0] == 1
