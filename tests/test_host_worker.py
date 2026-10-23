from monitor.workers import host_worker


def test_tcp_probe_can_keep_ping_disabled_resource_online(monkeypatch):
    monkeypatch.setattr(host_worker, "tcp_connect", lambda ip, port, timeout: (port == 8443, f"TCP/{port}"))
    target = {"ip": "192.0.2.10", "probe": {"methods": ["tcp"], "ports": [443, 8443],
                                                       "success_policy": "any"}}
    online, _, _, detail = host_worker.probe_target(target, 2, 1, .75)
    assert online is True
    assert "TCP/443" in detail and "TCP/8443" in detail


def test_host_notifications_do_not_report_initial_online_or_degraded_recovery():
    assert not host_worker.should_notify_transition(None, "online")
    assert not host_worker.should_notify_transition("degraded", "online")
    assert host_worker.should_notify_transition("online", "offline")
    assert host_worker.should_notify_transition("offline", "online")


def test_confirmed_outage_requires_two_successes_to_recover():
    status, failures, successes = host_worker.transition_state("offline", 4, 0, True, 4, 2)
    assert (status, failures, successes) == ("offline", 4, 1)
    assert not host_worker.should_notify_transition("offline", status)
    status, failures, successes = host_worker.transition_state(status, failures, successes, True, 4, 2)
    assert (status, failures, successes) == ("online", 0, 0)
    assert host_worker.should_notify_transition("offline", status)


def test_outage_requires_configured_failure_rounds():
    status, failures, successes = "online", 0, 0
    for _ in range(3):
        status, failures, successes = host_worker.transition_state(status, failures, successes, False, 4, 2)
        assert status == "degraded"
    status, failures, successes = host_worker.transition_state(status, failures, successes, False, 4, 2)
    assert status == "offline"


def test_icmp_outage_requires_full_confirmation_window():
    status, failures, successes = host_worker.transition_state(
        "online", 14, 0, False, 4, 2, 29 * 60 + 59, 30 * 60)
    assert (status, failures, successes) == ("degraded", 15, 0)
    status, failures, successes = host_worker.transition_state(
        status, failures, successes, False, 4, 2, 30 * 60, 30 * 60)
    assert status == "offline"


def test_virtual_machine_message_contains_physical_host_and_mac():
    message = host_worker.format_transition_message(
        {"ip": "172.16.21.134", "name": "一体化服务——测试", "kind": "virtual",
         "site": "97机房", "physical_host_ip": "172.16.21.19",
         "mac_address": "00:0c:29:64:a1:b9"},
        "offline", "2026-08-31T08:30:00+00:00", "2026-08-31T08:00:00+00:00", None,
        {"icmp": {"online": False, "loss_rate": 1.0, "latency_ms": None}, "tcp": {}},
        4, 2, 30)
    assert "【归属物理机IP】172.16.21.19" in message
    assert "【MAC地址】00:0c:29:64:a1:b9" in message
    assert "连续30分钟" in message


def test_database_tcp_monitor_overrides_legacy_yaml_target(tmp_path):
    from monitor.infrastructure.database import Database
    from monitor.domain.models import utc_now

    class Settings:
        config_path = tmp_path / "config" / "server.yaml"
        raw = {"hosts": [{"ip": "198.51.100.254", "name": "legacy", "probe": {"methods": ["icmp"]}}]}

    db = Database(tmp_path / "hosts.db"); db.initialize()
    timestamp = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,status,source,
               attributes_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("example-site-b", "default", "示例B机房公网", "site", "198.51.100.254", "示例B机房",
             "critical", "online", "host-monitor",
             '{"monitor_enabled":true,"probe":{"methods":["tcp"],"ports":[64443],"success_policy":"any"}}',
             timestamp, timestamp),
        )
    target = next(item for item in host_worker.load_targets(Settings(), db)
                  if item["ip"] == "198.51.100.254")
    assert target["probe"]["methods"] == ["tcp"]
    assert target["probe"]["ports"] == [64443]
