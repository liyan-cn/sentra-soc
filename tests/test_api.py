from pathlib import Path

from monitor.api.app import create_app, run_server
from monitor.infrastructure.database import Database
from monitor.domain.models import utc_now
from datetime import timedelta


class FakeSettings:
    admin_token = "test-secret"
    config_path = Path(__file__).parents[1] / "config" / "base.yaml"
    def section(self, name):
        return {"rules_file": "./config/rules.yaml"} if name == "policy" else {}


def test_database_lock_returns_retryable_response(tmp_path):
    import sqlite3
    db=Database(tmp_path/'busy.db'); db.initialize()
    app=create_app(FakeSettings(), db)
    @app.get('/test-busy')
    def busy():
        raise sqlite3.OperationalError('database is locked')
    response=app.test_client().get('/test-busy')
    assert response.status_code==503
    assert response.json['error']['code']=='DATABASE_BUSY'
    assert response.headers['Retry-After']=='3'


def test_async_discovery_is_scoped_and_saves_results(tmp_path,monkeypatch):
    import time
    monkeypatch.setattr('monitor.api.soc_features.ping',lambda *a,**kw:(True,0.0,1.0,'simulated'))
    monkeypatch.setattr('monitor.api.soc_features.tcp_connect',lambda *a,**kw:(False,'simulated'))
    db=Database(tmp_path/'async.db');db.initialize()
    app=create_app(FakeSettings(),db);client=app.test_client()
    headers={'Authorization':'Bearer test-secret'}
    response=client.post('/api/v1/assets/discover',headers=headers,json={'async':True,'network':'172.16.20.0/30'})
    assert response.status_code==202
    job_id=response.json['data']['id']
    for i in range(200):
        state=client.get('/api/v1/assets/discovery-jobs/'+job_id,headers=headers).json['data']
        if state['status'] not in ('queued','running'):break
        time.sleep(.01)
    assert state['status']=='completed',state
    assert state['result']['created']==2
    assert client.get('/api/v1/assets/discovery-jobs/'+job_id,headers={**headers,'X-Workspace-ID':'other'}).status_code==404
    app.extensions['discovery_jobs'].executor.shutdown(wait=True)


class FakeAiSettings(FakeSettings):
    def section(self, name):
        if name == "ai":
            return {"enabled": True, "provider": "openai", "base_url": "https://api.openai.com/v1",
                    "api_mode": "responses", "model": "gpt-5.6-terra", "reasoning_effort": "medium"}
        return super().section(name)


def test_windows_server_uses_waitress(monkeypatch):
    calls = []
    monkeypatch.setattr("monitor.api.app.platform.system", lambda: "Windows")
    monkeypatch.setattr("waitress.serve", lambda app, **options: calls.append((app, options)))
    monkeypatch.setenv("MONITOR_API_THREADS", "12")
    application = object()

    run_server(application, "127.0.0.1", 5001)

    assert calls == [(application, {"host": "127.0.0.1", "port": 5001, "threads": 12})]


def test_health_overview_and_auth(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/api/v1/overview").status_code == 401
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert b"monitor3_events_total" in metrics.data
    assert b"monitor3_actions_oldest_age_seconds" in metrics.data
    assert b"monitor3_service_heartbeat_age_seconds" in metrics.data
    assert client.delete("/api/v1/blacklist/missing").status_code == 401
    response = client.get("/api/v1/overview", headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    brain = client.get("/api/v1/soc/brain", headers={"Authorization": "Bearer test-secret"})
    assert brain.status_code == 200
    payload = brain.get_json()["data"]
    assert set(payload) == {
        "totals", "sources", "categories", "risks", "services", "hourly",
        "geography", "hosts", "vpn_sessions", "vpn_status", "generated_at",
    }
    assert payload["totals"]["events_24h"] == 0


def test_soc_workspace_assets_reports_and_ai_safety(tmp_path):
    db = Database(tmp_path / "soc.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}

    summary = client.get("/api/v1/workspaces/default/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.get_json()["data"]["enabled_models"] == 4

    asset = client.post("/api/v1/assets", headers=headers, json={
        "name": "核心业务主机", "asset_type": "physical", "ip": "192.0.2.10",
        "criticality": "critical", "reason": "测试资产纳管",
    })
    assert asset.status_code == 200
    assert len(client.get("/api/v1/assets", headers=headers).get_json()["data"]) == 1

    report = client.post("/api/v1/reports/generate", headers=headers,
                         json={"report_type": "daily", "reason": "测试日报"})
    assert report.status_code == 200
    assert "期间汇聚" in report.get_json()["data"]["summary"]

    ai_status = client.get("/api/v1/ai/status", headers=headers).get_json()["data"]
    assert ai_status["enabled"] is False
    assert client.post("/api/v1/ai/analyze", headers=headers, json={"hours": 24}).status_code == 200

    exported = client.get("/api/v1/data/export/events.csv", headers=headers)
    assert exported.status_code == 200
    assert exported.mimetype == "text/csv"


def test_private_subnet_discovery_adds_online_assets_and_guesses_os(tmp_path, monkeypatch):
    db = Database(tmp_path / "discovery.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    monkeypatch.setattr("monitor.api.soc_features.ping",
                        lambda ip, **kwargs: (ip.endswith(".1"), 0.0, 1.2, "ok"))
    monkeypatch.setattr("monitor.api.soc_features.tcp_connect",
                        lambda ip, port, timeout: (ip.endswith(".2") and port == 22, f"TCP/{port}"))
    response = client.post("/api/v1/assets/discover", headers=headers, json={
        "network": "192.168.50.0/30", "ping": True, "ssh": True, "rdp": True,
        "site": "测试机房", "reason": "测试网段探测",
    })
    assert response.status_code == 200
    payload = response.get_json()["data"]
    assert payload["scanned"] == 2 and payload["online"] == 2 and payload["created"] == 2
    assert {item["os_guess"] for item in payload["assets"]} == {"Linux", "未知"}
    rows = client.get("/api/v1/assets?page_size=10", headers=headers).get_json()["data"]
    assert {row["ip"] for row in rows} == {"192.168.50.1", "192.168.50.2"}


def test_network_inventory_updates_mac_and_physical_host_mapping(tmp_path):
    import json

    db = Database(tmp_path / "network-inventory.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    created = client.post("/api/v1/assets", headers=headers, json={
        "name": "一体化服务——测试", "asset_type": "virtual", "ip": "172.16.21.134",
        "criticality": "medium", "reason": "测试资产",
    })
    assert created.status_code == 200
    response = client.post("/api/v1/assets/network-inventory", headers=headers, json={
        "source": "核心交换机 ARP + 97机房资产表", "rows": [{
            "ip": "172.16.21.134", "mac_address": "000c-2964-a1b9",
            "physical_host_ip": "172.16.21.19", "vlan": "21", "interface": "Eth-Trunk2",
        }],
    })
    assert response.status_code == 200
    assert response.get_json()["data"]["matched_assets"] == 1
    with db.connect() as conn:
        row = conn.execute("SELECT attributes_json FROM soc_assets WHERE ip='172.16.21.134'").fetchone()
        inventory = conn.execute("SELECT * FROM asset_network_inventory WHERE ip='172.16.21.134'").fetchone()
    attrs = json.loads(row["attributes_json"])
    assert attrs["mac_address"] == "00:0c:29:64:a1:b9"
    assert attrs["physical_host_ip"] == "172.16.21.19"
    assert inventory["vlan"] == "21" and inventory["interface"] == "Eth-Trunk2"


def test_notification_channel_secrets_are_encrypted_and_masked(tmp_path):
    db = Database(tmp_path / "notifications.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    response = client.put("/api/v1/notification-channels/wechat", headers=headers, json={
        "name": "SOC 企业微信", "enabled": True,
        "webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-secret",
        "config": {"timeout_seconds": 5}, "reason": "测试配置",
    })
    assert response.status_code == 200
    rows = client.get("/api/v1/notification-channels", headers=headers).get_json()["data"]
    assert rows[0]["has_secret"] == 1 and "webhook" not in rows[0]["config"]
    with db.connect() as conn:
        stored = conn.execute("SELECT secret_encrypted FROM notification_channels").fetchone()[0]
    assert "qyapi.weixin.qq.com" not in stored


def test_ai_analysis_uses_aggregate_responses_payload(tmp_path, monkeypatch):
    db = Database(tmp_path / "ai.db"); db.initialize()
    client = create_app(FakeAiSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    monkeypatch.setenv("MONITOR_AI_API_KEY", "test-key")
    captured = {}

    class StubResponse:
        def raise_for_status(self):
            return None
        def json(self):
            return {"output": [{"content": [{"type": "output_text", "text": "总体风险平稳。"}]}]}

    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return StubResponse()

    monkeypatch.setattr("monitor.api.soc_features.requests.post", fake_post)
    response = client.post("/api/v1/ai/analyze", headers=headers,
                           json={"hours": 24, "analysis_type": "trend", "reason": "测试聚合研判"})
    assert response.status_code == 200
    assert captured["url"].endswith("/responses")
    assert captured["json"]["model"] == "gpt-5.6-terra"
    assert "raw_line" not in captured["json"]["input"]
    assert response.get_json()["data"]["analysis"] == "总体风险平稳。"


def test_dashboard_assets_are_packaged_and_csp_compatible(tmp_path):
    db = Database(tmp_path / "dashboard.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    page = client.get("/")
    css = client.get("/dashboard.css")
    script = client.get("/dashboard.js")
    batch_css = client.get("/dashboard-batch.css")
    batch_script = client.get("/dashboard-batch.js")
    automation_css = client.get("/automation.css")
    automation_script = client.get("/automation.js")
    soc_css = client.get("/soc-features.css")
    soc_script = client.get("/soc-features.js")
    assert page.status_code == css.status_code == script.status_code == 200
    assert batch_css.status_code == batch_script.status_code == 200
    assert automation_css.status_code == automation_script.status_code == 200
    assert soc_css.status_code == soc_script.status_code == 200
    assert "\u5b89\u5168\u8fd0\u8425\u4e2d\u5fc3" in page.get_data(as_text=True)
    assert '<script src="/dashboard.js?v=20261022-review1" defer></script>' in page.get_data(as_text=True)
    assert client.get('/dashboard.js?v=20261022-review1').status_code == 200
    assert '<script src="/dashboard-batch.js" defer></script>' in page.get_data(as_text=True)
    assert '<script src="/automation.js" defer></script>' in page.get_data(as_text=True)
    assert '<script src="/soc-features.js?v=20260916-backup1" defer></script>' in page.get_data(as_text=True)
    assert "reviewSelectAll" in page.get_data(as_text=True)
    assert "data-batch-review" in page.get_data(as_text=True)
    assert "<script>" not in page.get_data(as_text=True)
    assert css.mimetype == "text/css"
    assert script.mimetype == "application/javascript"
    assert "public" in css.headers["Cache-Control"]
    assert "max-age=3600" in script.headers["Cache-Control"]
    assert page.headers["Cache-Control"] == "no-cache"
    assert batch_script.mimetype == "application/javascript"
    assert "batchReview" in batch_script.get_data(as_text=True)
    assert "设备接入" in automation_script.get_data(as_text=True)
    assert "自动化剧本" in automation_script.get_data(as_text=True)
    assert "sessionStorage" in script.get_data(as_text=True)
    display = client.get("/display")
    screen = client.get("/screen")
    display_css = client.get("/display.css")
    display_js = client.get("/display.js")
    display_ui_fix = client.get("/display-ui-fix.js")
    assert display.status_code == screen.status_code == display_css.status_code == display_js.status_code == 200
    assert display_ui_fix.status_code == 200
    assert '<script src="/display.js?v=20260913-wall2" defer></script>' in display.get_data(as_text=True)
    assert '<script src="/display-ui-fix.js" defer></script>' not in display.get_data(as_text=True)
    assert 'class="trend-bar"' in display_js.get_data(as_text=True)
    assert 'style=' not in display_js.get_data(as_text=True)
    assert "trend-height-" in display_ui_fix.get_data(as_text=True)
    assert "实时安全态势感知" in display.get_data(as_text=True)
    assert "client_ip" not in display_js.get_data(as_text=True)


def test_attack_statistics_exclude_ignored_whitelist_events(tmp_path):
    db = Database(tmp_path / "attack-stats.db"); db.initialize()
    now = utc_now().isoformat()
    with db.transaction() as conn:
        for event_id, raw_hash, ip in (("external", "hash-external", "203.0.113.8"),
                                       ("internal", "hash-internal", "172.16.90.8")):
            conn.execute(
                """INSERT INTO security_events(
                    id,raw_hash,source,device_id,occurred_at,received_at,event_type,src_ip,
                    dst_ip,category,vendor_category,severity,attributes_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, raw_hash, "DPTECH_IPS", "device", now, now, "attack", ip,
                 None, "URL_SCAN", "URL_SCAN", "high", "{}"),
            )
        conn.execute(
            """INSERT INTO policy_decisions(
                id,event_id,decision,rule_id,rule_version,reason,window_count,location,created_at)
                VALUES('decision-external','external','OBSERVE','rule',1,'external',1,'北京',?)""", (now,)
        )
        conn.execute(
            """INSERT INTO policy_decisions(
                id,event_id,decision,rule_id,rule_version,reason,window_count,location,created_at)
                VALUES('decision-internal','internal','IGNORE','whitelist:1',1,'internal whitelist',1,'INTERNAL',?)""", (now,)
        )
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    brain = client.get("/api/v1/soc/brain", headers=headers).get_json()["data"]
    wall = client.get("/api/v1/display/overview", headers=headers).get_json()["data"]
    trend = client.get("/api/v1/stats/trend", headers=headers).get_json()["data"]
    assert brain["totals"]["events_24h"] == 1
    assert brain["totals"]["unique_sources_24h"] == 1
    assert wall["totals"]["events"] == 1
    assert wall["totals"]["sources"] == 1
    assert sum(row["events"] for row in trend) == 1
    assert all(row["location"] != "INTERNAL" for row in brain["geography"])


def test_pagination_metadata_validation_and_request_id(tmp_path):
    db = Database(tmp_path / "pagination.db"); db.initialize()
    with db.transaction() as conn:
        for index in range(3):
            conn.execute("INSERT INTO whitelist_entries(network,reason,created_at) VALUES(?,?,?)",
                         (f"192.0.2.{index}/32", "test", utc_now().isoformat()))
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Request-ID": "soc-console-123"}
    first = client.get("/api/v1/whitelist?page=1&page_size=2", headers=headers)
    assert first.status_code == 200
    assert len(first.get_json()["data"]) == 2
    assert first.get_json()["meta"] == {
        "request_id": "soc-console-123", "page": 1, "page_size": 2, "has_more": True,
    }
    assert first.headers["X-Request-ID"] == "soc-console-123"
    second = client.get("/api/v1/whitelist?page=2&page_size=2", headers=headers)
    assert len(second.get_json()["data"]) == 1
    assert second.get_json()["meta"]["has_more"] is False
    invalid = client.get("/api/v1/whitelist?page=nope", headers=headers)
    assert invalid.status_code == 400
    assert invalid.get_json()["error"]["code"] == "VALIDATION_ERROR"
    missing = client.get("/api/v1/does-not-exist", headers=headers)
    assert missing.status_code == 404
    assert missing.get_json()["error"]["code"] == "NOT_FOUND"


def test_unhandled_errors_are_json_and_do_not_leak_details(tmp_path):
    db = Database(tmp_path / "errors.db"); db.initialize()
    app = create_app(FakeSettings(), db)

    @app.get("/test-only-boom")
    def boom():
        raise RuntimeError("secret database path and credentials")

    client = app.test_client()
    response = client.get("/test-only-boom", headers={"X-Request-ID": "failure-123"})
    assert response.status_code == 500
    assert response.mimetype == "application/json"
    assert response.get_json() == {
        "error": {"code": "INTERNAL_ERROR", "message": "internal server error"},
        "meta": {"request_id": "failure-123"},
    }
    assert "secret" not in response.get_data(as_text=True)
    assert response.headers["X-Request-ID"] == "failure-123"


def test_readiness_requires_fresh_worker_heartbeats(tmp_path):
    class ProductionSettings(FakeSettings):
        def section(self, name):
            if name == "health":
                return {"required_services": ["action-worker"], "heartbeat_max_age_seconds": 60}
            return super().section(name)

    db = Database(tmp_path / "ready.db"); db.initialize()
    client = create_app(ProductionSettings(), db).test_client()
    assert client.get("/health/ready").status_code == 503
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO service_heartbeats(service,instance_id,status,updated_at) VALUES(?,?,?,?)",
            ("action-worker", "test", "ok", (utc_now() - timedelta(seconds=120)).isoformat()),
        )
    assert client.get("/health/ready").status_code == 503
    with db.transaction() as conn:
        conn.execute("UPDATE service_heartbeats SET updated_at=? WHERE service='action-worker'", (utc_now().isoformat(),))
    assert client.get("/health/ready").status_code == 200


def test_readiness_uses_service_specific_heartbeat_cadence(tmp_path):
    class CadenceSettings(FakeSettings):
        def section(self, name):
            if name == "health":
                return {
                    "required_services": ["host-worker"],
                    "heartbeat_max_age_seconds": 60,
                    "service_max_age_seconds": {"host-worker": 900},
                }
            return super().section(name)

    db = Database(tmp_path / "cadence.db"); db.initialize()
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO service_heartbeats(service,instance_id,status,updated_at) VALUES(?,?,?,?)",
            ("host-worker", "test", "ok", (utc_now() - timedelta(seconds=300)).isoformat()),
        )
    client = create_app(CadenceSettings(), db).test_client()

    assert client.get("/health/ready").status_code == 200


def test_whitelist_management_uses_authenticated_actor(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    created = client.post("/api/v1/whitelist", headers=headers,
                          json={"network": "10.20.30.40", "reason": "approved scanner"})
    assert created.status_code == 201
    entry_id = created.get_json()["data"]["id"]
    assert client.get("/api/v1/whitelist", headers=headers).status_code == 200
    disabled = client.delete(f"/api/v1/whitelist/{entry_id}", headers=headers,
                             json={"reason": "retired"})
    assert disabled.status_code == 200
    with db.connect() as conn:
        actors = {row[0] for row in conn.execute("SELECT actor FROM audit_logs")}
    assert actors == {"bootstrap-admin"}


def test_discovered_device_confirmation_and_quality_gate(tmp_path):
    db = Database(tmp_path / "devices.db"); db.initialize()
    now = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO discovered_devices
            (id,source_ip,status,log_glob,first_seen_at,last_seen_at,config_json,
             parsed_count,parse_success_rate,field_completeness)
            VALUES('d1','203.0.113.8','pending','/logs/*.log',?,?, '{}',20,.95,.9)""", (now, now))
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    confirmed = client.post("/api/v1/discovered-devices/d1/confirm", headers=headers,
                            json={"parser": "huawei_ips", "device_name": "40.1 华为 WAF",
                                  "reason": "confirmed from sample"})
    assert confirmed.status_code == 200
    promoted = client.post("/api/v1/discovered-devices/d1/promote", headers=headers,
                           json={"reason": "observation quality accepted"})
    assert promoted.status_code == 200
    with db.connect() as conn:
        row = conn.execute("SELECT status,parser,source,name FROM discovered_devices WHERE id='d1'").fetchone()
    assert tuple(row) == ("active", "huawei_ips", "HUAWEI_IPS", "40.1 华为 WAF")


def test_device_confirmation_ui_uses_select_with_manual_fallback():
    source = (Path(__file__).parents[1] / "src" / "monitor" / "resources" / "automation.js").read_text("utf-8")
    assert 'id="deviceParserSelect"' in source
    assert 'value="__other__"' in source
    assert "deviceCustomTypeField" in source
    assert "请选择解析器" not in source


def test_asset_can_enable_tcp_monitor_after_connectivity_validation(tmp_path, monkeypatch):
    monkeypatch.setattr("monitor.api.soc_features.tcp_connect",
                        lambda ip, port, timeout: (True, f"TCP/{port} connected"))
    db = Database(tmp_path / "assets.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    response = client.post("/api/v1/assets", headers=headers, json={
        "name": "会天 VPN 出口", "ip": "111.124.35.42", "asset_type": "site", "site": "会天机房",
        "tags": ["公网出口", "VPN"], "monitor_enabled": True,
        "probe": {"methods": ["tcp"], "ports": [443], "success_policy": "any"},
    })
    assert response.status_code == 200
    with db.connect() as conn:
        asset = conn.execute("SELECT source,attributes_json FROM soc_assets WHERE ip=?",
                             ("111.124.35.42",)).fetchone()
        host = conn.execute("SELECT kind,site FROM hosts WHERE ip=?", ("111.124.35.42",)).fetchone()
    assert asset["source"] == "host-monitor"
    assert "公网出口" in asset["attributes_json"]
    assert tuple(host) == ("site", "会天机房")


def test_existing_asset_persists_tcp_probe_and_updates_online_status(tmp_path, monkeypatch):
    monkeypatch.setattr("monitor.api.soc_features.tcp_connect",
                        lambda ip, port, timeout: (port == 64443, f"TCP/{port} connected"))
    db = Database(tmp_path / "asset-update.db"); db.initialize()
    timestamp = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,status,source,
               attributes_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("benxi", "default", "本溪本桓机房公网", "site", "221.203.107.254", "本溪本桓机房",
             "critical", "offline", "host-monitor", "{}", timestamp, timestamp),
        )
        conn.execute(
            """INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at)
               VALUES(?,?,?,?, 'offline',4,?,?)""",
            ("221.203.107.254", "本溪本桓机房公网", "site", "本溪本桓机房", timestamp, timestamp),
        )
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    response = client.put("/api/v1/assets/benxi", headers=headers, json={
        "name": "本溪本桓机房公网", "asset_type": "site", "site": "本溪本桓机房",
        "criticality": "critical", "monitor_enabled": True,
        "probe": {"methods": ["tcp"], "ports": [64443], "success_policy": "any"},
        "reason": "切换为 TCP 探测",
    })
    assert response.status_code == 200
    assert response.get_json()["data"]["probe"]["online"] is True
    with db.connect() as conn:
        asset = conn.execute("SELECT status,source,attributes_json FROM soc_assets WHERE id='benxi'").fetchone()
        host = conn.execute("SELECT status,consecutive_failures FROM hosts WHERE ip='221.203.107.254'").fetchone()
    attributes = __import__("json").loads(asset["attributes_json"])
    assert tuple(asset[:2]) == ("online", "host-monitor")
    assert attributes["monitor_enabled"] is True
    assert attributes["probe"]["methods"] == ["tcp"]
    assert attributes["probe"]["ports"] == [64443]
    assert tuple(host) == ("online", 0)


def test_alerts_include_location_destination_and_support_batch_status(tmp_path):
    db = Database(tmp_path / "alert-fields.db"); db.initialize()
    timestamp = utc_now().isoformat()
    with db.transaction() as conn:
        for index in range(2):
            event_id = f"event-{index}"
            conn.execute(
                """INSERT INTO security_events(id,raw_hash,source,device_id,occurred_at,received_at,event_type,
                   src_ip,dst_ip,category,vendor_category,severity,attributes_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, f"hash-{index}", "TOPSEC_WAF", "waf-1", timestamp, timestamp, "attack",
                 "203.0.113.8", "192.0.2.20", "WEB_ATTACK", "SQL", "high", "{}"),
            )
            conn.execute(
                """INSERT INTO policy_decisions(id,event_id,decision,rule_id,reason,window_count,location,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (f"decision-{index}", event_id, "OBSERVE", "rule", "detected", 1, "中国/四川/成都", timestamp),
            )
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret", "X-Workspace-ID": "default"}
    alerts = client.get("/api/v1/alerts?page_size=10", headers=headers).get_json()["data"]
    assert len(alerts) == 2
    assert alerts[0]["source_location"] == "中国/四川/成都"
    assert alerts[0]["dst_ip"] == "192.0.2.20"
    updated = client.post("/api/v1/alerts/batch-status", headers=headers, json={
        "ids": [row["id"] for row in alerts], "status": "closed", "reason": "批量确认为已处置",
    })
    assert updated.status_code == 200
    assert updated.get_json()["data"]["updated"] == 2
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM soc_alerts WHERE status='closed'").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE target_type='alert'").fetchone()[0] == 2


def test_brain_includes_observing_discovered_device_without_events(tmp_path):
    db = Database(tmp_path / "brain-discovery.db"); db.initialize()
    timestamp = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO discovered_devices(id,source_ip,name,status,parser,source,parsed_count,
               parse_success_rate,field_completeness,log_glob,first_seen_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("device-h3c", "192.0.2.21", "华三安全设备", "observing", "h3c_security",
             "H3C_SECURITY", 300, 1.0, .75, "/home/syslog/192.0.2.21/*.log", timestamp, timestamp),
        )
    client = create_app(FakeSettings(), db).test_client()
    data = client.get("/api/v1/soc/brain", headers={"Authorization": "Bearer test-secret"}).get_json()["data"]
    row = next(item for item in data["sources"] if item["device_ip"] == "192.0.2.21")
    assert row["display_name"] == "192.0.2.21 · 华三安全设备"
    assert row["lifecycle"] == "observing"
    assert row["sample_events"] == 300


def test_managed_playbook_can_be_saved_and_replayed_safely(tmp_path):
    db = Database(tmp_path / "playbooks.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    definition = {"id": "close-health", "name": "health", "enabled": False, "priority": 10,
                  "trigger": "review_created",
                  "match": {"decision": "MANUAL_REVIEW", "source": "DPTECH_WAF", "category": "health"},
                  "actions": [{"type": "close_review", "reason": "known health check"}]}
    saved = client.put("/api/v1/playbooks/close-health", headers=headers,
                       json={"definition": definition, "reason": "initial draft"})
    assert saved.status_code == 200
    listed = client.get("/api/v1/playbooks", headers=headers).get_json()["data"]
    assert next(row for row in listed if row["definition"]["id"] == "close-health")
    replayed = client.post("/api/v1/playbooks/replay", headers=headers,
                           json={"id": "close-health", "limit": 100})
    assert replayed.status_code == 200
    assert replayed.get_json()["data"] == {
        "analysis_only": True, "scanned": 0, "matched": 0, "match_rate": 0, "samples": []}


def test_manual_blacklist_is_audited_and_rejects_whitelist_conflict(tmp_path):
    db = Database(tmp_path / "blacklist.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    created = client.post("/api/v1/blacklist", headers=headers,
                          json={"ip": "203.0.113.8", "minutes": 60, "reason": "confirmed scanner"})
    assert created.status_code == 201
    with db.connect() as conn:
        row = conn.execute("SELECT desired_state,source,category FROM blacklist_entries WHERE ip=?",
                           ("203.0.113.8",)).fetchone()
        action = conn.execute("SELECT action_type FROM action_outbox WHERE aggregate_type='blacklist'").fetchone()
        audit_row = conn.execute("SELECT actor,action,reason FROM audit_logs WHERE target_type='blacklist'").fetchone()
    assert tuple(row) == ("pending_block", "MANUAL", "MANUAL")
    assert action[0] == "BLOCK"
    assert tuple(audit_row) == ("bootstrap-admin", "create", "confirmed scanner")

    client.post("/api/v1/whitelist", headers=headers,
                json={"network": "198.51.100.0/24", "reason": "trusted partner"})
    conflict = client.post("/api/v1/blacklist", headers=headers,
                           json={"ip": "198.51.100.9", "minutes": 60, "reason": "test"})
    assert conflict.status_code == 409
    assert conflict.get_json()["error"]["code"] == "WHITELIST_CONFLICT"


def test_display_overview_is_authenticated_and_sanitized(tmp_path):
    db = Database(tmp_path / "display.db"); db.initialize()
    timestamp = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO discovered_devices(id,source_ip,name,status,parser,source,parsed_count,
               parse_success_rate,field_completeness,log_glob,first_seen_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("display-h3c", "192.0.2.21", "华三安全设备", "observing", "h3c_security",
             "H3C_SECURITY", 300, 1.0, .75, "/home/syslog/192.0.2.21/*.log", timestamp, timestamp),
        )
    client = create_app(FakeSettings(), db).test_client()
    assert client.get("/api/v1/display/overview").status_code == 401
    assert client.get("/api/v1/screen/overview").status_code == 401
    response = client.get("/api/v1/display/overview",
                          headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200
    assert client.get("/api/v1/screen/overview",
                      headers={"Authorization": "Bearer test-secret"}).status_code == 200
    data = response.get_json()["data"]
    assert set(data) == {"totals", "hourly", "sources", "categories", "geography",
                         "risks", "sites", "generated_at"}
    discovered = next(item for item in data["sources"] if item["device_ip"] == "192.0.2.21")
    assert discovered["display_name"] == "192.0.2.21 · 华三安全设备"
    assert discovered["sample_events"] == 300
    assert "hosts" not in data and "vpn_sessions" not in data


def test_authenticated_policy_status_and_simulation(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    client = create_app(FakeSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    status = client.get("/api/v1/policies/status", headers=headers)
    assert status.status_code == 200
    simulated = client.post("/api/v1/policies/simulate", headers=headers, json={
        "source": "DPTECH_WAF", "category": "SQL", "src_ip": "8.8.8.8", "count": 100,
        "location": "UNKNOWN"
    })
    assert simulated.status_code == 200
    assert simulated.get_json()["data"]["analysis_only"] is True


def test_dead_action_retry_is_authorized_and_audited(tmp_path):
    db = Database(tmp_path / "retry.db"); db.initialize()
    now = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO action_outbox(id,action_type,aggregate_type,aggregate_id,payload_json,
               idempotency_key,status,available_at,created_at,updated_at,last_error,attempts)
               VALUES('a1','NOTIFY','notification','n1','{}','retry-test','dead',?,?,?,'network',8)""",
            (now, now, now),
        )
    client = create_app(FakeSettings(), db).test_client()
    assert client.get("/api/v1/actions").status_code == 401
    headers = {"Authorization": "Bearer test-secret"}
    assert client.get("/api/v1/actions?status=dead", headers=headers).status_code == 200
    assert client.post("/api/v1/actions/a1/retry", headers=headers, json={}).status_code == 400
    retried = client.post("/api/v1/actions/a1/retry", headers=headers, json={"reason": "provider recovered"})
    assert retried.status_code == 200
    with db.connect() as conn:
        action = conn.execute("SELECT status,attempts,last_error FROM action_outbox WHERE id='a1'").fetchone()
        audit = conn.execute("SELECT actor,action,reason FROM audit_logs WHERE target_id='a1'").fetchone()
    assert tuple(action) == ("pending", 0, None)
    assert tuple(audit) == ("bootstrap-admin", "retry", "provider recovered")


def test_authenticated_endpoint_rate_limit(tmp_path):
    class LimitedSettings(FakeSettings):
        def section(self, name):
            if name == "api":
                return {"auth_rate_limit_per_minute": 2}
            return super().section(name)

    db = Database(tmp_path / "limited.db"); db.initialize()
    client = create_app(LimitedSettings(), db).test_client()
    headers = {"Authorization": "Bearer test-secret"}
    assert client.get("/api/v1/whitelist", headers=headers).status_code == 200
    assert client.get("/api/v1/whitelist", headers=headers).status_code == 200
    limited = client.get("/api/v1/whitelist", headers=headers)
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "60"
