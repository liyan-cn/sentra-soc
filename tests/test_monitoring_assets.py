import json
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_prometheus_configuration_and_alerts_are_valid_yaml():
    config = yaml.safe_load((ROOT / "deploy/monitoring/prometheus.yml").read_text(encoding="utf-8"))
    rules = yaml.safe_load((ROOT / "deploy/monitoring/rules/monitor3.yml").read_text(encoding="utf-8"))
    assert config["scrape_configs"][0]["static_configs"][0]["targets"] == ["api:5001"]
    alerts = {rule["alert"]: rule for group in rules["groups"] for rule in group["rules"]}
    assert {"Monitor3ApiDown", "Monitor3WorkerUnhealthy", "Monitor3DeadActions",
            "Monitor3ActionBacklog", "Monitor3DatabaseLarge"} <= alerts.keys()
    assert all(rule.get("for") for rule in alerts.values())


def test_grafana_dashboard_is_provisioned_and_uses_known_metrics():
    dashboard = json.loads(
        (ROOT / "deploy/monitoring/grafana/dashboards/monitor3-overview.json").read_text(encoding="utf-8")
    )
    expressions = {target["expr"] for panel in dashboard["panels"] for target in panel.get("targets", [])}
    assert dashboard["uid"] == "monitor3-overview"
    assert "monitor3_actions_dead" in expressions
    assert "monitor3_service_heartbeat_age_seconds" in expressions
    assert len({panel["id"] for panel in dashboard["panels"]}) == len(dashboard["panels"])


def test_compose_monitoring_profile_is_opt_in():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    assert compose["services"]["prometheus"]["profiles"] == ["monitoring"]
    assert compose["services"]["grafana"]["profiles"] == ["monitoring"]
    assert compose["services"]["grafana"]["ports"][0].startswith("127.0.0.1:")


def test_compose_defines_complete_worker_topology_and_safe_mounts():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert {"api", "action", "maintenance", "collector", "vpn", "host", "backup"} <= services.keys()
    assert "/health/live" in " ".join(services["api"]["healthcheck"]["test"])
    assert services["collector"]["profiles"] == ["collectors"]
    assert services["vpn"]["profiles"] == ["vpn"]
    assert services["host"]["profiles"] == ["host-monitoring"]
    assert services["backup"]["restart"] == "no"
    assert any(str(volume).endswith(":/logs:ro") for volume in services["collector"]["volumes"])
    assert services["action"]["environment"]["MONITOR_WEBHOOK_SECRET"].endswith("}")
