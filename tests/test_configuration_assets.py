from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_source_and_packaged_defaults_have_matching_sections_and_keys():
    source = yaml.safe_load((ROOT / "config/base.yaml").read_text(encoding="utf-8"))
    packaged = yaml.safe_load((ROOT / "src/monitor/resources/base.yaml").read_text(encoding="utf-8"))
    assert source.keys() == packaged.keys()
    for section in source:
        if isinstance(source[section], dict):
            assert source[section].keys() == packaged[section].keys(), section


def test_default_configuration_contains_no_plaintext_secrets():
    config = yaml.safe_load((ROOT / "config/base.yaml").read_text(encoding="utf-8"))
    assert config["api"]["admin_token"] == ""
    assert config["firewall"]["password"] == ""
    assert config["notification"]["webhook"] == ""


def test_environment_example_lists_all_runtime_secrets():
    names = {
        line.split("=", 1)[0] for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert {"MONITOR_ADMIN_TOKEN", "MONITOR_FIREWALL_PASSWORD", "MONITOR_WECHAT_WEBHOOK",
            "MONITOR_SMTP_PASSWORD", "MONITOR_WEBHOOK_SECRET", "MONITOR_WEBHOOK_URL",
            "GRAFANA_ADMIN_PASSWORD"} <= names


def test_production_override_contains_no_secrets_and_uses_absolute_runtime_paths():
    config = yaml.safe_load((ROOT / "config/production.yaml.example").read_text(encoding="utf-8"))
    assert config["database"]["path"].startswith("/var/lib/monitor3/")
    assert config["policy"]["rules_file"].startswith("/etc/monitor3/")
    assert "password" not in config["firewall"]
    assert "admin_token" not in config["api"]
