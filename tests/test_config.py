from pathlib import Path

import pytest

from monitor.common.config import ConfigError, Settings, load_settings


def test_generic_webhook_url_prefers_environment(monkeypatch):
    settings = Settings({"notification": {"url": "https://config.invalid"}}, Path("config/base.yaml"))
    monkeypatch.setenv("MONITOR_WEBHOOK_URL", "https://environment.invalid")
    assert settings.generic_webhook_url == "https://environment.invalid"


def test_partial_configuration_inherits_packaged_defaults(tmp_path):
    override = tmp_path / "production.yaml"
    override.write_text("api:\n  port: 9000\nfirewall:\n  mode: dry_run\n", encoding="utf-8")
    settings = load_settings(str(override))
    assert settings.section("api")["port"] == 9000
    assert settings.section("api")["max_request_bytes"] == 1048576
    assert settings.section("firewall")["mode"] == "dry_run"
    assert settings.section("retention")["security_events_days"] == 180
    assert settings.section("geolocation")["failure_threshold"] == 5


def test_configuration_root_must_be_mapping(tmp_path):
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="root must be a mapping"):
        load_settings(str(invalid))
