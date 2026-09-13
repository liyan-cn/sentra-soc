from pathlib import Path

from monitor.cli import validate


class FakeSettings:
    raw = {"devices": [{"id": "one", "parser": "missing", "log_glob": ""}]}
    firewall_password = ""
    webhook = ""
    generic_webhook_url = ""
    smtp_password = ""
    def section(self, name):
        return {"mode": "disabled"} if name == "firewall" else {}


def test_config_validation_reports_plugin_and_path_errors():
    errors = validate(FakeSettings())
    assert any("plugin not found" in error for error in errors)
    assert any("log_glob" in error for error in errors)


def test_config_validation_rejects_unsafe_api_values():
    class InvalidApiSettings(FakeSettings):
        def section(self, name):
            if name == "api":
                return {"trusted_proxy_hops": 99, "max_request_bytes": "many"}
            return super().section(name)

    errors = validate(InvalidApiSettings())
    assert "api.trusted_proxy_hops must be between 0 and 5" in errors
    assert "api.max_request_bytes must be an integer" in errors


def test_config_validation_rejects_plugins_plaintext_secrets_and_bad_retention():
    class UnsafeSettings(FakeSettings):
        raw = {"devices": []}
        def section(self, name):
            values = {
                "firewall": {"mode": "disabled", "provider": "unknown", "password": "plain"},
                "notification": {"provider": "fanout", "channels": []},
                "retention": {"audit_logs_days": 0},
                "health": {"required_services": ["action-worker", "action-worker"]},
            }
            return values.get(name, {})

    errors = validate(UnsafeSettings())
    assert any("firewall.provider plugin not found" in error for error in errors)
    assert any("MONITOR_FIREWALL_PASSWORD" in error for error in errors)
    assert "notification.channels must be a non-empty list for fanout" in errors
    assert "retention.audit_logs_days must be between 1 and 36500" in errors
    assert "health.required_services must not contain duplicates" in errors


def test_enabled_webhook_requires_environment_url():
    class MissingWebhookSettings(FakeSettings):
        raw = {"devices": []}
        def section(self, name):
            if name == "notification":
                return {"provider": "webhook", "enabled": True}
            return {"mode": "disabled"} if name == "firewall" else {}

    assert "notification is enabled but MONITOR_WEBHOOK_URL is empty" in validate(MissingWebhookSettings())
