from __future__ import annotations

import os
from importlib import resources
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigError


def _merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


@dataclass(frozen=True)
class Settings:
    raw: dict[str, Any]
    config_path: Path

    def section(self, name: str) -> dict[str, Any]:
        value = self.raw.get(name, {})
        return value if isinstance(value, dict) else {}

    @property
    def database_path(self) -> Path:
        raw = os.getenv("MONITOR_DB_PATH") or self.section("database").get("path", "./data/monitor.db")
        return _resolve(self.config_path.parent.parent, raw)

    @property
    def data_dir(self) -> Path:
        return _resolve(self.config_path.parent.parent, self.section("app").get("data_dir", "./data"))

    @property
    def admin_token(self) -> str:
        return os.getenv("MONITOR_ADMIN_TOKEN") or str(self.section("api").get("admin_token", ""))

    @property
    def webhook(self) -> str:
        return os.getenv("MONITOR_WECHAT_WEBHOOK") or str(self.section("notification").get("webhook", ""))

    @property
    def generic_webhook_url(self) -> str:
        return os.getenv("MONITOR_WEBHOOK_URL") or str(self.section("notification").get("url", ""))

    @property
    def firewall_password(self) -> str:
        return os.getenv("MONITOR_FIREWALL_PASSWORD") or str(self.section("firewall").get("password", ""))

    @property
    def smtp_password(self) -> str:
        return os.getenv("MONITOR_SMTP_PASSWORD") or ""

    @property
    def webhook_secret(self) -> str:
        return os.getenv("MONITOR_WEBHOOK_SECRET") or ""

    def device(self, device_id: str) -> dict[str, Any]:
        for device in self.raw.get("devices", []):
            if device.get("id") == device_id:
                return device
        raise ConfigError(f"Unknown device: {device_id}")


def _resolve(root: Path, value: str | os.PathLike) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


def load_settings(path: str | None = None) -> Settings:
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("PyYAML is required; install project dependencies first") from exc
    defaults = yaml.safe_load(resources.files("monitor.resources").joinpath("base.yaml").read_text(
        encoding="utf-8")) or {}
    candidate = path or os.getenv("MONITOR_CONFIG")
    if not candidate:
        source_tree = Path(__file__).resolve().parents[3] / "config" / "base.yaml"
        working_tree = Path.cwd() / "config" / "base.yaml"
        if working_tree.exists():
            candidate = working_tree
        elif source_tree.exists():
            candidate = source_tree
        else:
            candidate = Path(str(resources.files("monitor.resources").joinpath("base.yaml")))
    config_path = Path(candidate).expanduser().resolve()
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as stream:
        override = yaml.safe_load(stream) or {}
    if not isinstance(override, dict):
        raise ConfigError("Configuration root must be a mapping")
    raw = _merge(defaults, override)
    extra = os.getenv("MONITOR_DEVICES_CONFIG")
    if extra:
        with Path(extra).open("r", encoding="utf-8") as stream:
            raw = _merge(raw, yaml.safe_load(stream) or {})
    settings = Settings(raw=raw, config_path=config_path)
    return settings
