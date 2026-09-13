from __future__ import annotations

from monitor.infrastructure.geolocation import GeoLocationService
from monitor.infrastructure.notifier import WeChatNotifier
from monitor.infrastructure.providers import create_huawei_action
from monitor.infrastructure.nftables import create_nftables_action
from monitor.infrastructure.threat_intel import create_static_threat_intel
from monitor.infrastructure.generic_notifiers import (create_fanout_notifier, create_smtp_notifier,
                                                       create_webhook_notifier, create_sms_webhook_notifier)
from monitor.parsers.registry import BUILTINS as PARSER_BUILTINS
from monitor.sources import FileTailSource
from .registry import PluginRegistry


def create_registry() -> PluginRegistry:
    registry = PluginRegistry()
    for name, factory in PARSER_BUILTINS.items():
        registry.register("parsers", name, factory)
    registry.register("sources", "file_tail", FileTailSource)
    registry.register("actions", "huawei_ssh", create_huawei_action)
    registry.register("actions", "nftables", create_nftables_action)
    registry.register("notifiers", "wechat", lambda config, **_: WeChatNotifier(
        config.get("webhook", ""), bool(config.get("enabled", False))))
    registry.register("notifiers", "webhook", create_webhook_notifier)
    registry.register("notifiers", "smtp", create_smtp_notifier)
    registry.register("notifiers", "sms_webhook", create_sms_webhook_notifier)
    registry.register("notifiers", "fanout", lambda config, **context: create_fanout_notifier(
        config, registry=registry, **context))
    registry.register("geolocation", "ip_api", lambda config, **kwargs: GeoLocationService(
        kwargs["database"], endpoint=config.get("endpoint", "http://ip-api.com/json/{ip}?lang=zh-CN"),
        ttl_days=int(config.get("ttl_days", 7)), timeout_seconds=float(config.get("timeout_seconds", 3)),
        failure_ttl_minutes=int(config.get("failure_ttl_minutes", 60)),
        failure_threshold=int(config.get("failure_threshold", 5)),
        circuit_breaker_seconds=int(config.get("circuit_breaker_seconds", 60))))
    registry.register("threat_intel", "static", create_static_threat_intel)
    return registry
