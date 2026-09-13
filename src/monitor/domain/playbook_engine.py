from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from monitor.domain.models import SecurityEvent


@dataclass(frozen=True, slots=True)
class PlaybookContext:
    decision: str
    window_count: int
    location: str = "UNKNOWN"
    threat_tags: tuple[str, ...] = ()
    threat_confidence: int = 0

    @property
    def geo_status(self) -> str:
        return "unknown" if self.location in ("", "UNKNOWN") else "known"


class PlaybookEngine:
    """Priority-ordered automation playbooks.

    Version 1 intentionally supports only automatic review closure. Destructive
    actions remain in the existing action outbox and require separate policy.
    """

    def __init__(self, playbooks: list[dict[str, Any]]):
        self.playbooks = sorted(
            (item for item in playbooks if item.get("enabled", False)),
            key=lambda item: int(item.get("priority", 0)), reverse=True,
        )

    def match_auto_close(self, event: SecurityEvent, context: PlaybookContext) -> dict[str, Any] | None:
        for playbook in self.playbooks:
            if str(playbook.get("trigger", "review_created")) != "review_created":
                continue
            if not self._matches(playbook.get("match", {}), event, context):
                continue
            for action in playbook.get("actions", []):
                if action.get("type") == "close_review":
                    return {"playbook": playbook, "action": action}
        return None

    @staticmethod
    def _matches(match: dict[str, Any], event: SecurityEvent, context: PlaybookContext) -> bool:
        def values(name: str) -> list[str]:
            value = match.get(name)
            if value is None:
                return []
            return [str(value)] if isinstance(value, str) else [str(item) for item in value]

        if choices := values("decision"):
            if context.decision not in {item.upper() for item in choices}:
                return False
        if choices := values("source"):
            if event.source not in choices:
                return False
        if choices := values("category"):
            if event.category not in choices:
                return False
        if pattern := match.get("category_regex"):
            if not re.search(str(pattern), event.category, re.IGNORECASE):
                return False
        if choices := values("severity"):
            if event.severity not in choices:
                return False
        if context.window_count < int(match.get("count_gte", 0)):
            return False
        if "count_lte" in match and context.window_count > int(match["count_lte"]):
            return False
        if status := match.get("geo_status"):
            if context.geo_status != str(status):
                return False
        if networks := values("src_network"):
            address = ipaddress.ip_address(event.src_ip)
            if not any(address in ipaddress.ip_network(network, strict=False) for network in networks):
                return False
        if tags := values("threat_tag"):
            if set(tags).isdisjoint(context.threat_tags):
                return False
        if context.threat_confidence < int(match.get("threat_confidence_gte", 0)):
            return False
        return True
