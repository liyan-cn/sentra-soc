from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from monitor.domain.models import DecisionType, PolicyDecision, SecurityEvent


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    window_count: int
    location: str = "UNKNOWN"
    threat_tags: tuple[str, ...] = ()
    threat_confidence: int = 0

    @property
    def geo_status(self) -> str:
        return "unknown" if self.location in ("", "UNKNOWN") else "known"


class PolicyEngine:
    """Priority-ordered, first-match policy evaluator.

    The schema intentionally stays small and declarative. New conditions can be
    added without embedding organization-specific behavior in workers.
    """

    def __init__(self, policies: list[dict[str, Any]]):
        self.policies = sorted(policies, key=lambda rule: int(rule.get("priority", 0)), reverse=True)

    def evaluate(self, event: SecurityEvent, context: EvaluationContext) -> PolicyDecision:
        for rule in self.policies:
            if not rule.get("enabled", True) or not self._matches(rule.get("match", {}), event, context):
                continue
            decision = DecisionType(str(rule.get("decision", "OBSERVE")).upper())
            return PolicyDecision(
                event_id=event.id, decision=decision, rule_id=str(rule["id"]),
                reason=str(rule.get("reason", f"matched policy {rule['id']}")),
                window_count=context.window_count, location=context.location,
                block_minutes=self._duration_minutes(rule.get("duration_minutes", 0)),
            )
        return PolicyDecision(event.id, DecisionType.OBSERVE, "default-observe", "no policy matched",
                              context.window_count, context.location)

    @staticmethod
    def _matches(match: dict, event: SecurityEvent, context: EvaluationContext) -> bool:
        sources = match.get("source")
        if sources and event.source not in ([sources] if isinstance(sources, str) else sources):
            return False
        categories = match.get("category")
        if categories and event.category not in ([categories] if isinstance(categories, str) else categories):
            return False
        if pattern := match.get("category_regex"):
            if not re.search(str(pattern), event.category, re.IGNORECASE):
                return False
        severities = match.get("severity")
        if severities and event.severity not in ([severities] if isinstance(severities, str) else severities):
            return False
        if context.window_count < int(match.get("count_gte", 0)):
            return False
        if status := match.get("geo_status"):
            if context.geo_status != status:
                return False
        regions = match.get("region_in")
        if regions and not any(str(region) in context.location for region in regions):
            return False
        excluded = match.get("region_not_in")
        if excluded and any(str(region) in context.location for region in excluded):
            return False
        tags = match.get("threat_tag")
        if tags:
            required = {str(tags)} if isinstance(tags, str) else {str(tag) for tag in tags}
            if required.isdisjoint(context.threat_tags):
                return False
        if context.threat_confidence < int(match.get("threat_confidence_gte", 0)):
            return False
        return True

    @staticmethod
    def _duration_minutes(value: Any) -> int:
        if isinstance(value, int):
            return value
        text = str(value or "0").strip().lower()
        match = re.fullmatch(r"(\d+)(m|h|d)?", text)
        if not match:
            raise ValueError(f"invalid policy duration: {value}")
        amount, unit = int(match.group(1)), match.group(2) or "m"
        return amount * {"m": 1, "h": 60, "d": 1440}[unit]
