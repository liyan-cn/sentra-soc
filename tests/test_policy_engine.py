from datetime import datetime, timezone

from monitor.domain.models import DecisionType, SecurityEvent
from monitor.domain.policy_engine import EvaluationContext, PolicyEngine


def make_event(category="scan"):
    return SecurityEvent(source="SURICATA", device_id="sensor", event_type="attack",
                         occurred_at=datetime.now(timezone.utc), src_ip="8.8.8.8", category=category)


def test_priority_and_duration():
    engine = PolicyEngine([
        {"id": "review", "priority": 10, "match": {"count_gte": 1}, "decision": "MANUAL_REVIEW"},
        {"id": "c2", "priority": 100, "match": {"category_regex": "c2|trojan", "count_gte": 1},
         "decision": "BLOCK", "duration_minutes": "7d"},
    ])
    result = engine.evaluate(make_event("C2 callback"), EvaluationContext(1, "US/CA"))
    assert result.decision == DecisionType.BLOCK
    assert result.block_minutes == 10080


def test_unknown_geo_can_be_reviewed():
    engine = PolicyEngine([{"id": "unknown", "match": {"geo_status": "unknown"}, "decision": "MANUAL_REVIEW"}])
    assert engine.evaluate(make_event(), EvaluationContext(10, "UNKNOWN")).decision == DecisionType.MANUAL_REVIEW
