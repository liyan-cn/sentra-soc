from datetime import datetime, timezone

from monitor.domain.models import DecisionType, SecurityEvent
from monitor.domain.policy_engine import EvaluationContext, PolicyEngine
from monitor.infrastructure.threat_intel import StaticThreatIntelProvider


def test_static_intel_longest_prefix_and_policy_match():
    provider = StaticThreatIntelProvider({"indicators": [
        {"network": "8.8.0.0/16", "tags": ["scanner"], "confidence": 60},
        {"network": "8.8.8.8", "tags": ["botnet"], "confidence": 95},
    ]})
    intel = provider.lookup("8.8.8.8")
    assert intel["tags"] == ["botnet"]
    event = SecurityEvent(source="TEST", device_id="d", event_type="attack",
                          occurred_at=datetime.now(timezone.utc), src_ip="8.8.8.8")
    engine = PolicyEngine([{"id": "intel", "match": {"threat_tag": "botnet", "threat_confidence_gte": 90},
                            "decision": "BLOCK", "duration_minutes": "1d"}])
    result = engine.evaluate(event, EvaluationContext(1, "UNKNOWN", tuple(intel["tags"]), intel["confidence"]))
    assert result.decision == DecisionType.BLOCK
