from datetime import datetime, timezone

import pytest

from monitor.common.errors import ConfigError
from monitor.common.playbooks import PlaybookLoader
from monitor.domain.models import DecisionType, SecurityEvent
from monitor.domain.playbook_engine import PlaybookContext, PlaybookEngine
from monitor.infrastructure.database import Database
from monitor.services.event_service import EventService


def event(category="health-check", severity="low"):
    return SecurityEvent("DPTECH_WAF", "waf-1", "attack", datetime.now(timezone.utc),
                         "203.0.113.8", category=category, severity=severity, raw_line=category)


def playbook(enabled=True):
    return {"id": "close-health", "enabled": enabled, "priority": 10, "trigger": "review_created",
            "match": {"decision": "MANUAL_REVIEW", "source": "DPTECH_WAF",
                      "category_regex": "health", "severity": "low", "count_lte": 20},
            "actions": [{"type": "close_review", "reason": "known health check"}]}


def test_engine_matches_explicit_low_risk_playbook_only():
    engine = PlaybookEngine([playbook()])
    context = PlaybookContext("MANUAL_REVIEW", 10, "UNKNOWN")
    assert engine.match_auto_close(event(), context)["playbook"]["id"] == "close-health"
    assert engine.match_auto_close(event(severity="high"), context) is None
    assert engine.match_auto_close(event(), PlaybookContext("MANUAL_REVIEW", 21)) is None


def test_auto_close_is_audited_without_enqueuing_enforcement(tmp_path):
    db = Database(tmp_path / "playbook.db"); db.initialize()
    rules = {"defaults": {"window_seconds": 300, "warn_threshold": 1, "block_threshold": None}}
    decision = EventService(db, rules, playbooks=[playbook()], playbook_version="abc123").submit(event())
    assert decision.decision == DecisionType.MANUAL_REVIEW
    with db.connect() as conn:
        review = conn.execute("SELECT status,resolution FROM review_cases").fetchone()
        execution = conn.execute("SELECT playbook_id,status,playbook_version FROM playbook_executions").fetchone()
        audit = conn.execute("SELECT actor,action FROM audit_logs").fetchone()
        actions = conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0]
    assert tuple(review) == ("auto_closed", "known health check")
    assert tuple(execution) == ("close-health", "succeeded", "abc123")
    assert tuple(audit) == ("playbook:close-health", "auto_close")
    assert actions == 0


def test_loader_rejects_match_all_auto_close(tmp_path):
    config = tmp_path / "config"; config.mkdir()
    path = config / "playbooks.yaml"
    path.write_text("playbooks: [{id: unsafe, enabled: true, match: {}, actions: [{type: close_review, reason: x}]}]", encoding="utf-8")

    class Settings:
        config_path = config / "base.yaml"
        def section(self, _name): return {"file": "./config/playbooks.yaml"}

    with pytest.raises(ConfigError):
        PlaybookLoader(Settings()).load()
