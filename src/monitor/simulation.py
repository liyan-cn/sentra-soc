from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from monitor.domain.models import SecurityEvent
from monitor.common.errors import IgnoredLog
from monitor.parsers import get_parser
from monitor.services.event_service import EventService


def simulate(rules: dict, *, source: str, category: str, src_ip: str, count: int,
             location: str = "UNKNOWN", severity: str = "high",
             threat_tags: list[str] | None = None, threat_confidence: int = 0,
             local_region: str = "") -> dict:
    event = SecurityEvent(
        source=source, device_id="simulation", event_type="attack",
        occurred_at=datetime.now(timezone.utc), src_ip=src_ip,
        category=category, severity=severity, raw_line="simulation",
    )
    service = EventService(None, rules, local_region)
    rule = rules.get(source, rules.get("defaults", {}))
    decision = service._decide(event, rule, count, location, {
        "tags": threat_tags or [], "confidence": threat_confidence,
    })
    return {
        "event": {"source": source, "src_ip": src_ip, "category": category, "severity": severity},
        "context": {"count": count, "location": location, "threat_tags": threat_tags or [],
                    "threat_confidence": threat_confidence},
        "decision": decision.decision.value,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "block_minutes": decision.block_minutes,
    }


def replay(rules: dict, parser_name: str, device_id: str, path: str | Path,
           limit: int = 10000, local_region: str = "") -> dict:
    parser = get_parser(parser_name)
    service = EventService(None, rules, local_region)
    windows = defaultdict(int)
    decisions = Counter()
    failures = 0
    ignored = 0
    samples = []
    processed = 0
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if processed >= limit:
                break
            try:
                event = parser.parse(line, device_id)
                windows[(event.source, event.src_ip)] += 1
                count = windows[(event.source, event.src_ip)]
                rule = rules.get(event.source, rules.get("defaults", {}))
                decision = service._decide(event, rule, count, "UNKNOWN", {})
                decisions[decision.decision.value] += 1
                if len(samples) < 20 and decision.decision.value not in ("OBSERVE", "IGNORE"):
                    samples.append({"line": line_number, "src_ip": event.src_ip, "category": event.category,
                                    "count": count, "decision": decision.decision.value,
                                    "rule_id": decision.rule_id})
                processed += 1
            except IgnoredLog:
                ignored += 1
            except Exception:
                failures += 1
    return {
        "mode": "analysis_only",
        "file": str(Path(path).resolve()),
        "parser": parser_name,
        "processed": processed,
        "parse_failures": failures,
        "ignored": ignored,
        "decisions": dict(sorted(decisions.items())),
        "samples": samples,
        "side_effects": False,
    }


def print_report(report: dict) -> None:
    print(json.dumps(report, ensure_ascii=False, indent=2))
