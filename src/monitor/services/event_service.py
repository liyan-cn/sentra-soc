from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import timedelta

from monitor.domain.models import DecisionType, PolicyDecision, SecurityEvent, utc_now
from monitor.domain.policy_engine import EvaluationContext, PolicyEngine
from monitor.domain.playbook_engine import PlaybookContext, PlaybookEngine
from monitor.repositories.event_repository import EventRepository
from monitor.services.whitelist_service import find_whitelist_match


class EventService:
    def __init__(self, database, rules: dict, local_region: str = "", playbooks: list[dict] | None = None,
                 playbook_version: str = "", observation_only: bool = False):
        self.db = database
        self.rules = rules
        self.local_region = local_region
        self.policy_engine = PolicyEngine(rules.get("policies", [])) if rules.get("policies") else None
        self.playbook_engine = PlaybookEngine(playbooks or [])
        self.playbook_version = playbook_version or "unversioned"
        self.observation_only = observation_only

    def submit(self, event: SecurityEvent, location: str = "UNKNOWN", threat: dict | None = None) -> PolicyDecision | None:
        ipaddress.ip_address(event.src_ip)
        rule = self.rules.get(event.source, self.rules.get("defaults", {}))
        window = int(rule.get("window_seconds", 300))
        since = (event.occurred_at - timedelta(seconds=window)).isoformat()
        now = utc_now()
        with self.db.transaction(immediate=True) as conn:
            if not EventRepository.insert(conn, event):
                return None
            whitelist = find_whitelist_match(conn, event.src_ip, now.isoformat())
            if whitelist:
                decision = PolicyDecision(
                    event.id, DecisionType.IGNORE, f"whitelist:{whitelist['id']}",
                    f"matched {whitelist['network']}: {whitelist['reason'] or 'no reason'}", 1, location,
                )
                EventRepository.save_decision(conn, decision)
                return decision
            count = EventRepository.window_count(conn, event, since)
            if self.observation_only:
                decision = PolicyDecision(event.id, DecisionType.OBSERVE, "observation-mode",
                                          "device is in observation mode; automated actions suppressed",
                                          count, location)
                EventRepository.save_decision(conn, decision)
                return decision
            decision = self._decide(event, rule, count, location, threat or {})
            EventRepository.save_decision(conn, decision)
            if decision.decision == DecisionType.BLOCK:
                expires = now + timedelta(minutes=decision.block_minutes)
                blacklist_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO blacklist_entries
                    (id,ip,desired_state,actual_state,first_seen_at,last_seen_at,desired_expires_at,
                     hit_count,category,source,location)
                    VALUES(?,?,'pending_block','unknown',?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET
                      desired_state='pending_block', last_seen_at=excluded.last_seen_at,
                      desired_expires_at=MAX(blacklist_entries.desired_expires_at,excluded.desired_expires_at),
                      hit_count=blacklist_entries.hit_count+excluded.hit_count,
                      category=excluded.category,source=excluded.source,location=excluded.location,
                      version=blacklist_entries.version+1""",
                    (blacklist_id, event.src_ip, now.isoformat(), now.isoformat(), expires.isoformat(),
                     count, event.category, event.source, location),
                )
                row = conn.execute("SELECT id,version FROM blacklist_entries WHERE ip=?", (event.src_ip,)).fetchone()
                self._enqueue(conn, "BLOCK", "blacklist", row["id"],
                              {"ip": event.src_ip, "minutes": decision.block_minutes, "category": event.category},
                              f"block:{row['id']}:{row['version']}", 100)
            elif decision.decision == DecisionType.MANUAL_REVIEW:
                review_id = str(uuid.uuid4())
                dedup = f"{event.src_ip}:{event.source}:{event.category}"
                automation = self.playbook_engine.match_auto_close(event, PlaybookContext(
                    decision.decision.value, count, location,
                    tuple((threat or {}).get("tags", [])), int((threat or {}).get("confidence", 0)),
                ))
                review_status = "auto_closed" if automation else "open"
                resolution = automation["action"]["reason"] if automation else None
                closed_at = now.isoformat() if automation else None
                conn.execute(
                    """INSERT INTO review_cases
                    (id,dedup_key,event_id,ip,category,source,status,count,reason,resolution,created_at,updated_at,closed_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(dedup_key) WHERE status IN ('open','claimed') DO UPDATE SET
                      count=excluded.count,updated_at=excluded.updated_at,reason=excluded.reason""",
                    (review_id, dedup, event.id, event.src_ip, event.category, event.source, review_status,
                     count, decision.reason, resolution, now.isoformat(), now.isoformat(), closed_at),
                )
                if automation:
                    playbook = automation["playbook"]
                    conn.execute(
                        """INSERT INTO playbook_executions
                        (id,playbook_id,playbook_version,event_id,review_id,action_type,status,reason,details_json,created_at)
                        VALUES(?,?,?,?,?,'close_review','succeeded',?,?,?)""",
                        (str(uuid.uuid4()), str(playbook["id"]), self.playbook_version, event.id, review_id,
                         resolution, json.dumps({"count": count, "location": location}, ensure_ascii=False),
                         now.isoformat()),
                    )
                    conn.execute(
                        """INSERT INTO audit_logs(actor,action,target_type,target_id,reason,after_json,source_ip,created_at)
                        VALUES(?,?,?,?,?,?,?,?)""",
                        (f"playbook:{playbook['id']}", "auto_close", "review", review_id, resolution,
                         json.dumps({"status": "auto_closed"}, ensure_ascii=False), "system", now.isoformat()),
                    )
            return decision

    def _decide(self, event, rule, count, location, threat=None) -> PolicyDecision:
        if self.policy_engine:
            threat = threat or {}
            decision = self.policy_engine.evaluate(event, EvaluationContext(
                count, location, tuple(threat.get("tags", [])), int(threat.get("confidence", 0))))
            if decision.decision == DecisionType.BLOCK and decision.block_minutes <= 0:
                decision.block_minutes = int(rule.get("block_minutes", self.rules.get("defaults", {}).get("block_minutes", 10000)))
            return decision
        block = rule.get("block_threshold")
        warn = int(rule.get("warn_threshold", 50))
        is_local = bool(self.local_region) and location != "UNKNOWN" and self.local_region in location
        if block is not None and count >= int(block) and not is_local and location != "UNKNOWN":
            return PolicyDecision(event.id, DecisionType.BLOCK, event.source,
                                  f"count {count} reached block threshold {block}", count, location,
                                  int(rule.get("block_minutes", self.rules.get("defaults", {}).get("block_minutes", 10000))))
        if count >= warn:
            reason = "local region requires review" if is_local else "location unknown or warning threshold reached"
            return PolicyDecision(event.id, DecisionType.MANUAL_REVIEW, event.source, reason, count, location)
        return PolicyDecision(event.id, DecisionType.OBSERVE, event.source, "below threshold", count, location)

    @staticmethod
    def _enqueue(conn, action_type, aggregate_type, aggregate_id, payload, key, priority=0):
        now = utc_now().isoformat()
        conn.execute(
            """INSERT OR IGNORE INTO action_outbox
            (id,action_type,aggregate_type,aggregate_id,payload_json,idempotency_key,status,priority,available_at,created_at,updated_at)
            VALUES(?,?,?,?,?,?,'pending',?,?,?,?)""",
            (str(uuid.uuid4()), action_type, aggregate_type, aggregate_id,
             json.dumps(payload, ensure_ascii=False), key, priority, now, now, now),
        )
