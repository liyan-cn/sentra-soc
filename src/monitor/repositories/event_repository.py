from __future__ import annotations

from monitor.domain.models import PolicyDecision, SecurityEvent, utc_now


class EventRepository:
    @staticmethod
    def insert(conn, event: SecurityEvent) -> bool:
        cur = conn.execute(
            """INSERT OR IGNORE INTO security_events
            (id,raw_hash,source,device_id,occurred_at,received_at,event_type,src_ip,dst_ip,category,vendor_category,severity,attributes_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event.id, event.raw_hash, event.source, event.device_id, event.occurred_at.isoformat(),
             event.received_at.isoformat(), event.event_type, event.src_ip, event.dst_ip, event.category,
             event.vendor_category, event.severity, event.attributes_json()),
        )
        return cur.rowcount == 1

    @staticmethod
    def window_count(conn, event: SecurityEvent, since: str) -> int:
        return conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE src_ip=? AND source=? AND occurred_at>=?",
            (event.src_ip, event.source, since),
        ).fetchone()[0]

    @staticmethod
    def save_decision(conn, decision: PolicyDecision) -> None:
        conn.execute(
            """INSERT OR IGNORE INTO policy_decisions
            (id,event_id,decision,rule_id,reason,window_count,location,created_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (decision.id, decision.event_id, decision.decision.value, decision.rule_id,
             decision.reason, decision.window_count, decision.location, utc_now().isoformat()),
        )

