from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DecisionType(StrEnum):
    IGNORE = "IGNORE"
    OBSERVE = "OBSERVE"
    NOTIFY = "NOTIFY"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    BLOCK = "BLOCK"


@dataclass(slots=True)
class SecurityEvent:
    source: str
    device_id: str
    event_type: str
    occurred_at: datetime
    src_ip: str
    dst_ip: str | None = None
    category: str = "Unknown"
    vendor_category: str = ""
    severity: str = "medium"
    attributes: dict = field(default_factory=dict)
    raw_line: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    received_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        # Store normalized instants, not local wall-clock strings. Preserve raw
        # evidence and report drift instead of rewriting delayed events to now.
        from datetime import timedelta
        local = timezone(timedelta(hours=8))
        self.occurred_at = self.occurred_at.replace(tzinfo=self.occurred_at.tzinfo or local).astimezone(timezone.utc)
        self.received_at = self.received_at.replace(tzinfo=self.received_at.tzinfo or local).astimezone(timezone.utc)
        skew = round((self.occurred_at - self.received_at).total_seconds(), 3)
        self.attributes['time_validation'] = {
            'display_timezone': 'Asia/Shanghai', 'offset_from_received_seconds': skew,
            'status': 'future_clock' if skew > 300 else 'delayed_or_clock_skew' if skew < -300 else 'consistent',
        }

    @property
    def raw_hash(self) -> str:
        base = f"{self.device_id}\0{self.raw_line}".encode("utf-8", errors="replace")
        return hashlib.sha256(base).hexdigest()

    def attributes_json(self) -> str:
        return json.dumps(self.attributes, ensure_ascii=False, separators=(",", ":"))


@dataclass(slots=True)
class PolicyDecision:
    event_id: str
    decision: DecisionType
    rule_id: str
    reason: str
    window_count: int = 1
    location: str = "UNKNOWN"
    block_minutes: int = 0
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
