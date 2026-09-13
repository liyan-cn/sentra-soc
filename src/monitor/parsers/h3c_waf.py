from __future__ import annotations

import re

from monitor.common.errors import ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


def _slash_value(line: str, names: tuple[str, ...]) -> str | None:
    for name in names:
        match = re.search(rf"(?:^|[,\s]){re.escape(name)}\s*/\s*([^,]+)", line, re.I)
        if match:
            return match.group(1).strip()
    return None


class H3cWafParser:
    source = "H3C_WAF"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        if "H3CWAF:" not in line.upper():
            raise ParseError("not an H3C WAF event")
        src = _slash_value(line, ("客户端IP", "sip", "client_ip"))
        dst = _slash_value(line, ("服务器IP", "dip", "server_ip"))
        category = _slash_value(line, ("事件", "msg", "event_name"))
        severity_id = _slash_value(line, ("severity_id", "威胁")) or ""
        if not src:
            raise ParseError("H3C WAF event has no client IP")
        severity = "critical" if severity_id in {"1", "严重"} else "high"
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(src), dst_ip=valid_ip(dst) if dst else None,
            category=(category or "WAFAttack")[:200], vendor_category=(category or "WAFAttack")[:200],
            severity=severity, raw_line=line.rstrip(),
            attributes={"format": "H3CWAF_SLASH", "vendor": "H3C", "severity_id": severity_id},
        )


def create_parser():
    return H3cWafParser()
