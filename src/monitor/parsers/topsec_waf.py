from __future__ import annotations

import re

from monitor.common.errors import ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


class TopsecWafParser:
    source = "TOPSEC_WAF"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        src_match = re.search(r"sip=[\x22\x27]?([\d.]+)", line)
        if not src_match:
            raise ParseError("Topsec event has no sip")
        dst_match = re.search(r"dip=[\x22\x27]?([\d.]+)", line)
        category_match = re.search(r"msg=[\x22\x27]?[^\x22\x27]*（([^）]+)）", line)
        if category_match:
            category = category_match.group(1).strip()
        else:
            message = re.search(r"msg=[\x22\x27]?([^\x22\x27\s;]+)", line)
            category = message.group(1).strip() if message else "SecurityEvent"
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(src_match.group(1)), dst_ip=valid_ip(dst_match.group(1)) if dst_match else None,
            category=category, vendor_category=category, severity="high", raw_line=line.rstrip(),
            attributes={"format": "TOPSEC_KV"},
        )


def create_parser():
    return TopsecWafParser()

