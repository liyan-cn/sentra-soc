from __future__ import annotations

import re

from monitor.common.errors import ParseError
from monitor.domain.models import SecurityEvent
from .base import parse_time, valid_ip


IP = r"(?P<{}>\d{{1,3}}(?:\.\d{{1,3}}){{3}})"
TIME = r"(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"


class RegexSecurityParser:
    def __init__(self, source: str, patterns: list[re.Pattern]):
        self.source = source
        self.patterns = patterns

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        for pattern in self.patterns:
            match = pattern.search(line)
            if not match:
                continue
            data = match.groupdict()
            src = valid_ip(data["src"])
            dst = valid_ip(data["dst"]) if data.get("dst") else None
            category = (data.get("category") or "Unknown").strip()[:200]
            return SecurityEvent(
                source=self.source, device_id=device_id, event_type="attack",
                occurred_at=parse_time(data.get("time")), src_ip=src, dst_ip=dst,
                category=category, vendor_category=category, raw_line=line.rstrip("\r\n"),
                attributes={"parser": self.source.lower()},
            )
        raise ParseError(f"line does not match {self.source} format")


def common_patterns() -> list[re.Pattern]:
    return [
        re.compile(TIME + r".*?(?:src(?:_ip)?|source-ip)[=: ]+" + IP.format("src") +
                   r".*?(?:dst(?:_ip)?|destination-ip)[=: ]+" + IP.format("dst") +
                   r".*?(?:category|event|signature|attack)[=: ]+(?P<category>[^,;|]+)", re.I),
        re.compile(r"(?:src(?:_ip)?|source-ip)[=: ]+" + IP.format("src") +
                   r".*?(?:dst(?:_ip)?|destination-ip)[=: ]+" + IP.format("dst") +
                   r".*?(?:category|event|signature|attack)[=: ]+(?P<category>[^,;|]+)", re.I),
        re.compile(IP.format("src") + r"\s*(?:->|to)\s*" + IP.format("dst") +
                   r".*?(?P<category>[A-Za-z][\w ./-]{2,100})", re.I),
    ]

