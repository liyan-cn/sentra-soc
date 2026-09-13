from __future__ import annotations

import re

from monitor.common.errors import ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


_EXTENSION = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=((?:(?!\s[A-Za-z][A-Za-z0-9_]*=).)*)")


def _unescape(value: str) -> str:
    return value.replace(r"\=", "=").replace(r"\n", "\n").replace(r"\\", "\\").strip()


def parse_cef(line: str) -> tuple[list[str], dict[str, str]]:
    marker = line.find("CEF:")
    if marker < 0:
        raise ParseError("not a CEF event")
    parts = re.split(r"(?<!\\)\|", line[marker:], maxsplit=7)
    if len(parts) != 8:
        raise ParseError("incomplete CEF header")
    fields = [_unescape(value) for value in parts[:7]]
    extension = {match.group(1): _unescape(match.group(2)) for match in _EXTENSION.finditer(parts[7])}
    return fields, extension


class CefSecurityParser:
    source = "CEF_SECURITY"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        header, values = parse_cef(line)
        src = values.get("src") or values.get("sourceAddress")
        if not src:
            raise ParseError("CEF event has no source address")
        dst = values.get("dst") or values.get("destinationAddress")
        category = values.get("cat") or values.get("act") or header[5] or "SecurityEvent"
        severity_value = (values.get("severity") or header[6] or "medium").casefold()
        severity = "critical" if severity_value in {"10", "very-high", "critical"} else (
            "high" if severity_value in {"7", "8", "9", "high"} else "medium"
        )
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(src), dst_ip=valid_ip(dst) if dst else None,
            category=category[:200], vendor_category=header[5][:200], severity=severity,
            raw_line=line.rstrip(), attributes={"format": "CEF", "vendor": header[1],
                                                "product": header[2], "action": values.get("act", "")},
        )


def create_parser():
    return CefSecurityParser()
