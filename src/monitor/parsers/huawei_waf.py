from __future__ import annotations

import re

from monitor.common.errors import IgnoredLog, ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


def _field(line: str, name: str) -> str | None:
    match = re.search(rf"(?:^|[,\s]){re.escape(name)}=[\"']?([^,\)\"']+)", line, re.I)
    return match.group(1).strip() if match else None


class HuaweiWafParser:
    source = "HUAWEI_WAF"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        formats = ("IPS/4/DETECT", "ASSOC/4/ATTACK")
        fmt = next((item for item in formats if item in line.upper()), None)
        if not fmt:
            raise IgnoredLog("not a Huawei WAF threat event")
        src, dst = _field(line, "SrcIp"), _field(line, "DstIp")
        if not src:
            raise ParseError("Huawei WAF event has no source IP")
        category = _field(line, "Category") or _field(line, "SignName") or "WAFThreat"
        signature = _field(line, "SignName") or category
        action = _field(line, "Action") or ""
        severity_value = (_field(line, "Severity") or "high").casefold()
        severity = "critical" if severity_value in {"critical", "very-high", "1"} else "high"
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(src), dst_ip=valid_ip(dst) if dst else None,
            category=category[:200], vendor_category=signature[:200], severity=severity,
            raw_line=line.rstrip(), attributes={"signature": signature, "format": fmt,
                                                "vendor": "Huawei", "device_type": "WAF", "action": action},
        )


def create_parser():
    return HuaweiWafParser()
