from __future__ import annotations

import re

from monitor.common.errors import IgnoredLog, ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


def field(line: str, name: str) -> str | None:
    match = re.search(rf"{re.escape(name)}:([^;`]+)", line)
    return match.group(1).strip() if match else None


class DPTechWafParser:
    source = "DPTECH_WAF"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        if "%%WAF/WEBATTACK" in line:
            category = field(line, "att_level1")
            if not category:
                raise ParseError("DPTech WEBATTACK has no att_level1")
            second, third = field(line, "att_level2") or "", field(line, "att_level3") or ""
            threat = "/".join(x for x in (second, third) if x)
            fmt = "WEBATTACK"
        elif "log-type:basic-attack" in line and "event:alert" in line:
            category, threat, fmt = field(line, "attack-name"), "", "BASIC_ATTACK"
            if not category:
                raise ParseError("DPTech BASIC_ATTACK has no attack-name")
        else:
            raise IgnoredLog("unsupported DPTech WAF event")
        src, dst = field(line, "source-ip"), field(line, "destination-ip")
        if not src or not dst:
            raise ParseError("DPTech WAF event has no source/destination IP")
        src, dst = valid_ip(src), valid_ip(dst)
        if src == dst:
            raise IgnoredLog("DPTech WAF self-test traffic")
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=src, dst_ip=dst, category=category, vendor_category=threat or category,
            severity="high", raw_line=line.rstrip(), attributes={"threat_type": threat, "format": fmt},
        )


def create_parser():
    return DPTechWafParser()
