from __future__ import annotations

import re

from monitor.common.errors import ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .vendor_time import syslog_time


class HuaweiIpsParser:
    source = "HUAWEI_IPS"
    _ips = re.compile(r"SrcIp=(?P<src>[\d.]+).*?DstIp=(?P<dst>[\d.]+)")

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        if "IPS/4/DETECT" not in line:
            raise ParseError("not a Huawei IPS DETECT event")
        match = self._ips.search(line)
        if not match:
            raise ParseError("Huawei IPS event has no source/destination IP")
        category_match = re.search(r"Category=([^,)]+)", line)
        signature_match = re.search(r'SignName="([^"]+)"', line)
        category = (category_match.group(1).strip() if category_match else "Unknown")
        signature = signature_match.group(1).strip() if signature_match else category
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(match.group("src")), dst_ip=valid_ip(match.group("dst")),
            category=category, vendor_category=signature, severity="high", raw_line=line.rstrip(),
            attributes={"signature": signature, "format": "IPS/4/DETECT"},
        )


def create_parser():
    return HuaweiIpsParser()

