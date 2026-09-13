from __future__ import annotations

import re

from monitor.common.errors import IgnoredLog, ParseError
from monitor.detection.url_rules import detect_malicious_url
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .dptech_waf import field
from .vendor_time import syslog_time


NETWORK_ATTACKS = {x.casefold() for x in (
    "land", "Tracert", "Icmp unreach", "Large icmp", "Icmp redirect",
    "SYN flood", "UDP flood", "ICMP flood",
)}


class DPTechIpsParser:
    source = "DPTECH_IPS"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        if "event:alert" not in line:
            raise IgnoredLog("not a DPTech IPS alert")
        src, dst = field(line, "source-ip"), field(line, "destination-ip")
        if not src or not dst:
            raise ParseError("DPTech IPS event has no source/destination IP")
        src, dst = valid_ip(src), valid_ip(dst)
        if src == dst:
            raise IgnoredLog("DPTech IPS self-test traffic")
        attributes = {}
        if "log-type:url_class" in line:
            host = (field(line, "url_class_host") or "").split(":")[0]
            if not host:
                raise ParseError("DPTech URL class event has no host")
            url = field(line, "url_class_url") or ""
            detection = detect_malicious_url(host, url)
            if not detection:
                raise IgnoredLog("ordinary DPTech URL classification traffic")
            category = detection["category"]
            attributes.update({"host": host, "url": url[:2048], "local_rule_id": detection["id"],
                               "mitre_technique": detection.get("mitre", "")})
            severity = detection.get("severity", "high")
        else:
            attack = field(line, "attack-name")
            if not attack:
                raise ParseError("DPTech IPS event has no attack-name")
            exploit = re.match(r"^\((\d+)\)(.+)$", attack)
            if exploit:
                category = exploit.group(2).strip()
                attributes["vulnerability_id"] = exploit.group(1)
            elif attack.casefold() in NETWORK_ATTACKS:
                category = attack
            else:
                raise IgnoredLog("DPTech IPS attack type is not monitored")
            severity = "high"
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=src, dst_ip=dst, category=category, vendor_category=category,
            severity=severity, raw_line=line.rstrip(), attributes=attributes,
        )


def create_parser():
    return DPTechIpsParser()
