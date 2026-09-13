from __future__ import annotations

import ipaddress


class StaticThreatIntelProvider:
    """Offline CIDR/IP indicators suitable for air-gapped and test deployments."""

    def __init__(self, config: dict):
        self.indicators = []
        for item in config.get("indicators", []):
            network = ipaddress.ip_network(str(item["network"]), strict=False)
            self.indicators.append((network, {
                "matched": True,
                "indicator": str(network),
                "tags": sorted({str(tag) for tag in item.get("tags", [])}),
                "confidence": max(0, min(100, int(item.get("confidence", 50)))),
                "source": str(item.get("source", "static")),
            }))
        self.indicators.sort(key=lambda entry: entry[0].prefixlen, reverse=True)

    def lookup(self, ip: str) -> dict:
        address = ipaddress.ip_address(ip)
        for network, result in self.indicators:
            if address.version == network.version and address in network:
                return dict(result)
        return {"matched": False, "tags": [], "confidence": 0, "source": "static"}


def create_static_threat_intel(config: dict, **_):
    return StaticThreatIntelProvider(config)

