from __future__ import annotations

from monitor.infrastructure.firewall import HuaweiFirewallClient
from monitor.plugins.contracts import ActionResult


class HuaweiActionProvider:
    def __init__(self, config: dict, password: str):
        self.client = HuaweiFirewallClient(config, password)

    def apply(self, payload: dict) -> ActionResult:
        self.client.block(payload["ip"], int(payload["minutes"]), payload.get("category", "monitor3"))
        return ActionResult(True, "blocked")

    def revoke(self, payload: dict) -> ActionResult:
        self.client.unblock(payload["ip"])
        return ActionResult(True, "unblocked")

    def inspect(self, subject: str) -> ActionResult:
        return ActionResult(False, "unknown", details={"reason": "standalone inspect not implemented"})


def create_huawei_action(config: dict, **secrets):
    return HuaweiActionProvider(config, secrets.get("password", ""))

