from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess  # Used only with argument arrays and bounded execution; no shell.  # nosec B404
from typing import Callable

from monitor.common.errors import ExternalServiceError
from monitor.plugins.contracts import ActionResult


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


class NftablesActionProvider:
    """Manage an existing nftables set without invoking a shell."""

    def __init__(self, config: dict, runner: Callable = subprocess.run):
        self.family = str(config.get("family", "inet"))
        self.table = str(config.get("table", "filter"))
        self.set_name = str(config.get("set", "monitor3_blocklist"))
        self.binary = str(config.get("binary", "nft"))
        self.runner = runner
        if self.family not in {"inet", "ip", "ip6", "bridge", "arp", "netdev"}:
            raise ValueError("invalid nftables family")
        for value in (self.table, self.set_name):
            if not IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid nftables identifier: {value}")

    def apply(self, payload: dict) -> ActionResult:
        ip = str(ipaddress.ip_address(payload["ip"]))
        current = self.inspect(ip)
        if current.success:
            return current
        seconds = max(60, int(payload.get("minutes", 60)) * 60)
        self._run(["add", "element", self.family, self.table, self.set_name,
                   "{", ip, "timeout", f"{seconds}s", "}"])
        verified = self.inspect(ip)
        if not verified.success:
            raise ExternalServiceError("nftables did not confirm blocked IP")
        return verified

    def revoke(self, payload: dict) -> ActionResult:
        ip = str(ipaddress.ip_address(payload["ip"]))
        if not self.inspect(ip).success:
            return ActionResult(True, "unblocked", details={"idempotent": True})
        self._run(["delete", "element", self.family, self.table, self.set_name, "{", ip, "}"])
        if self.inspect(ip).success:
            raise ExternalServiceError("nftables still contains IP after deletion")
        return ActionResult(True, "unblocked")

    def inspect(self, subject: str) -> ActionResult:
        ip = str(ipaddress.ip_address(subject))
        result = self._run(["list", "set", self.family, self.table, self.set_name], allow_failure=True)
        if result.returncode != 0:
            return ActionResult(False, "unknown", details={"error": result.stderr[-500:]})
        found = re.search(rf"(?<![\dA-Fa-f:.]){re.escape(ip)}(?![\dA-Fa-f:.])", result.stdout) is not None
        return ActionResult(found, "blocked" if found else "unblocked")

    def _run(self, args: list[str], allow_failure: bool = False):
        if shutil.which(self.binary) is None and self.runner is subprocess.run:
            raise ExternalServiceError(f"nftables binary not found: {self.binary}")
        result = self.runner([self.binary, *args], capture_output=True, text=True, timeout=10, shell=False)
        if result.returncode != 0 and not allow_failure:
            raise ExternalServiceError(f"nftables command failed: {result.stderr[-500:]}")
        return result


def create_nftables_action(config: dict, **_):
    return NftablesActionProvider(config)

