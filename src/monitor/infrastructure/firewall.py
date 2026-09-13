from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timedelta

from monitor.common.errors import ExternalServiceError


class HuaweiFirewallClient:
    def __init__(self, config: dict, password: str):
        self.config = config
        self.password = password

    def block(self, ip: str, minutes: int, description: str) -> None:
        ip = str(ipaddress.ip_address(ip))
        minutes = int(minutes)
        if not 1 <= minutes <= 525600:
            raise ValueError("firewall block duration must be between 1 and 525600 minutes")
        description = re.sub(r"[^A-Za-z0-9_-]", "_", description)[:63]
        command = f"firewall blacklist item source-ip {ip} timeout {minutes} description {description}"
        outputs = self._commands(["sys", command, "display firewall blacklist item"])
        if not self._contains_ip(outputs[-1], ip):
            raise ExternalServiceError("firewall did not confirm blocked IP")

    def unblock(self, ip: str) -> None:
        ip = str(ipaddress.ip_address(ip))
        outputs = self._commands(["sys", f"undo firewall blacklist item source-ip {ip}",
                                  "display firewall blacklist item"])
        if self._contains_ip(outputs[-1], ip):
            raise ExternalServiceError("firewall did not confirm unblocked IP")

    def list_items(self, list_type: str) -> list[dict]:
        if list_type not in {"blacklist", "whitelist"}:
            raise ValueError("list_type must be blacklist or whitelist")
        output = self._commands([f"display firewall {list_type} item"])[0]
        return self.parse_list_output(output, list_type)

    @staticmethod
    def parse_list_output(output: str, list_type: str) -> list[dict]:
        pattern = re.compile(
            r"^[ \t]*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})[ \t]*/[ \t]*any[ \t]*"
            r"\((?P<direction>src|dst)\)[ \t]*/[ \t]*(?P<protocol>\S+)[ \t]+"
            r"(?P<reason>\S+)[ \t]+(?P<inserted>\d{4}-\d{2}-\d{2}[ \t]+\d{2}:\d{2}:\d{2})[ \t]+"
            r"(?P<age>Permanent|\d+)[ \t]+(?P<hits>\d+)[ \t]*(?P<description>[^\r\n]*)\r?$",
            re.MULTILINE,
        )
        items = []
        for match in pattern.finditer(output):
            values = match.groupdict()
            ip = str(ipaddress.ip_address(values["ip"]))
            inserted = datetime.strptime(values["inserted"], "%Y-%m-%d %H:%M:%S")
            permanent = values["age"] == "Permanent"
            expires = None if permanent else (inserted + timedelta(minutes=int(values["age"]))).isoformat()
            items.append({
                "list_type": list_type, "direction": values["direction"], "ip": ip,
                "protocol": values["protocol"], "reason": values["reason"],
                "inserted_at": inserted.isoformat(), "age_time": values["age"],
                "expires_at": expires, "permanent": permanent,
                "hit_count": int(values["hits"]), "description": values["description"].strip(),
            })
        return items

    @staticmethod
    def _contains_ip(output: str, expected: str) -> bool:
        candidates = re.findall(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f:.]+)(?![0-9A-Fa-f:.])", output)
        for candidate in candidates:
            try:
                if str(ipaddress.ip_address(candidate)) == expected:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _failed(output: str) -> bool:
        return re.search(r"(?:^|\n)\s*(?:%\s*)?(?:error|invalid command|failed)\s*[: ]", output, re.I) is not None

    def _commands(self, commands: list[str]) -> list[str]:
        try:
            import paramiko
        except ImportError as exc:
            raise ExternalServiceError("paramiko is required for the Huawei firewall provider") from exc
        client = paramiko.SSHClient()
        known_hosts = self.config.get("known_hosts")
        if known_hosts:
            client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(self.config["host"], port=int(self.config.get("port", 22)),
                           username=self.config["username"], password=self.password,
                           timeout=10, allow_agent=False, look_for_keys=False)
            channel = client.invoke_shell()
            command_timeout = max(1.0, min(float(self.config.get("command_timeout_seconds", 10)), 60.0))
            time.sleep(0.2)
            while channel.recv_ready():
                channel.recv(8192)
            outputs = []
            for command in commands:
                channel.send(command + "\n")
                output = ""
                deadline = time.monotonic() + command_timeout
                last_data = time.monotonic()
                while time.monotonic() < deadline:
                    if channel.recv_ready():
                        chunk = channel.recv(8192).decode("utf-8", errors="replace")
                        output += chunk
                        if "More" in chunk:
                            channel.send(" ")
                        last_data = time.monotonic()
                        continue
                    if output and time.monotonic() - last_data >= 0.25:
                        break
                    time.sleep(0.05)
                if not output:
                    raise ExternalServiceError("firewall command timed out without response")
                if self._failed(output):
                    raise ExternalServiceError("firewall command failed")
                outputs.append(output)
            return outputs
        finally:
            client.close()
