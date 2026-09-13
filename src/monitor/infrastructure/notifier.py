from __future__ import annotations

from monitor.common.errors import ExternalServiceError


class WeChatNotifier:
    def __init__(self, webhook: str, enabled: bool = False):
        self.webhook = webhook
        self.enabled = enabled

    def send(self, content: str) -> None:
        if not self.enabled:
            return
        if not self.webhook:
            raise ExternalServiceError("notification enabled but webhook is empty")
        try:
            import requests
        except ImportError as exc:
            raise ExternalServiceError("requests is required for the WeChat notifier") from exc
        response = requests.post(self.webhook, json={"msgtype": "text", "text": {"content": content[:4000]}}, timeout=5)
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200 or body.get("errcode") != 0:
            raise ExternalServiceError(f"WeChat request failed: HTTP {response.status_code}")
