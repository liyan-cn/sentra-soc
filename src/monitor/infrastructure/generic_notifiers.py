from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
from email.message import EmailMessage

from monitor.common.errors import ExternalServiceError
from monitor.domain.models import utc_now


class FanoutNotifier:
    def __init__(self, notifiers: list, require_all: bool = True):
        self.notifiers = notifiers
        self.require_all = require_all

    def send(self, content: str) -> None:
        errors = []
        successes = 0
        for notifier in self.notifiers:
            try:
                notifier.send(content)
                successes += 1
            except Exception as exc:
                errors.append(str(exc))
        if errors and (self.require_all or successes == 0):
            raise ExternalServiceError("notification fanout failed: " + "; ".join(errors))


class WebhookNotifier:
    def __init__(self, config: dict, secret: str = ""):
        self.enabled = bool(config.get("enabled", False))
        self.url = str(config.get("url", ""))
        self.secret = secret
        self.timeout = float(config.get("timeout_seconds", 5))

    def send(self, content: str) -> None:
        if not self.enabled:
            return
        if not self.url:
            raise ExternalServiceError("webhook notifier URL is empty")
        try:
            import requests
        except ImportError as exc:
            raise ExternalServiceError("requests is required for webhook notifications") from exc
        payload = json.dumps({"type": "monitor3.notification", "timestamp": utc_now().isoformat(),
                              "content": content}, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-Monitor3-Signature"] = "sha256=" + hmac.new(
                self.secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        response = requests.post(self.url, data=payload, headers=headers, timeout=self.timeout)
        if not 200 <= response.status_code < 300:
            raise ExternalServiceError(f"webhook request failed: HTTP {response.status_code}")


class SMTPNotifier:
    def __init__(self, config: dict, password: str = ""):
        self.enabled = bool(config.get("enabled", False))
        self.config = config
        self.password = password

    def send(self, content: str) -> None:
        if not self.enabled:
            return
        required = ("host", "from", "to")
        missing = [field for field in required if not self.config.get(field)]
        if missing:
            raise ExternalServiceError(f"SMTP configuration missing: {', '.join(missing)}")
        message = EmailMessage()
        message["Subject"] = str(self.config.get("subject", "Monitor 3.0 notification"))
        message["From"] = self.config["from"]
        recipients = self.config["to"] if isinstance(self.config["to"], list) else [self.config["to"]]
        message["To"] = ", ".join(recipients)
        message.set_content(content)
        host, port = self.config["host"], int(self.config.get("port", 465))
        username = str(self.config.get("username", ""))
        if self.config.get("ssl", True):
            client = smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context())
        else:
            client = smtplib.SMTP(host, port, timeout=10)
            if self.config.get("starttls", True):
                client.starttls(context=ssl.create_default_context())
        try:
            if username:
                client.login(username, self.password)
            client.send_message(message, to_addrs=recipients)
        finally:
            client.quit()


class SMSWebhookNotifier:
    """Generic adapter for an organisation's SMS HTTP gateway.

    Different carriers expose different APIs, so Monitor sends a small neutral
    JSON envelope that can be accepted directly or translated by an internal
    webhook gateway.
    """
    def __init__(self, config: dict, token: str = ""):
        self.enabled = bool(config.get("enabled", False))
        self.url = str(config.get("url", ""))
        self.recipients = config.get("recipients", [])
        self.token = token
        self.timeout = float(config.get("timeout_seconds", 5))

    def send(self, content: str) -> None:
        if not self.enabled:
            return
        if not self.url or not self.recipients:
            raise ExternalServiceError("SMS webhook URL or recipients are empty")
        try:
            import requests
        except ImportError as exc:
            raise ExternalServiceError("requests is required for SMS webhook notifications") from exc
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = requests.post(self.url, json={"recipients": self.recipients,
                                 "content": content[:1000], "source": "monitor3"},
                                 headers=headers, timeout=self.timeout)
        if not 200 <= response.status_code < 300:
            raise ExternalServiceError(f"SMS webhook request failed: HTTP {response.status_code}")


def create_webhook_notifier(config: dict, **secrets):
    return WebhookNotifier(config, secrets.get("secret", ""))


def create_smtp_notifier(config: dict, **secrets):
    return SMTPNotifier(config, secrets.get("password", ""))


def create_sms_webhook_notifier(config: dict, **secrets):
    return SMSWebhookNotifier(config, secrets.get("token", ""))


def create_fanout_notifier(config: dict, **context):
    registry = context["registry"]
    notifiers = []
    for channel in config.get("channels", []):
        provider = str(channel.get("provider", ""))
        if not provider or provider == "fanout":
            raise ExternalServiceError("fanout channel must use a non-fanout provider")
        factory = registry.load("notifiers", provider)
        notifiers.append(factory(
            channel,
            password=context.get("password", ""),
            secret=context.get("secret", ""),
        ))
    if not notifiers:
        raise ExternalServiceError("fanout notifier has no channels")
    return FanoutNotifier(notifiers, bool(config.get("require_all", True)))
