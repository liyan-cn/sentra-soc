from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken

from monitor.common.errors import ExternalServiceError
from monitor.infrastructure.generic_notifiers import FanoutNotifier


class DisabledNotifier:
    def send(self, content: str) -> None:
        return None


def _cipher(settings) -> Fernet:
    material = os.getenv("MONITOR_CONFIG_ENCRYPTION_KEY") or settings.admin_token
    if not material:
        raise ExternalServiceError("notification encryption key is not configured")
    key = base64.urlsafe_b64encode(hashlib.sha256(material.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(settings, secret: dict) -> str:
    if not secret:
        return ""
    return _cipher(settings).encrypt(json.dumps(secret, ensure_ascii=False).encode("utf-8")).decode("ascii")


def decrypt_secret(settings, ciphertext: str) -> dict:
    if not ciphertext:
        return {}
    try:
        return json.loads(_cipher(settings).decrypt(ciphertext.encode("ascii")).decode("utf-8"))
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise ExternalServiceError("stored notification secret cannot be decrypted") from exc


def database_notifier(db, settings, registry):
    """Build enabled Web-managed channels, or fall back to file/env config.

    The database contains only encrypted channel secrets.  Once any Web channel
    exists, its enabled flags become authoritative so an operator can disable
    all destinations without editing files.
    """
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM notification_channels ORDER BY provider").fetchall()
    if not rows:
        config = settings.section("notification")
        factory = registry.load("notifiers", str(config.get("provider", "wechat")))
        return factory({**config, "webhook": settings.webhook, "url": settings.generic_webhook_url},
                       password=settings.smtp_password, secret=settings.webhook_secret,
                       registry=registry)
    notifiers = []
    for row in rows:
        if not row["enabled"]:
            continue
        config = json.loads(row["config_json"] or "{}")
        secret = decrypt_secret(settings, row["secret_encrypted"])
        provider = row["provider"]
        factory = registry.load("notifiers", provider)
        if provider == "wechat":
            config.update({"enabled": True, "webhook": secret.get("webhook", "")})
        elif provider == "smtp":
            config["enabled"] = True
        elif provider == "sms_webhook":
            config.update({"enabled": True, "url": secret.get("url", "")})
        notifiers.append(factory(config, password=secret.get("password", ""),
                                 token=secret.get("token", ""), registry=registry))
    if not notifiers:
        return DisabledNotifier()
    return notifiers[0] if len(notifiers) == 1 else FanoutNotifier(notifiers, require_all=False)
