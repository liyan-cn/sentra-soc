from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


ROLES = {"viewer": 10, "reviewer": 20, "operator": 30, "admin": 40}


@dataclass(frozen=True, slots=True)
class Identity:
    token_id: str
    name: str
    role: str

    def permits(self, required: str) -> bool:
        return ROLES.get(self.role, 0) >= ROLES.get(required, 999)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenAuthenticator:
    def __init__(self, database, bootstrap_admin_token: str = "", usage_update_seconds: int = 300):  # Empty means unconfigured; not a usable hard-coded credential.  # nosec B107
        self.db = database
        self.bootstrap_hash = token_hash(bootstrap_admin_token) if bootstrap_admin_token else ""
        self.usage_update_seconds = max(0, int(usage_update_seconds))

    def authenticate(self, token: str) -> Identity | None:
        if not token:
            return None
        digest = token_hash(token)
        if self.bootstrap_hash and hmac.compare_digest(self.bootstrap_hash, digest):
            return Identity("bootstrap", "bootstrap-admin", "admin")
        now = datetime.now(timezone.utc).isoformat()
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT id,name,role,token_hash,last_used_at FROM api_tokens
                WHERE token_hash=? AND enabled=1 AND (expires_at IS NULL OR expires_at>?)""",
                (digest, now),
            ).fetchone()
            if not row or not hmac.compare_digest(row["token_hash"], digest):
                return None
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=self.usage_update_seconds)).isoformat()
        if self.usage_update_seconds == 0 or not row["last_used_at"] or row["last_used_at"] < cutoff:
            with self.db.transaction() as conn:
                conn.execute(
                    """UPDATE api_tokens SET last_used_at=? WHERE id=?
                       AND (last_used_at IS NULL OR last_used_at<?)""", (now, row["id"], cutoff)
                )
        return Identity(row["id"], row["name"], row["role"])
