import uuid

from monitor.api.auth import TokenAuthenticator, token_hash
from monitor.domain.models import utc_now
from monitor.infrastructure.database import Database


def test_database_token_authentication_and_role(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    with db.transaction() as conn:
        conn.execute("INSERT INTO api_tokens(id,name,token_hash,role,created_at) VALUES(?,?,?,?,?)",
                     (str(uuid.uuid4()), "soc", token_hash("secret"), "operator", utc_now().isoformat()))
    identity = TokenAuthenticator(db).authenticate("secret")
    assert identity.name == "soc"
    assert identity.permits("reviewer")
    assert not identity.permits("admin")
    assert TokenAuthenticator(db).authenticate("wrong") is None


def test_bootstrap_token_is_admin(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    identity = TokenAuthenticator(db, "bootstrap").authenticate("bootstrap")
    assert identity.role == "admin"


def test_token_usage_write_is_throttled(tmp_path):
    db = Database(tmp_path / "usage.db"); db.initialize()
    token_id = str(uuid.uuid4())
    with db.transaction() as conn:
        conn.execute("INSERT INTO api_tokens(id,name,token_hash,role,created_at) VALUES(?,?,?,?,?)",
                     (token_id, "reader", token_hash("reader-secret"), "viewer", utc_now().isoformat()))
    authenticator = TokenAuthenticator(db, usage_update_seconds=300)
    assert authenticator.authenticate("reader-secret") is not None
    with db.connect() as conn:
        first = conn.execute("SELECT last_used_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()[0]
    assert authenticator.authenticate("reader-secret") is not None
    with db.connect() as conn:
        second = conn.execute("SELECT last_used_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()[0]
    assert first == second
