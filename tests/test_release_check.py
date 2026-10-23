from pathlib import Path

from monitor.domain.models import utc_now
from monitor.infrastructure.backups import create_backup
from monitor.infrastructure.database import Database
from monitor.release_check import run_release_checks


class Settings:
    config_path = Path(__file__).parents[1] / "config/base.yaml"
    def section(self, name):
        values = {
            "policy": {"rules_file": "./config/rules.yaml"},
            "operations": {"min_free_disk_mb": 1},
            "backup": {"max_age_hours": 30},
            "health": {"required_services": []},
        }
        return values.get(name, {})


def test_release_check_passes_core_checks_without_required_backup(tmp_path):
    db = Database(tmp_path / "release.db"); db.initialize()
    checks = run_release_checks(Settings(), db, [], require_backup=False)
    results = {check["name"]: check for check in checks}
    assert all(check["ok"] for check in checks)
    assert results["database-integrity"]["journal_mode"] == "wal"
    assert results["recent-backup"]["required"] is False


def test_release_check_requires_fresh_backup_and_worker(tmp_path):
    class ProductionSettings(Settings):
        def section(self, name):
            if name == "health":
                return {"required_services": ["action-worker"], "heartbeat_max_age_seconds": 180}
            return super().section(name)

    db = Database(tmp_path / "release.db"); db.initialize()
    failed = {check["name"]: check for check in
              run_release_checks(ProductionSettings(), db, [], require_backup=True)}
    assert failed["recent-backup"]["ok"] is False
    assert failed["required-workers"]["ok"] is False

    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO service_heartbeats(service,instance_id,status,updated_at) VALUES(?,?,?,?)",
            ("action-worker", "test", "ok", utc_now().isoformat()),
        )
    create_backup(db)
    passed = run_release_checks(ProductionSettings(), db, [], require_backup=True)
    assert all(check["ok"] for check in passed)


def test_release_integrity_check_is_bounded_and_timeout_is_not_success(tmp_path,monkeypatch):
    import monitor.release_check as module
    db=Database(tmp_path/'release.db');db.initialize()
    def timeout(path,full,timeout_seconds):
        assert path==db.path and full is True and timeout_seconds==60
        raise TimeoutError('validation deadline reached')
    monkeypatch.setattr(module,'_check_database',timeout)
    results={check['name']:check for check in run_release_checks(Settings(),db,[])}
    assert results['database-integrity']['ok'] is False
    assert 'deadline' in results['database-integrity']['error']
    assert results['disk-space']['ok'] is True
