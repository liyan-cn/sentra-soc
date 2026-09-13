from monitor.infrastructure.backups import create_backup, prune_backups, rehearse_restore, restore_backup, verify_backup
from monitor.infrastructure.database import Database
import pytest
import subprocess
import sys
import json
from monitor.infrastructure.backups import _backup_lock, backup_status


def test_backup_lock_excludes_concurrent_and_recovers_after_crash(tmp_path):
    with _backup_lock(tmp_path):
        with pytest.raises(ValueError, match='already running'):
            with _backup_lock(tmp_path):
                pass
    code='from pathlib import Path; from monitor.infrastructure.backups import _backup_lock; import os,sys; lock=_backup_lock(Path(sys.argv[1])); lock.__enter__(); os._exit(0)'
    subprocess.run([sys.executable,'-c',code,str(tmp_path)],check=True,timeout=15)
    with _backup_lock(tmp_path):
        pass


def test_backup_status_rejects_truncated_snapshot(tmp_path):
    db = Database(tmp_path / 'live.db'); db.initialize()
    report = create_backup(db)
    assert backup_status(db)['status']=='ok'
    with open(report['path'],'r+b') as stream:stream.truncate(100)
    assert backup_status(db)['status']=='invalid'


def test_backup_status_rejects_bad_manifest_shape(tmp_path):
    db = Database(tmp_path / 'live.db'); db.initialize()
    report = create_backup(db)
    from pathlib import Path
    Path(report['path']+'.json').write_text('[]',encoding='utf8')
    assert backup_status(db)['status']=='invalid'


def test_verifier_has_hard_timeout(tmp_path, monkeypatch):
    from monitor.infrastructure.backups import _check_database
    def timeout(*args, **kwargs):
        assert kwargs['timeout'] == 600
        raise subprocess.TimeoutExpired(args[0], 600)
    monkeypatch.setattr(subprocess, 'run', timeout)
    with pytest.raises(TimeoutError, match='verifier stopped'):
        _check_database(tmp_path / 'snapshot.db')


def test_backup_verify_and_restore_with_safety_copy(tmp_path):
    db = Database(tmp_path / "live.db"); db.initialize()
    with db.transaction() as conn:
        conn.execute("INSERT INTO whitelist_entries(network,reason,created_at) VALUES('10.0.0.0/8','before','now')")
    result = create_backup(db, tmp_path / "snapshot.db")
    assert result["integrity"] == "ok"
    assert verify_backup(tmp_path / "snapshot.db")["sha256"] == result["sha256"]
    with db.transaction() as conn:
        conn.execute("DELETE FROM whitelist_entries")
    restored = restore_backup(db, tmp_path / "snapshot.db")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM whitelist_entries").fetchone()[0] == 1
    assert restored["safety_backup"]["integrity"] == "ok"


def test_backup_cannot_overwrite_live_database(tmp_path):
    db = Database(tmp_path / "live.db"); db.initialize()
    try:
        create_backup(db, db.path)
    except ValueError as exc:
        assert "live database" in str(exc)
    else:
        raise AssertionError("live database must not be used as backup destination")


def test_prune_removes_only_old_automatic_backups_and_manifests(tmp_path):
    for index in range(4):
        backup = tmp_path / f"monitor3-2026010{index}T000000Z.db"
        backup.write_bytes(str(index).encode())
        backup.with_suffix(".db.json").write_text("{}", encoding="utf-8")
    manual = tmp_path / "manual.db"
    safety = tmp_path / "pre-restore-20260101T000000Z.db"
    manual.write_bytes(b"manual")
    safety.write_bytes(b"safety")

    result = prune_backups(tmp_path, keep_last=2)

    assert len(result["removed"]) == 2
    assert len(list(tmp_path.glob("monitor3-*.db"))) == 2
    assert len(list(tmp_path.glob("monitor3-*.db.json"))) == 2
    assert manual.exists() and safety.exists()


def test_restore_rehearsal_never_modifies_live_database(tmp_path):
    live = Database(tmp_path / "live.db"); live.initialize()
    with live.transaction() as conn:
        conn.execute("INSERT INTO whitelist_entries(network,reason,created_at) VALUES('192.0.2.0/24','test','now')")
    backup = create_backup(live, tmp_path / "rehearsal-source.db")

    report = rehearse_restore(backup["path"])

    assert report["integrity"] == "ok"
    assert report["live_database_modified"] is False
    assert report["source_sha256"] == backup["sha256"]
    with live.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM whitelist_entries").fetchone()[0] == 1
