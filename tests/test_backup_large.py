import json
import subprocess
import pytest
from monitor.infrastructure import backups
from monitor.infrastructure.database import Database
from monitor.workers import backup_worker


def test_configured_validation_timeout_and_cache(tmp_path, monkeypatch):
    monkeypatch.setenv('MONITOR_BACKUP_VERIFY_TIMEOUT_SECONDS','7200')
    monkeypatch.setenv('MONITOR_BACKUP_VERIFY_CACHE_MB','128')
    def timeout(args, **kwargs):
        assert kwargs['timeout']==7200
        assert args[-1]=='131072'
        raise subprocess.TimeoutExpired(args,7200)
    monkeypatch.setattr(subprocess,'run',timeout)
    with pytest.raises(TimeoutError,match='7200 seconds.*not verified'):
        backups._check_database(tmp_path/'snapshot.db')


@pytest.mark.parametrize('value',['0','-1','999999','bad'])
def test_invalid_validation_timeout_rejected(tmp_path,monkeypatch,value):
    monkeypatch.setenv('MONITOR_BACKUP_VERIFY_TIMEOUT_SECONDS',value)
    with pytest.raises(ValueError):backups._check_database(tmp_path/'snapshot.db')


def test_worker_full_small_backup_and_isolated_rehearsal(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize()
    backup_worker.run(db)
    with db.connect() as c:
        rows={r[0]:json.loads(r[1]) for r in c.execute("SELECT name,value_json FROM runtime_settings WHERE name LIKE 'backup_%'")}
    assert rows['backup_run']['status']=='ok'
    assert rows['backup_run']['phase']=='complete'
    assert rows['backup_run']['backup_verified'] is True
    assert rows['backup_last_rehearsal']['live_database_modified'] is False
    assert rows['backup_last_rehearsal']['integrity']=='ok'
    assert backups.backup_status(db)['status']=='ok'


def test_validation_failure_does_not_run_rehearsal_or_publish(tmp_path,monkeypatch):
    db=Database(tmp_path/'live.db');db.initialize()
    def fail(*args,**kwargs):raise TimeoutError('verifier stopped')
    monkeypatch.setattr(backups,'_check_database',fail)
    monkeypatch.setattr(backup_worker,'rehearse_restore',lambda *a,**kw:pytest.fail('must not rehearse'))
    with pytest.raises(TimeoutError):backup_worker.run(db)
    with db.connect() as c:
        run=json.loads(c.execute("SELECT value_json FROM runtime_settings WHERE name='backup_run'").fetchone()[0])
        message=json.loads(c.execute("SELECT payload_json FROM action_outbox WHERE action_type='NOTIFY'").fetchone()[0])
    assert run['status']=='failed' and run['phase']=='database_check'
    assert run['checked_at'] and '校验备份数据库' in message['content']
    assert not list((tmp_path/'backups').glob('*.db.json'))


def test_rehearsal_failure_keeps_verified_backup(tmp_path,monkeypatch):
    db=Database(tmp_path/'live.db');db.initialize()
    def fail(source,progress,**kwargs):
        progress('rehearsal_validation')
        raise TimeoutError('isolated validation timed out')
    monkeypatch.setattr(backup_worker,'rehearse_restore',fail)
    with pytest.raises(TimeoutError):backup_worker.run(db)
    with db.connect() as c:
        run=json.loads(c.execute("SELECT value_json FROM runtime_settings WHERE name='backup_run'").fetchone()[0])
        assert c.execute("SELECT 1 FROM runtime_settings WHERE name='backup_last_rehearsal'").fetchone() is None
    assert run['phase']=='rehearsal_validation' and run['backup_verified'] is True
    assert backups.backup_status(db)['status']=='ok'
