import json
import pytest
from monitor.infrastructure.database import Database
from monitor.workers import backup_worker


@pytest.mark.parametrize('muted',[False,True])
def test_backup_mute_preserves_failure_and_other_notifications(tmp_path,monkeypatch,muted):
    from monitor.services.event_service import EventService
    db=Database(tmp_path/'test.db');db.initialize()
    with db.transaction() as c:
        EventService._enqueue(c,'NOTIFY','security','test',{'content':'security alert'},'test-security',90)
    if muted:monkeypatch.setenv('MONITOR_BACKUP_FAILURE_NOTIFY','0')
    else:monkeypatch.delenv('MONITOR_BACKUP_FAILURE_NOTIFY',raising=False)
    def fail(*args,**kwargs):raise TimeoutError('validation exceeded 7200 seconds')
    monkeypatch.setattr(backup_worker,'create_backup',fail)
    with pytest.raises(TimeoutError):backup_worker.run(db)
    with db.connect() as c:
        state=json.loads(c.execute("SELECT value_json FROM runtime_settings WHERE name='backup_run'").fetchone()[0])
        assert state['status']=='failed' and '7200' in state['error']
        assert c.execute("SELECT count(*) FROM action_outbox WHERE aggregate_type='backup'").fetchone()[0]==(0 if muted else 1)
        assert c.execute("SELECT status FROM action_outbox WHERE idempotency_key='test-security'").fetchone()[0]=='pending'
