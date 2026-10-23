import json
import os
from datetime import timedelta
from pathlib import Path
import pytest
from monitor.domain.models import utc_now
from monitor.infrastructure.database import Database
from monitor.infrastructure import backups
from monitor.workers.action_worker import claim,finish


def test_newer_invalid_manifest_does_not_hide_last_good_backup(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize()
    good=backups.create_backup(db,tmp_path/'backups/monitor3-good.db')
    bad=tmp_path/'backups/monitor3-bad.db.json';bad.write_text('[]')
    os.utime(bad,(bad.stat().st_atime,bad.stat().st_mtime+10))
    status=backups.backup_status(db)
    assert status['status']=='ok' and status['created_at']==good['created_at']
    assert status['invalid_manifests']==1 and status['warning']


def test_unverified_backup_does_not_displace_good_backup_during_prune(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize()
    good=backups.create_backup(db,tmp_path/'backups/monitor3-good.db')
    unverified=tmp_path/'backups/monitor3-newer.db';unverified.write_bytes(b'unverified')
    unverified.with_suffix('.db.json').write_text('{}')
    result=backups.prune_backups(tmp_path/'backups',keep_last=1)
    assert Path(good['path']).exists() and unverified.exists()
    assert result['removed']==[] and result['skipped']==[unverified.name]


def test_manifest_without_digest_cannot_pass_explicit_verification(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize()
    report=backups.create_backup(db,tmp_path/'snapshot.db')
    Path(report['path']+'.json').write_text('{}')
    with pytest.raises(ValueError,match='checksum metadata'):backups.verify_backup(report['path'])


def test_restore_rejects_live_source_before_validation(tmp_path,monkeypatch):
    db=Database(tmp_path/'live.db');db.initialize()
    monkeypatch.setattr(backups,'verify_backup',lambda *a,**k:pytest.fail('must reject before verification'))
    with pytest.raises(ValueError,match='live database'):backups.restore_backup(db,db.path)


def add_notification(db,attempts=0):
    now=utc_now().isoformat()
    with db.transaction() as c:
        c.execute("""INSERT INTO action_outbox(id,action_type,aggregate_type,aggregate_id,payload_json,
            idempotency_key,status,available_at,created_at,updated_at,attempts,max_attempts)
            VALUES('n','NOTIFY','notification','test','{"content":"test"}','lease-test','pending',?,?,?,?,3)""",
            (now,now,now,attempts))


def expire(db):
    with db.transaction() as c:
        c.execute("UPDATE action_outbox SET locked_until=? WHERE id='n'",((utc_now()-timedelta(seconds=1)).isoformat(),))


def test_crashed_worker_notification_is_recovered_and_old_owner_cannot_finish(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize();add_notification(db)
    first=claim(db,'old-worker',60)
    assert claim(db,'other-worker',60) is None
    expire(db)
    second=claim(db,'new-worker',60)
    assert second['id']==first['id'] and second['attempts']==1
    assert finish(db,first,True) is False
    with db.connect() as c:assert c.execute('SELECT count(*) FROM notification_logs').fetchone()[0]==0
    assert finish(db,second,True) is True
    with db.connect() as c:
        assert c.execute("SELECT status FROM action_outbox WHERE id='n'").fetchone()[0]=='succeeded'
        assert c.execute('SELECT count(*) FROM notification_logs').fetchone()[0]==1


def test_expired_worker_at_attempt_limit_becomes_dead(tmp_path):
    db=Database(tmp_path/'live.db');db.initialize();add_notification(db,attempts=2)
    claim(db,'old',60);expire(db)
    assert claim(db,'new',60) is None
    with db.connect() as c:
        assert c.execute("SELECT status FROM action_outbox WHERE id='n'").fetchone()[0]=='dead'


def test_console_and_wall_share_exact_24_hour_boundary(tmp_path,monkeypatch):
    import importlib
    from datetime import datetime,timezone
    from monitor.api.app import create_app
    module=importlib.import_module('monitor.api.app')
    fixed=datetime(2026,10,22,10,30,tzinfo=timezone.utc)
    monkeypatch.setattr(module,'utc_now',lambda:fixed)
    class Settings:
        admin_token='test'
        config_path=Path(__file__).parents[1]/'config/base.yaml'
        def section(self,name):return {}
    db=Database(tmp_path/'window.db');db.initialize()
    with db.transaction() as c:
        for id,when,ip in [('old','2026-10-21T10:10:00+00:00','192.0.2.1'),
                           ('boundary','2026-10-21T10:30:00+00:00','192.0.2.2'),
                           ('new','2026-10-22T10:00:00+00:00','192.0.2.2'),
                           ('empty','2026-10-22T10:00:00+00:00','')]:
            c.execute("""INSERT INTO soc_alerts(id,workspace_id,title,source,severity,occurred_at,updated_at,src_ip)
                VALUES(?,'default','test','TEST','low',?,?,?)""",(id,when,when,ip))
        # Hourly rollups cannot decide a partial-hour boundary, nor include alerts without event IDs.
        c.execute("INSERT INTO source_alert_hourly_stats VALUES('2026-10-21T10','d','TEST','192.0.2.1',99)")
    client=create_app(Settings(),db).test_client();headers={'Authorization':'Bearer test'}
    brain=client.get('/api/v1/soc/brain',headers=headers).json['data']
    wall=client.get('/api/v1/display/overview',headers=headers).json['data']
    assert brain['totals']['events_24h']==wall['totals']['events']==3
    assert brain['totals']['unique_sources_24h']==wall['totals']['sources']==1
    assert brain['hourly']==wall['hourly']
    assert sum(x['events'] for x in wall['hourly'])==3
