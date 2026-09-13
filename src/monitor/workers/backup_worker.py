"""Scheduled verified backup and isolated restore drill; never restores live DB."""
import json
from datetime import datetime,timezone
from monitor.common.config import load_settings
from monitor.infrastructure.storage_factory import create_storage
from monitor.infrastructure.backups import create_backup,prune_backups,rehearse_restore
from monitor.domain.models import utc_now

def main():
    settings=load_settings();db=create_storage(settings)
    try:
        with db.transaction(immediate=True) as conn:
            conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_run',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps({'status':'running','checked_at':utc_now().isoformat()}),utc_now().isoformat()))
        report=create_backup(db)
        print(json.dumps(report),flush=True)
        with db.connect() as conn:
            previous=conn.execute("SELECT value_json FROM runtime_settings WHERE name='backup_last_rehearsal'").fetchone()
        due=not previous
        if previous:
            last=json.loads(previous[0])
            due=(utc_now()-datetime.fromisoformat(last['checked_at'])).total_seconds()>7*86400
        if due:
            rehearsal=rehearse_restore(report['path'])
            rehearsal['checked_at']=utc_now().isoformat()
            with db.transaction(immediate=True) as conn:
                conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_last_rehearsal',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps(rehearsal),utc_now().isoformat()))
            print(json.dumps(rehearsal),flush=True)
        print(json.dumps(prune_backups(db.path.parent/'backups',keep_last=2)),flush=True)
        with db.transaction(immediate=True) as conn:
            conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_run',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps({'status':'ok','checked_at':utc_now().isoformat()}),utc_now().isoformat()))
    except Exception as exc:
        from monitor.services.event_service import EventService
        with db.transaction(immediate=True) as conn:
            conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_run',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps({'status':'failed','error':str(exc)[:300]}),utc_now().isoformat()))
            EventService._enqueue(conn,'NOTIFY','backup','daily',{'content':'Monitor3数据库备份/恢复演练失败，请检查安全数据页面。'},'backup-failed:'+utc_now().date().isoformat(),90)
        raise

if __name__=='__main__':main()
