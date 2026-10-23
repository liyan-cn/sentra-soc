"""Scheduled verified backup and isolated restore drill; never restores live DB."""
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime,timezone
from monitor.common.config import load_settings
from monitor.infrastructure.storage_factory import create_storage
from monitor.infrastructure.backups import create_backup,prune_backups,rehearse_restore,_backup_lock
from monitor.domain.models import utc_now

PHASES = {'starting':'准备备份', 'snapshot':'复制数据库快照', 'database_check':'校验备份数据库',
          'compact_snapshot':'整理隔离备份副本（不修改生产库）',
          'checksum':'计算备份摘要', 'publish':'生成备份清单',
          'rehearsal_database_check':'演练前校验备份', 'rehearsal_checksum':'演练前核对摘要',
          'rehearsal_copy':'复制隔离演练数据库', 'rehearsal_migrations':'验证隔离库升级',
          'rehearsal_validation':'校验隔离恢复数据库', 'prune':'按保留策略清理旧备份', 'complete':'备份流程完成'}


def save_run(db, state):
    now=utc_now().isoformat()
    with db.transaction(immediate=True) as conn:
        conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_run',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps({**state,'checked_at':now}),now))


@contextmanager
def run_heartbeat(db, state, guard):
    stop=threading.Event()
    def beat():
        while not stop.wait(30):
            with guard: snapshot=dict(state)
            try: save_run(db,snapshot)
            except Exception as exc: print('backup heartbeat write failed: '+str(exc)[:160],flush=True)
    save_run(db,state)
    thread=threading.Thread(target=beat,daemon=True)
    thread.start()
    try: yield
    finally:
        stop.set()
        thread.join()


def run(db):
    state={'status':'running','phase':'starting','phase_label':PHASES['starting'],
           'started_at':utc_now().isoformat()}
    guard=threading.Lock()
    def progress(phase,percent=None):
        with guard:
            changed=state['phase']!=phase
            state.update(phase=phase,phase_label=PHASES.get(phase,phase),progress_percent=percent)
        if changed: print(json.dumps({'phase':phase,'label':PHASES.get(phase,phase)},ensure_ascii=False),flush=True)
    try:
        with run_heartbeat(db,state,guard):
            report=create_backup(db,progress=progress)
            print(json.dumps(report),flush=True)
            with guard: state['backup_verified']=True
            with db.connect() as conn:
                previous=conn.execute("SELECT value_json FROM runtime_settings WHERE name='backup_last_rehearsal'").fetchone()
            due=True
            if previous:
                try:
                    last=json.loads(previous[0])
                    age=(utc_now()-datetime.fromisoformat(last['checked_at'])).total_seconds()
                    due=last.get('integrity')!='ok' or last.get('live_database_modified') is not False or not 0<=age<7*86400
                except (ValueError,TypeError,KeyError,AttributeError): pass
            if due:
                rehearsal=rehearse_restore(report['path'],progress=progress,verified_report=report)
                rehearsal['checked_at']=utc_now().isoformat()
                with db.transaction(immediate=True) as conn:
                    conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_last_rehearsal',?,?) ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",(json.dumps(rehearsal),utc_now().isoformat()))
                print(json.dumps(rehearsal),flush=True)
            progress('prune')
            print(json.dumps(prune_backups(db.path.parent/'backups',keep_last=2)),flush=True)
        progress('complete')
        save_run(db,{**state,'status':'ok'})
    except Exception as exc:
        from monitor.services.event_service import EventService
        save_run(db,{**state,'status':'failed','error':str(exc)[:300]})
        if os.environ.get('MONITOR_BACKUP_FAILURE_NOTIFY', '1') != '0':
            with db.transaction(immediate=True) as conn:
                EventService._enqueue(conn,'NOTIFY','backup','daily',{'content':f"Monitor3备份流程失败：{state['phase_label']}；{str(exc)[:160]}。请检查安全数据页面。"},'backup-failed:'+utc_now().date().isoformat(),90)
        else:
            print('Backup failure notification muted; failure remains recorded in backup_run.',flush=True)
        raise


def main():
    settings=load_settings();db=create_storage(settings)
    lock_dir=db.path.parent/'backup-worker'
    lock_dir.mkdir(parents=True,exist_ok=True)
    # Include rehearsal and status updates in the scheduled worker's lock scope.
    with _backup_lock(lock_dir): run(db)

if __name__=='__main__':main()
