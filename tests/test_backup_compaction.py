import os
import sqlite3
import subprocess
import pytest
from monitor.infrastructure.database import Database
from monitor.infrastructure import backups


def make_db(tmp_path):
    db=Database(tmp_path/'live.db')
    db.initialize()
    with db.transaction() as c:
        c.execute('CREATE TABLE compact_fixture(id INTEGER PRIMARY KEY, content BLOB)')
        c.executemany('INSERT INTO compact_fixture VALUES(?,?)',[(i,bytes(8192)) for i in range(100)])
        c.execute('DELETE FROM compact_fixture WHERE id<80')
    return db


def test_opt_in_compaction_preserves_live_rows_and_checks_output(tmp_path,monkeypatch):
    db=make_db(tmp_path)
    with db.connect() as c:
        before=list(c.execute('SELECT id,length(content) FROM compact_fixture'))
        live_size=c.execute('PRAGMA page_count').fetchone()[0]*4096
    phases=[]
    monkeypatch.setenv('MONITOR_BACKUP_COMPACT_SNAPSHOT','1')
    result=backups.create_backup(db,progress=lambda phase,*args:phases.append(phase))
    assert phases.index('compact_snapshot')<phases.index('database_check')
    assert result['size']<live_size and result['integrity']=='ok'
    with db.connect() as c:assert [tuple(r) for r in c.execute('SELECT id,length(content) FROM compact_fixture')]==[tuple(r) for r in before]
    with sqlite3.connect(result['path']) as c:
        assert c.execute('PRAGMA freelist_count').fetchone()[0]==0
        assert c.execute('SELECT count(*) FROM compact_fixture').fetchone()[0]==20


def test_compaction_rejects_live_and_hardlink(tmp_path):
    db=make_db(tmp_path)
    with pytest.raises(ValueError,match='live database'):backups._compact_snapshot(db.path,db.path)
    alias=tmp_path/'alias.db.tmp-1'
    os.link(db.path,alias)
    with pytest.raises(ValueError,match='live database'):backups._compact_snapshot(alias,db.path)


def test_compaction_timeout_never_publishes_success(tmp_path,monkeypatch):
    db=make_db(tmp_path)
    monkeypatch.setenv('MONITOR_BACKUP_COMPACT_SNAPSHOT','1')
    def fail(*args,**kwargs):raise subprocess.TimeoutExpired(args[0],7200)
    monkeypatch.setattr(subprocess,'run',fail)
    with pytest.raises(TimeoutError,match='not verified'):backups.create_backup(db)
    assert not list((tmp_path/'backups').glob('*.db.json'))
    assert not list((tmp_path/'backups').glob('*.db'))


def test_compaction_disabled_by_default(tmp_path,monkeypatch):
    db=make_db(tmp_path)
    monkeypatch.delenv('MONITOR_BACKUP_COMPACT_SNAPSHOT',raising=False)
    monkeypatch.setattr(backups,'_compact_snapshot',lambda *a:pytest.fail('must remain opt-in'))
    assert backups.create_backup(db)['integrity']=='ok'
