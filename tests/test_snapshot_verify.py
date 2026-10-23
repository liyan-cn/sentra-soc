import hashlib
import importlib.util
import json
import random
import sqlite3
from pathlib import Path
import pytest
from monitor.infrastructure.snapshot_verify import CHUNK,MirrorReader,build_mirror,check_mirror,verify_snapshot


def test_mirror_reads_match_original_across_boundaries_and_eof(tmp_path):
    source=tmp_path/'snapshot.db'
    content=random.Random(42).randbytes(CHUNK*7+123)
    source.write_bytes(content);root=tmp_path/'mirror';root.mkdir()
    metadata=build_mirror(source,root)
    assert metadata['source_sha256']==hashlib.sha256(content).hexdigest()
    reader=MirrorReader(root,cache_bytes=CHUNK*2)
    try:
        cases=[(0,100),(CHUNK-1,8192),(len(content)-12,500),(len(content)+5,10)]
        cases.extend((random.Random(i).randrange(len(content)),i*97) for i in range(100))
        for offset,size in cases:assert reader.read(size,offset)==content[offset:offset+size]
    finally:reader.close()


@pytest.mark.parametrize('filename',['data','index'])
def test_mirror_corruption_cannot_pass_verification(tmp_path,filename):
    source=tmp_path/'snapshot.db';source.write_bytes(bytes(CHUNK*3))
    root=tmp_path/'mirror';root.mkdir();build_mirror(source,root)
    path=root/filename
    with path.open('r+b') as stream:
        value=stream.read(1);stream.seek(0);stream.write(bytes([value[0]^1]))
    with pytest.raises(ValueError,match='checksum mismatch'):MirrorReader(root)


def test_active_wal_is_rejected(tmp_path):
    source=tmp_path/'snapshot.db';source.write_bytes(bytes(4096))
    Path(str(source)+'-wal').write_bytes(b'pending transaction')
    with pytest.raises(ValueError,match='nonempty WAL'):build_mirror(source,tmp_path)


def make_database(path,orphan=False):
    connection=sqlite3.connect(path)
    connection.executescript('CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); INSERT INTO schema_migrations VALUES(1); CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,parent_id INTEGER REFERENCES parent(id),value BLOB);')
    connection.execute('INSERT INTO parent VALUES(1)')
    connection.executemany('INSERT INTO child VALUES(?,?,?)',[(i,2 if orphan else 1,b'test'*2000) for i in range(200)])
    connection.commit();connection.close()


requires_apsw=pytest.mark.skipif(any(importlib.util.find_spec(name) is None for name in ('apsw','zstandard')),
                              reason='optional isolated verifier dependencies not installed')


@requires_apsw
def test_sqlite_full_check_and_file_identity_are_preserved(tmp_path):
    source=tmp_path/'snapshot.db';make_database(source)
    before=hashlib.sha256(source.read_bytes()).hexdigest()
    report=verify_snapshot(source,full=True)
    assert report['checks']==['ok'] and report['foreign_key_errors']==0
    assert report['source_sha256']==before==hashlib.sha256(source.read_bytes()).hexdigest()
    assert report['versions']==[1] and report['backend']=='compressed-readonly'
    assert not list(tmp_path.glob('monitor3-verify-*'))


@requires_apsw
def test_sqlite_corruption_is_not_hidden_by_mirror(tmp_path):
    source=tmp_path/'snapshot.db';make_database(source)
    with source.open('r+b') as stream:stream.write(b'broken database!!')
    with pytest.raises(Exception):verify_snapshot(source)
    assert not list(tmp_path.glob('monitor3-verify-*'))


@requires_apsw
def test_full_verification_checks_foreign_keys(tmp_path):
    source=tmp_path/'snapshot.db';make_database(source,orphan=True)
    with pytest.raises(ValueError,match='foreign key'):verify_snapshot(source,full=True)


@requires_apsw
def test_backup_and_restore_use_isolated_compressed_verifier(tmp_path,monkeypatch):
    import os
    import apsw
    from monitor.infrastructure.database import Database
    from monitor.infrastructure.backups import create_backup,rehearse_restore
    monkeypatch.setenv('MONITOR_BACKUP_VERIFY_BACKEND','compressed')
    # The deployment's optional dependency lives outside the application's venv.
    monkeypatch.setenv('MONITOR_BACKUP_VERIFIER_DEPS',str(Path(apsw.__file__).parents[1]))
    db=Database(tmp_path/'live.db');db.initialize()
    report=create_backup(db)
    assert report['backend']=='compressed-readonly' and report['integrity']=='ok'
    assert rehearse_restore(report['path'])['live_database_modified'] is False
    assert not list((tmp_path/'backups').glob('monitor3-check-*'))


def test_mirror_timeout_cleans_parent_owned_workspace(tmp_path,monkeypatch):
    import subprocess
    from monitor.infrastructure.backups import _check_snapshot
    source=tmp_path/'snapshot.db';make_database(source)
    monkeypatch.setenv('MONITOR_BACKUP_VERIFY_BACKEND','compressed')
    def timeout(*args,**kwargs):
        assert kwargs['timeout']>=600
        raise subprocess.TimeoutExpired(args[0],kwargs['timeout'])
    monkeypatch.setattr(subprocess,'run',timeout)
    with pytest.raises(TimeoutError,match='not verified'):_check_snapshot(source)
    assert not list(tmp_path.glob('monitor3-check-*'))


def test_rehearsal_reuses_fresh_report_but_checks_exact_copy_digest(tmp_path,monkeypatch):
    from monitor.infrastructure.database import Database
    from monitor.infrastructure import backups
    db=Database(tmp_path/'live.db');db.initialize()
    report=backups.create_backup(db)
    monkeypatch.setattr(backups,'verify_backup',lambda *a,**k:pytest.fail('fresh report should avoid a redundant source scan'))
    assert backups.rehearse_restore(report['path'],verified_report=report)['live_database_modified'] is False


def test_rehearsal_rejects_changed_source_with_old_report(tmp_path):
    from monitor.infrastructure.database import Database
    from monitor.infrastructure import backups
    db=Database(tmp_path/'live.db');db.initialize()
    report=backups.create_backup(db)
    with open(report['path'],'r+b') as stream:
        stream.seek(512);value=stream.read(1);stream.seek(512);stream.write(bytes([value[0]^1]))
    with pytest.raises(ValueError,match='does not match'):
        backups.rehearse_restore(report['path'],verified_report=report)
    assert not list((tmp_path/'backups').glob('monitor3-restore-test-*'))
