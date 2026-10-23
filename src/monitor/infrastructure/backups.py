from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import shutil
import time
import subprocess  # Used only with argument arrays and bounded execution; no shell.  # nosec B404
import sys
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _check_database(path: Path, full: bool = False, *, timeout_seconds: int | None = None) -> dict:
    # A SQLite VM progress callback cannot interrupt a long single VM operation.
    # A separate process provides a real wall-clock bound without touching live data.
    code = '''import sqlite3,sys,json
from pathlib import Path
with sqlite3.connect(Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True) as conn:
 conn.execute('PRAGMA cache_size=-'+sys.argv[3])
 checks=[r[0] for r in conn.execute('PRAGMA '+sys.argv[2])]
 versions=[r[0] for r in conn.execute('SELECT version FROM schema_migrations ORDER BY version')]
 tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
 foreign_key_errors=0
 if sys.argv[2]=='integrity_check':
  for row in conn.execute('PRAGMA foreign_key_check'):
   foreign_key_errors+=1
   if foreign_key_errors>=100:break
 journal_mode=conn.execute('PRAGMA journal_mode').fetchone()[0]
 print(json.dumps(dict(checks=checks,versions=versions,tables=tables,foreign_key_errors=foreign_key_errors,journal_mode=journal_mode)))
'''
    check = 'integrity_check' if full else 'quick_check'
    # Allow large snapshots to finish, while retaining a real, bounded timeout.
    size = path.stat().st_size if path.exists() else 0
    automatic = min(7200, max(600, int(size / (1024**3) * 120)))
    timeout = int(timeout_seconds if timeout_seconds is not None else os.environ.get('MONITOR_BACKUP_VERIFY_TIMEOUT_SECONDS', automatic))
    cache_mb = int(os.environ.get('MONITOR_BACKUP_VERIFY_CACHE_MB', '128'))
    if not 60 <= timeout <= 21600:
        raise ValueError('backup verification timeout must be between 60 and 21600 seconds')
    if not 16 <= cache_mb <= 512:
        raise ValueError('backup verification cache must be between 16 and 512 MiB')
    try:
        result = subprocess.run([sys.executable, '-c', code, str(path.resolve()), check, str(cache_mb*1024)],
                                capture_output=True, text=True, timeout=timeout, check=True)  # Fixed executable and argument array, no shell; execution is bounded.  # nosec B603
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f'backup database validation exceeded {timeout} seconds; verifier stopped; snapshot not verified') from exc
    report = json.loads(result.stdout)
    if report['checks'] != ['ok']:
        raise ValueError('backup integrity check failed: ' + '; '.join(report['checks'][:5]))
    if report.get('foreign_key_errors',0):raise ValueError('backup foreign key validation failed')
    return report


def verify_backup(path: str | Path, full: bool = False, *, progress=None) -> dict:
    backup = Path(path).expanduser().resolve()
    if not backup.is_file():
        raise FileNotFoundError(backup)
    if progress: progress('database_check')
    report = _check_snapshot(backup, full)
    if progress: progress('checksum')
    checksum = sha256_file(backup)
    if report.get('source_sha256') and report['source_sha256']!=checksum:
        raise ValueError('snapshot bytes changed after mirror verification')
    manifest_path = backup.with_suffix(backup.suffix + ".json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError('invalid backup manifest')
        expected = manifest.get("sha256")
        if not isinstance(expected,str) or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
            raise ValueError('invalid backup checksum metadata')
        if expected != checksum:
            raise ValueError("backup checksum does not match manifest")
    result={"path": str(backup), "sha256": checksum, "size": backup.stat().st_size,
            "schema_versions": report['versions'], "integrity": 'ok',
            "check_type": 'integrity_check' if full else 'quick_check'}
    for key in ('backend','sqlite_version','compressed_size','check_seconds'):
        if key in report:result[key]=report[key]
    return result


def _check_snapshot(path: Path, full: bool = False) -> dict:
    backend=os.environ.get('MONITOR_BACKUP_VERIFY_BACKEND','direct')
    if backend=='direct':return _check_database(path,full)
    if backend!='compressed':raise ValueError('unknown backup verification backend')
    size=path.stat().st_size
    timeout=int(os.environ.get('MONITOR_BACKUP_VERIFY_TIMEOUT_SECONDS',min(7200,max(600,int(size/1024**3*120)))))
    if not 60<=timeout<=21600:raise ValueError('invalid backup verification timeout')
    if shutil.disk_usage(path.parent).free<size+64*1024**2:
        raise ValueError('insufficient space for verification mirror')
    environment=dict(os.environ)
    dependency_path=environment.get('MONITOR_BACKUP_VERIFIER_DEPS','')
    if dependency_path:
        dependency_path=str(Path(dependency_path).resolve(strict=True))
        environment['PYTHONPATH']=dependency_path+(os.pathsep+environment['PYTHONPATH'] if environment.get('PYTHONPATH') else '')
    # The parent owns cleanup even if the verifier is killed by its hard timeout.
    with tempfile.TemporaryDirectory(prefix='monitor3-check-',dir=path.parent) as work:
        command=[sys.executable,'-m','monitor.infrastructure.snapshot_verify','--input',str(path.resolve()),'--work-root',work]
        if full:command.append('--full')
        try:
            result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=timeout,env=environment)  # Fixed executable and argument array, no shell; execution is bounded.  # nosec B603
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f'compressed snapshot validation exceeded {timeout} seconds; verifier stopped; snapshot not verified') from exc
        except subprocess.CalledProcessError as exc:
            raise ValueError('compressed snapshot validation failed: '+exc.stderr[-1200:]) from exc
        report=json.loads(result.stdout)
        if report.get('checks')!=['ok'] or report.get('foreign_key_errors',0):
            raise ValueError('snapshot validation did not return a passing result')
        digest=report.get('source_sha256','')
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('snapshot verifier omitted a valid source digest')
        return report


@contextmanager
def _backup_lock(directory: Path):
    """OS-owned lock releases after a crash; keep its inode to prevent lock races."""
    lock_path = directory / '.monitor3-backup.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    locked = False
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b'0')
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise ValueError('another backup is already running') from exc
        yield
    finally:
        if locked:
            if os.name == 'nt':
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def create_backup(database, output: str | Path | None = None, *, progress=None) -> dict:
    if getattr(database, "dialect", "") != "sqlite":
        raise ValueError("this backup implementation supports SQLite only")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = Path(output).expanduser().resolve() if output else (
        database.path.parent / "backups" / f"monitor3-{timestamp}.db")
    if destination == database.path.resolve():
        raise ValueError("backup destination cannot be the live database")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError('backup destination already exists; refusing overwrite')
    required = database.path.stat().st_size + 512*1024*1024
    if shutil.disk_usage(destination.parent).free < required:
        raise ValueError('insufficient free space for a safe backup')
    with _backup_lock(destination.parent):
        if destination.exists():
            raise ValueError('backup destination already exists; refusing overwrite')
        return _create_backup_locked(database, destination, progress)


def _create_backup_locked(database, destination: Path, report_progress=None) -> dict:
    temporary = destination.with_suffix(destination.suffix + '.tmp-' + str(os.getpid()))
    deadline = time.monotonic() + 1800
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('backup exceeded 30 minute limit')
        if report_progress: report_progress('snapshot', round(100*(total-remaining)/max(total,1),1))
    try:
        if report_progress: report_progress('snapshot', 0)
        with database.connect() as source, closing(sqlite3.connect(temporary)) as target:
            source.execute('BEGIN')
            source.execute('SELECT count(*) FROM schema_migrations').fetchone()
            source.backup(target, pages=256, progress=progress, sleep=.05)
            target.commit()
        # A published snapshot is a standalone file, not dependent on WAL sidecars.
        with closing(sqlite3.connect(temporary)) as target:
            target.execute('PRAGMA journal_mode=DELETE')
        # Opt-in only: compact the disposable copy, NEVER the production database.
        # Enable only after measuring this path on the deployment's isolated data.
        if os.environ.get('MONITOR_BACKUP_COMPACT_SNAPSHOT', '0') == '1':
            if report_progress: report_progress('compact_snapshot')
            _compact_snapshot(temporary, database.path)
        result = verify_backup(temporary, progress=report_progress)
        if report_progress: report_progress('publish')
        os.replace(temporary, destination)
        result.update({"path": str(destination),
                       "created_at": datetime.now(timezone.utc).isoformat()})
        manifest = destination.with_suffix(destination.suffix + ".json")
        manifest_tmp = manifest.with_suffix(manifest.suffix + ".tmp")
        manifest_tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(manifest_tmp, manifest)
        return result
    finally:
        if temporary.exists():
            temporary.unlink()


def _compact_snapshot(snapshot: Path, live_database: Path) -> dict:
    snapshot, live_database = Path(snapshot).resolve(), Path(live_database).resolve()
    if snapshot == live_database or os.path.samefile(snapshot, live_database):
        raise ValueError('refusing to compact the live database')
    if '.db.tmp-' not in snapshot.name:
        raise ValueError('compaction requires a disposable backup snapshot')
    size = snapshot.stat().st_size
    if shutil.disk_usage(snapshot.parent).free < 2*size + 512*1024**2:
        raise ValueError('insufficient free space for isolated snapshot compaction')
    timeout = int(os.environ.get('MONITOR_BACKUP_COMPACT_TIMEOUT_SECONDS','7200'))
    if not 60 <= timeout <= 21600:
        raise ValueError('snapshot compaction timeout must be between 60 and 21600 seconds')
    code = '''import sqlite3,sys,json
from pathlib import Path
p=Path(sys.argv[1])
with sqlite3.connect(p.as_uri()+'?mode=rw',uri=True) as conn:
 conn.execute('PRAGMA journal_mode=DELETE')
 conn.execute('PRAGMA cache_size=-131072')
 conn.execute('VACUUM')
 print(json.dumps({'size':p.stat().st_size,'free_pages':conn.execute('PRAGMA freelist_count').fetchone()[0]}))
'''
    try:
        result = subprocess.run([sys.executable,'-c',code,str(snapshot)],
                                capture_output=True,text=True,check=True,timeout=timeout,
                                env={**os.environ,'TMPDIR':str(snapshot.parent),'SQLITE_TMPDIR':str(snapshot.parent)})  # Fixed executable and argument array, no shell; execution is bounded.  # nosec B603
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError('isolated snapshot compaction timed out; backup not verified') from exc
    return json.loads(result.stdout)


def _manifest_info(manifest_path: Path) -> tuple[dict, float]:
    if manifest_path.is_symlink(): raise ValueError('backup manifest must not be a symlink')
    if manifest_path.stat().st_size > 65536: raise ValueError('backup manifest is too large')
    info=json.loads(manifest_path.read_text(encoding='utf8'))
    if not isinstance(info,dict): raise ValueError('invalid backup manifest')
    created=datetime.fromisoformat(info['created_at'])
    age=(datetime.now(timezone.utc)-created).total_seconds()/3600
    db_file=manifest_path.with_suffix('')
    if db_file.is_symlink() or not db_file.is_file():raise ValueError('backup file missing or symlink')
    if not isinstance(info['size'],int) or isinstance(info['size'],bool) or info['size']<=0:
        raise ValueError('invalid backup file size')
    if db_file.stat().st_size != info['size'] or info['integrity'] != 'ok':
        raise ValueError('backup file size or verification status changed')
    checksum=info.get('sha256','')
    if not isinstance(checksum,str) or len(checksum)!=64 or any(c not in '0123456789abcdef' for c in checksum):
        raise ValueError('invalid backup checksum metadata')
    if age < -5/60:raise ValueError('backup timestamp is in the future')
    return info,age


def backup_status(database):
    root=database.path.parent/'backups'
    candidates=sorted(root.glob('monitor3-*.db.json'),key=lambda p:p.stat().st_mtime,reverse=True) if root.exists() else []
    if not candidates:return {'status':'missing','message':'尚无已验证数据库备份'}
    invalid=0
    for candidate in candidates:
        try:
            info,age=_manifest_info(candidate)
        except (ValueError,KeyError,OSError,TypeError):
            invalid+=1
            continue
        result={'status':'ok' if age<=30 else 'stale','created_at':info['created_at'],
            'age_hours':round(age,2),'size':info['size'],'integrity':info['integrity'],
            'message':'备份已验证' if age<=30 else '备份超过30小时未更新'}
        if invalid:
            result.update(invalid_manifests=invalid,warning='发现更新的异常备份清单，当前显示最近有效备份')
        return result
    return {'status':'invalid','message':'备份清单或文件异常','invalid_manifests':invalid}


def prune_backups(directory: str | Path, keep_last: int = 14) -> dict:
    """Remove only old automatic monitor3-*.db backups and their manifests."""
    root = Path(directory).expanduser().resolve()
    keep = max(1, int(keep_last))
    if not root.exists():
        return {"directory": str(root), "kept": 0, "removed": []}
    # Incomplete/unverified files must never displace the last known good copies.
    with _backup_lock(root):
        verified=[];skipped=[]
        for item in root.glob('monitor3-*.db'):
            try:
                info,_=_manifest_info(item.with_suffix('.db.json'))
                verified.append((datetime.fromisoformat(info['created_at']),item))
            except (ValueError,KeyError,OSError,TypeError):skipped.append(item.name)
        verified.sort(key=lambda pair:(pair[0],pair[1].name),reverse=True)
        removed=[]
        for _,backup in verified[keep:]:
            backup.unlink()
            backup.with_suffix('.db.json').unlink()
            removed.append(backup.name)
        return {'directory':str(root),'kept':min(len(verified),keep),'removed':removed,'skipped':skipped}


def rehearse_restore(source: str | Path, work_directory: str | Path | None = None, *, progress=None, verified_report=None) -> dict:
    """Restore into an isolated temporary database and apply current migrations without touching live data."""
    def report(phase, percent=None):
        if progress: progress('rehearsal_'+phase, percent)
    if verified_report is None:
        verified=verify_backup(source,progress=report)
    else:
        # Only the caller that just created/verified this snapshot supplies this
        # report. The copy's byte digest below proves those exact bytes were used.
        verified=dict(verified_report)
        digest=verified.get('sha256','')
        if (Path(verified.get('path','')).resolve()!=Path(source).resolve()
                or verified.get('integrity')!='ok'
                or verified.get('check_type') not in ('quick_check','integrity_check')
                or verified.get('size')!=Path(source).stat().st_size
                or not isinstance(digest,str) or len(digest)!=64
                or any(c not in '0123456789abcdef' for c in digest)):
            raise ValueError('invalid verified snapshot report for rehearsal')
    from monitor.infrastructure.database import Database
    work_root = Path(work_directory).resolve() if work_directory else Path(source).resolve().parent
    if shutil.disk_usage(work_root).free < Path(source).stat().st_size + 512*1024*1024:
        raise ValueError('insufficient space for isolated restore rehearsal')
    with tempfile.TemporaryDirectory(prefix="monitor3-restore-test-", dir=work_root) as directory:
        candidate = Path(directory) / "rehearsal.db"
        report('copy', 0)
        deadline = time.monotonic() + 1800
        def copy_progress(status, remaining, total):
            if time.monotonic() > deadline:
                raise TimeoutError('isolated restore copy exceeded 30 minute limit')
            report('copy', round(100*(total-remaining)/max(total,1),1))
        snapshot=Path(source).expanduser().resolve()
        with snapshot.open('rb') as stream:header=stream.read(100)
        standalone=header[18:20]==b'\x01\x01' and not any(
            Path(str(snapshot)+suffix).exists() and Path(str(snapshot)+suffix).stat().st_size
            for suffix in ('-wal','-journal'))
        if verified_report is not None and not standalone:
            raise ValueError('verified report reuse requires a standalone snapshot')
        if standalone:
            # A verified standalone snapshot can be copied sequentially. Its digest
            # is checked while reading, avoiding slow page-by-page SQLite I/O.
            digest=hashlib.sha256();copied=0;total=snapshot.stat().st_size
            with snapshot.open('rb') as src,candidate.open('xb') as dst:
                while block:=src.read(4*1024**2):
                    dst.write(block);digest.update(block);copied+=len(block)
                    copy_progress(0,total-copied,total)
                dst.flush();os.fsync(dst.fileno())
            if digest.hexdigest()!=verified['sha256']:
                raise ValueError('restore rehearsal copy does not match verified snapshot')
        else:
            with closing(sqlite3.connect(snapshot.as_uri()+'?mode=ro',uri=True)) as backup_conn, \
                    closing(sqlite3.connect(candidate)) as target:
                backup_conn.backup(target, pages=256, progress=copy_progress)
        report('migrations')
        database = Database(candidate)
        database.initialize()
        report('validation')
        checked = _check_snapshot(candidate)
        integrity, versions = 'ok', checked['versions']
        required = {"security_events", "policy_decisions", "action_outbox", "audit_logs"}
        if not required <= set(checked['tables']):
            raise ValueError("restore rehearsal failed application schema validation")
    return {"source": verified["path"], "source_sha256": verified["sha256"],
            "integrity": integrity,"check_type":"quick_check", "schema_versions": versions, "required_tables": sorted(required),
            "live_database_modified": False}


def restore_backup(database, source: str | Path) -> dict:
    if getattr(database, "dialect", "") != "sqlite":
        raise ValueError("this restore implementation supports SQLite only")
    source=Path(source).expanduser().resolve()
    if source==database.path.resolve() or (source.exists() and os.path.samefile(source,database.path)):
        raise ValueError('restore source cannot be the live database or its alias')
    verified = verify_backup(source)
    safety = create_backup(database, database.path.parent / "backups" /
                           f"pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db")
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as backup_conn, database.connect() as target:
        backup_conn.backup(target, pages=256)
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    database.initialize()
    return {"restored_from": verified, "safety_backup": safety, "restored_at": datetime.now(timezone.utc).isoformat()}
