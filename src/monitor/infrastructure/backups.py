from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import shutil
import time
import subprocess
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


def _check_database(path: Path, full: bool = False) -> dict:
    # A SQLite VM progress callback cannot interrupt a long single VM operation.
    # A separate process provides a real wall-clock bound without touching live data.
    code = '''import sqlite3,sys,json
from pathlib import Path
with sqlite3.connect(Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True) as conn:
 conn.execute('PRAGMA cache_size=-32768')
 checks=[r[0] for r in conn.execute('PRAGMA '+sys.argv[2])]
 versions=[r[0] for r in conn.execute('SELECT version FROM schema_migrations ORDER BY version')]
 tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
 print(json.dumps(dict(checks=checks,versions=versions,tables=tables)))
'''
    check = 'integrity_check' if full else 'quick_check'
    try:
        result = subprocess.run([sys.executable, '-c', code, str(path.resolve()), check],
                                capture_output=True, text=True, timeout=600, check=True)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError('backup database validation exceeded 10 minutes; verifier stopped') from exc
    report = json.loads(result.stdout)
    if report['checks'] != ['ok']:
        raise ValueError('backup integrity check failed: ' + '; '.join(report['checks'][:5]))
    return report


def verify_backup(path: str | Path, full: bool = False) -> dict:
    backup = Path(path).expanduser().resolve()
    if not backup.is_file():
        raise FileNotFoundError(backup)
    report = _check_database(backup, full)
    checksum = sha256_file(backup)
    manifest_path = backup.with_suffix(backup.suffix + ".json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("sha256")
        if expected and expected != checksum:
            raise ValueError("backup checksum does not match manifest")
    return {"path": str(backup), "sha256": checksum, "size": backup.stat().st_size,
            "schema_versions": report['versions'], "integrity": 'ok',
            "check_type": 'integrity_check' if full else 'quick_check'}


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


def create_backup(database, output: str | Path | None = None) -> dict:
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
        return _create_backup_locked(database, destination)


def _create_backup_locked(database, destination: Path) -> dict:
    temporary = destination.with_suffix(destination.suffix + '.tmp-' + str(os.getpid()))
    deadline = time.monotonic() + 1800
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('backup exceeded 30 minute limit')
    try:
        with database.connect() as source, closing(sqlite3.connect(temporary)) as target:
            source.execute('BEGIN')
            source.execute('SELECT count(*) FROM schema_migrations').fetchone()
            source.backup(target, pages=256, progress=progress, sleep=.05)
            target.commit()
        result = verify_backup(temporary)
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


def backup_status(database):
    root=database.path.parent/'backups'
    candidates=sorted(root.glob('monitor3-*.db.json'),key=lambda p:p.stat().st_mtime,reverse=True) if root.exists() else []
    if not candidates:return {'status':'missing','message':'尚无已验证数据库备份'}
    try:
        info=json.loads(candidates[0].read_text(encoding='utf8'))
        created=datetime.fromisoformat(info['created_at'])
        age=(datetime.now(timezone.utc)-created).total_seconds()/3600
        db_file=candidates[0].with_suffix('')
        if not db_file.is_file():raise ValueError('backup file missing')
        if db_file.stat().st_size != info['size'] or info['integrity'] != 'ok':
            raise ValueError('backup file size or verification status changed')
        checksum=info.get('sha256','')
        if not isinstance(checksum,str) or len(checksum)!=64 or any(c not in '0123456789abcdef' for c in checksum):
            raise ValueError('invalid backup checksum metadata')
        if age < -5/60:raise ValueError('backup timestamp is in the future')
        return {'status':'ok' if age<=30 else 'stale','created_at':info['created_at'],
            'age_hours':round(age,2),'size':info['size'],'integrity':info['integrity'],
            'message':'备份已验证' if age<=30 else '备份超过30小时未更新'}
    except (ValueError,KeyError,OSError,TypeError):return {'status':'invalid','message':'备份清单或文件异常'}


def prune_backups(directory: str | Path, keep_last: int = 14) -> dict:
    """Remove only old automatic monitor3-*.db backups and their manifests."""
    root = Path(directory).expanduser().resolve()
    keep = max(1, int(keep_last))
    if not root.exists():
        return {"directory": str(root), "kept": 0, "removed": []}
    backups = sorted(
        (item for item in root.glob("monitor3-*.db") if item.is_file()),
        key=lambda item: (item.stat().st_mtime_ns, item.name), reverse=True,
    )
    removed = []
    for backup in backups[keep:]:
        manifest = backup.with_suffix(backup.suffix + ".json")
        backup.unlink()
        if manifest.is_file():
            manifest.unlink()
        removed.append(backup.name)
    return {"directory": str(root), "kept": min(len(backups), keep), "removed": removed}


def rehearse_restore(source: str | Path, work_directory: str | Path | None = None) -> dict:
    """Restore into an isolated temporary database and apply current migrations without touching live data."""
    verified = verify_backup(source)
    from monitor.infrastructure.database import Database
    work_root = Path(work_directory).resolve() if work_directory else Path(source).resolve().parent
    if shutil.disk_usage(work_root).free < Path(source).stat().st_size + 512*1024*1024:
        raise ValueError('insufficient space for isolated restore rehearsal')
    with tempfile.TemporaryDirectory(prefix="monitor3-restore-test-", dir=work_root) as directory:
        candidate = Path(directory) / "rehearsal.db"
        with closing(sqlite3.connect(Path(source).expanduser().resolve())) as backup_conn, \
                closing(sqlite3.connect(candidate)) as target:
            backup_conn.backup(target, pages=256)
        database = Database(candidate)
        database.initialize()
        report = _check_database(candidate)
        integrity, versions = 'ok', report['versions']
        required = {"security_events", "policy_decisions", "action_outbox", "audit_logs"}
        if not required <= set(report['tables']):
            raise ValueError("restore rehearsal failed application schema validation")
    return {"source": verified["path"], "source_sha256": verified["sha256"],
            "integrity": integrity,"check_type":"quick_check", "schema_versions": versions, "required_tables": sorted(required),
            "live_database_modified": False}


def restore_backup(database, source: str | Path) -> dict:
    if getattr(database, "dialect", "") != "sqlite":
        raise ValueError("this restore implementation supports SQLite only")
    verified = verify_backup(source)
    safety = create_backup(database, database.path.parent / "backups" /
                           f"pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db")
    with closing(sqlite3.connect(Path(source).expanduser().resolve())) as backup_conn, database.connect() as target:
        backup_conn.backup(target, pages=256)
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    database.initialize()
    return {"restored_from": verified, "safety_backup": safety, "restored_at": datetime.now(timezone.utc).isoformat()}
