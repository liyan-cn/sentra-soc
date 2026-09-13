"""Seven-day rolling raw-log retention; dry-run unless --apply is supplied."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

NAME = re.compile(r'^(\d{4}-\d{2}-\d{2})(?:-(\d{2}))?(?:-[^/]+)?\.log(?:\.gz)?$')
LOCAL = timezone(timedelta(hours=8))

def expired(path, st, cutoff):
    match = NAME.fullmatch(path.name)
    if not match or not stat.S_ISREG(st.st_mode) or st.st_mtime >= cutoff:
        return False
    try:
        start = datetime.strptime(match[1], '%Y-%m-%d').replace(tzinfo=LOCAL)
        if match[2] is not None:
            start = start.replace(hour=int(match[2]))
        end = start + (timedelta(hours=1) if match[2] is not None else timedelta(days=1))
        return end.timestamp() <= cutoff
    except ValueError:
        return False

def clean(root, protected, opened, cutoff, apply=False):
    root = root.resolve(strict=True)
    count = size = skipped = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(directory)/name).is_symlink()]
        for name in names:
            p = Path(directory)/name
            st = p.lstat()
            if not expired(p, st, cutoff): continue
            if p in protected or (st.st_dev, st.st_ino) in opened:
                skipped += 1
                continue
            assert p.resolve().is_relative_to(root) and not p.is_symlink()
            if apply:
                current = p.lstat()
                if (st.st_ino,st.st_mtime_ns,st.st_size)!=(current.st_ino,current.st_mtime_ns,current.st_size):
                    skipped += 1
                    continue
                p.unlink()
            count += 1
            size += st.st_size
    return {'mode':'apply' if apply else 'dry-run','files':count,'bytes':size,'protected_files':skipped}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    root = Path('/home/syslog')
    assert not root.is_symlink() and root.resolve(strict=True)==root
    with sqlite3.connect('file:/home/monitor3.0/data/monitor.db?mode=ro',uri=True,timeout=10) as conn:
        protected = {Path(row[0]).resolve() for row in conn.execute('SELECT file_path FROM collector_checkpoints') if row[0]}
    opened = set()
    for process in Path('/proc').iterdir():
        if not process.name.isdigit(): continue
        try:
            for fd in (process/'fd').iterdir():
                try:
                    st=fd.stat(); opened.add((st.st_dev,st.st_ino))
                except FileNotFoundError: pass
        except FileNotFoundError: pass
    result=clean(root,protected,opened,time.time()-7*86400,args.apply)
    print(json.dumps(result),flush=True)

if __name__=='__main__': main()
