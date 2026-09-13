import importlib.util
from pathlib import Path
from datetime import datetime, timezone
import os

spec=importlib.util.spec_from_file_location('syslog_retention',Path(__file__).parents[1]/'deploy/syslog_retention.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def test_retention_is_bounded_and_protects_active_files(tmp_path):
    cutoff=datetime(2026,9,5,5,tzinfo=timezone.utc).timestamp()
    def add(name):
        p=tmp_path/name
        p.write_text('test')
        os.utime(p,(cutoff-86400,cutoff-86400))
        return p
    old=add('2026-09-04-12.log')
    recent=add('2026-09-05-13.log')
    protected=add('2026-09-03-12.log')
    opened=add('2026-09-02-12.log')
    unknown=add('monitor.db')
    touched=add('2026-09-01-12.log')
    os.utime(touched,(cutoff+1,cutoff+1))
    invalid=add('2026-09-01-99.log')
    identity={(opened.stat().st_dev,opened.stat().st_ino)}
    result=module.clean(tmp_path,{protected},identity,cutoff)
    assert result['files']==1 and old.exists()
    result=module.clean(tmp_path,{protected},identity,cutoff,True)
    assert result['files']==1 and not old.exists()
    assert all(p.exists() for p in (recent,protected,opened,unknown,touched,invalid))
