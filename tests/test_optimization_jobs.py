import time
from unittest.mock import Mock
import pytest
from monitor.infrastructure.database import Database
from monitor.services.asset_discovery_jobs import validate_network,DiscoveryJobs

@pytest.mark.parametrize('value',['10.0.0.0/8','172.16.0.0/16','127.0.0.0/24','169.254.1.0/24','8.8.8.0/24','::1/128'])
def test_network_rejected_before_enumeration(value):
    with pytest.raises(ValueError):validate_network(value)

def wait_job(jobs,job):
    for _ in range(200):
        state=jobs.get(job['id'],'default')
        if state['status'] not in ('queued','running'):return state
        time.sleep(.01)
    raise AssertionError('job did not finish')

def test_job_persists_progress_and_retries_save_without_rescan(tmp_path):
    db=Database(tmp_path/'jobs.db');db.initialize()
    probe=Mock(return_value={'online':True,'tcp':{'22':True},'detail':'simulated'})
    save=Mock(side_effect=[RuntimeError('database busy'),{'created':2,'existing':0}])
    jobs=DiscoveryJobs(db,probe,save)
    job=jobs.submit({'network':'172.16.20.0/30'},'default','admin')
    result=wait_job(jobs,job)
    assert result['status']=='save_failed' and result['progress']==2
    assert jobs.get(job['id'],'another-workspace') is None
    result=wait_job(jobs,jobs.retry(job['id'],'default'))
    assert result['status']=='completed'
    assert probe.call_count==2
    assert save.call_count==2
    jobs.executor.shutdown(wait=True)

def test_retention_cursor_passes_nonexpired_rows(tmp_path):
    from monitor.workers.maintenance_worker import _delete_batch
    db=Database(tmp_path/'cursor.db');db.initialize()
    with db.transaction() as conn:
        conn.executemany("INSERT INTO parse_failures(device_id,raw_hash,sample,error,first_seen_at,last_seen_at) VALUES('d',?,'x','x','2000',?)",[(str(i),'2099' if i<500 else '2000') for i in range(501)])
    assert _delete_batch(db,'parse_failures','last_seen_at','2020',100,max_batches=1)==0
    assert _delete_batch(db,'parse_failures','last_seen_at','2020',100,max_batches=1)==1


def test_stale_job_is_visible_and_retry_does_not_rescan(tmp_path):
    import json
    db=Database(tmp_path/'stale.db');db.initialize()
    probe=Mock();save=Mock(return_value={'created':0,'existing':0})
    jobs=DiscoveryJobs(db,probe,save)
    with db.transaction() as conn:
        conn.execute("INSERT INTO asset_discovery_jobs(id,workspace_id,actor,status,request_json,result_json,created_at,updated_at) VALUES('stale','default','admin','running','{}',?,'2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00')",(json.dumps({'scan_complete':True,'assets':[]}),))
    assert jobs.get('stale','default')['status']=='interrupted'
    assert jobs.get('stale','other') is None
    completed=wait_job(jobs,jobs.retry('stale','default'))
    assert completed['status']=='completed'
    probe.assert_not_called()
    jobs.executor.shutdown(wait=True)
