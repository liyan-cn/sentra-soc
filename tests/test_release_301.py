import pytest
from monitor.services.asset_discovery_jobs import DiscoveryJobs
from monitor.workers.maintenance_worker import _delete_batch


def test_discovery_update_rejects_untrusted_column_before_database_access():
    job=DiscoveryJobs(None,None,None)
    try:
        with pytest.raises(ValueError,match='unsupported discovery job field'):
            job.update('test',**{'status = NULL; DROP TABLE hosts; --':'bad'})
    finally:job.executor.shutdown()


@pytest.mark.parametrize('table,column',[('hosts','created_at'),('audit_logs','created_at; DROP TABLE hosts')])
def test_retention_rejects_unknown_identifiers_before_database_access(table,column):
    with pytest.raises(ValueError,match='unsupported retention target'):
        _delete_batch(None,table,column,'2026-01-01',10)
