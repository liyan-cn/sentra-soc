from datetime import timedelta
from pathlib import Path
import uuid
import pytest

from monitor.api.app import create_app
from monitor.api.auth import token_hash
from monitor.infrastructure.database import Database
from monitor.common.retention import effective_retention
from monitor.sources import FileTailSource
from monitor.domain.models import utc_now


class Settings:
    admin_token = 'test-admin'
    config_path = Path(__file__).parents[1] / 'config/base.yaml'
    raw = {'devices': [{'id': 'h3c', 'source': 'H3C_SECURITY', 'parser': 'h3c_security'}]}
    def section(self, name):
        return {'policy': {'rules_file': './config/rules.yaml'},
                'retention': {'security_events_days': 180}}.get(name, {})


@pytest.mark.parametrize('value,expected', [
    ('{"status":"running","checked_at":"2000-01-01T00:00:00+00:00"}','interrupted'),
    ('[]','invalid'), ('broken','invalid'),
])
def test_backup_status_handles_interrupted_or_invalid_run(context, value, expected):
    db,client=context
    with db.transaction() as conn:
        conn.execute("INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('backup_run',?,'now')",(value,))
    response=client.get('/api/v1/data/backup-status',headers={'Authorization':'Bearer test-admin'})
    assert response.status_code==200
    assert response.json['data']['backup_run']['status']==expected


@pytest.fixture
def context(tmp_path):
    db = Database(tmp_path / 'test.db'); db.initialize()
    return db, create_app(Settings(), db).test_client()


def test_retention_admin_validation_confirmation_persistence_and_audit(context):
    db, client = context
    url = '/api/v1/data/retention'
    headers = {'Authorization': 'Bearer test-admin'}
    body = {'retention': {'security_events_days': 7}, 'reason': 'reduce database retention'}
    assert client.put(url, json=body).status_code == 401
    assert client.put(url, json=body, headers=headers).status_code == 409
    body['confirm_shortening'] = True
    assert client.put(url, json=body, headers=headers).status_code == 200
    restarted = create_app(Settings(), db).test_client()
    assert restarted.get(url, headers=headers).json['data']['security_events_days'] == 7
    with db.connect() as conn:
        assert effective_retention(Settings(), conn)['security_events_days'] == 7
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE target_type='retention'").fetchone()[0] == 1
        assert conn.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 0
    with db.transaction() as conn:
        conn.execute("INSERT INTO api_tokens(id,name,token_hash,role,created_at) VALUES(?,?,?,?,?)",
                     (str(uuid.uuid4()), 'viewer', token_hash('test-viewer'), 'viewer', utc_now().isoformat()))
    assert client.put(url, json=body, headers={'Authorization':'Bearer test-viewer'}).status_code == 403


@pytest.mark.parametrize('value', [0, -1, 3651, True, '7', 1.5])
def test_retention_rejects_invalid_days(context, value):
    _, client = context
    assert client.put('/api/v1/data/retention', headers={'Authorization':'Bearer test-admin'},
                      json={'retention': {'security_events_days': value}, 'reason':'test',
                            'confirm_shortening':True}).status_code == 400


def test_permit_logs_count_once_without_inventing_alerts(context, tmp_path):
    db, client = context
    log = tmp_path / 'h3c.log'
    log.write_text('ordinary permit\nordinary permit\n', encoding='utf-8')
    source = FileTailSource(db, 'h3c', str(log))
    checkpoint = source.poll(10)[-1].checkpoint
    source.commit(checkpoint); source.commit(checkpoint)
    for path in ('/api/v1/soc/brain', '/api/v1/display/overview'):
        result = client.get(path, headers={'Authorization':'Bearer test-admin'}).json['data']
        row = next(x for x in result['sources'] if x['device_id']=='h3c')
        assert row['processed_lines'] == 2
        assert row['events'] == 0
        assert row['last_ingested_at']


def test_same_length_truncated_file_is_counted_as_new(context, tmp_path):
    db, _ = context
    log = tmp_path / 'truncated.log'; log.write_bytes(b'one\nlonger\n')
    source = FileTailSource(db, 'h3c', str(log))
    source.commit(source.poll(10)[-1].checkpoint)
    log.write_bytes(b'two\n')
    rows = source.poll(10); source.commit(rows[-1].checkpoint)
    assert source.poll(10) == []
    with db.connect() as conn:
        assert conn.execute('SELECT SUM(line_count) FROM ingestion_hourly_stats').fetchone()[0] == 3


def test_retention_keeps_active_vpn_sessions(context):
    from monitor.workers.vpn_worker import process_line
    from monitor.workers.maintenance_worker import _delete_batch
    class Geo:
        def lookup(self, ip): return 'test'
    db, _ = context
    process_line(db, Geo(), 'vpn-test', 'Jan  1 00:00:00 FW USERLOGINSUCC User Name=alice, Virtual IP=172.16.90.8, Client IP=203.0.113.8')
    assert _delete_batch(db, 'vpn_sessions', 'login_at', utc_now().isoformat(), 100) == 0
