from datetime import datetime,timezone
from monitor.parsers.base import parse_time
from monitor.parsers.vendor_time import syslog_time
from monitor.domain.models import SecurityEvent

def test_utc_and_local_time_represent_same_instant():
    expected=datetime(2026,9,12,11,0,tzinfo=timezone.utc)
    assert parse_time('2026-09-12T11:00:00Z')==expected
    assert parse_time('2026-09-12T19:00:00+08:00')==expected
    assert parse_time('2026-09-12 19:00:00')==expected
    assert syslog_time('Sep 12 19:00:00 FW event',expected)==expected
    assert syslog_time('<134>1 2026-09-12T11:00:00Z FW event',expected)==expected

def test_year_boundary_and_delayed_logs_are_not_retimed_to_now():
    reference=datetime(2027,1,1,0,0,tzinfo=timezone.utc)
    assert syslog_time('Dec 31 23:59:00 FW event',reference)==datetime(2026,12,31,15,59,tzinfo=timezone.utc)
    assert syslog_time('Dec 20 10:00:00 FW event',reference)==datetime(2026,12,20,2,0,tzinfo=timezone.utc)

def test_clock_validation_preserves_evidence_and_flags_future():
    now=datetime(2026,9,12,11,0,tzinfo=timezone.utc)
    event=SecurityEvent('test','device','attack',parse_time('2026-09-13T11:00:00Z'),'1.1.1.1',raw_line='evidence',received_at=now)
    assert event.attributes['time_validation']['status']=='future_clock'
    assert event.attributes['time_validation']['offset_from_received_seconds']==86400
    assert event.raw_line=='evidence'
    assert event.occurred_at.day==13
