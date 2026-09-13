from monitor.infrastructure.database import Database
from monitor.sources import FileTailSource


def test_archived_partial_tail_does_not_block_new_rotation(tmp_path):
    import os,time
    old=tmp_path/'01.log';new=tmp_path/'02.log'
    old.write_bytes(b'complete\nfragment');new.write_bytes(b'new event\n')
    os.utime(old,(time.time()-120,time.time()-120))
    db=Database(tmp_path/'tails.db');db.initialize()
    source=FileTailSource(db,'d',str(tmp_path/'*.log'))
    rows=source.poll(10)
    assert rows[-1].data=='fragment'
    assert rows[-1].checkpoint['unterminated_tail'] is True
    source.commit(rows[-1].checkpoint)
    assert source.poll(10)[0].data=='new event\n'


def test_active_partial_tail_waits_for_newline(tmp_path):
    log=tmp_path/'active.log';log.write_bytes(b'partial')
    db=Database(tmp_path/'active.db');db.initialize()
    source=FileTailSource(db,'d',str(log))
    assert source.poll()==[]
    with log.open('ab') as f:f.write(b' complete\n')
    assert source.poll()[0].data=='partial complete\n'


def test_checkpoint_resume_and_truncate(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("one\ntwo\n", encoding="utf-8")
    db = Database(tmp_path / "test.db"); db.initialize()
    source = FileTailSource(db, "device", str(log))
    first = source.poll(1)
    assert first[0].data == "one\n"
    source.commit(first[0].checkpoint)
    resumed = FileTailSource(db, "device", str(log))
    assert resumed.poll(1)[0].data == "two\n"
    log.write_text("x\n", encoding="utf-8")
    assert resumed.poll(1)[0].data == "x\n"


def test_multiple_files_are_consumed_in_order(tmp_path):
    first_log = tmp_path / "01.log"
    second_log = tmp_path / "02.log"
    first_log.write_text("first\n", encoding="utf-8")
    second_log.write_text("second\n", encoding="utf-8")
    db = Database(tmp_path / "test.db"); db.initialize()
    source = FileTailSource(db, "ordered", str(tmp_path / "*.log"))
    first = source.poll(10)
    assert [row.data for row in first] == ["first\n"]
    source.commit(first[-1].checkpoint)
    second = source.poll(10)
    assert [row.data for row in second] == ["second\n"]


def test_live_source_fast_forwards_a_stale_checkpoint(tmp_path):
    import os
    import time

    first_log = tmp_path / "01.log"
    current_log = tmp_path / "02.log"
    first_log.write_text("old\n", encoding="utf-8")
    current_log.write_text("current\n", encoding="utf-8")
    old = time.time() - 7200
    os.utime(first_log, (old, old))
    db = Database(tmp_path / "test.db"); db.initialize()
    original = FileTailSource(db, "live", str(tmp_path / "*.log"))
    record = original.poll(1)[0]
    original.commit(record.checkpoint)

    live = FileTailSource(db, "live", str(tmp_path / "*.log"),
                          start_at_end=False, max_checkpoint_lag_seconds=60)
    assert live.poll(1)[0].data == "current\n"


def test_latest_file_can_be_read_from_its_beginning(tmp_path):
    import os
    import time

    old_log = tmp_path / "01.log"
    current_log = tmp_path / "02.log"
    old_log.write_text("historical\n", encoding="utf-8")
    current_log.write_text("today-login\n", encoding="utf-8")
    old = time.time() - 7200
    os.utime(old_log, (old, old))
    db = Database(tmp_path / "latest.db"); db.initialize()
    source = FileTailSource(
        db, "audit", str(tmp_path / "*.log"), start_at_latest_file=True,
    )

    record = source.poll(1)[0]
    assert record.data == "today-login\n"
    assert record.checkpoint["file_path"] == str(current_log)


def test_live_source_skips_excessive_byte_backlog(tmp_path):
    log = tmp_path / "busy.log"
    log.write_text("first\n", encoding="utf-8")
    db = Database(tmp_path / "bytes.db"); db.initialize()
    original = FileTailSource(db, "busy", str(log))
    first = original.poll(1)[0]
    original.commit(first.checkpoint)
    with log.open("a", encoding="utf-8") as stream:
        stream.write("old\n" * 100 + "recent\n")
    source = FileTailSource(db, "busy", str(log), max_checkpoint_lag_bytes=16)
    records = source.poll(10)
    assert records[-1].data == "recent\n"
    assert len(records) < 10
