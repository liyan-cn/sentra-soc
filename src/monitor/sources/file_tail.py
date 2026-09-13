from __future__ import annotations

import glob
import os
import time
from pathlib import Path

from monitor.domain.models import utc_now
from monitor.plugins.contracts import RawRecord


class FileTailSource:
    """Incremental file source with persisted inode/offset checkpoints.

    It reads one file to EOF before switching to a newer file. A truncated file
    restarts at zero. Checkpoints are committed only after the caller finishes
    processing a record.
    """

    def __init__(self, database, source_id: str, pattern: str, start_at_end: bool = False,
                 max_checkpoint_lag_seconds: int = 0, start_at_latest_file: bool = False,
                 max_checkpoint_lag_bytes: int = 0):
        self.db = database
        self.source_id = source_id
        self.pattern = pattern
        self.start_at_end = start_at_end
        # Read the newest rotation from its beginning. This is useful for a
        # low-volume audit stream where today's login record must be replayed,
        # while years of old rotations must not delay live monitoring.
        self.start_at_latest_file = start_at_latest_file
        self.max_checkpoint_lag_seconds = max(0, int(max_checkpoint_lag_seconds))
        self.max_checkpoint_lag_bytes = max(0, int(max_checkpoint_lag_bytes))
        self.path: str | None = None
        self.inode = ""
        self.offset = 0
        self._checkpoint_version = None
        self._restore()

    def _restore(self) -> None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT file_path,inode,offset,updated_at FROM collector_checkpoints WHERE device_id=?", (self.source_id,)
            ).fetchone()
        if row:
            self.path, self.inode, self.offset = row["file_path"], row["inode"], int(row["offset"])
            self._checkpoint_version = row['updated_at']

    def _files(self) -> list[str]:
        return sorted(
            (path for path in glob.glob(self.pattern) if os.path.isfile(path)),
            key=lambda path: (os.path.getmtime(path), path),
        )

    @staticmethod
    def _identity(path: str) -> str:
        stat = os.stat(path)
        return f"{stat.st_dev}:{stat.st_ino}"

    def _select(self) -> bool:
        files = self._files()
        if not files:
            self.path, self.inode, self.offset = None, "", 0
            return False
        # A busy source can otherwise spend weeks replaying historical files.
        # Live-only readers (for example the VPN presence view) may explicitly
        # fast-forward to the newest file when their checkpoint is too old.
        if self.path in files and self.max_checkpoint_lag_seconds and len(files) > 1:
            newest = files[-1]
            lag = os.path.getmtime(newest) - os.path.getmtime(self.path)
            if lag > self.max_checkpoint_lag_seconds:
                self.path, self.inode = newest, self._identity(newest)
                self.offset = os.path.getsize(newest) if self.start_at_end else 0
                return True
        # A service outage can leave a checkpoint far behind inside the same
        # high-volume file. Live presence/readiness views should catch up to a
        # bounded recent tail instead of replaying obsolete traffic for hours.
        if self.path in files and os.path.exists(self.path):
            identity = self._identity(self.path)
            size = os.path.getsize(self.path)
            if identity == self.inode:
                if size < self.offset:
                    self.offset = 0
                if size > self.offset:
                    return True
        if self.path in files:
            current = files.index(self.path)
            candidate = files[min(current + 1, len(files) - 1)]
        else:
            candidate = files[-1] if self.start_at_end or self.start_at_latest_file else files[0]
        identity = self._identity(candidate)
        if candidate != self.path or identity != self.inode:
            first_selection = self.path is None or self.path not in files
            self.path, self.inode = candidate, identity
            self.offset = os.path.getsize(candidate) if self.start_at_end and first_selection else 0
        return True

    def poll(self, batch_size: int = 100) -> list[RawRecord]:
        if not self._select() or not self.path:
            return []
        records: list[RawRecord] = []
        with Path(self.path).open("rb") as stream:
            stream.seek(self.offset)
            size = os.fstat(stream.fileno()).st_size
            if self.max_checkpoint_lag_bytes and size - self.offset > self.max_checkpoint_lag_bytes:
                target = size - self.max_checkpoint_lag_bytes
                stream.seek(target - 1)
                if stream.read(1) != b"\n":
                    stream.readline()  # Skip only a partial first record.
            while len(records) < batch_size:
                line = stream.readline()
                if not line:
                    break
                unterminated = not line.endswith(b"\n")
                if unterminated:
                    files = self._files()
                    # A still-active file may be mid-write. A stable older
                    # rotation with a successor must not block all future files.
                    if (self.path not in files or files[-1] == self.path
                            or time.time() - os.fstat(stream.fileno()).st_mtime < 60):
                        break
                records.append(RawRecord(
                    data=line.decode("utf-8", errors="replace").replace("\r\n", "\n"),
                    source_id=self.source_id,
                    checkpoint={"file_path": self.path, "inode": self.inode, "offset": stream.tell(),
                                "line_count": len(records) + 1, "batch_start": self.offset,
                                "previous_updated_at": self._checkpoint_version,
                                "unterminated_tail": unterminated},
                ))
        return records

    def commit(self, checkpoint: dict) -> None:
        path = checkpoint["file_path"]
        inode = checkpoint["inode"]
        offset = int(checkpoint["offset"])
        # Acquire the single SQLite writer slot before executing the UPSERT.
        # A deferred transaction can begin successfully and then fail on the
        # first write under collector load, bypassing BEGIN retry handling.
        with self.db.transaction(immediate=True, retries=8) as conn:
            previous = conn.execute("SELECT file_path,inode,offset,updated_at FROM collector_checkpoints WHERE device_id=?",
                                    (self.source_id,)).fetchone()
            duplicate = (previous and previous['file_path'] == path and previous['inode'] == inode
                         and previous['offset'] == offset
                         and previous['updated_at'] != checkpoint.get('previous_updated_at'))
            if duplicate:
                return
            timestamp = utc_now().isoformat()
            if checkpoint.get('line_count'):
                conn.execute("""INSERT INTO ingestion_hourly_stats(hour,device_id,line_count,last_seen_at)
                             VALUES(?,?,?,?) ON CONFLICT(hour,device_id) DO UPDATE SET
                             line_count=line_count+excluded.line_count,last_seen_at=excluded.last_seen_at""",
                             (timestamp[:13], self.source_id, checkpoint['line_count'], timestamp))
            conn.execute(
                """INSERT INTO collector_checkpoints(device_id,file_path,inode,offset,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET file_path=excluded.file_path,
                inode=excluded.inode,offset=excluded.offset,updated_at=excluded.updated_at""",
                (self.source_id, path, inode, offset, timestamp),
            )
        self.path, self.inode, self.offset = path, inode, offset
        self._checkpoint_version = timestamp

    def health(self) -> dict:
        return {"source": self.source_id, "pattern": self.pattern, "file": self.path, "offset": self.offset,
                "status": "ready" if self.path else "waiting"}
