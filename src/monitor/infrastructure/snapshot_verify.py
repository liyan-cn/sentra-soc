"""Read-only SQLite checks over a SHA-256 protected, compressed byte mirror.

Only immutable, standalone snapshots are accepted. The business SQLite runtime
is unchanged; APSW is loaded only by this optional verification subprocess.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import tempfile
import time
import uuid
import zlib

CHUNK=65536
RECORD=struct.Struct('<QI32s')


def digest_file(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block:=stream.read(4*1024**2):result.update(block)
    return result.hexdigest()


def identity(path):
    stat=Path(path).stat()
    return stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns


def check_sidecars(source):
    for suffix in ('-wal','-journal'):
        sidecar=Path(str(source)+suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError('snapshot has a nonempty WAL or journal; refuse an inconsistent mirror')


def build_mirror(source,root,progress=None,codec='zlib'):
    source=Path(source).resolve();root=Path(root)
    check_sidecars(source)
    before=identity(source)
    if before[2]<512:raise ValueError('snapshot is too small')
    source_hash=hashlib.sha256();data_hash=hashlib.sha256();index_hash=hashlib.sha256()
    if codec=='zstd':
        import zstandard
        compress=zstandard.ZstdCompressor(level=1).compress
    elif codec=='zlib':compress=lambda block:zlib.compress(block,1)
    else:raise ValueError('unsupported mirror codec')
    offset=0;copied=0;last=time.monotonic()
    with source.open('rb') as src,(root/'data').open('xb') as dst,(root/'index').open('xb') as index:
        while block:=src.read(CHUNK):
            source_hash.update(block)
            compressed=compress(block)
            record=RECORD.pack(offset,len(compressed),hashlib.sha256(block).digest())
            dst.write(compressed);index.write(record)
            data_hash.update(compressed);index_hash.update(record)
            offset+=len(compressed);copied+=len(block)
            if progress and time.monotonic()-last>=15:
                progress({'phase':'mirror_build','bytes':copied,'total':before[2],'compressed_bytes':offset})
                last=time.monotonic()
        dst.flush();index.flush()
        os.fsync(dst.fileno());os.fsync(index.fileno())
    check_sidecars(source)
    if identity(source)!=before:raise ValueError('snapshot changed during mirror construction')
    metadata={'size':copied,'chunk_size':CHUNK,'codec':codec,'source_sha256':source_hash.hexdigest(),
              'data_sha256':data_hash.hexdigest(),'index_sha256':index_hash.hexdigest(),
              'compressed_size':offset,'source_identity':list(before)}
    (root/'metadata.json').write_text(json.dumps(metadata),encoding='utf8')
    return metadata


class MirrorReader:
    def __init__(self,root,cache_bytes=64*1024**2,progress=None):
        root=Path(root)
        self.meta=json.loads((root/'metadata.json').read_text(encoding='utf8'))
        self.size=self.meta['size'];self.chunk=self.meta['chunk_size']
        if self.meta.get('codec','zlib')=='zstd':
            import zstandard
            self.decompress=zstandard.ZstdDecompressor().decompress
        elif self.meta.get('codec','zlib')=='zlib':self.decompress=zlib.decompress
        else:raise ValueError('unsupported mirror codec')
        if self.chunk!=CHUNK or self.size<512:raise ValueError('invalid mirror dimensions')
        if (root/'index').stat().st_size!=((self.size+CHUNK-1)//CHUNK)*RECORD.size:
            raise ValueError('mirror index size mismatch')
        if digest_file(root/'index')!=self.meta['index_sha256'] or digest_file(root/'data')!=self.meta['data_sha256']:
            raise ValueError('mirror checksum mismatch')
        self.files=[];self.maps=[]
        try:
            for name in ('data','index'):
                stream=(root/name).open('rb');self.files.append(stream)
                self.maps.append(mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ))
        except Exception:
            self.close();raise
        self.data,self.index=self.maps
        self.cache=OrderedDict();self.capacity=max(1,cache_bytes//CHUNK)
        self.read_calls=0;self.cache_hits=0
        self.progress=progress;self.last_progress=time.monotonic()

    def read(self,amount,offset):
        if amount<0 or offset<0:raise ValueError('invalid mirror read')
        self.read_calls+=1
        if self.progress and self.read_calls%8192==0 and time.monotonic()-self.last_progress>=15:
            self.progress({'phase':'sqlite_check','read_calls':self.read_calls,'cache_hits':self.cache_hits})
            self.last_progress=time.monotonic()
        end=min(self.size,offset+amount);parts=[]
        while offset<end:
            number=offset//CHUNK
            if number in self.cache:
                block=self.cache[number];self.cache.move_to_end(number);self.cache_hits+=1
            else:
                position,length,expected=RECORD.unpack_from(self.index,number*RECORD.size)
                if length<=0 or position+length>len(self.data):raise ValueError('invalid mirror block extent')
                block=self.decompress(self.data[position:position+length])
                expected_size=min(CHUNK,self.size-number*CHUNK)
                if len(block)!=expected_size or hashlib.sha256(block).digest()!=expected:
                    raise ValueError('mirror block checksum mismatch')
                self.cache[number]=block
                if len(self.cache)>self.capacity:self.cache.popitem(last=False)
            count=min(end-offset,len(block)-offset%CHUNK)
            if count<=0:raise ValueError('invalid mirror block length')
            parts.append(block[offset%CHUNK:offset%CHUNK+count]);offset+=count
        return b''.join(parts)

    def close(self):
        for memory in reversed(getattr(self,'maps',[])):memory.close()
        for stream in reversed(getattr(self,'files',[])):stream.close()
        self.maps=[];self.files=[]


def check_mirror(root,full=False,progress=None):
    import apsw
    reader=MirrorReader(root,progress=progress)
    class ReadOnlyFile:
        def xRead(self,amount,offset):return reader.read(amount,offset)
        def xFileSize(self):return reader.size
        def xClose(self):pass
        def xLock(self,level):pass
        def xUnlock(self,level):pass
        def xCheckReservedLock(self):return False
        def xFileControl(self,operation,pointer):return False
        def xSectorSize(self):return 4096
        def xDeviceCharacteristics(self):return apsw.SQLITE_IOCAP_IMMUTABLE
        def xWrite(self,*args):raise apsw.ReadOnlyError('verification mirror is read-only')
        def xTruncate(self,*args):raise apsw.ReadOnlyError('verification mirror is read-only')
        def xSync(self,*args):pass
    class ReadOnlyVFS(apsw.VFS):
        def __init__(self,name):super().__init__(name,'')
        def xOpen(self,name,flags):
            if flags[0] & apsw.SQLITE_OPEN_MAIN_DB:
                flags[1]=apsw.SQLITE_OPEN_READONLY
                return ReadOnlyFile()
            raise apsw.ReadOnlyError('no auxiliary files allowed')
        def xAccess(self,path,flags):return False
        def xDelete(self,*args):raise apsw.ReadOnlyError('no deletions allowed')
    name='monitor-snapshot-'+uuid.uuid4().hex
    vfs=ReadOnlyVFS(name);connection=None
    started=time.monotonic()
    try:
        virtual=(Path(root).resolve()/'virtual.db').as_uri()+'?mode=ro&immutable=1'
        connection=apsw.Connection(virtual,
                                  flags=apsw.SQLITE_OPEN_READONLY|apsw.SQLITE_OPEN_URI,vfs=name)
        connection.execute('PRAGMA cache_size=-65536')
        checks=[r[0] for r in connection.execute('PRAGMA '+('integrity_check' if full else 'quick_check'))]
        if checks!=['ok']:raise ValueError('snapshot integrity check failed: '+'; '.join(checks[:5]))
        foreign=0
        if full:
            for row in connection.execute('PRAGMA foreign_key_check'):
                foreign+=1
                if foreign>=100:break
        if foreign:raise ValueError('snapshot foreign key check failed')
        return {'checks':checks,'versions':[r[0] for r in connection.execute('SELECT version FROM schema_migrations ORDER BY version')],
                'tables':[r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")],
                'journal_mode':connection.execute('PRAGMA journal_mode').fetchone()[0],
                'foreign_key_errors':foreign,'sqlite_version':apsw.sqlite_lib_version(),
                'backend':'compressed-readonly','source_sha256':reader.meta['source_sha256'],
                'compressed_size':reader.meta['compressed_size'],'check_seconds':round(time.monotonic()-started,3),
                'read_calls':reader.read_calls,'cache_hits':reader.cache_hits}
    finally:
        if connection:connection.close()
        vfs.unregister();reader.close()


def verify_snapshot(source,work_root=None,full=False,progress=None,codec='zstd'):
    source=Path(source).resolve()
    before=identity(source)
    with tempfile.TemporaryDirectory(prefix='monitor3-verify-',dir=work_root or source.parent) as directory:
        os.chmod(directory,0o700)
        build_mirror(source,directory,progress,codec)
        if progress:progress({'phase':'mirror_check','source_bytes':before[2]})
        report=check_mirror(directory,full,progress)
        check_sidecars(source)
        if identity(source)!=before:raise ValueError('snapshot changed during verification')
        return report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--input',required=True)
    parser.add_argument('--full',action='store_true');parser.add_argument('--report')
    parser.add_argument('--work-root');parser.add_argument('--codec',choices=['zlib','zstd'],default='zstd');args=parser.parse_args()
    report=verify_snapshot(args.input,work_root=args.work_root,full=args.full,codec=args.codec,
                           progress=lambda data:print(json.dumps(data),file=__import__('sys').stderr,flush=True))
    if args.report:
        destination=Path(args.report);temporary=destination.with_suffix('.tmp')
        temporary.write_text(json.dumps(report,indent=2),encoding='utf8');os.replace(temporary,destination)
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
