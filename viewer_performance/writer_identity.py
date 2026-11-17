"""Durable implementation/lease identity and bounded publication telemetry.

These private files are telemetry, never the authoritative publication cursor.
An absent, stale or replaced lease cannot be made valid by a receipt file.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from p24_foundation.viewer_runtime import atomic_json

ACTIVE = 'Viewer_Writer_Active.json'
IDENTITY_KEYS = ('instance_token','python_pid','implementation_build','implementation_source_sha256',
    'canonical_runtime_source_sha256','backend_pid','backend_start','server_started',
    'database_oid','client_port','client_addr','application_name','telemetry_slot')
LEASE_SQL = """SELECT a.pid AS backend_pid,EXTRACT(EPOCH FROM a.backend_start)::text AS backend_start,
    EXTRACT(EPOCH FROM pg_postmaster_start_time())::text AS server_started,d.oid::bigint AS database_oid,
    a.client_port,host(a.client_addr) AS client_addr,a.application_name
    FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_database d ON d.datname=a.datname
    WHERE a.datname=current_database() AND EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
        WHERE l.pid=a.pid AND l.locktype='advisory' AND l.classid=240026 AND l.objid=1
        AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted AND l.database=d.oid)
    ORDER BY a.pid LIMIT 2"""
MAX_JOURNAL_BYTES = 4*1024*1024
JOURNAL_SLOTS = 4
INSTANCE_SLOTS = 4


def identity_key(record):
    return tuple(record.get(k) for k in IDENTITY_KEYS)


class WriterIdentity:
    def __init__(self, root, *, build, source, runtime,enabled=True):
        self.directory = Path(root)/'AnomalyDetection/reports'
        self.token = uuid.uuid4().hex
        self.app = 'P24.Fast.'+self.token
        self.record = dict(instance_token=self.token,python_pid=os.getpid(),
            implementation_build=build,implementation_source_sha256=source,
            canonical_runtime_source_sha256=runtime,telemetry_slot=0)
        self.bound = False
        self.enabled=enabled
        self.sequence = 0
        self.slot = 0
        self.owner_slot=0

    def bind_if_owner(self, raw):
        if not self.enabled or self.bound:return
        rows = raw.execute(LEASE_SQL).fetchall()
        if not rows or len(rows)!=1 or rows[0]['backend_pid']!=raw.info.backend_pid:return
        row = dict(rows[0])
        if row['application_name']!=self.app:raise ValueError('writer_identity_application_changed')
        self.directory.mkdir(parents=True,exist_ok=True)
        try:old=json.loads((self.directory/ACTIVE).read_text(encoding='utf-8'));previous=int(old.get('telemetry_slot',-1))
        except (OSError,ValueError,TypeError):previous=-1
        self.owner_slot=(previous+1)%INSTANCE_SLOTS
        for slot in range(JOURNAL_SLOTS):
            with (self.directory/f'Viewer_Writer_Journal_{self.owner_slot}_{slot}.jsonl').open('wb') as stream:
                stream.flush();os.fsync(stream.fileno())
        self.record.update(row,registered_ns=time.time_ns(),journal_slots=JOURNAL_SLOTS,
            journal_max_bytes_per_slot=MAX_JOURNAL_BYTES,telemetry_slot=self.owner_slot,
            retained_instance_slots=INSTANCE_SLOTS)
        names=['work_mem','temp_buffers','jit','wal_compression','fsync','full_page_writes',
            'synchronous_commit','wal_level','shared_buffers','statement_timeout','lock_timeout']
        self.record['effective_writer_settings']=[dict(item) for item in raw.execute(
            'SELECT name,setting,unit FROM pg_catalog.pg_settings WHERE name=ANY(%s) ORDER BY name',(names,)).fetchall()]
        # Only the holder of the existing singleton lease writes the pointer.
        # Closing an old connection never overwrites a replacement's receipt.
        atomic_json(self.directory/f'Viewer_Writer_Record_{self.owner_slot}.json',self.record)
        atomic_json(self.directory/ACTIVE,self.record)
        self.bound = True

    def append(self, value):
        if not self.bound:return
        self.sequence += 1
        record = dict(value,sequence=self.sequence,writer_identity=self.record)
        body=(json.dumps(record,ensure_ascii=True,separators=(',',':'))+'\n').encode('ascii')
        if len(body)>65536:raise ValueError('writer_telemetry_record_too_large')
        def path():return self.directory/f'Viewer_Writer_Journal_{self.owner_slot}_{self.slot}.jsonl'
        if path().exists() and path().stat().st_size+len(body)>MAX_JOURNAL_BYTES:
            self.slot=(self.slot+1)%JOURNAL_SLOTS
            # This bounded telemetry ring does not remove database receipts,
            # evidence, model history, feedback or replay checkpoints.
            with path().open('wb') as stream:stream.flush();os.fsync(stream.fileno())
        with path().open('ab') as stream:
            stream.write(body);stream.flush();os.fsync(stream.fileno())


def read_identity(root, lease):
    path=Path(root)/'AnomalyDetection/reports'/ACTIVE
    if not path.is_file():raise ValueError('writer_implementation_receipt_missing')
    if path.stat().st_size>65536:raise ValueError('writer_identity_receipt_too_large')
    value=json.loads(path.read_text(encoding='utf-8'))
    token=value.get('instance_token','')
    if len(token)!=32 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('writer_identity_token_invalid')
    if type(value.get('python_pid'))is not int or value['python_pid']<=0:
        raise ValueError('writer_python_pid_missing')
    if type(value.get('telemetry_slot'))is not int or not 0<=value['telemetry_slot']<INSTANCE_SLOTS:
        raise ValueError('writer_telemetry_slot_invalid')
    if len(lease)!=1 or any(value.get(k)!=lease[0].get(k) for k in
            ('backend_pid','backend_start','server_started','database_oid','client_port','client_addr','application_name')):
        raise ValueError('writer_receipt_does_not_match_current_lease')
    if value.get('application_name')!='P24.Fast.'+token:
        raise ValueError('writer_identity_application_mismatch')
    return value


def recent_publications(root, identity):
    rows=[]
    directory=Path(root)/'AnomalyDetection/reports'
    for slot in range(JOURNAL_SLOTS):
        path=directory/f"Viewer_Writer_Journal_{identity['telemetry_slot']}_{slot}.jsonl"
        if not path.exists():continue
        with path.open('rb') as stream:
            size=stream.seek(0,2);offset=max(0,size-256*1024);stream.seek(offset)
            if offset:stream.readline()
            body=stream.read(256*1024)
        # Ignore an incomplete last line, which the next poll can complete.
        for line in body.splitlines(keepends=True):
            if not line.endswith(b'\n'):continue
            item=json.loads(line)
            if identity_key(item.get('writer_identity',{}))!=identity_key(identity):
                raise ValueError('writer_journal_identity_changed')
            rows.append(item)
    return sorted(rows,key=lambda row:row['sequence'])


def measured_publication(original):
    def publish(db,path,start,end,**kwargs):
        identity=getattr(db,'writer_identity',None)
        if identity is None:return original(db,path,start,end,**kwargs)
        began=time.perf_counter();db._capacity_writes={};db._capacity_commit_seconds=0.
        prior=db.one('SELECT w.generation FROM viewer_live_windows w WHERE w.start_ns=? AND w.end_ns=? '
            'AND EXISTS(SELECT 1 FROM viewer_live_receipts r WHERE r.start_ns=w.start_ns AND r.end_ns=w.end_ns '
            'AND r.generation=w.generation AND r.file_hash=w.file_hash AND r.records=w.records)',(start,end))
        try:
            result=original(db,path,start,end,**kwargs)
        except BaseException:
            identity.append(dict(status='PUBLICATION_FAILED_OUTCOME_REQUIRES_DATABASE_RECEIPT',
                start_ns=start,end_ns=end,mode=kwargs.get('mode','forward'),
                elapsed_seconds=time.perf_counter()-began,writes=db._capacity_writes))
            raise
        seconds=time.perf_counter()-began
        wait=kwargs.get('capture_wait_seconds')
        wait=kwargs.get('capture_seconds',0) if wait is None else wait
        identity.append(dict(status=result['status'],start_ns=start,end_ns=end,
            new_complete_window=prior is None and result['status']=='PUBLISHED',
            mode=result.get('mode'),generation=result.get('generation'),records=result.get('records'),
            new_events=result.get('new_events'),impacted_requests=result.get('impacted_requests'),
            finished_ns=time.time_ns(),publication_through_commit_seconds=seconds,
            capture_seconds=kwargs.get('capture_seconds',0),capture_wait_seconds=wait,
            receive_through_commit_seconds=wait+seconds,commit_seconds=db._capacity_commit_seconds,
            writes=db._capacity_writes,canonical_receipt_is_authoritative=True))
        return result
    return publish
