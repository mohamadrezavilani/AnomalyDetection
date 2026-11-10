"""Viewer-only, atomic incremental publisher and closed-window scheduler.

No detector or application database is opened by this module. Capture files
are immutable; publication and its durable cursor share one DB transaction.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import gzip
import hashlib
import json
import time
import uuid

from .viewer_data import utc_ns, source_identity

FIVE_NS=300_000_000_000
SECOND_NS=1_000_000_000


def iso(ns):
    return datetime.fromtimestamp(ns/SECOND_NS,timezone.utc).isoformat()


def now_ns():
    return time.time_ns()


def peak_rss_kib():
    """Process peak working set, without a new runtime dependency."""
    import os,sys
    try:
        if os.name=='nt':
            import ctypes
            from ctypes import wintypes
            class MemoryCounters(ctypes.Structure):
                _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD),
                    ('PeakWorkingSetSize',ctypes.c_size_t),('WorkingSetSize',ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage',ctypes.c_size_t),('QuotaPagedPoolUsage',ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage',ctypes.c_size_t),('QuotaNonPagedPoolUsage',ctypes.c_size_t),
                    ('PagefileUsage',ctypes.c_size_t),('PeakPagefileUsage',ctypes.c_size_t)]
            counters=MemoryCounters();counters.cb=ctypes.sizeof(counters)
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.GetCurrentProcess.restype=wintypes.HANDLE
            psapi=ctypes.WinDLL('psapi',use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(MemoryCounters),wintypes.DWORD]
            if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):return None
            return int(counters.PeakWorkingSetSize//1024)
        import resource
        value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value//1024 if sys.platform=='darwin' else value)
    except (ImportError,OSError,AttributeError):return None


def hash_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda:stream.read(1024*1024),b''):h.update(part)
    return h.hexdigest()


def checked_window(start,end):
    if (isinstance(start,bool) or not isinstance(start,int) or start<0 or
        start%FIVE_NS or end!=start+FIVE_NS):raise ValueError('invalid_closed_window')


def validate_capture(path,start,end):
    """Strict admission for live publication (legacy manual import stays intact)."""
    proof,_=_read_verified_capture(path,start,end)
    return proof


def _read_verified_capture(path,start,end):
    checked_window(start,end)
    # Hash and parse the same byte snapshot even if the path is replaced.
    compressed=Path(path).read_bytes()
    digest=hashlib.sha256(compressed).hexdigest()
    with gzip.open(BytesIO(compressed),'rt',encoding='utf-8') as stream:
        payload=json.load(stream)
    del compressed
    rows=payload.get('logs');proof=payload.get('verification') or {}
    if (utc_ns(payload.get('window_start'))!=start or utc_ns(payload.get('window_end'))!=end
        or payload.get('complete') is not True or not isinstance(rows,list)
        or type(payload.get('count')) is not int or payload['count']!=len(rows)):
        raise ValueError('capture_bounds_or_count_invalid')
    if (not isinstance(proof,dict) or proof.get('counts_match') is not True
        or proof.get('query_snapshot_complete') is not True
        or proof.get('reached_empty_page') is not True
        or proof.get('total_relation')!='eq'
        or type(proof.get('expected_total')) is not int
        or proof.get('expected_total')!=len(rows)
        or proof.get('returned_records')!=len(rows)
        or proof.get('unique_origins')!=len(rows)):
        raise ValueError('capture_proof_incomplete')
    identities=set()
    last_event_ns=0
    for row in rows:
        if not isinstance(row,dict):raise ValueError('capture_non_object_row')
        identity=source_identity(row);at=utc_ns(row.get('@timestamp'))
        if (not all(identity) or identity in identities or at is None or not start<=at<end
            or not isinstance(row.get('message'),str)):
            raise ValueError('capture_identity_or_event_invalid')
        identities.add(identity)
        last_event_ns=max(last_event_ns,at)
    return dict(sha256=digest,records=len(rows),proof=proof,last_event_ns=last_event_ns),payload


def initialize_live(db):
    """Additive schema only. No raw/human data is reset or removed."""
    db.init_semantic_index()
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_live_state(
       id INTEGER PRIMARY KEY CHECK(id=1), stream_key TEXT NOT NULL,
       keys_fingerprint TEXT NOT NULL,start_ns BIGINT NOT NULL,next_ns BIGINT NOT NULL,
       generation BIGINT NOT NULL,last_publish_ns BIGINT,last_attempt_ns BIGINT,
       last_success_ns BIGINT,last_error TEXT,worker_status TEXT NOT NULL,
       overlap_windows INTEGER NOT NULL,lag_seconds INTEGER NOT NULL,
       last_event_ns BIGINT NOT NULL DEFAULT 0)''')
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_live_windows(
       start_ns BIGINT PRIMARY KEY,end_ns BIGINT NOT NULL,file_hash TEXT NOT NULL,
       records BIGINT NOT NULL,first_publish_ns BIGINT NOT NULL,last_publish_ns BIGINT NOT NULL,
       rechecked_epoch_ns BIGINT NOT NULL,generation BIGINT NOT NULL)''')
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_live_receipts(
       receipt_id TEXT PRIMARY KEY,start_ns BIGINT NOT NULL,end_ns BIGINT NOT NULL,
       file_hash TEXT NOT NULL,mode TEXT NOT NULL,generation BIGINT NOT NULL,
       records BIGINT NOT NULL,new_events BIGINT NOT NULL,impacted_requests BIGINT NOT NULL,
       elapsed_seconds DOUBLE PRECISION NOT NULL,published_ns BIGINT NOT NULL,
       proof_json TEXT NOT NULL,capture_seconds DOUBLE PRECISION NOT NULL,
       cycle_seconds DOUBLE PRECISION NOT NULL)''')
    db.sql('CREATE INDEX IF NOT EXISTS vlr_window ON viewer_live_receipts(start_ns,published_ns)')
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_live_resumes(
       resume_id TEXT PRIMARY KEY,previous_next_ns BIGINT NOT NULL,
       resumed_from_ns BIGINT NOT NULL,resumed_at_ns BIGINT NOT NULL,
       stream_key TEXT NOT NULL,keys_fingerprint TEXT NOT NULL,reason TEXT NOT NULL,
       CHECK(resumed_from_ns>previous_next_ns))''')
    db.sql('CREATE INDEX IF NOT EXISTS vei_origin_request ON viewer_events(origin_key,request_key)')
    db.conn.commit()


@contextmanager
def single_worker(db,lock_path):
    """Session advisory lock on PG; OS-released cross-platform lock offline."""
    handle=None
    if not db.sqlite:
        locked=db.one('SELECT pg_try_advisory_lock(240026,1) AS locked')['locked']
        db.conn.commit()
        if not locked:raise ValueError('viewer_worker_already_running')
    else:
        path=Path(lock_path);path.parent.mkdir(parents=True,exist_ok=True)
        handle=path.open('a+b')
        try:
            import os
            if os.name=='nt':
                import msvcrt
                if path.stat().st_size==0:handle.write(b'0');handle.flush()
                handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            handle.close();raise ValueError('viewer_worker_already_running') from None
    try:yield
    finally:
        if handle:handle.close()
        elif not db.sqlite:
            try:
                db.conn.rollback()
                db.sql('SELECT pg_advisory_unlock(240026,1)');db.conn.commit()
            except Exception:pass  # Connection close releases the session lock.


def bind_stream(db,*,start_ns,stream_key,overlap_windows=2,lag_seconds=60):
    checked_window(start_ns,start_ns+FIVE_NS)
    if type(overlap_windows) is not int or not 0<=overlap_windows<=288:
        raise ValueError('invalid_overlap_windows')
    if type(lag_seconds) is not int or not 0<=lag_seconds<=86400:
        raise ValueError('invalid_lag_seconds')
    state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
    if state:
        if (state['stream_key']!=stream_key or state['start_ns']!=start_ns
            or state['keys_fingerprint']!=db.keys.fingerprint):
            raise ValueError('live_stream_or_keys_changed')
        db.sql('UPDATE viewer_live_state SET overlap_windows=?,lag_seconds=? WHERE id=1',
               (overlap_windows,lag_seconds))
    else:
        # M1 has no durable key binding. Verify retained source identities
        # before adopting its DB; a wrong/new key file must never duplicate it.
        from .viewer_data import token
        for old in db.all('SELECT origin_key,version_key FROM viewer_events LIMIT 10'):
            raw=db.get_raw(old['origin_key'],old['version_key'])
            identity=source_identity(raw) if raw else (None,None)
            if (not all(identity) or token(db.keys,'origin',list(identity))!=old['origin_key']
                or token(db.keys,'version',raw)!=old['version_key']):
                raise ValueError('existing_viewer_keys_or_raw_identity_mismatch')
        db.sql('''INSERT INTO viewer_live_state VALUES(1,?,?,?,?,0,NULL,NULL,NULL,NULL,'starting',?,?,0)''',
               (stream_key,db.keys.fingerprint,start_ns,start_ns,overlap_windows,lag_seconds))
    db.conn.commit()


def live_history_coverage(db):
    """Small checkpoint metadata only; missing table means a pre-resume install.

    A seek never fabricates empty captures. Later real manual rechecks reduce
    the outstanding count using the published-window ledger, not raw counts.
    """
    db.sql('SAVEPOINT live_resume_probe')
    try:
        rows=db.all('''SELECT r.resume_id,r.previous_next_ns,r.resumed_from_ns,r.resumed_at_ns,
            COUNT(w.start_ns) AS recovered_windows
            FROM viewer_live_resumes r LEFT JOIN viewer_live_windows w
              ON w.start_ns>=r.previous_next_ns AND w.end_ns<=r.resumed_from_ns
            GROUP BY r.resume_id,r.previous_next_ns,r.resumed_from_ns,r.resumed_at_ns
            ORDER BY r.resumed_from_ns''')
    except Exception as exc:
        db.sql('ROLLBACK TO SAVEPOINT live_resume_probe');db.sql('RELEASE SAVEPOINT live_resume_probe')
        if not (type(exc).__name__=='UndefinedTable' or
                type(exc).__name__=='OperationalError' and 'no such table' in str(exc).lower()):raise
        rows=[]
    else:db.sql('RELEASE SAVEPOINT live_resume_probe')
    gaps=[]
    for row in rows:
        missing=(row['resumed_from_ns']-row['previous_next_ns'])//FIVE_NS-row['recovered_windows']
        if missing:
            gaps.append(dict(from_utc=iso(row['previous_next_ns']),to_utc=iso(row['resumed_from_ns']),
                             unprocessed_windows=int(missing)))
    return dict(history_has_gaps=bool(gaps),historical_gap_windows=sum(g['unprocessed_windows'] for g in gaps),
        historical_gaps=gaps,history_resume_count=len(rows),
        recent_coverage_from_utc=iso(rows[-1]['resumed_from_ns']) if rows else None)


def resume_recent(db,*,lookback_windows=2,now=None,fault=None):
    """Explicit owner-requested seek under the caller's singleton worker lock.

    Keep the original config binding, evidence, projections and keys. The
    durable cursor and an append-only record of skipped coverage commit once.
    Re-running within the same closed-window epoch is a no-op.
    """
    if type(lookback_windows) is not int or not 1<=lookback_windows<=288:
        raise ValueError('invalid_recent_window_count')
    now=now_ns() if now is None else now
    if type(now) is not int or now<0:raise ValueError('invalid_recent_start_time')
    try:
        db.write_lock()
        state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
        if not state:raise ValueError('live_stream_not_initialized')
        if state['keys_fingerprint']!=db.keys.fingerprint:raise ValueError('live_keys_changed')
        closed=(now-state['lag_seconds']*SECOND_NS)//FIVE_NS*FIVE_NS
        target=closed-lookback_windows*FIVE_NS
        if target<=state['next_ns']:
            db.conn.rollback()
            return dict(status='NO_CHANGE',reason='already_at_or_after_recent_start',live=live_status(db,now=now))
        checked_window(target,target+FIVE_NS)
        db.sql('''INSERT INTO viewer_live_resumes VALUES(?,?,?,?,?,?,?)''',
            (uuid.uuid4().hex,state['next_ns'],target,now,state['stream_key'],db.keys.fingerprint,
             'owner_requested_recent_start'))
        if fault:fault('after_resume_receipt')
        db.sql("UPDATE viewer_live_state SET next_ns=?,last_error=NULL,worker_status='scheduled_recent' WHERE id=1",(target,))
        if fault:fault('before_resume_commit')
        db.conn.commit()
        return dict(status='RESCHEDULED',previous_next_utc=iso(state['next_ns']),resumed_from_utc=iso(target),
            skipped_windows=int((target-state['next_ns'])//FIVE_NS),
            retained_data_modified=False,configured_start_changed=False,live=live_status(db,now=now))
    except BaseException:
        db.conn.rollback();raise


def affected_closure(db,keys,*,limit=250000):
    """Invalidate old and new RequestIDs and their entire payment groups.

    Even a newly conflicting origin must retract the old version's positive
    claims. Include old links, not just newly admissible ones, in the closure.
    This is maintenance dependency traversal, never evidence of a human action.
    """
    found=set(keys);front=set(keys);visited_groups=set()
    if len(found)>limit:raise ValueError('affected_dependency_budget_exceeded')
    while front:
        groups=set()
        ordered=sorted(front)
        for start in range(0,len(ordered),500):
            batch=ordered[start:start+500]
            if db.sqlite:
                query="SELECT DISTINCT link_key FROM viewer_links WHERE link_domain='platform_payment' AND request_key IN ("+','.join('?' for _ in batch)+')'
            else:
                query='''SELECT DISTINCT a.link_key FROM (VALUES '''+','.join('(?)' for _ in batch)+''') k(request_key)
                    CROSS JOIN LATERAL (SELECT source.link_key FROM viewer_links source
                    WHERE source.request_key=k.request_key AND source.link_domain='platform_payment' OFFSET 0) a'''
            groups.update(r['link_key'] for r in db.all(query,batch))
        # A payment group is a hyperedge, not a clique of RequestID pairs.
        # Expanding a group of N requests once avoids N*N joined rows before
        # DISTINCT. This cache lives only inside this publication transaction.
        unseen=sorted(groups-visited_groups);visited_groups.update(unseen)
        new=set()
        for start in range(0,len(unseen),500):
            batch=unseen[start:start+500]
            if db.sqlite:
                query="SELECT DISTINCT request_key FROM viewer_links WHERE link_domain='platform_payment' AND request_key IS NOT NULL AND link_key IN ("+','.join('?' for _ in batch)+')'
            else:
                query='''SELECT DISTINCT b.request_key FROM (VALUES '''+','.join('(?)' for _ in batch)+''') k(link_key)
                    CROSS JOIN LATERAL (SELECT source.request_key FROM viewer_links source
                    WHERE source.link_domain='platform_payment' AND source.link_key=k.link_key
                    AND source.request_key IS NOT NULL OFFSET 0) b'''
            # A larger component cannot be published under this existing
            # guard. Bound materialization before allocating the whole graph.
            new.update(r['request_key'] for r in db.all(query+' LIMIT ?',[*batch,limit+1]))
            if len(found|new)>limit:raise ValueError('affected_dependency_budget_exceeded')
        front=new-found;found.update(front)
        db.progress('dependency_closure',requests=len(found),payment_groups=len(visited_groups))
    return sorted(found)


def publish_capture(db,path,start,end,*,mode='forward',epoch_ns=None,fault=None,capture_seconds=0,
                    capture_wait_seconds=None):
    """All visible projections and cursor commit together; retry is idempotent.

    fault is an injectable acceptance hook, never configured by the application.
    A post-commit disconnect is reconciled by reading the durable next cursor,
    not by deleting evidence or inventing a later checkpoint.
    """
    started=time.monotonic()
    db.progress('validate_capture')
    path=Path(path).resolve()
    proof,payload=_read_verified_capture(path,start,end)
    capture_wait=capture_seconds if capture_wait_seconds is None else capture_wait_seconds
    if mode not in ('forward','recheck','manual_recheck'):raise ValueError('invalid_publish_mode')
    def stage(name):
        db.progress(name)
        if fault:fault(name)
    try:
        db.write_lock()
        # An explicitly requested, transaction-local optimization. No durability
        # flags or global PostgreSQL settings change. A permission/feature error
        # aborts the entire publication rather than silently weakening safety.
        compression=getattr(db,'_publication_wal_compression',None)
        if compression is not None:
            if db.sqlite or compression not in ('pglz','lz4','zstd'):
                raise ValueError('invalid_viewer_wal_compression')
            # Identifiers come exclusively from the fixed allowlist above.
            db.sql('SET LOCAL wal_compression = '+compression)
            db.progress('publication_wal_compression',method=compression)
        state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
        if not state:raise ValueError('live_stream_not_initialized')
        if state['keys_fingerprint']!=db.keys.fingerprint:raise ValueError('live_keys_changed')
        if mode=='forward' and start!=state['next_ns']:raise ValueError('noncontiguous_forward_window')
        if mode=='recheck' and not db.one('SELECT start_ns FROM viewer_live_windows WHERE start_ns=?',(start,)):
            raise ValueError('recheck_unpublished_window')
        if mode=='manual_recheck' and start>=state['next_ns']:
            raise ValueError('manual_recheck_cannot_skip_forward_gap')
        result=db.ingest([path],commit=False,_validated_capture=(proof['sha256'],payload))[0]
        del payload
        if result['status'] not in ('IMPORTED','ALREADY_IMPORTED'):raise ValueError('capture_ingest_rejected')
        if result['sha256']!=proof['sha256']:raise ValueError('capture_changed_during_publication')
        stage('after_ingest')
        checkpoint=db.semantic_checkpoint()
        if not checkpoint or checkpoint['state']!='ready' or state['generation']==0:
            # Explicit one-time bootstrap/adoption. Never performed per cycle.
            db.rebuild(commit=False)
            db.rebuild_payment_contract(commit=False)
            db.build_semantic_index(commit=False)
            impacted=db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n']
            bootstrap=True
        else:
            keys=affected_closure(db,db._ingest_impacted)
            impacted=len(keys);bootstrap=False
            added_requests=0
            for begin in range(0,len(keys),500):
                batch=keys[begin:begin+500]
                existing=db.one('SELECT COUNT(*) AS n FROM viewer_requests WHERE request_key IN ('+
                    ','.join('?' for _ in batch)+')',batch)['n']
                added_requests+=len(batch)-existing
            if keys:
                # Existing requests can make index probes cost more than the
                # original semijoin. Use them only for sparse forward work.
                existing_requests=len(keys)-added_requests
                use_indexed_scope=mode=='forward' and existing_requests*100<=len(keys)
                db.rebuild(request_keys=keys,commit=False,use_indexed_scope=use_indexed_scope)
                stage('after_requests')
                db.rebuild_payment_contract(request_keys=keys,commit=False,reuse_projection_events=True)
                stage('after_relations')
                db.reconcile_semantic_requests(keys,commit=False)
        stage('after_semantics')
        # Any new evidence may affect the journey even when its semantic anchor
        # stayed unchanged. Fence every published generation, including rechecks.
        semantic=db.semantic_checkpoint()
        generation=max(state['generation'],semantic['generation'])+1
        db.sql("UPDATE viewer_semantic_checkpoint SET generation=?,indexed_requests=?,updated_at=? WHERE id=1",
               (generation,semantic['indexed_requests']+(0 if bootstrap else added_requests),iso(now_ns())))
        # indexed_requests is bookkeeping of read-model request candidates, not
        # a behavior count. Compute exactly on bootstrap only; online uses delta.
        stamp=now_ns();elapsed=time.monotonic()-started
        db.sql('''INSERT INTO viewer_live_windows VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(start_ns) DO UPDATE SET file_hash=excluded.file_hash,
          records=excluded.records,last_publish_ns=excluded.last_publish_ns,
          rechecked_epoch_ns=excluded.rechecked_epoch_ns,generation=excluded.generation''',
          (start,end,proof['sha256'],proof['records'],stamp,stamp,epoch_ns or 0,generation))
        db.sql('''INSERT INTO viewer_live_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
          (uuid.uuid4().hex,start,end,proof['sha256'],mode,generation,proof['records'],
           result.get('new_events',0),impacted,elapsed,stamp,json.dumps(proof['proof'],ensure_ascii=True),
           capture_seconds,capture_wait+elapsed))
        db.sql('''UPDATE viewer_live_state SET next_ns=?,generation=?,last_publish_ns=?,
            last_success_ns=?,last_event_ns=?,last_error=NULL,worker_status='published' WHERE id=1''',
          (end if mode=='forward' else state['next_ns'],generation,stamp,stamp,
           max(state['last_event_ns'],proof['last_event_ns'])))
        stage('before_commit')
        try:
            current_digest=hash_file(path)
        except OSError:
            raise ValueError('capture_changed_during_publication') from None
        if current_digest!=proof['sha256']:
            raise ValueError('capture_changed_during_publication')
        db.conn.commit()
        stage('after_commit')
        return dict(status='PUBLISHED',mode=mode,records=proof['records'],new_events=result.get('new_events',0),
                    window_start_utc=iso(start),window_end_utc=iso(end),
                    impacted_requests=impacted,bootstrap=bootstrap,generation=generation,
                    capture_method=proof['proof'].get('method','unknown'),
                    elapsed_seconds=round(time.monotonic()-started,3),capture_seconds=round(capture_seconds,3),
                    capture_wait_seconds=round(capture_wait,3),
                    capture_overlap_seconds=round(max(0,capture_seconds-capture_wait),3),
                    total_cycle_seconds=round(capture_wait+time.monotonic()-started,3))
    except BaseException:
        db.conn.rollback();db._active_projection_scope=False
        raise


def live_status(db,*,now=None):
    """No global raw/request counts in the UI refresh path."""
    now=now or now_ns()
    db.sql('SAVEPOINT live_status_probe')
    try:state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
    except Exception as exc:
        db.sql('ROLLBACK TO SAVEPOINT live_status_probe');db.sql('RELEASE SAVEPOINT live_status_probe')
        if not (type(exc).__name__=='UndefinedTable' or
                type(exc).__name__=='OperationalError' and 'no such table' in str(exc).lower()):raise
        return dict(status='NOT_STARTED',source_finality='not_established')
    else:db.sql('RELEASE SAVEPOINT live_status_probe')
    if not state:return dict(status='NOT_STARTED',source_finality='not_established')
    closed=(now-state['lag_seconds']*SECOND_NS)//FIVE_NS*FIVE_NS
    backlog=max(0,(closed-state['next_ns'])//FIVE_NS)
    latest=db.one('SELECT MAX(end_ns) AS n FROM viewer_live_windows')['n']
    activity=state['last_success_ns']
    stale=activity is None or now-activity>max(600,state['lag_seconds']+300)*SECOND_NS
    coverage=live_history_coverage(db)
    return dict(status='ERROR' if state['last_error'] else 'STALE' if stale else 'CATCHING_UP' if backlog else 'CURRENT',
        worker_status=state['worker_status'],generation=state['generation'],
        started_from_utc=iso(state['start_ns']),continuous_published_to_utc=iso(state['next_ns']),
        continuous_published_from_utc=coverage['recent_coverage_from_utc'] or iso(state['start_ns']),
        last_complete_window_utc=iso(latest) if latest else None,
        last_publish_utc=iso(state['last_publish_ns']) if state['last_publish_ns'] else None,
        last_success_utc=iso(activity) if activity else None,
        last_observed_event_utc=iso(state['last_event_ns']) if state['last_event_ns'] else None,
        backlog_windows=int(backlog),lag_seconds=state['lag_seconds'],overlap_windows=state['overlap_windows'],
        last_error=state['last_error'],source_finality='not_established',
        earlier_history='not_claimed_complete',late_evidence_beyond_overlap='manual_recheck_required',**coverage)


class LiveWorker:
    def __init__(self,db,capture,*,prefetch=None):
        self.db=db;self.capture=capture;self.prefetch=prefetch

    def step(self,*,now=None,recheck_start=None,prefetch_next=True):
        now=now or now_ns();db=self.db
        state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
        if not state:raise ValueError('live_stream_not_initialized')
        closed=(now-state['lag_seconds']*SECOND_NS)//FIVE_NS*FIVE_NS
        if recheck_start is not None:
            start=recheck_start;mode='manual_recheck'
        elif state['next_ns']<closed:
            start=state['next_ns'];mode='forward'
        else:
            # One recent recheck per tick, once per newly closed window epoch.
            # Old failures do not skip a forward gap or force full-history work.
            row=db.one('''SELECT start_ns FROM viewer_live_windows
               WHERE start_ns>=? AND end_ns<=? AND rechecked_epoch_ns<?
               ORDER BY start_ns LIMIT 1''',
               (max(state['start_ns'],closed-state['overlap_windows']*FIVE_NS),closed,closed))
            if not row:
                db.sql("UPDATE viewer_live_state SET worker_status='waiting' WHERE id=1");db.conn.commit()
                status=live_status(db,now=now);db.conn.rollback()
                return dict(status='WAITING',live=status)
            start=row['start_ns'];mode='recheck'
        end=start+FIVE_NS
        checked_window(start,end)
        if end>closed:raise ValueError('window_not_closed')
        db.sql("UPDATE viewer_live_state SET last_attempt_ns=?,worker_status='capturing' WHERE id=1",(now,))
        db.conn.commit()
        try:
            from .viewer_data import tehran
            db.progress('capture',mode=mode,window_start_utc=iso(start),window_start_tehran=tehran(start),
                operation_fa='دریافت پنجرهٔ جدید' if mode=='forward' else 'بازبینی شواهد دیررس')
            began=time.monotonic()
            metadata={}
            if mode=='forward' and self.prefetch is not None:
                metadata=self.prefetch.take(start,end)
                path=metadata.pop('path');capture_seconds=metadata['capture_seconds']
                db.progress('capture_ready',**metadata)
                # Only capture overlaps publication. No other thread ever
                # opens this DB connection or advances a projection/cursor.
                if prefetch_next and self.prefetch.prepare(end,end+FIVE_NS,closed_ns=closed):
                    db.progress('prefetch_started',window_start_utc=iso(end))
            else:
                if self.prefetch is not None:self.prefetch.cancel()
                path=self.capture(start,end)  # Always a fresh ES traversal on recheck.
                capture_seconds=time.monotonic()-began
            result=publish_capture(db,path,start,end,mode=mode,epoch_ns=closed if mode!='forward' else 0,
                                   capture_seconds=capture_seconds,
                                   capture_wait_seconds=metadata.get('capture_wait_seconds'))
            result.update({k:v for k,v in metadata.items() if k!='capture_seconds' and k!='capture_wait_seconds'})
            return result
        except Exception as exc:
            if self.prefetch is not None:self.prefetch.cancel()
            db.conn.rollback()
            # Fixed codes only; never persist raw ES/driver messages or credentials.
            code='capture_or_publication_failed'
            if isinstance(exc,ValueError) and str(exc) in (
                'capture_proof_incomplete','capture_bounds_or_count_invalid',
                'capture_ingest_rejected','affected_dependency_budget_exceeded'):
                code=str(exc)
            try:
                db.sql("UPDATE viewer_live_state SET last_error=?,worker_status='retry_pending' WHERE id=1",(code,))
                db.conn.commit()
            except Exception:db.conn.rollback()
            raise RuntimeError(code) from None
