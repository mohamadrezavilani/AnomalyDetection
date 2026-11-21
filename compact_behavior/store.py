"""One compact publication transaction, with no reads of legacy tables."""
from __future__ import annotations
from collections import Counter
import re
import time
from . import CONTRACT, EXTRACTOR, FEATURES, FIVE
from .extract import Limits, LimitExceeded, canonical, digest, behavior_id, merge, materialize


class Store:
    def __init__(self,config,*,schema='p24_compact',limits=Limits()):
        if not re.fullmatch(r'p24_compact(?:_[a-z0-9_]{1,40})?',schema):raise ValueError('compact_schema_required')
        import psycopg
        from psycopg.rows import dict_row
        parameters={k:v for k,v in config.items() if k not in ('autocommit','row_factory','options','application_name')}
        parameters.update(autocommit=True,row_factory=dict_row,connect_timeout=10,
                          application_name='P24.Compact.prototype',options='-c statement_timeout=60000 -c jit=off')
        self.conn=psycopg.connect(**parameters);self.schema=schema;self.limits=limits
    def close(self):self.conn.close()
    def init(self):
        s=self.schema
        with self.conn.transaction():
            self.conn.execute(f'CREATE SCHEMA IF NOT EXISTS {s}')
            for statement in [
                f'''CREATE TABLE IF NOT EXISTS {s}.streams(stream_id TEXT PRIMARY KEY,contract TEXT NOT NULL,
                    extractor TEXT NOT NULL,feature_version TEXT NOT NULL,start_ns BIGINT NOT NULL,next_ns BIGINT NOT NULL)''',
                f'''CREATE TABLE IF NOT EXISTS {s}.behaviors(behavior_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,session_id TEXT,observed_at_ns BIGINT,api TEXT,reported_duration DOUBLE PRECISION,
                    result_code TEXT,result_kind TEXT NOT NULL,kind TEXT NOT NULL,quality JSONB NOT NULL,
                    features JSONB NOT NULL,content_hash TEXT NOT NULL,revision BIGINT NOT NULL DEFAULT 1)''',
                f'CREATE INDEX IF NOT EXISTS compact_session_time ON {s}.behaviors(stream_id,session_id,observed_at_ns,behavior_id)',
                f'CREATE INDEX IF NOT EXISTS compact_time ON {s}.behaviors(stream_id,observed_at_ns,behavior_id)',
                f'CREATE TABLE IF NOT EXISTS {s}.behavior_payloads(behavior_id TEXT PRIMARY KEY,state JSONB NOT NULL)',
                f'''CREATE TABLE IF NOT EXISTS {s}.pending_requests(behavior_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
                    state JSONB NOT NULL,content_hash TEXT NOT NULL)''',
                f'''CREATE TABLE IF NOT EXISTS {s}.dirty_windows(stream_id TEXT NOT NULL,session_id TEXT NOT NULL,
                    start_ns BIGINT NOT NULL,version BIGINT NOT NULL DEFAULT 1,processed_version BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY(stream_id,session_id,start_ns))''',
                f'''CREATE TABLE IF NOT EXISTS {s}.windows(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,end_ns BIGINT NOT NULL,
                    source_records BIGINT NOT NULL,extracted_requests BIGINT NOT NULL,content_hash TEXT NOT NULL,
                    PRIMARY KEY(stream_id,start_ns))''',
            ]:self.conn.execute(statement)
    def cursor(self,stream):
        row=self.conn.execute(f'SELECT next_ns FROM {self.schema}.streams WHERE stream_id=%s',(stream,)).fetchone()
        return row['next_ns'] if row else None
    def publish(self,stream,start,end,states,source_records,*,fault=None):
        from psycopg.types.json import Jsonb
        if end-start!=FIVE or start%FIVE:raise ValueError('aligned_five_minute_window_required')
        if len(states)>self.limits.requests:raise LimitExceeded('window_request_limit')
        s=self.schema;began=time.monotonic();times={};phase=time.monotonic()
        context=self.conn.transaction();context.__enter__();exiting=False
        try:
            # One publisher for this stream, without a global cross-stream lock.
            number=int(digest(stream)[:15],16)
            self.conn.execute('SELECT pg_advisory_xact_lock(%s)',(number,))
            row=self.conn.execute(f'SELECT * FROM {s}.streams WHERE stream_id=%s FOR UPDATE',(stream,)).fetchone()
            if row:
                if (row['contract'],row['extractor'],row['feature_version'])!=(CONTRACT,EXTRACTOR,FEATURES):
                    raise ValueError('compact_input_contract_changed')
                if start>row['next_ns']:raise ValueError('compact_checkpoint_gap')
            else:
                self.conn.execute(f'INSERT INTO {s}.streams VALUES(%s,%s,%s,%s,%s,%s)',(stream,CONTRACT,EXTRACTOR,FEATURES,start,start))
            existed=self.conn.execute(f'SELECT 1 FROM {s}.windows WHERE stream_id=%s AND start_ns=%s',(stream,start)).fetchone()
            if row and start<row['next_ns'] and not existed:raise ValueError('window_before_stream_start')
            self.conn.execute('CREATE TEMP TABLE compact_keys(behavior_id TEXT PRIMARY KEY) ON COMMIT DROP')
            keyed={behavior_id(stream,k):v for k,v in states.items()}
            with self.conn.cursor().copy('COPY compact_keys FROM STDIN') as copy:
                for key in keyed:copy.write_row((key,))
            # Indexed lookups happen once per request, not once per source log.
            old={r['behavior_id']:r for r in self.conn.execute(f'''SELECT k.behavior_id,p.state,b.session_id,
                    b.observed_at_ns,b.content_hash,b.revision FROM compact_keys k CROSS JOIN LATERAL
                    (SELECT * FROM {s}.behavior_payloads p WHERE p.behavior_id=k.behavior_id LIMIT 1) p
                    JOIN {s}.behaviors b ON b.behavior_id=k.behavior_id
                    UNION ALL SELECT k.behavior_id,p.state,NULL,NULL,p.content_hash,0::bigint FROM compact_keys k
                    CROSS JOIN LATERAL(SELECT * FROM {s}.pending_requests p WHERE p.behavior_id=k.behavior_id LIMIT 1) p''').fetchall()}
            times['read_existing_seconds']=time.monotonic()-phase;phase=time.monotonic()
            changed=[];pending=[];dirty=set();quality=Counter();inserted=updated=unchanged=0
            for key,incoming in keyed.items():
                previous=old.get(key);state=merge(previous['state'],incoming,self.limits) if previous else incoming
                body=materialize(stream,state)
                if body is None:
                    signature=digest(state)
                    if not previous or signature!=previous['content_hash']:pending.append((key,stream,Jsonb(state),signature))
                    continue
                quality.update(body['quality']);signature=digest([body,state])
                if previous and previous['revision'] and signature==previous['content_hash']:unchanged+=1;continue
                inserted+=not previous or not previous['revision'];updated+=bool(previous and previous['revision'])
                for session,at in [(body['session_id'],body['observed_at_ns']),
                                   (previous['session_id'],previous['observed_at_ns']) if previous else (None,None)]:
                    if session is not None and at is not None:dirty.add((stream,session,at//FIVE*FIVE))
                changed.append((key,stream,body['request_id'],body['session_id'],body['observed_at_ns'],body['api'],
                                body['reported_duration'],body['result_code'],body['result_kind'],body['kind'],
                                Jsonb(body['quality']),Jsonb(body['features']),signature,Jsonb(state)))
            times['merge_features_seconds']=time.monotonic()-phase;phase=time.monotonic()
            self.conn.execute(f'CREATE TEMP TABLE compact_stage (LIKE {s}.behaviors INCLUDING DEFAULTS) ON COMMIT DROP')
            self.conn.execute('ALTER TABLE compact_stage ADD COLUMN state JSONB')
            cols='behavior_id,stream_id,request_id,session_id,observed_at_ns,api,reported_duration,result_code,result_kind,kind,quality,features,content_hash'
            with self.conn.cursor().copy('COPY compact_stage('+cols+',state) FROM STDIN') as copy:
                for value in changed:copy.write_row(value)
            assignment=','.join(f'{name}=excluded.{name}' for name in cols.split(',') if name!='behavior_id')
            self.conn.execute(f'''INSERT INTO {s}.behaviors({cols}) SELECT {cols} FROM compact_stage ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET {assignment},revision={s}.behaviors.revision+1
                WHERE {s}.behaviors.content_hash IS DISTINCT FROM excluded.content_hash''')
            self.conn.execute(f'''INSERT INTO {s}.behavior_payloads SELECT behavior_id,state FROM compact_stage ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET state=excluded.state
                WHERE {s}.behavior_payloads.state IS DISTINCT FROM excluded.state''')
            self.conn.execute(f'DELETE FROM {s}.pending_requests p USING compact_stage x WHERE p.behavior_id=x.behavior_id')
            self.conn.execute('CREATE TEMP TABLE compact_pending(behavior_id TEXT,stream_id TEXT,state JSONB,content_hash TEXT) ON COMMIT DROP')
            with self.conn.cursor().copy('COPY compact_pending FROM STDIN') as copy:
                for value in pending:copy.write_row(value)
            self.conn.execute(f'''INSERT INTO {s}.pending_requests SELECT * FROM compact_pending ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET state=excluded.state,content_hash=excluded.content_hash
                WHERE {s}.pending_requests.content_hash IS DISTINCT FROM excluded.content_hash''')
            self.conn.execute('CREATE TEMP TABLE compact_dirty(stream_id TEXT,session_id TEXT,start_ns BIGINT) ON COMMIT DROP')
            with self.conn.cursor().copy('COPY compact_dirty FROM STDIN') as copy:
                for value in sorted(dirty):copy.write_row(value)
            self.conn.execute(f'''INSERT INTO {s}.dirty_windows(stream_id,session_id,start_ns) SELECT * FROM compact_dirty
                ON CONFLICT(stream_id,session_id,start_ns) DO UPDATE SET version={s}.dirty_windows.version+1''')
            pending_total=self.conn.execute(f'SELECT count(*) AS n FROM {s}.pending_requests').fetchone()['n']
            dirty_total=self.conn.execute(f'SELECT count(*) AS n FROM {s}.dirty_windows WHERE processed_version<version').fetchone()['n']
            if pending_total>self.limits.pending_requests:raise LimitExceeded('pending_request_limit_no_checkpoint_advance')
            if dirty_total>self.limits.dirty_windows:raise LimitExceeded('dirty_window_limit_no_checkpoint_advance')
            window_hash=digest([source_records,sorted((k,digest(v)) for k,v in keyed.items())])
            self.conn.execute(f'''INSERT INTO {s}.windows VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(stream_id,start_ns)
                DO UPDATE SET source_records=excluded.source_records,extracted_requests=excluded.extracted_requests,
                content_hash=excluded.content_hash WHERE {s}.windows.content_hash IS DISTINCT FROM excluded.content_hash''',
                (stream,start,end,source_records,len(states),window_hash))
            self.conn.execute(f'UPDATE {s}.streams SET next_ns=GREATEST(next_ns,%s) WHERE stream_id=%s',(end,stream))
            times['write_seconds']=time.monotonic()-phase
            if fault:fault('before_commit')
            phase=time.monotonic();exiting=True;context.__exit__(None,None,None);times['commit_seconds']=time.monotonic()-phase
        except BaseException as exc:
            if not exiting:context.__exit__(type(exc),exc,exc.__traceback__)
            raise
        if fault:fault('after_commit')
        return dict(status='COMPACT_WINDOW_COMMITTED',fresh_publication=not bool(existed),start_ns=start,end_ns=end,
                    source_records=source_records,requests=len(states),inserted=int(inserted),updated=int(updated),
                    unchanged=unchanged,pending_requests=pending_total,dirty_windows=dirty_total,
                    changed_quality=dict(quality),database_seconds=time.monotonic()-began,**times)
    def measure(self):
        s=self.schema
        rows=self.conn.execute('''SELECT c.relname,pg_total_relation_size(c.oid) AS total_bytes
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='r'
            ORDER BY c.relname''',(s,)).fetchall()
        counts={name:self.conn.execute(f'SELECT count(*) AS n FROM {s}.{name}').fetchone()['n']
                for name in ['behaviors','behavior_payloads','pending_requests','dirty_windows','windows']}
        import json
        backend=self.conn.info.backend_pid;stats={}
        if self.conn.info.server_version>=180000:
            for label,fn in [('io','pg_stat_get_backend_io'),('wal','pg_stat_get_backend_wal')]:
                values=[dict(r) for r in self.conn.execute(f'SELECT * FROM {fn}(%s)',(backend,)).fetchall()]
                stats[label]=json.loads(json.dumps(values,default=str))
        return dict(tables=[dict(x) for x in rows],rows=counts,total_bytes=sum(x['total_bytes'] for x in rows),
                    backend_pid=backend,backend_cumulative_stats=stats,
                    backend_stats_limitations='Snapshots can lag; reads include OS cache; RSS is not summed across PG backends.')
