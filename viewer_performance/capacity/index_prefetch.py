"""Qualification only: bounded, disposable read-ahead before indexed writes.

Read results never decide identity, duplication or publication. The publisher
still uses the original COPY/INSERT statements and its own transaction. Reader
connections only touch already committed index pages; an invisible concurrent
row or failed hint cannot make an evidence row disappear.
"""
from concurrent.futures import FIRST_COMPLETED,ThreadPoolExecutor,wait
import threading
import time
import uuid

from p24_foundation.viewer_origin_storage import active,key_sql
from .local_projection_keys import LocalProjectionKeysDB

TABLES=('viewer_events','viewer_raw_events')
BATCH=128
DEADLINE_SECONDS=20
STATEMENT_MS=3000


def probe_sql(table):
    if table not in TABLES:raise ValueError('prefetch_table_not_allowed')
    return ('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT found.hit FROM '
        'unnest(%s::text[],%s::text[]) AS wanted(origin_key,version_key) '
        'CROSS JOIN LATERAL (SELECT 1 AS hit FROM public.'+table+' stored WHERE '+
        key_sql('stored.origin_key')+'='+key_sql('wanted.origin_key')+' AND '+
        key_sql('stored.version_key')+'='+key_sql('wanted.version_key')+
        ' OFFSET 0) found')


class IndexPrefetchDB(LocalProjectionKeysDB):
    def __init__(self,*,prefetch_workers=2,**kwargs):
        if prefetch_workers not in (1,2,4):raise ValueError('prefetch_workers_must_be_1_2_or_4')
        super().__init__(**kwargs)
        self._prefetch_config=dict(kwargs.get('config') or {})
        self._prefetch_workers=prefetch_workers
        self._prefetch_ready=False
        self._prefetch_pool=None
        self._prefetch_local=threading.local()
        self._prefetch_connections=[]
        self._prefetch_lock=threading.Lock()
        self.prefetch_stats=dict(workers=prefetch_workers,batch_keys=BATCH,
            max_inflight_keys=prefetch_workers*BATCH,max_pending_observed=0,
            deadline_seconds_per_table=DEADLINE_SECONDS,statement_timeout_ms=STATEMENT_MS,
            calls=0,keys=0,batches=0,successful_batches=0,failures_total=0,wall_seconds=0.,reader_query_seconds=0.,
            shared_read_blocks=0,shared_hit_blocks=0,deadline_stops=0,failures=[],
            readonly_connections_verified=0,results_used_for_semantic_decisions=False,
            main_write_statements_changed=False,physical_disk_reads_inferred=False,
            helper_counters_are_not_writer_counters=True)

    def prepare_candidate(self):
        result=super().prepare_candidate()
        if not self.sqlite:
            if not active(self):raise ValueError('prefetch_requires_binary_origin_layout')
            self._prefetch_pool=self._prefetch_pool or ThreadPoolExecutor(max_workers=self._prefetch_workers,
                thread_name_prefix='capacity-readonly')
            self._prefetch_ready=True
        return dict(result,prefetch_workers=self._prefetch_workers,native_exercised=not self.sqlite)

    def _reader(self):
        import psycopg
        reader=getattr(self._prefetch_local,'reader',None)
        if reader is None or reader.closed:
            config=dict(self._prefetch_config)
            config['connect_timeout']=3
            config['application_name']='P24.Capacity.index-prefetch'
            config['options']=(config.get('options','')+' -c default_transaction_read_only=on'
                ' -c statement_timeout='+str(STATEMENT_MS)+' -c lock_timeout=100'
                ' -c max_parallel_workers_per_gather=0')
            reader=psycopg.connect(**config,autocommit=True)
            try:
                readonly=reader.execute("SELECT current_setting('transaction_read_only')").fetchone()[0]
                if readonly!='on':raise ValueError('prefetch_reader_not_readonly')
            except BaseException:
                reader.close();raise
            self._prefetch_local.reader=reader
            with self._prefetch_lock:
                self._prefetch_connections=[r for r in self._prefetch_connections if not r.closed]
                self._prefetch_connections.append(reader)
                self.prefetch_stats['readonly_connections_verified']+=1
        return reader

    def _probe(self,table,keys):
        started=time.perf_counter()
        try:
            reader=self._reader()
            row=reader.execute(probe_sql(table),([r['origin_key'] for r in keys],
                [r['version_key'] for r in keys])).fetchone()
            # Only root cumulative counters: never sum parent and child nodes.
            plan=row[0][0]['Plan']
            return dict(keys=len(keys),query_seconds=time.perf_counter()-started,
                shared_read_blocks=plan.get('Shared Read Blocks',0),
                shared_hit_blocks=plan.get('Shared Hit Blocks',0))
        except Exception as exc:
            # No exception text, DSN, keys, query or plan predicates in receipts.
            return dict(keys=len(keys),query_seconds=time.perf_counter()-started,
                failure=dict(error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None)))

    def _record(self,future):
        result=future.result();stats=self.prefetch_stats
        stats['keys']+=result['keys'];stats['batches']+=1
        stats['reader_query_seconds']+=result['query_seconds']
        stats['shared_read_blocks']+=result.get('shared_read_blocks',0)
        stats['shared_hit_blocks']+=result.get('shared_hit_blocks',0)
        if result.get('failure'):
            stats['failures_total']+=1
            # Bound diagnostics even if all hints fail for the entire history.
            if len(stats['failures'])<16:stats['failures'].append(result['failure'])
        else:stats['successful_batches']+=1

    def _prefetch(self,stage,table):
        if not self._prefetch_ready:return
        if table not in TABLES or stage!='viewer_stage_'+table.removeprefix('viewer_'):
            raise ValueError('prefetch_stage_not_allowed')
        began=time.perf_counter();deadline=began+DEADLINE_SECONDS
        self.prefetch_stats['calls']+=1
        pending=set()
        cursor=self.conn.cursor(name='capacity_prefetch_'+uuid.uuid4().hex)
        try:
            cursor.execute('SELECT origin_key,version_key FROM '+stage+' ORDER BY origin_key,version_key')
            while time.perf_counter()<deadline:
                keys=[dict(row) for row in cursor.fetchmany(BATCH)]
                if not keys:break
                pending.add(self._prefetch_pool.submit(self._probe,table,keys))
                self.prefetch_stats['max_pending_observed']=max(
                    self.prefetch_stats['max_pending_observed'],len(pending))
                if len(pending)>=self._prefetch_workers:
                    done,pending=wait(pending,return_when=FIRST_COMPLETED)
                    for future in done:self._record(future)
            else:self.prefetch_stats['deadline_stops']+=1
        finally:
            cursor.close()
            # At most workers outstanding, each with its own 3-second SQL and
            # connection bounds. All connections are read-only and results are
            # discarded before the unchanged authoritative write proceeds.
            for future in pending:self._record(future)
            self.prefetch_stats['wall_seconds']+=time.perf_counter()-began

    def _copy_ingest_stage_into_table(self,stage,table,columns,order):
        if table=='viewer_events':self._prefetch(stage,table)
        return super()._copy_ingest_stage_into_table(stage,table,columns,order)

    def _insert_ingest_stage_into_table(self,stage,table,columns,order,conflict=''):
        if table=='viewer_raw_events':self._prefetch(stage,table)
        return super()._insert_ingest_stage_into_table(stage,table,columns,order,conflict)

    def candidate_report(self):
        return dict(super().candidate_report(),index_prefetch=self.prefetch_stats)

    def close(self):
        try:
            if self._prefetch_pool:self._prefetch_pool.shutdown(wait=True,cancel_futures=True)
            for reader in self._prefetch_connections:reader.close()
        finally:super().close()
