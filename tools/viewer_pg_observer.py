"""Read-only bounded PostgreSQL telemetry for exactly one native Viewer probe.

Separate observer connection; never logs SQL text, credentials, raw evidence or
parameter values. Cluster-wide deltas are informational, not per-PID attribution.
"""
from __future__ import annotations
import importlib.util
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


def load_viewer_database(path):
    spec=importlib.util.spec_from_file_location('viewer_observer_local_config',Path(path).resolve())
    if spec is None or spec.loader is None:raise ValueError('private_config_unavailable')
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    name=str(cfg.DATABASE.get('dbname',''))
    if name!='p24_design_viewer':raise ValueError('observer_requires_p24_design_viewer')
    return dict(cfg.DATABASE)


def numeric_delta(before,after):
    """Report only nonnegative monotonic deltas; stats may reset during a run."""
    if not isinstance(before,dict) or not isinstance(after,dict):return None
    result={}
    for key,value in after.items():
        old=before.get(key)
        if isinstance(value,(float,int)) and not isinstance(value,bool) and isinstance(old,(float,int)):
            diff=value-old
            result[key]=round(diff,3) if diff>=0 else None
    return result or None


class PostgreSQLObserver:
    INTERVAL_SECONDS=2
    MAX_SAMPLES=390

    def __init__(self,config,backend_pid,*,interval=None):
        self.config=dict(config);self.backend_pid=backend_pid
        self.interval=interval if interval is not None else self.INTERVAL_SECONDS
        self.samples=[];self.errors=[];self.start_stats={};self.end_stats={}
        self.inventory=[];self.settings=[];self._stop=threading.Event();self._thread=None
        self.status='NOT_STARTED';self.started_at_utc=None

    def start(self):
        if self._thread is not None:raise ValueError('observer_already_started')
        self._thread=threading.Thread(target=self._run,name='viewer-pg-readonly-observer',daemon=True)
        self._thread.start()
        return self

    @staticmethod
    def _fetch(conn,query,args=()):
        with conn.cursor() as cur:
            cur.execute(query,args)
            names=[d.name for d in cur.description] if cur.description else []
            return [dict(zip(names,row)) for row in cur.fetchall()]

    def _optional(self,conn,name,query,args=()):
        try:return self._fetch(conn,query,args)
        except Exception as exc:
            if name not in self.errors:
                self.errors.append(name)
            return None

    def _stats(self,conn):
        result={}
        # Cluster-global counters may contain activity from other databases.
        for name,query in (
            ('database', '''SELECT blks_read,blks_hit,tup_inserted,tup_updated,
                      temp_bytes,deadlocks FROM pg_stat_database WHERE datname=current_database()'''),
            ('wal', 'SELECT wal_records,wal_fpi,wal_bytes FROM pg_stat_wal'),
            ('checkpointer', '''SELECT num_timed,num_requested,write_time,sync_time,
                               buffers_written FROM pg_stat_checkpointer'''),
            ('io', '''SELECT COALESCE(sum(reads),0) AS reads,COALESCE(sum(writes),0) AS writes,
                     COALESCE(sum(extends),0) AS extends,COALESCE(sum(fsyncs),0) AS fsyncs,
                     COALESCE(sum(read_time),0) AS read_time,
                     COALESCE(sum(write_time),0) AS write_time
                     FROM pg_stat_io''')):
            rows=self._optional(conn,name,query)
            if rows:result[name]={k:float(v) if hasattr(v,'as_tuple') else v for k,v in rows[0].items() if v is not None}
        return result

    def _inventory(self,conn):
        settings=self._optional(conn,'settings',"""SELECT name,setting,unit,pending_restart
            FROM pg_settings WHERE name=ANY(%s) ORDER BY name""",(list((
                'server_version','shared_buffers','work_mem','wal_buffers','wal_compression',
                'max_wal_size','min_wal_size','checkpoint_timeout','checkpoint_completion_target',
                'wal_init_zero','wal_recycle','full_page_writes','fsync','synchronous_commit',
                'track_io_timing','track_wal_io_timing','wal_level')),))
        if settings:self.settings=settings
        names=('viewer_events','viewer_raw_events','viewer_event_captures','viewer_links','viewer_requests')
        rows=self._optional(conn,'relation_inventory','''
          SELECT relname,n_live_tup,n_dead_tup,last_autovacuum,last_autoanalyze,
           pg_relation_size(relid) AS heap_bytes,pg_indexes_size(relid) AS index_bytes
          FROM pg_stat_user_tables WHERE schemaname=current_schema()
          AND relname = ANY(%s) ORDER BY relname''',(list(names),))
        if rows:
            self.inventory=[{k:(v.isoformat() if hasattr(v,'isoformat') else v)
                             for k,v in row.items()} for row in rows]

    def _sample(self,conn):
        activity=self._optional(conn,'activity','''
           SELECT state,wait_event_type,wait_event,
                cardinality(pg_blocking_pids(pid)) AS blockers
           FROM pg_stat_activity WHERE pid=%s''',(self.backend_pid,))
        progress=self._optional(conn,'copy_progress','''
           SELECT command,type,bytes_processed,tuples_processed
           FROM pg_stat_progress_copy WHERE pid=%s''',(self.backend_pid,))
        now=datetime.now(timezone.utc).isoformat()
        row=dict(at_utc=now,elapsed_seconds=round(time.monotonic()-self._started,2))
        if activity:row.update({k:v for k,v in activity[0].items() if v is not None})
        if progress:row['copy']={k:v for k,v in progress[0].items() if v is not None}
        self.samples.append(row)

    def _run(self):
        self._started=time.monotonic();self.started_at_utc=datetime.now(timezone.utc).isoformat()
        try:
            import psycopg
            options=dict(self.config);options['connect_timeout']=min(5,int(options.get('connect_timeout',5)))
            with psycopg.connect(**options,autocommit=True) as conn:
                conn.execute('SET statement_timeout = 2000')
                conn.execute('SET default_transaction_read_only = on')
                self.status='ACTIVE';self._inventory(conn);self.start_stats=self._stats(conn)
                while len(self.samples)<self.MAX_SAMPLES and not self._stop.is_set():
                    self._sample(conn)
                    if self._stop.wait(self.interval):break
                self.end_stats=self._stats(conn)
        except Exception as exc:
            self.status='NOT_AVAILABLE' if not self.samples else 'PARTIAL'
            self.errors.append('observer_'+type(exc).__name__)

    def stop(self):
        self._stop.set()
        if self._thread:self._thread.join(timeout=9)
        if self._thread and self._thread.is_alive():self.errors.append('observer_shutdown_timeout')
        deltas={}
        for name in ('database','wal','checkpointer','io'):
            delta=numeric_delta(self.start_stats.get(name),self.end_stats.get(name))
            if delta:deltas[name]=delta
        wait_summary={}
        for sample in self.samples:
            key=(sample.get('wait_event_type') or 'none')+'/'+(sample.get('wait_event') or 'none')
            wait_summary[key]=wait_summary.get(key,0)+1
        return dict(status=self.status,backend_pid=self.backend_pid,sample_interval_seconds=self.interval,
            samples=self.samples,wait_sample_counts=wait_summary,relation_inventory=self.inventory,
            postgres_settings=self.settings,
            counter_deltas=deltas,unavailable_metrics=self.errors,
            limitations=['WAL/checkpointer/pg_stat_io are cluster-wide, not attributable to this PID',
                         'Sampler interval can miss short waits; no SQL text or payload recorded',
                         'Counters can reset; negative deltas are not reported'])
