"""Three bounded, instrumented production-DB lanes; no database copies.

Viewer-only publishes fresh windows, AD-only observes their target queues,
then both process the next fresh windows. This is a live diagnostic, not a
paired speedup experiment. Run the downloaded file outside the installation.
"""
import argparse
from contextlib import contextmanager
import cProfile
from datetime import datetime,timezone
from functools import wraps
import hashlib
import json
import re
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
import time
import uuid
import zipfile

TOOL='P24-THREE-MODE-20261119-1'
FIVE=300_000_000_000


def read(path,default=None):
    try:return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except (OSError,ValueError):return default


def save(path,value):
    from p24_foundation.viewer_runtime import atomic_json
    atomic_json(Path(path),value)


def notice(status,**values):
    print(json.dumps(dict(status=status,**values),ensure_ascii=True,default=str),flush=True)


def failure(exc):
    value=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
               sqlstate=getattr(exc,'sqlstate',None))
    if isinstance(getattr(exc,'details',None),dict):value['details']=exc.details
    return value


class StopDiagnostic(BaseException):pass


class RuntimeProfile:
    """Installed computation is unchanged; connection proxies only time calls."""
    def __init__(self,project,directory,role,seconds,*,monitor_interval=5):
        from viewer_performance.capacity.trace import Trace
        self.project=Path(project);self.directory=Path(directory);self.role=role
        self.trace=Trace();self.profiler=cProfile.Profile();self.done=threading.Event()
        self.monitor_interval=monitor_interval
        self.connections=[];self.began=time.monotonic();self.deadline=self.began+seconds
        self.state=dict(tool=TOOL,role=role,status='STARTING',pid=os.getpid(),windows=[],
            instrumented=True,instrumentation_overhead_included=True,actor_evaluation_attempts_in_targets=0,
            actor_evaluation_attempts_outside_targets=0,full_method_acceptance='NOT_ASSIGNED')
        self.lock=threading.Lock();self.thread=threading.Thread(target=self.monitor,daemon=True)

    def stopping(self):return time.monotonic()>=self.deadline or (self.directory/(self.role+'-stop.json')).exists()

    def checkpoint(self):
        if self.stopping():raise StopDiagnostic()

    def report(self,terminal=False):
        with self.lock:
            result=dict(self.state,elapsed_seconds=round(time.monotonic()-self.began,3),
                client_cpu_seconds=round(time.process_time()-self.cpu_start,3),
                active_backends=[dict(pid=c.info.backend_pid) for c in list(self.connections) if not c.closed],
                trace=self.trace.report())
            result['trace']['limitations']=[s for s in result['trace']['limitations'] if 'Elasticsearch' not in s]
            result['trace']['limitations'].append('Times are diagnostic; no production speed or accuracy acceptance is assigned.')
            if terminal:
                rows=[]
                for item in self.profiler.getstats():
                    code=item.code
                    if isinstance(code,str):name=code
                    else:
                        p=Path(code.co_filename)
                        name=(str(p.relative_to(self.project)) if p.is_relative_to(self.project) else p.name)+':'+str(code.co_firstlineno)+':'+code.co_name
                    rows.append(dict(function=name,calls=item.callcount,self_seconds=item.inlinetime,cumulative_seconds=item.totaltime))
                result['python_top']=sorted(rows,key=lambda x:-x['cumulative_seconds'])[:120]
                result['python_profile_times_are_wall_including_waits']=True
            save(self.directory/(self.role+'.json'),result)

    def monitor(self):
        while not self.done.wait(self.monitor_interval):
            try:self.report()
            except Exception as exc:self.state['report_failure']=failure(exc)
            if self.stopping():
                for connection in list(self.connections):
                    try:
                        if not connection.closed:connection.cancel()
                    except Exception:pass

    def wrap(self,obj,name,label=None):
        original=getattr(obj,name,None)
        if not callable(original):return lambda:None
        @wraps(original)
        def measured(*args,**kwargs):
            self.checkpoint()
            with self.trace.span(label or 'method:'+name):return original(*args,**kwargs)
        setattr(obj,name,measured)
        return lambda:setattr(obj,name,original)

    @contextmanager
    def active(self):
        import psycopg
        from viewer_performance.capacity.trace import Connection,Cursor
        profile=self
        class ProfileCursor(Cursor):
            def fetchone(self):
                value=super().fetchone();profile.state['rows_fetched']=profile.state.get('rows_fetched',0)+int(value is not None);return value
            def fetchall(self):
                value=super().fetchall();profile.state['rows_fetched']=profile.state.get('rows_fetched',0)+len(value);return value
            def fetchmany(self,*args,**kwargs):
                value=super().fetchmany(*args,**kwargs);profile.state['rows_fetched']=profile.state.get('rows_fetched',0)+len(value);return value
            def __iter__(self):
                for value in super().__iter__():
                    profile.state['rows_fetched']=profile.state.get('rows_fetched',0)+1;yield value
        class ProfileConnection(Connection):
            def __setattr__(self,name,value):
                if name in ('raw','trace'):object.__setattr__(self,name,value)
                else:setattr(self.raw,name,value)
            def execute(self,statement,*args,**kwargs):
                profile.checkpoint()
                with self.trace.span('driver:execute',statement):value=self.raw.execute(statement,*args,**kwargs)
                return ProfileCursor(value,self.trace)
            def cursor(self,*args,**kwargs):return ProfileCursor(self.raw.cursor(*args,**kwargs),self.trace)
            def __enter__(self):self.raw.__enter__();return self
            def __exit__(self,*args):
                with self.trace.span('driver:connection_exit'):return self.raw.__exit__(*args)
        original=psycopg.connect
        from viewer_performance.capacity import trace as trace_module
        original_relations=trace_module.RELATIONS
        trace_module.RELATIONS=re.compile(r'\b(?:viewer_|adp_)[a-z][a-z0-9_]*\b',re.I)
        trace_module.signature.cache_clear()
        def connect(*args,**kwargs):
            profile.checkpoint()
            with profile.trace.span('driver:connect'):raw=original(*args,**kwargs)
            self.connections=[c for c in self.connections if not c.closed];self.connections.append(raw)
            return ProfileConnection(raw,self.trace)
        psycopg.connect=connect;self.cpu_start=time.process_time();self.profiler.enable();self.thread.start()
        try:
            with self.trace.span('role:total'):yield self
        finally:
            self.profiler.disable();psycopg.connect=original;self.done.set();self.thread.join(10);self.report(terminal=True)
            trace_module.RELATIONS=original_relations;trace_module.signature.cache_clear()


def viewer_lane(profile,windows):
    from viewer_performance import fast_writer
    from viewer_performance.Run_Viewer_Web import existing_options
    from viewer_performance.Run_Viewer_Memory import memory_info
    from viewer_performance.Run_Viewer_Catchup import (choose_overrides,supported_compression,activate_profile,SETTINGS_SQL,NAMES)
    from viewer_performance.history_replay import HistoryReplay,pending_day
    from p24_foundation import viewer_data,viewer_online
    from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture
    from viewer_performance.capacity.trace import METHODS
    project=profile.project;cfg=runpy.run_path(str(project/'viewer_config.local.py'))
    settings=cfg.get('LIVE') or {};options=existing_options(project)
    import psycopg
    from psycopg.rows import dict_row
    parameters=dict(options['config']);parameters.pop('autocommit',None);parameters.pop('row_factory',None)
    with psycopg.connect(**parameters,autocommit=True,row_factory=dict_row) as conn:
        before={r['name']:r for r in conn.execute(SETTINGS_SQL,(list(NAMES),)).fetchall()}
        compression=supported_compression(conn)
    selected=read(profile.directory.parent/'settings.json',{})
    overrides=selected.get('writer_overrides')
    if overrides is None:overrides=choose_overrides(before,memory_info(),compression)
    directory=Path(settings.get('capture_dir','private/viewer_captures'))
    if not directory.is_absolute():directory=project/directory
    capture=ElasticCapture(ElasticREST(cfg['ELASTICSEARCH']),directory,page_size=settings.get('page_size',5000),
                          max_seconds=settings.get('capture_budget_seconds',240))
    def acquire(begin,end):
        profile.checkpoint()
        with profile.trace.span('source:elasticsearch_capture'):path=capture(begin,end)
        with profile.trace.span('source:capture_hash'):
            digest=hashlib.sha256()
            with Path(path).open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
            profile.state.setdefault('captures',[]).append(dict(path=str(path),start_ns=begin,end_ns=end,
                compressed_bytes=Path(path).stat().st_size,compressed_sha256=digest.hexdigest()))
        return path
    with fast_writer.activate(),activate_profile(viewer_data,before,overrides):
        with viewer_data.ViewerDB(**options) as db,viewer_online.single_worker(db,directory/'viewer_worker.lock'):
            profile.state['status']='INITIALIZING'
            with profile.trace.span('setup:viewer_init'):db.init();viewer_online.initialize_live(db)
            # The existing stream and replay are adopted, never initialized at
            # a new date and never handed off to an automatically spawned AD.
            day=pending_day(db);db.conn.rollback()
            replay=HistoryReplay(db,day) if day else None
            profile.state['selected_session_overrides']=overrides
            profile.state['effective_writer_settings']=db.all(SETTINGS_SQL.replace('%s','?'),(list(NAMES),));db.conn.rollback()
            profile.state['backend_pid']=db.conn.info.backend_pid
            profile.state['writer_identity']=dict(db.writer_identity.record)
            restores=[profile.wrap(db,name,'viewer:'+name) for name in (*METHODS,'_rebuild_requests','build_semantic_index')]
            try:
                while len(profile.state['windows'])<windows:
                    profile.checkpoint();profile.state['status']='PUBLISHING'
                    started=time.monotonic();cpu=time.process_time()
                    with profile.trace.span('viewer:whole_window'):
                        if replay:
                            outcome=replay.step(acquire)
                            if outcome['status']=='HISTORY_REPLAY_COMPLETE':replay=None;continue
                            if outcome['status']!='HISTORY_WINDOW_PUBLISHED':
                                profile.state['complete_windows_skipped']=profile.state.get('complete_windows_skipped',0)+outcome.get('skipped',0)
                                continue
                            result=outcome['publication']
                        else:
                            row=db.one('SELECT * FROM viewer_live_state WHERE id=1');db.conn.rollback();begin=row['next_ns']
                            if begin+FIVE>time.time_ns()-row['lag_seconds']*1_000_000_000:
                                with profile.trace.span('viewer:wait_for_source'):time.sleep(1)
                                continue
                            capture_started=time.monotonic();path=acquire(begin,begin+FIVE);capture_seconds=time.monotonic()-capture_started
                            result=viewer_online.publish_capture(db,path,begin,begin+FIVE,capture_seconds=capture_seconds)
                    start_ns=int(datetime.fromisoformat(result['window_start_utc'].replace('Z','+00:00')).timestamp())*1_000_000_000
                    profile.state['windows'].append(dict(result,start_ns=start_ns,end_ns=start_ns+FIVE,whole_cycle_seconds=time.monotonic()-started,
                        client_cpu_seconds=time.process_time()-cpu))
                    profile.report()
                profile.state['status']='THREE_FRESH_PUBLICATIONS_FINISHED'
            finally:
                for restore in reversed(restores):restore()


def ad_lane(profile):
    sys.path.insert(0,str(profile.project/'AnomalyDetection'))
    from anomaly_detection import product_worker,product_store,product_source,runtime_lanes,scenario_worker
    from anomaly_detection import product_engine,scenario_store,population
    from anomaly_detection.process_control import write_json
    manifest=read(profile.project/'AnomalyDetection/RELEASE_MANIFEST.json')
    class CountedCache(dict):
        def __init__(self,values,label):
            super().__init__(values);self.counts=profile.state.setdefault('cache_probes',{}).setdefault(label,dict(hits=0,misses=0,clears=0,removed_entries=0))
        def __contains__(self,key):
            found=super().__contains__(key);self.counts['hits' if found else 'misses']+=1;return found
        def get(self,key,default=None):
            found=dict.__contains__(self,key);self.counts['hits' if found else 'misses']+=1;return super().get(key,default)
        def clear(self):self.counts['clears']+=1;self.counts['removed_entries']+=len(self);return super().clear()
    original_init=product_store.ProductStore.__init__
    def init(store,*args,**kwargs):
        original_init(store,*args,**kwargs)
        for label in ('model_cache','reference_inputs_cache'):setattr(store,label,CountedCache(getattr(store,label),label))
    product_store.ProductStore.__init__=init
    from anomaly_detection.viewer_priority import ViewerPriority
    original_admit=ViewerPriority.admit
    def admit(*args,**kwargs):
        with profile.trace.span('ad:admission_probe'):result=original_admit(*args,**kwargs)
        profile.state['admission']=result;return result
    ViewerPriority.admit=admit
    def observed_write(path,value):
        if Path(path).name=='product_status.json':
            profile.state['worker']={k:value.get(k) for k in ('state','phase','scenario_phase','owner','heartbeat_ns',
                'pid','instance_token','build_id','source_sha256',
                'evaluated_jobs','scenario_evaluations','source_pages','audited_requests','source_failures_total',
                'owned_apply_failures_total','scenario_failures_total','evaluation_timeouts_total','input_contract',
                'input_contract_check','behavior_scope_migration','last_source_failure','last_storage_failure','last_scenario_failure')}
            for key in ('window_lanes','last_source_failure_event','last_owned_apply_failure_event','last_evaluation_failure_event','last_fatal_failure'):
                profile.state['worker'][key]=value.get(key)
        return write_json(path,value)
    old_write=product_worker.write_json;product_worker.write_json=observed_write
    restores=[profile.wrap(obj,name,label) for obj,name,label in (
        (runtime_lanes,'maintenance','ad:maintenance'),(scenario_worker,'step','ad:scenario_turn'),
        (scenario_store,'process_one','ad:scenario_model'),(population,'process_one','ad:population_model'),
        (product_store.ProductStore,'complete','ad:save_evaluation'),
        (product_store.ProductStore,'apply_audit','ad:apply_evidence'),
        (product_source.ProductSource,'metadata','ad:source_metadata'),
        (product_source.ProductSource,'audit','ad:source_evidence'))]
    original=product_worker.evaluate_job
    def evaluate(store,job,*args,**kwargs):
        targets=set(read(profile.directory/'targets.json',{}).get('targets',[]))
        inside=job['target_ns'] in targets
        key='actor_evaluation_attempts_in_targets' if inside else 'actor_evaluation_attempts_outside_targets'
        profile.state[key]+=1
        with profile.trace.span('ad:evaluate_'+kwargs.get('mode','full')+(':target' if inside else ':other_history')):return original(store,job,*args,**kwargs)
    product_worker.evaluate_job=evaluate
    def wait(seconds):
        profile.checkpoint();yielding=profile.state.get('admission',{}).get('admitted') is False
        with profile.trace.span('ad:yield_to_viewer' if yielding else 'ad:poll_wait'):time.sleep(seconds)
    try:
        profile.state['status']='RUNNING'
        product_worker.run(profile.project/'AnomalyDetection',manifest['source_sha256'],wait=wait,web=False)
        profile.state['status']='WORKER_RETURNED'
    finally:
        product_worker.write_json=old_write;product_worker.evaluate_job=original
        product_store.ProductStore.__init__=original_init;ViewerPriority.admit=original_admit
        for restore in reversed(restores):restore()


def child(args):
    profile=RuntimeProfile(args.project,args.directory,args.child,args.seconds)
    try:
        with profile.active():
            try:
                if args.child=='viewer':viewer_lane(profile,args.windows)
                else:ad_lane(profile)
            except StopDiagnostic:profile.state['status']='STOPPED_AT_BOUNDARY_OR_DEADLINE'
            except Exception as exc:profile.state.update(status='TIME_LIMIT' if profile.stopping() else 'FAILED',failure=failure(exc))
    except Exception as exc:
        profile.state.update(status='PROFILE_FAILED',failure=failure(exc));profile.cpu_start=time.process_time();profile.report(True)
    return 0 if profile.state['status']!='FAILED' and profile.state['status']!='PROFILE_FAILED' else 2


def source_snapshot(db):
    live=dict(db.execute('SELECT * FROM public.viewer_live_state WHERE id=1').fetchone())
    present=db.execute("SELECT to_regclass('public.viewer_history_replay_state') AS name").fetchone()['name']
    replay=dict(db.execute('SELECT * FROM public.viewer_history_replay_state WHERE id=1').fetchone() or {}) if present else {}
    scope=dict(db.execute('SELECT contract,epoch,state FROM public.viewer_product_scope WHERE id=1').fetchone() or {})
    settings=[dict(r) for r in db.execute("SELECT name,setting,unit FROM pg_settings WHERE name=ANY(%s) ORDER BY name",
        (['shared_buffers','work_mem','temp_buffers','jit','wal_compression','fsync','full_page_writes','synchronous_commit','track_io_timing','track_wal_io_timing'],)).fetchall()]
    return dict(live=live,replay=replay,scope=scope,server_settings=settings)


def target_progress(db,targets):
    if not targets:return dict(status='WAITING_FOR_FRESH_PUBLICATIONS',observed_target_queues_drained=False)
    try:
        with db.transaction():
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            db.execute("SET LOCAL statement_timeout='1000ms'")
            return _target_progress(db,targets)
    except Exception as exc:return dict(status='UNAVAILABLE',failure=failure(exc),observed_target_queues_drained=False)


def _target_progress(db,targets):
    """Observed target work only; empty or timed-out queries are not completion."""
    if not targets:return dict(status='WAITING_FOR_FRESH_PUBLICATIONS',observed_target_queues_drained=False)
    try:
        from AnomalyDetection.anomaly_detection import EVALUATOR_VERSION
        shared=[dict(r) for r in db.execute('SELECT start_ns,complete FROM anomaly_detection.adp_source_windows WHERE start_ns=ANY(%s)',(targets,)).fetchall()]
        actor=dict(db.execute("SELECT COUNT(*) AS total,COUNT(*) FILTER(WHERE dirty OR processed_version<>version OR primary_processed_version IS DISTINCT FROM primary_version OR COALESCE(jsonb_array_length(evaluation::jsonb->'pending_families'),1)>0 OR COALESCE(evaluation::jsonb->>'evaluator_version','')<>%s) AS pending FROM anomaly_detection.adp_jobs WHERE target_ns=ANY(%s) AND target_scope IS DISTINCT FROM 'COVERAGE_ONLY'",(EVALUATOR_VERSION,targets)).fetchone())
        models=db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_model_queue WHERE target_ns=ANY(%s)',(targets,)).fetchone()['n']
        population=dict(db.execute('SELECT COUNT(*) AS total,COUNT(*) FILTER(WHERE dirty OR processed_version<>version) AS pending FROM anomaly_detection.adp_population_jobs WHERE start_ns=ANY(%s)',(targets,)).fetchone())
        scenario=dict(db.execute('SELECT COUNT(*) AS total,COUNT(*) FILTER(WHERE dirty OR processed_version<>version) AS pending FROM anomaly_detection.adp_scenario_jobs WHERE target_ns=ANY(%s)',(targets,)).fetchone())
        traffic={r['start_ns']:r['complete'] for r in db.execute("SELECT start_ns,BOOL_AND(COALESCE((body::jsonb->>'complete')::boolean,FALSE)) AS complete FROM anomaly_detection.adp_traffic_counts WHERE start_ns=ANY(%s) GROUP BY start_ns",(targets,)).fetchall()}
        profiles=db.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_profile_tasks t WHERE EXISTS(SELECT 1 FROM anomaly_detection.adp_window_members m WHERE m.request_key=t.request_key AND m.start_ns=ANY(%s)) OR EXISTS(SELECT 1 FROM anomaly_detection.adp_profiles p WHERE p.request_key=t.request_key AND (p.at_ns/%s)*%s=ANY(%s))',(targets,FIVE,FIVE,targets)).fetchone()['n']
        states={r['name']:json.loads(r['body']) for r in db.execute("SELECT name,body FROM anomaly_detection.adp_state WHERE name=ANY(%s)",(['fresh_cursor','scenario_traffic_cursor','service_sample_fresh_cursor','behavior_scope_migration_v2'],)).fetchall()}
        end=max(targets)+FIVE
        censuses={k:states.get(k,{}).get('next_ns',0)>=end for k in ('fresh_cursor','scenario_traffic_cursor','service_sample_fresh_cursor')}
        drained=(len(shared)==len(targets) and all(r['complete'] for r in shared) and population['total']==len(targets)
            and not any((actor['pending'],models,population['pending'],scenario['pending'],profiles)) and all(censuses.values())
            and all(traffic.get(at) is True for at in targets))
        return dict(status='READ',shared=shared,actor=actor,model_queue=models,population=population,scenario=scenario,
            profile_refreshes=profiles,cursor_coverage=censuses,cursors={key:states.get(key) for key in censuses},
            traffic_window_coverage=traffic,migration=states.get('behavior_scope_migration_v2'),
            observed_target_queues_drained=drained,full_method_coverage='NOT_CERTIFIED_BY_QUEUE_DRAIN')
    except Exception as exc:return dict(status='UNAVAILABLE',failure=failure(exc),observed_target_queues_drained=False)


class ProductionHost:
    def __init__(self,project):
        from viewer_performance.financial_screen import host
        self.h=host;self.project=project
    def reader(self):return self.h.product_reader(self.project)
    def stop(self,role):
        if role!='viewer':return self.h.stop_role(self.project,role)
        for _ in range(12):
            value,code=self.command('viewer_performance/Stop_Viewer_Worker.py','--stop')
            if not code and value.get('status') in ('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED'):return value
            if value.get('status')!='VIEWER_BACKEND_STOP_PENDING':
                raise self.h.HostOperationError('VIEWER_STOP_FAILED',value)
            time.sleep(1)
        raise ValueError('VIEWER_LEASE_DID_NOT_DRAIN')
    def inventory(self):return self.h.inventory(self.project)
    def command(self,*args):return self.h.command(self.project,*args)


def backend_counters(db,rows):
    """Per-backend counters may lag and do not include short unseen sessions."""
    values=[]
    for row in rows:
        if row.get('backend_type')!='client backend':continue
        try:
            io=[dict(r) for r in db.execute('SELECT * FROM pg_stat_get_backend_io(%s)',(row['pid'],)).fetchall()]
            wal=dict(db.execute('SELECT * FROM pg_stat_get_backend_wal(%s)',(row['pid'],)).fetchone())
            values.append(dict(pid=row['pid'],backend_start=str(row['backend_start']),io=io,wal=wal))
        except Exception as exc:values.append(dict(pid=row['pid'],status='UNAVAILABLE',failure=failure(exc)))
    # Decimal/stat-reset timestamps are preserved as strings, never guessed 0.
    return json.loads(json.dumps(values,default=str))


def viewer_targets(value):
    return [w['start_ns'] for w in value.get('windows',[]) if type(w.get('start_ns')) is int]


def phase(project,directory,mode,windows,seconds,host,*,targets=None):
    from AnomalyDetection.validation.observe_viewer_live import activity_rows,source_inventory
    from viewer_performance.financial_screen.resources import process_usage,available_memory
    directory.mkdir(parents=True);save(directory/'targets.json',dict(targets=targets or []))
    began=time.monotonic();children={};logs=[];samples=[];conditions=[];progress={};last_notice=-30;last_progress=-30
    inventory,names=source_inventory(project)
    def start(role):
        log=(directory/(role+'-console.txt')).open('wb');logs.append(log)
        args=[sys.executable,'-X','utf8','-B',str(Path(__file__).resolve()),'--project',str(project),'--directory',str(directory),
              '--child',role,'--seconds',str(seconds),'--windows',str(windows)]
        child=subprocess.Popen(args,cwd=project,stdout=log,stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0),env={**os.environ,'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1'})
        children[role]=child
    with host.reader() as db:before=source_snapshot(db)
    try:
        if mode!='viewer_only':start('ad')
        if mode!='ad_only':start('viewer')
        while time.monotonic()-began<seconds:
            elapsed=time.monotonic()-began
            role_reports={k:read(directory/(k+'.json'),{}) for k in children}
            viewer=role_reports.get('viewer',{});observed=viewer.get('windows',[])
            if mode!='ad_only':
                targets=viewer_targets(viewer)
                save(directory/'targets.json',dict(targets=targets))
            with host.reader() as db:
                rows=[dict(r) for r in db.execute("SELECT pid,backend_start,application_name,backend_type,state,wait_event_type,wait_event,query,EXTRACT(EPOCH FROM(clock_timestamp()-query_start))::float AS query_age_seconds,pg_blocking_pids(pid) AS blocking_pids FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() ORDER BY pid LIMIT 129").fetchall()]
                extra={}
                if elapsed-last_progress>=30:
                    progress=target_progress(db,targets or []);last_progress=elapsed
                    extra['backend_counters']=backend_counters(db,rows)
            active={k:[v['pid'] for v in d.get('active_backends',[])] for k,d in role_reports.items()}
            known={pid for values in active.values() for pid in values}
            if elapsed>15 and any(row['backend_type']=='client backend' and row['state']=='active' and row['pid'] not in known
                    and not (row.get('application_name') or '').startswith(('AnomalyDetection.','P24.Fast.','P24.Viewer.')) for row in rows):
                conditions.append('UNEXPECTED_DATABASE_CLIENT_ACTIVITY')
            classified=activity_rows(rows,names)
            resources={str(d['pid']):process_usage(d['pid']) for d in role_reports.values() if d.get('pid')}
            for row in rows:resources[str(row['pid'])]=process_usage(row['pid'])
            samples.append(dict(elapsed_seconds=round(elapsed,3),activity=classified,role_backends=active,
                processes=resources,available_memory_bytes=available_memory(),**extra))
            if mode=='viewer_only' and any('anomaly' in (r.get('application_name') or '').lower() or '.AD.' in (r.get('application_name') or '') for r in rows):
                conditions.append('UNEXPECTED_AD_DATABASE_ACTIVITY')
            if mode=='ad_only' and any((r.get('application_name') or '').startswith('P24.Fast.') for r in rows):conditions.append('UNEXPECTED_VIEWER_DATABASE_ACTIVITY')
            if elapsed-last_notice>=30:
                try:
                    ad_status,_=host.command('AnomalyDetection/run_anomaly.py','worker-status')
                    web_status,_=host.command('viewer_performance/Stop_Viewer_Web.py')
                    if ad_status['web']['locked'] or web_status.get('status')!='NO_VIEWER_WEB_LISTENER':conditions.append('WEB_PROCESS_PRESENT')
                    if mode=='viewer_only' and ad_status['process']['locked']:conditions.append('AD_WORKER_PRESENT_IN_VIEWER_ONLY')
                    if mode!='viewer_only' and elapsed>20 and not ad_status['process']['locked']:conditions.append('AD_WORKER_MISSING')
                except Exception as exc:conditions.append('ROLE_OBSERVATION_UNAVAILABLE:'+type(exc).__name__)
                notice('THREE_MODE_PROGRESS',mode=mode,elapsed_seconds=round(elapsed),fresh_windows=len(targets or []),
                    targets_requested=windows,ad=progress);last_notice=elapsed
            viewer_done=mode!='ad_only' and children['viewer'].poll() is not None
            if viewer_done:
                viewer=read(directory/'viewer.json',{})
                latest_targets=viewer_targets(viewer)
                if latest_targets!=targets:
                    targets=latest_targets;save(directory/'targets.json',dict(targets=targets))
                    progress=dict(status='TARGET_SET_CHANGED',observed_target_queues_drained=False);last_progress=-30
            if mode=='viewer_only' and viewer_done:break
            if mode=='combined' and viewer_done and viewer.get('status')!='THREE_FRESH_PUBLICATIONS_FINISHED':
                conditions.append('VIEWER_EXITED_WITHOUT_THREE_PUBLICATIONS');break
            if mode=='ad_only' and progress.get('observed_target_queues_drained'):break
            if mode=='combined' and viewer_done and len(targets)==windows and progress.get('observed_target_queues_drained'):break
            if any(p.poll() is not None and (role!='viewer' or mode=='ad_only') for role,p in children.items()):
                conditions.append('ROLE_EXITED_BEFORE_PHASE_END');break
            time.sleep(min(5,max(0,seconds-(time.monotonic()-began))))
    finally:
        for role,p in children.items():save(directory/(role+'-stop.json'),dict(requested_ns=time.time_ns()))
        for role,p in children.items():
            try:p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                conditions.append('FORCED_ROLE_STOP:'+role)
                host.stop('viewer' if role=='viewer' else 'ad')
                p.wait(timeout=20)
        for log in logs:log.close()
    role_reports={k:read(directory/(k+'.json'),{}) for k in children}
    if mode!='ad_only':
        targets=viewer_targets(role_reports.get('viewer',{}));save(directory/'targets.json',dict(targets=targets))
    with host.reader() as db:
        after=source_snapshot(db);progress=target_progress(db,targets or [])
        receipts=[dict(r) for r in db.execute('SELECT w.start_ns,w.end_ns,w.generation,w.records,r.file_hash,r.new_events,r.published_ns FROM public.viewer_live_windows w JOIN public.viewer_live_receipts r ON r.start_ns=w.start_ns AND r.generation=w.generation AND r.file_hash=w.file_hash AND r.records=w.records WHERE w.start_ns=ANY(%s)',(targets or [],)).fetchall()]
    if any(r.get('status') in ('FAILED','PROFILE_FAILED') for r in role_reports.values()):conditions.append('CHILD_OPERATION_FAILED')
    if before['scope']!=after['scope']:conditions.append('INPUT_SCOPE_CHANGED')
    if before['server_settings']!=after['server_settings']:conditions.append('POSTGRES_SETTINGS_CHANGED')
    if mode!='ad_only' and (len(receipts)!=len(targets or []) or any(r['generation']<=before['live']['generation'] for r in receipts)):
        conditions.append('FRESH_COMMITTED_PUBLICATIONS_UNVERIFIED')
    complete=len(targets or [])==windows and (mode=='viewer_only' or progress.get('observed_target_queues_drained'))
    result=dict(mode=mode,status='DIAGNOSTIC_TARGETS_FINISHED' if complete and not conditions else 'PARTIAL_DIAGNOSTIC',
        elapsed_seconds=time.monotonic()-began,targets=targets or [],requested_windows=windows,conditions_issues=sorted(set(conditions)),
        source_before=before,source_after=after,canonical_receipts=receipts,ad_target_progress=progress,roles=role_reports,samples=samples,
        production_capacity_acceptance='NOT_ASSIGNED',full_method_acceptance='NOT_ASSIGNED',
        comparable_paired_inputs=False,existing_backlog_is_serviced=True)
    result['installed_source_inventory']=inventory
    result['counter_limitations']=['Per-backend WAL/I/O snapshots can lag and miss short source sessions.',
        'PG file reads can be served from OS cache; physical device traffic is not attributed.',
        'RSS includes shared pages and must not be summed across PostgreSQL processes.']
    save(directory/'phase.json',result);return result


def run(project,receipt,windows,seconds,host):
    from viewer_performance.Behavior_Release import restore
    project=Path(project).resolve();folder=project/'AnomalyDetection/reports'/('Three_Mode_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
    folder.mkdir(parents=True);out=folder/'run.json';old=read(receipt)
    if not isinstance(old,dict) or not (old.get('before') or {}).get('restore_plan'):raise ValueError('EXISTING_ROLE_RESTORE_RECEIPT_REQUIRED')
    plan=old['before']['restore_plan']
    state=dict(tool=TOOL,status='PREPARING',project=str(project),before=dict(restore_plan=plan),disabled_tasks=[],
        attempted_roles=[],stopping_started=False,phases=[],database='p24_design_viewer',product_data_may_be_modified=True,
        database_copies=0,checkpoint_seek=False,scenario_families_disabled=[],source_filter_changed=False,
        maximum_seconds_per_phase=seconds,restore_failures=[],dedicated_web_traffic='STOPPED')
    def record(status):state['status']=status;save(out,state);notice(status,output=str(out))
    try:
        from tools.check_viewer_install import verify_release
        if verify_release(project)['status']!='PASS':raise ValueError('INSTALLED_CODE_INVENTORY_MISMATCH')
        state['app_manifest']=read(project/'AnomalyDetection/RELEASE_MANIFEST.json')
        state['app_manifest'].pop('files_sha256',None)
        state['viewer_manifest']=read(project/'viewer_performance/FAST_WRITER_MANIFEST.json',{})
        state['viewer_manifest'].pop('files_sha256',None)
        state['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        ad,code=host.command('AnomalyDetection/run_anomaly.py','worker-status')
        viewer,_=host.command('viewer_performance/Stop_Viewer_Worker.py');web,_=host.command('viewer_performance/Stop_Viewer_Web.py')
        if viewer.get('status') not in ('VIEWER_WORKER_IDENTIFIED','NO_VIEWER_LOCK_OWNER_OBSERVED','VIEWER_BACKEND_WITHOUT_CLIENT'):
            raise host.h.HostOperationError('VIEWER_CONTROL_UNAVAILABLE_BEFORE_TEST',viewer)
        if web.get('status') not in ('VIEWER_WEB_IDENTIFIED','NO_VIEWER_WEB_LISTENER'):
            raise host.h.HostOperationError('VIEWER_WEB_CONTROL_UNAVAILABLE_BEFORE_TEST',web)
        plan['active']=dict(ad_worker=ad['process']['locked'],ad_web=ad['web']['locked'],
            viewer=viewer.get('status')=='VIEWER_WORKER_IDENTIFIED' or viewer.get('status')=='VIEWER_BACKEND_WITHOUT_CLIENT' and plan['active']['viewer'],
            viewer_web=web.get('status')=='VIEWER_WEB_IDENTIFIED')
        snapshot=host.inventory();state['original_task_states']=snapshot['tasks']
        state['stopping_started']=True;state['attempted_roles']=['ad','viewer','viewer_web']
        record('DISABLING_PROJECT_AUTOSTART')
        for task in snapshot['tasks']:
            if task['Enabled']:state['disabled_tasks'].append(task);save(out,state);host.h.task_change(task,False)
            if task['State']=='Running' and task['Name']!='P24-Office-LAN-Proxy':host.h.task_control(task,'stop')
        for role in ('ad','viewer','viewer_web'):
            record('STOPPING_'+role.upper());host.stop('web' if role=='viewer_web' else role)
        proxy=plan.get('reviewed_proxy')
        if proxy:
            # Refresh only the old proxy PIDs from its unchanged actual argv;
            # old installation-receipt PIDs are not live process identities.
            from viewer_performance.financial_screen.reviewed_host import words,norm
            now=host.inventory();expected=[norm(v) for v in words(proxy['processes'][0]['CommandLine'])[1:]]
            matches=[p for p in now['processes'] if [norm(v) for v in words(p.get('CommandLine') or '')[1:]]==expected]
            proxy['processes']=matches
            if matches:state['attempted_roles'].append('proxy');record('STOPPING_LAN_PROXY');host.h.stop_reviewed_proxy(project,proxy)
        with host.reader() as db:state['frozen_cursors']=host.h.cursors(db)
        from viewer_performance.Run_Viewer_Catchup import SETTINGS_SQL,NAMES,choose_overrides,supported_compression
        from viewer_performance.Run_Viewer_Memory import memory_info
        with host.reader() as db:
            settings={r['name']:dict(r) for r in db.execute(SETTINGS_SQL,(list(NAMES),)).fetchall()}
            codec=supported_compression(db)
        save(folder/'settings.json',dict(writer_overrides=choose_overrides(settings,memory_info(),codec)))
        record('RUNNING_VIEWER_ONLY')
        a=phase(project,folder/'01_viewer_only','viewer_only',windows,seconds,host);state['phases'].append(a);save(out,state)
        record('RUNNING_AD_ONLY')
        b=phase(project,folder/'02_ad_only','ad_only',windows,seconds,host,targets=a['targets']) if a['targets'] else dict(
            mode='ad_only',status='SKIPPED_NO_PUBLISHED_TARGETS',targets=[],requested_windows=windows)
        state['phases'].append(b);save(out,state)
        record('RUNNING_COMBINED')
        c=phase(project,folder/'03_combined','combined',windows,seconds,host);state['phases'].append(c);save(out,state)
        a_settings=a.get('roles',{}).get('viewer',{}).get('effective_writer_settings')
        c_settings=c.get('roles',{}).get('viewer',{}).get('effective_writer_settings')
        state['viewer_settings_match_between_lanes']=bool(a_settings and a_settings==c_settings)
    except BaseException as exc:state['failure']=failure(exc)
    finally:
        record('RESTORING_ORIGINAL_ROLES')
        try:
            if state['stopping_started']:restore(project,out,state)
            else:
                for task in state['disabled_tasks']:host.h.task_change(task,True)
        except BaseException as exc:state['restore_error']=failure(exc)
        status='THREE_MODE_DIAGNOSTIC_EXPORTED' if len(state['phases'])==3 and not state.get('failure') and not state.get('restore_error') else 'THREE_MODE_PARTIAL_SEND_BUNDLE'
        record(status)
        manager_report(folder,state)
        bundle=folder.with_suffix('.zip')
        with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
            for file in folder.rglob('*'):
                if file.is_file():z.write(file,file.relative_to(folder))
        notice(status,output=str(bundle),phases=[dict(mode=p['mode'],status=p['status']) for p in state['phases']])
    return state


def manager_report(folder,state):
    lines=['# Three-mode live diagnostic', '', 'Status: '+state['status'],
        'Production DB: p24_design_viewer; no database copies; different fresh inputs/history between Viewer lanes.',
        'Instrumentation overhead is included. Queue drain is not accuracy/full-method/capacity acceptance.', '']
    for phase in state['phases']:
        lines+=['## '+phase['mode'], 'Status: '+phase['status'],
            'Elapsed seconds: '+str(phase.get('elapsed_seconds')), 'Published/target windows: '+str(phase.get('targets')),
            'Condition issues: '+str(phase.get('conditions_issues')), 'AD target progress: '+json.dumps(phase.get('ad_target_progress'),ensure_ascii=True), '']
        for role,value in phase.get('roles',{}).items():
            lines+=['### '+role, 'Client CPU seconds: '+str(value.get('client_cpu_seconds')),
                'Actor attempts in targets / other history: '+str(value.get('actor_evaluation_attempts_in_targets'))+' / '+str(value.get('actor_evaluation_attempts_outside_targets')),
                'Cache probe counts (not unique model evaluations): '+str(value.get('cache_probes')), '',
                '| Path | Exclusive seconds | Inclusive seconds | Calls | Failures |', '|---|---:|---:|---:|---:|']
            rows=(value.get('trace') or {}).get('spans') or {}
            for name,row in sorted(rows.items(),key=lambda x:-x[1]['exclusive_seconds'])[:20]:
                lines.append('| '+name+' | '+str(row['exclusive_seconds'])+' | '+str(row['inclusive_seconds'])+' | '+str(row['calls'])+' | '+str(row['failures'])+' |')
            lines+=['', 'Inclusive paths overlap; do not add them. Client CPU excludes PostgreSQL backend CPU.', '']
    lines+=['## Restoration',json.dumps(dict(failure=state.get('failure'),restore_error=state.get('restore_error'),
        restore_failures=state.get('restore_failures')),ensure_ascii=True)]
    (Path(folder)/'MANAGER_REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


@contextmanager
def controller_lock(project):
    """Two simultaneous controllers would invalidate all three lanes."""
    path=Path(project)/'AnomalyDetection/reports/Three_Mode_Controller.lock';path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as stream:
        stream.seek(0)
        if os.name=='nt':
            import msvcrt
            if path.stat().st_size==0:stream.write(b'0');stream.flush();stream.seek(0)
            msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:
            if os.name=='nt':stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(stream,fcntl.LOCK_UN)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,required=True)
    p.add_argument('--release-receipt',type=Path);p.add_argument('--windows',type=int,default=3)
    p.add_argument('--restore-receipt',type=Path)
    p.add_argument('--seconds',type=int,default=2700);p.add_argument('--child',choices=('viewer','ad'))
    p.add_argument('--directory',type=Path);a=p.parse_args();a.project=a.project.resolve()
    if a.windows!=3 or not 30<=a.seconds<=2700:p.error('three windows; 30..2700 seconds per phase')
    os.chdir(a.project);sys.path.insert(0,str(a.project))
    if a.child:
        if not a.directory:p.error('--directory required for child')
        return child(a)
    if not (a.release_receipt or a.restore_receipt):p.error('--release-receipt required')
    if os.name!='nt' or not __import__('ctypes').windll.shell32.IsUserAnAdmin():p.error('Run as Administrator on the Windows server.')
    with controller_lock(a.project):
        if a.restore_receipt:
            from viewer_performance.Behavior_Release import restore
            state=read(a.restore_receipt)
            if Path(state['project']).resolve()!=a.project:p.error('restore receipt belongs to another project')
            for directory in a.restore_receipt.parent.glob('0*_*'):
                for role in ('ad','viewer'):save(directory/(role+'-stop.json'),{'requested_ns':time.time_ns()})
            host=ProductionHost(a.project);host.stop('ad');host.stop('viewer');host.stop('web')
            restore(a.project,a.restore_receipt,state);notice('THREE_MODE_ROLES_RESTORED',output=str(a.restore_receipt));return 0
        state=run(a.project,a.release_receipt,a.windows,a.seconds,ProductionHost(a.project))
    return 0 if state['status']=='THREE_MODE_DIAGNOSTIC_EXPORTED' else 2


if __name__=='__main__':raise SystemExit(main())
