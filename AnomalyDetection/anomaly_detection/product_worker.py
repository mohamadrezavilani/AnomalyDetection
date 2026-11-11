"""One native PG writer; bounded/fair source lanes and unrestricted historical jobs."""
from pathlib import Path
import time
import sys

from . import BUILD_ID,FIVE_NS
from .native_pg import prepare
from .product_store import ProductStore
from .product_source import ProductSource
from .history_scope import WRITER_LOCK,effective_floor
from .product_engine import evaluate_job
from .product_control import spawn
from .process_control import OwnedProcessLock,read_json,write_json,safe_failure,process_owner


def run(root,sha, *, source_factory=ProductSource,prepare_pg=prepare,clock=None,wait=None,max_cycles=None,web=True,instance_token=None):
    root=Path(root).resolve();clock=clock or time;wait=wait or time.sleep
    with OwnedProcessLock(root,'baseline_worker',sha,instance_token=instance_token) as owner:
        state=dict(owner.owner,state='STARTING',phase='open_postgresql',heartbeat_ns=clock.time_ns(),
            storage_backend='postgresql',architecture='PG_PRODUCT_V1',source_modified=False,source_checkpoint_modified=False,
            source_pages=0,evaluated_jobs=0,audited_requests=0,cohort_windows=0,source_attempts=0,
            historical_recheck_age_limit=None,operator_parameters_required=False,operator_alerts=0,precision_recall='NOT_EVALUATED',sqlite_loaded='sqlite3' in sys.modules)
        raw=store=source=None;next_connect=next_source=next_report=next_heartbeat=next_web=0.;turn=cycles=iterations=0
        from .viewer_priority import ViewerPriority
        viewer_priority=ViewerPriority()
        from .product_scheduling import EvaluationScheduler
        from .source_scheduling import WindowContinuations
        scheduler=EvaluationScheduler()
        continuations=WindowContinuations()
        def publish(force=False):
            nonlocal next_heartbeat
            if force or clock.monotonic()>=next_heartbeat:
                state['heartbeat_ns']=clock.time_ns();write_json(root/'reports/product_status.json',state)
                next_heartbeat=clock.monotonic()+2
        def owned_statement_progress(value):
            # Real statement boundaries, not a background "alive" ticker.
            # A single stuck SQL call still makes this heartbeat stale.
            state['owned_statement']=value
            publish()
        publish(True)
        def read_pages(lane,initial=None):
            state['active_source_lane']=lane
            from .product_pipeline import read_window_burst
            read_phase=state['phase']
            def set_phase(part):
                state['phase']='apply_shared_window' if part=='apply' else read_phase
            results=read_window_burst(source,store,clock=clock,cursor_name=lane,initial_cursor=initial,progress=set_phase)
            state['phase']=read_phase
            state['window_apply_blocked']=False
            complete=sum(r['status']=='COMPLETE' for r in results)
            restarts=sum(r['status']=='RESTART_SNAPSHOT' for r in results)
            progress=state.setdefault('window_lanes',{}).setdefault(lane,{'page_reads':0,'completed':0,'snapshot_restarts':0})
            progress['page_reads']+=len(results);progress['completed']+=complete;progress['snapshot_restarts']+=restarts
            progress['last_status']=results[-1]['status'];progress['cursor']=store.state(lane)
            state['cohort_windows']+=complete
            if lane=='fresh_cursor':
                state['fresh_windows']=state.get('fresh_windows',0)+complete
                state['fresh_page_reads']=state.get('fresh_page_reads',0)+len(results)
                state['fresh_snapshot_restarts']=state.get('fresh_snapshot_restarts',0)+restarts
            continuations.notice(lane,results[-1])
            return results[-1]
        def audit_candidates():
            nonlocal keys,job,audit_size_key,apply_started
            from .audit_scope import keys as scoped_keys
            job=None;audit_until=clock.monotonic()+1.0
            for _ in range(4):
                state['phase']='select_owned_audit'
                keys=scoped_keys(store,clock.time_ns(),limit=1)
                if not keys:break
                audit_size_key='priority_audit_size';state['phase']='read_request_evidence';publish(True);read_started=clock.monotonic()
                audit_packet=source.audit(keys)
                state['last_audit_read_seconds']=round(clock.monotonic()-read_started,6)
                state['phase']='apply_request_evidence';publish(True);apply_started=clock.monotonic()
                state['last_audit']=store.apply_audit(audit_packet)
                state['audited_requests']+=len(keys);state['candidate_audit_requests']=state.get('candidate_audit_requests',0)+len(keys)
                state['last_source_failure']=None;state['audit_apply_blocked']=False
                state['last_audit_apply_seconds']=round(clock.monotonic()-apply_started,6)
                if clock.monotonic()>=audit_until:break
        try:
            while max_cycles is None or iterations<max_cycles:
                iterations+=1
                manifest=read_json(root/'RELEASE_MANIFEST.json',{})
                if manifest.get('build_id')!=BUILD_ID or manifest.get('source_sha256')!=sha:
                    state.update(state='STOPPED',stop_reason='RELEASE_CHANGED');break
                if read_json(root/'data/A2W_stop_request.json',{}).get('instance_token')==owner.owner['instance_token']:
                    state.update(state='STOPPED',stop_reason='REQUESTED');break
                if store is None:
                    if clock.monotonic()<next_connect:publish();wait(.5);continue
                    state.update(state='PREPARING_POSTGRESQL',phase='connect_owned_postgresql');publish(True)
                    try:
                        from .owned_sql import ObservedConnection
                        raw=ObservedConnection(prepare_pg(root),clock.monotonic,observer=owned_statement_progress);store=ProductStore(raw)
                        state['phase']='acquire_owned_writer_lease';publish(True)
                        acquired=raw.execute('SELECT pg_try_advisory_lock(%s) AS acquired',(WRITER_LOCK,)).fetchone()['acquired']
                        if not acquired:raise RuntimeError('owned product writer lease unavailable')
                        state['phase']='prepare_owned_schema';publish(True)
                        store.initialize();state['storage_ready']=True;state['last_storage_failure']=None
                        state['initialization_schema']=store.initialization_schema
                        state['analysis_history_floor_ns']=store.history_floor_ns
                    except Exception as exc:
                        state['last_initialization_failure']={'phase':state['phase'],'step':getattr(store,'initialization_step',None),'at_ns':clock.time_ns(),'failure':safe_failure(exc),'queries':raw.metrics() if callable(getattr(raw,'metrics',None)) else []}
                        if raw:raw.close()
                        raw=store=None;state.update(state='WAITING_FOR_DATABASE_LOCK' if getattr(exc,'sqlstate',None)=='55P03' else 'WAITING_FOR_POSTGRESQL',last_storage_failure=safe_failure(exc));next_connect=clock.monotonic()+10
                        publish(True);wait(.2);continue
                if source is None and clock.monotonic()>=next_source:
                    try:
                        source=source_factory(root.parent)
                        if hasattr(source,'analysis_floor_ns'):
                            source.analysis_floor_ns=store.history_floor_ns
                        state['last_source_failure']=None
                    except Exception as exc:state['last_source_failure']=safe_failure(exc);next_source=clock.monotonic()+30
                elif source is not None and hasattr(source,'analysis_floor_ns'):
                    source.analysis_floor_ns=store.history_floor_ns
                state.update(state='DEGRADED_SOURCE' if state.get('last_source_failure') else
                    'DEGRADED_OWNED_APPLY' if any(state.get(k) for k in ('semantic_apply_blocked','audit_apply_blocked','window_apply_blocked')) else 'RUNNING',phase='owned_historical_import')
                try:
                    keys=[];job=None
                    # Serving existing owned results is independent of the
                    # disk admission decision for background analysis.
                    if web and clock.monotonic()>=next_web:
                        if not process_owner(root,'web')['locked']:spawn(root,'web-run')
                        next_web=clock.monotonic()+30;state['web_url']='http://127.0.0.1:5022/'
                    try:
                        admission=viewer_priority.admit(source,clock)
                        state['viewer_admission']=admission
                        if admission['mode']!='PROBE_UNAVAILABLE':state.pop('viewer_admission_failure',None)
                    except Exception as exc:
                        # Unavailable metadata is not proof of an idle writer.
                        # Keep the previous product behavior while reporting it.
                        state['viewer_admission_failure']=safe_failure(exc)
                        admission={'admitted':True,'mode':'PROBE_UNAVAILABLE'}
                    if not admission['admitted']:
                        state.update(state='WAITING_FOR_VIEWER_PUBLICATION',phase='yield_disk_to_viewer')
                        publish();wait(.5);continue
                    cycles+=1
                    from .runtime_lanes import maintenance
                    from .population import process_one as population_process
                    maintenance(store,clock,cycles,state)
                    job=None
                    if clock.monotonic()>=next_report:
                        state['phase']='refresh_statistics';publish(True)
                        state['statistics']=store.report();state['statistics_at_ns']=clock.time_ns()
                        state['statistics_status']=state['statistics']['statistics_collection']['status']
                        state['statistics_section_failures']={k:v for k,v in state['statistics']['statistics_collection']['sections'].items() if v['status']!='CURRENT'}
                        next_report=clock.monotonic()+30
                    if source is not None and clock.monotonic()>=next_source:
                        continuation=continuations.take()
                        if continuation is None:turn+=1
                        began=clock.monotonic();state['source_attempts']+=1
                        from .product_pipeline import read_window,apply_window,owned_context
                        lane=turn%8;job=None;keys=[]
                        state['active_source_lane']=continuation or {0:'fresh_cursor',1:'fresh_cursor',2:'semantic_keyset',3:'audit_priority',4:'fresh_cursor',5:'learning_cursor',6:'journey',7:'audit_history'}[lane]
                        if continuation is not None:
                            state['phase']='read_'+continuation;publish(True)
                            result=read_pages(continuation)
                            state['source_continuations']=state.get('source_continuations',0)+1
                            state['last_window_continuation']=result
                        elif lane in (0,1,4):
                            state['phase']='read_fresh_window';publish(True)
                            result=read_pages('fresh_cursor')
                            state['last_window']=result
                            # Once caught up, refresh overlap through the separate
                            # reserved lane. The forward cursor never rewinds.
                            if result['status']=='CAUGHT_UP':
                                after=store.state('overlap_cursor')
                                if not after.get('target_ns') and source.last_source:
                                    end=source.last_source['next_ns']
                                    store.save_state('overlap_cursor',{'target_ns':end-(2 if turn%16<8 else 1)*FIVE_NS})
                                read_pages('overlap_cursor')
                        elif lane==2:
                            state['phase']='read_semantic_keyset';publish(True)
                            cursor=store.state('semantic_cursor');read_started=clock.monotonic();packet=source.page(cursor.get('after'))
                            state['last_semantic_read_seconds']=round(clock.monotonic()-read_started,6)
                            state['last_source_failure']=None
                            state['phase']='apply_semantic_keyset';publish(True);apply_started=clock.monotonic()
                            state['last_page']=store.apply_rows(packet['rows'],packet['source'],cursor_state=('semantic_cursor',
                                {'after':packet['after'],'completed_passes':cursor.get('completed_passes',0)+int(not packet['has_more'])}))
                            state['last_semantic_apply_seconds']=round(clock.monotonic()-apply_started,6)
                            state['semantic_apply_blocked']=False
                            state['source_pages']+=1
                        elif lane in (3,7):
                            priority_limit=max(1,min(64,store.state('priority_audit_size',{'n':64}).get('n',64)))
                            regular_limit=max(1,min(8,store.state('regular_audit_size',{'n':8}).get('n',8)))
                            audit_size_key='regular_audit_size'
                            # Reserve fresh evidence independently of persistent candidates.
                            # Both lanes remain age-unbounded through the history turn.
                            if lane==3 and turn%16==11:
                                keys=store.audit_keys(clock.time_ns(),limit=regular_limit,fresh=True)
                            elif lane==3:
                                keys=store.audit_keys(clock.time_ns(),limit=priority_limit,priority=True)
                                if keys:audit_size_key='priority_audit_size'
                                else:keys=store.audit_keys(clock.time_ns(),limit=regular_limit,fresh=True)
                            else:keys=store.audit_keys(clock.time_ns(),limit=regular_limit,revisit=True)
                            keys=keys or store.audit_keys(clock.time_ns(),limit=regular_limit)
                            state['audit_batch_sizes']={'priority':priority_limit,'regular':regular_limit}
                            if keys:
                                state['phase']='read_request_evidence';publish(True);read_started=clock.monotonic()
                                audit_packet=source.audit(keys)
                                state['last_audit_read_seconds']=round(clock.monotonic()-read_started,6)
                                state['last_source_failure']=None
                                state['phase']='apply_request_evidence';publish(True);apply_started=clock.monotonic()
                                state['last_audit']=store.apply_audit(audit_packet)
                                state['last_audit_apply_seconds']=round(clock.monotonic()-apply_started,6)
                                state['audited_requests']+=len(keys)
                                state['audit_apply_blocked']=False
                        elif lane==5:
                            state['phase']='read_learning_window';publish(True)
                            repair=store.state('scope_repair_cursor')
                            if not repair.get('target_ns') and source.last_source:
                                pending=store.raw.execute("SELECT start_ns FROM anomaly_detection.adp_source_windows WHERE complete=FALSE "
                                    "AND source::jsonb->>'needs_scope_repair'='true' AND start_ns>=%s AND start_ns<%s ORDER BY start_ns DESC LIMIT 1",
                                    (effective_floor(source.last_source),source.last_source['next_ns'])).fetchone()
                                repair={'target_ns':pending['start_ns']} if pending else {}
                            if repair and turn%16==5:
                                repaired=read_pages('scope_repair_cursor',repair)
                                state['scope_repair_reads']=state.get('scope_repair_reads',0)+1
                                state['scope_repairs']=state.get('scope_repairs',0)+int(repaired['status'] in ('COMPLETE','ALREADY_COMPLETE'))
                            else:
                                cursor=store.state('learning_cursor')
                                if not cursor and source.last_source:
                                    cursor={'next_ns':max(FIVE_NS,effective_floor(source.last_source),source.last_source['next_ns']-72*FIVE_NS)}
                                result=read_pages('learning_cursor',cursor)
                                if result['status']=='CAUGHT_UP':
                                    older=store.state('older_learning_cursor') or {'next_ns':max(FIVE_NS,effective_floor(source.last_source),source.last_source['next_ns']-56*288*FIVE_NS)}
                                    read_pages('older_learning_cursor',older)
                        else:
                            from .product_enrichment import next_key,save,defer
                            from .viewer_bridge import read_journey
                            enrichment_key=next_key(store,clock.time_ns(),oldest=turn%32==6)
                            if enrichment_key and (source.project/'p24_foundation').is_dir():
                                state['phase']='read_viewer_journey';publish(True)
                                try:
                                    save(store,enrichment_key,read_journey(source,enrichment_key))
                                    state['journey_reads']=state.get('journey_reads',0)+1
                                except Exception:
                                    defer(store,enrichment_key,clock.time_ns());raise
                            job=store.next_job(clock.time_ns(),recent=False)
                            if job and not owned_context(store,job) and turn%16==6:
                                state['phase']='read_historical_session';publish(True)
                                context=source.context(job);store.save_context(job,context)
                        state['last_source_failure']=None
                        if source.last_source:
                            source_state=source.last_source;wait_seconds=source_state.get('lag_seconds',60)
                            from .service_reference import bootstrap,MODEL_VERSION
                            previous_import=store.state('root_reference_import')
                            if previous_import.get('model_version')!=MODEL_VERSION or clock.time_ns()-store.state('root_reference_scan').get('at_ns',0)>=60_000_000_000:
                                try:imported=bootstrap(store,source.project,source_state)
                                except Exception as exc:
                                    imported={'status':'LOCAL_REFERENCE_IMPORT_BLOCKED','failure':safe_failure(exc),'model_version':MODEL_VERSION}
                                if imported['status']=='ALREADY_IMPORTED' and previous_import.get('status')=='IMPORTED_ROOT_RATE_REFERENCE':
                                    imported=dict(previous_import,model_version=MODEL_VERSION)
                                store.save_state('root_reference_import',imported);state['root_reference']=imported
                                store.save_state('root_reference_scan',{'at_ns':clock.time_ns()})
                            eligible=((clock.time_ns()-wait_seconds*1_000_000_000)//FIVE_NS)*FIVE_NS
                            state['source_status']={key:source_state.get(key) for key in ('generation','next_ns','captured_at_ns','semantic_state','source_role','source_read_only')}
                            state['source_status']['eligible_end_ns']=eligible
                            state['source_status']['backlog_seconds']=max(0,(eligible-source_state['next_ns'])/1e9)
                            state['source_status']['retention_cutoff_ns']=source_state.get('retention_cutoff_ns',0)
                            if store.history_floor_ns:
                                state['source_status']['analysis_floor_ns']=store.history_floor_ns
                                published=source_state.get('scope_latest_published_end_ns')
                                state['source_status']['scope_latest_published_end_ns']=published
                                state['source_status']['scope_status']=(
                                    'SCOPE_WINDOW_PUBLISHED' if published else 'WAITING_FOR_FIRST_SCOPE_WINDOW')
                        elapsed=clock.monotonic()-began;state['last_source_seconds']=round(elapsed,6)
                        if callable(getattr(source,'page_sizes',None)):state['source_page_sizes']=source.page_sizes()
                        state['last_source_query_metrics']=getattr(source,'last_metrics',[])
                        waiting_scope=(state.get('source_status',{}).get('scope_status')=='WAITING_FOR_FIRST_SCOPE_WINDOW')
                        minimum=1.0 if waiting_scope else .05
                        next_source=clock.monotonic()+(.05 if continuations.ready() else max(minimum,2*elapsed))
                    # Reserve the same audit budget before a potentially slow
                    # evaluation every fourth turn. Neither side owns all turns.
                    audit_first=cycles%4==1
                    if source is not None and audit_first:audit_candidates()
                    # Local batches consume shared window summaries without a
                    # new Viewer GROUP BY for every session/target.
                    from .product_pipeline import owned_context
                    state['phase']='evaluate_dispatch';until=clock.monotonic()+.30
                    for batch_index in range(16):
                        job=None;state['phase']='evaluate_dispatch'
                        job,evaluation_lane=scheduler.choose(store,clock.time_ns())
                        ready_lane=evaluation_lane in ('live','ready')
                        if not job:break
                        evaluation_started=clock.monotonic()
                        state['evaluation_lane']=evaluation_lane
                        state['evaluating_target']={'session_key':job['session_key'],'target_ns':job['target_ns'],'version':job['version']}
                        state['phase']='evaluate_context'
                        if evaluation_lane=='advanced':context=owned_context(store,job)
                        else:
                            from .primary_pipeline import context as primary_context
                            context=primary_context(store,job)
                        if context:
                            context=store.save_context(job,context);job=dict(job,version=context['job_version'])
                        if context:
                            def evaluation_progress(name):
                                state['phase']='evaluate_'+name
                                publish()
                            state['last_evaluation']=evaluate_job(store,job,context,clock.time_ns(),progress=evaluation_progress,mode='full' if evaluation_lane=='advanced' else 'primary')
                            if state['last_evaluation']['status']=='APPLIED':
                                state['evaluated_jobs']+=1
                                state['ready_lane_evaluations']=state.get('ready_lane_evaluations',0)+int(ready_lane)
                                state['live_lane_evaluations']=state.get('live_lane_evaluations',0)+int(evaluation_lane=='live')
                            else:state['input_retries']=state.get('input_retries',0)+1
                        else:
                            if evaluation_lane=='advanced':
                                from .model_queue import defer as defer_model
                                defer_model(store,job,clock.time_ns())
                            else:store.defer_job(job,clock.time_ns(),'WAITING_FOR_SHARED_WINDOW_OR_HISTORY_LANE')
                        evaluation_seconds=clock.monotonic()-evaluation_started
                        timings=state.setdefault('evaluation_timing',{'attempts':0,'seconds':0.,'maximum_seconds':0.})
                        timings['attempts']+=1;timings['seconds']=round(timings['seconds']+evaluation_seconds,6)
                        timings['last_seconds']=round(evaluation_seconds,6)
                        timings['maximum_seconds']=round(max(timings['maximum_seconds'],evaluation_seconds),6)
                        if clock.monotonic()>=until:break
                    if source is not None and not audit_first:audit_candidates()
                    if cycles%16==0:
                        job=None;state['phase']='evaluate_population'
                        state['last_population_evaluation']=population_process(store,clock.time_ns(),recent=cycles%32==0)
                    state['last_owned_query_metrics']=raw.metrics()
                    state['last_storage_failure']=None;publish();wait(.05)
                except Exception as exc:
                    failure=safe_failure(exc)
                    if str(exc)=='PRODUCT_CONTEXT_INPUT_CHANGED_RETRY':
                        state['input_retries']=state.get('input_retries',0)+1
                        publish(True);continue
                    state['last_owned_query_metrics']=raw.metrics()
                    if state['phase'].startswith('evaluate_') and getattr(exc,'sqlstate',None)=='57014':
                        # Read statements are autocommit; owned mutations unwind
                        # their transaction/savepoint before reaching this block.
                        # Keep the writer lease, caches and classification progress.
                        state.update(state='DEGRADED_EVALUATION',last_storage_failure=failure)
                        state['evaluation_timeouts_total']=state.get('evaluation_timeouts_total',0)+1
                        state['last_evaluation_failure_event']={'phase':state['phase'],'at_ns':clock.time_ns(),
                            'failure':failure,'target':({'session_key':job['session_key'],'target_ns':job['target_ns'],
                                'version':job['version']} if job else None),'queries':raw.metrics()}
                        if job:
                            if state.get('evaluation_lane')=='advanced':
                                from .model_queue import defer as defer_model
                                defer_model(store,job,clock.time_ns())
                            else:store.defer_job(job,clock.time_ns(),'OWNED_EVALUATION_QUERY_TIMEOUT_RETRY')
                        if state['phase']=='evaluate_population' and getattr(store,'active_population_target',None) is not None:
                            store.raw.execute('UPDATE anomaly_detection.adp_population_jobs SET due_ns=%s WHERE start_ns=%s AND dirty=TRUE',(clock.time_ns()+30_000_000_000,store.active_population_target))
                        publish(True);wait(.05);continue
                    if state['phase']=='apply_request_evidence' and getattr(exc,'sqlstate',None)=='57014':
                        # The owned audit transaction has rolled back; retry without
                        # classifying a successful read as a Viewer failure.
                        state.update(state='DEGRADED_OWNED_APPLY',audit_apply_blocked=True,last_storage_failure=failure)
                        state['owned_apply_failures_total']=state.get('owned_apply_failures_total',0)+1
                        state['last_owned_apply_failure_event']={'phase':state['phase'],'at_ns':clock.time_ns(),
                            'failure':failure,'elapsed_seconds':round(clock.monotonic()-apply_started,6),'rows':len(keys)}
                        store.defer_audits(keys,clock.time_ns())
                        if len(keys)>1:store.save_state(audit_size_key,{'n':max(1,len(keys)//2)})
                        next_source=clock.monotonic()+10;publish(True);wait(.2);continue
                    if state['phase']=='apply_shared_window' and getattr(exc,'sqlstate',None) in ('57014','55P03'):
                        state.update(state='DEGRADED_OWNED_APPLY',window_apply_blocked=True,last_storage_failure=failure)
                        state['owned_apply_failures_total']=state.get('owned_apply_failures_total',0)+1
                        state['last_owned_apply_failure_event']={
                            'phase':state['phase'],'lane':state.get('active_source_lane'),
                            'at_ns':clock.time_ns(),'failure':failure,'queries':raw.metrics()}
                        next_source=clock.monotonic()+10
                        publish(True);wait(.2);continue
                    if state['phase']=='apply_semantic_keyset' and getattr(exc,'sqlstate',None)=='57014':
                        # apply_rows owns a rollback-safe transaction. Retry a
                        # smaller semantic batch; do not throttle window reads.
                        state.update(state='DEGRADED_OWNED_APPLY',semantic_apply_blocked=True,last_storage_failure=failure)
                        state['owned_apply_failures_total']=state.get('owned_apply_failures_total',0)+1
                        state['last_owned_apply_failure_event']={'phase':state['phase'],'at_ns':clock.time_ns(),'failure':failure,
                            'elapsed_seconds':round(clock.monotonic()-apply_started,6),'rows':len(packet['rows'])}
                        if callable(getattr(source,'reduce_page_size',None)):source.reduce_page_size('semantic_keyset')
                        if callable(getattr(source,'page_sizes',None)):state['source_page_sizes']=source.page_sizes()
                        next_source=clock.monotonic()+10;publish(True);wait(.2);continue
                    if state['phase']=='select_owned_audit' and getattr(exc,'sqlstate',None)=='57014':
                        state.update(state='DEGRADED_EVIDENCE_QUEUE',last_storage_failure=failure)
                        state['last_evidence_queue_failure']={'at_ns':clock.time_ns(),'queries':raw.metrics(),'failure':failure}
                        publish(True);wait(.05);continue
                    if state['phase'].startswith(('read_','audit_')):
                        state.update(state='DEGRADED_SOURCE',last_source_failure=failure)
                        state['source_failures_total']=state.get('source_failures_total',0)+1
                        state['last_source_failure_event']={'phase':state['phase'],'lane':state.get('active_source_lane'),
                            'at_ns':clock.time_ns(),'failure':failure,'queries':getattr(source,'last_metrics',[])}
                        if job:store.defer_job(job,clock.time_ns(),failure['code'])
                        if keys:store.defer_audits(keys,clock.time_ns())
                        if keys and state['phase']=='read_request_evidence' and len(keys)>1:
                            store.save_state(audit_size_key,{'n':max(1,len(keys)//2)})
                        if source and getattr(exc,'sqlstate',None)=='57014' and (state.get('active_source_lane','').endswith('_cursor') or state.get('active_source_lane')=='semantic_keyset'):
                            if callable(getattr(source,'reduce_page_size',None)):source.reduce_page_size(state['active_source_lane'])
                            else:source.page_size=max(64,source.page_size//2)
                        if callable(getattr(source,'page_sizes',None)):state['source_page_sizes']=source.page_sizes()
                        next_source=clock.monotonic()+10
                    else:
                        state.update(state='DEGRADED_STORAGE',last_storage_failure=failure)
                        try:raw.close()
                        finally:raw=store=None;next_connect=clock.monotonic()+10
                    publish(True);wait(.2)
                finally:
                    # Reserved content/model work also runs after a failed
                    # source read, primary evaluation or evidence selection.
                    if store is not None:
                        from .scenario_worker import step as scenario_step
                        scenario_step(store,source,clock,cycles,state)
                        publish()
            else:state.update(state='STOPPED',stop_reason='OFFLINE_TEST_CYCLE_BOUND')
        except KeyboardInterrupt:state.update(state='STOPPED',stop_reason='INTERRUPTED')
        except Exception as exc:
            state.update(stop_reason='WORKER_FAILED',last_fatal_failure={'phase':state['phase'],'failure':safe_failure(exc)})
            raise
        finally:
            if raw:raw.close()
            state['state_before_stop']=state['state'];state.update(state='STOPPED',phase='stopped');publish(True)
        return 0
