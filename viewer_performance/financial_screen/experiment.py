"""Sequential scope screen. All test databases are newly owned by this call.

Correctness and capacity allocate different databases. No output oracle runs
inside a capacity lane. The admin connection never opens the product database.
"""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_online import initialize_live,bind_stream
from viewer_performance.capacity import counters
from viewer_performance.capacity.baseline import distribution,capture_jobs,SETTINGS
from viewer_performance.capacity.oracle import EVIDENCE,PROJECTIONS,digest_table
from viewer_performance.fast_writer import BASE_RUNTIME,verify_sources
from .contracts import MODES,SCENARIOS,coverage
from .fixtures import corpus,seed,FIVE
from .identity import source_identity
from .modes import ScreenDB,publisher
from .resources import Sampler
from .instrumentation import ScopeTrace


def required_tables(mode):
    result={t:'*' for t in EVIDENCE if mode!='D' or t!='viewer_links'}
    if mode!='D':result['viewer_requests']='*'
    if mode in ('A','C'):
        result.update({t:c for t,c in PROJECTIONS.items() if t.startswith(('viewer_contract_','viewer_semantic_'))})
    if mode=='A':result.update(PROJECTIONS)
    return result


def retained_snapshot(db,mode):
    """Correctness-only, complete hashes of each claimed retained relation."""
    return {table:digest_table(db,table,columns) for table,columns in required_tables(mode).items()}


class ExclusiveViolation(ValueError):pass


class LaneFailure(Exception):
    def __init__(self,exc,partial):
        super().__init__(type(exc).__name__);self.failure=dict(error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,(ValueError,TimeoutError,AssertionError)) else None,
            sqlstate=getattr(exc,'sqlstate',None));self.partial=partial


def assert_idle(admin,owned=()):
    rows=admin.execute("""SELECT pid,datname,application_name,state,xact_start IS NOT NULL AS transaction_open
        FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()
        AND (datname LIKE 'p24_design_%%' OR application_name ~* '(p24|anomaly|viewer)')
        AND NOT(datname=ANY(%s))""",(list(owned),)).fetchall()
    if rows:raise ExclusiveViolation('PROJECT_DATABASE_SESSIONS_STILL_PRESENT')


@contextmanager
def allocated(admin,parameters,keys,mode,created,stats):
    from psycopg import sql
    name='p24_design_capacity_fs_'+uuid.uuid4().hex[:16]+'_qualification'
    # CREATE succeeds only for a nonexistent name. No existing database is adopted.
    admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));created.append(name);stats['allocated']+=1
    from viewer_performance.behavior_resources import wal_codec
    codec=wal_codec(admin)
    config={**parameters,'dbname':name,'connect_timeout':5,
        'options':'-c jit=off -c work_mem=64MB -c temp_buffers=128MB -c wal_compression='+codec+' -c lock_timeout=10000'}
    db=None
    try:
        db=ScreenDB(config=config,keys_path=keys,mode=mode)
        yield db
    finally:
        if db is not None:db.close()
        # Only this call's successful allocations may be dropped. Never FORCE.
        admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)));created.remove(name);stats['dropped']+=1


def run_lane(db,jobs,setup_jobs,*,purpose,guard,deadline,notice,existing_stream=False,boundary_oracle=None):
    began=time.perf_counter()
    if not existing_stream:
        db.init();initialize_live(db)
        all_jobs=setup_jobs+jobs
        bind_stream(db,start_ns=all_jobs[0]['start'],stream_key='financial-scope-screen')
    settings=db.all('SELECT name,setting,unit FROM pg_settings WHERE name=ANY(?)',(list(SETTINGS),))
    effective={r['name']:r['setting'] for r in settings}
    if any(effective.get(k)!='on' for k in ('fsync','full_page_writes','synchronous_commit')):
        raise ValueError('DURABILITY_MUST_REMAIN_ON')
    db.conn.rollback()
    setup=time.perf_counter();windows=[]
    for job in setup_jobs:
        guard();remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('SCOPE_SCREEN_BUDGET_EXHAUSTED')
        db.sql("SELECT set_config('statement_timeout',?,false)",(str(max(1,int(remaining*1000))),))
        publisher(db)(job['path'],job['start'],job['start']+FIVE)
    setup_seconds=time.perf_counter()-setup
    for ordinal,job in enumerate(jobs):
        guard();remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('SCOPE_SCREEN_BUDGET_EXHAUSTED')
        db.sql("SELECT set_config('statement_timeout',?,false)",(str(max(1,int(remaining*1000))),));db.conn.commit()
        events=[];trace=ScopeTrace();mutations=[]
        db.progress_callback=lambda item:events.append(item) if item['stage'] in (
            'projection_publish_complete','rebuild_requests_aggregate_complete','ingest_origin_lookup_complete',
            'ingest_merge_complete','contract_read_complete') else None
        trace.attach(db);trace.before_commit=lambda raw:mutations.append(counters.transaction(raw))
        before=counters.snapshot(trace.original_conn);counts=dict(db.screen_counts)
        writes={k:dict(v) for k,v in db._capacity_writes.items()};commit_before=db._capacity_commit_seconds
        clock=time.perf_counter();cpu=time.process_time()
        notice(dict(status='FINANCIAL_SCREEN_WINDOW',purpose=purpose,mode=db.mode,ordinal=ordinal,kind=job['kind']))
        try:
            with trace.span('publication'):
                result=publisher(db,trace)(job['path'],job['start'],job['start']+FIVE,mode=job['mode'])
            publication_seconds=time.perf_counter()-clock;client_cpu=time.process_time()-cpu
        except BaseException as exc:
            lost=time.perf_counter()-clock;rollback=time.perf_counter()
            db.conn.rollback()
            raise LaneFailure(exc,dict(mode=db.mode,purpose=purpose,windows=windows,
                failed_window=dict(ordinal=ordinal,kind=job['kind'],elapsed_lost_seconds=lost,
                    additional_rollback_seconds=time.perf_counter()-rollback,trace=trace.report()),
                initialization_history_and_attempt_seconds=time.perf_counter()-began)) from exc
        finally:trace.detach();db.progress_callback=None
        check=db.one('SELECT generation FROM viewer_live_windows WHERE start_ns=?',(job['start'],))
        if not check or check['generation']!=result['generation']:raise AssertionError('COMMITTED_BOUNDARY_NOT_READABLE')
        contract_seconds=time.perf_counter()-clock
        after=counters.snapshot(db.conn);db.conn.rollback()
        own_counts={k:v-counts[k] for k,v in db.screen_counts.items()}
        final_writes={k:dict(calls=v['calls']-writes.get(k,{}).get('calls',0),
            seconds=v['seconds']-writes.get(k,{}).get('seconds',0)) for k,v in db._capacity_writes.items()}
        request_delta=[e for e in events if e.get('stage')=='projection_publish_complete' and e.get('table')=='viewer_requests']
        changed=sum(e.get('written_rows',0)+e.get('deleted_rows',0) for e in request_delta) if request_delta else None
        # No post-window full scans in a capacity lane. Correctness is another DB.
        oracle=(boundary_oracle(db,job) if boundary_oracle else retained_snapshot(db,db.mode)) if purpose=='correctness' else None
        db.conn.rollback()
        windows.append(dict(ordinal=ordinal,kind=job['kind'],capture_sha256=job['sha256'],
            records=job['records'],new_events=result['new_events'],impacted_requests=result['impacted_requests'],
            fresh_coverage_window=job['mode']=='forward',
            committed_receive_file_to_contract_seconds=contract_seconds,
            publication_seconds=publication_seconds,client_cpu_seconds=client_cpu,
            commit_seconds=db._capacity_commit_seconds-commit_before,
            counts=own_counts,actually_changed_request_rows=changed,
            changed_request_count_unavailable_on_bootstrap=changed is None,
            final_copy_insert=final_writes,trace=trace.report(),projection_mutations=events,
            writer_transaction_counters=mutations,writer_backend_counters=counters.delta(before,after),
            full_output_oracle=oracle,full_table_oracle_executed=purpose=='correctness' and boundary_oracle is None,
            affected_scope_oracle_executed=purpose=='correctness' and boundary_oracle is not None,
            deferred_work_is_not_complete=db.mode!='A'))
        guard()
    return dict(mode=db.mode,purpose=purpose,output_contract=coverage(db.mode),writer_settings=settings,
        backend_pid=db.conn.info.backend_pid,scope_identity=db.scope_identity,windows=windows,
        history_setup_publication_seconds=setup_seconds,
        initialization_history_and_windows_seconds=time.perf_counter()-began,
        per_window=distribution([w['committed_receive_file_to_contract_seconds'] for w in windows]),
        input_download='NOT_RUN_CAPTURE_FILE_REPLAY',cache_state='UNCONTROLLED_OS_CACHE_NO_CACHE_FLUSH',
        whole_product_capacity='NOT_RUN',ad_consumption='NOT_RUN_NO_FINANCIAL_ADAPTER')


def summarize(lanes):
    """No reduction estimate from correctness lanes or incomplete comparisons."""
    rows=[]
    for history in sorted({l['history_requests'] for l in lanes if l['purpose']=='capacity'}):
        group=[l for l in lanes if l['purpose']=='capacity' and l['history_requests']==history]
        reference=[w['committed_receive_file_to_contract_seconds'] for l in group if l['mode']=='A' for w in l['windows']]
        for mode in MODES:
            subset=[l for l in group if l['mode']==mode]
            values=[w['committed_receive_file_to_contract_seconds'] for l in subset for w in l['windows']]
            fresh=[w for l in subset for w in l['windows'] if w['fresh_coverage_window']]
            seconds=sum(w['committed_receive_file_to_contract_seconds'] for w in fresh)
            rows.append(dict(mode=mode,history_requests=history,distribution=distribution(values),
                newly_committed_coverage_windows=len(fresh),new_evidence=sum(w['new_events'] for w in fresh),
                diagnostic_file_replay_windows_per_hour=3600*len(fresh)/seconds if seconds else None,
                includes_es_acquisition=False,product_usable=False,
                balanced_complete_pairs={l.get('pair') for l in subset}=={0,1},
                all_boundary_time_reduction=1-sum(values)/sum(reference) if reference and len(values)==len(reference)
                    and {l.get('pair') for l in subset}=={0,1} and {l.get('pair') for l in group if l['mode']=='A'}=={0,1} else None,
                retained_output=coverage(mode),deferred_financial_scenarios=[s['id'] for s in SCENARIOS
                    if any(coverage(mode).get(f)!='COMPLETE' for f in s['required'])],
                recommendation='MEASURE_ON_LARGER_HISTORY_BEFORE_PRODUCT_DECISION'))
    return rows


def feature_decisions(rows,costs):
    result=[]
    definitions=(
        ('immutable_evidence_and_provenance','D',(),('F1','F2','F3','F4','F5'),'RETAIN_NO_DATA_DELETION','storage_path_redesign'),
        ('payment_reconstruction_and_item_outcomes','B1',('method:rebuild_payment_contract','method:_reconcile_payment_outcomes'),('F1','F2','F4'),'DIAGNOSTIC_OMISSION_ONLY','consumer_invalidation_required'),
        ('payment_dependency_expansion','B2',('method:dependency_closure',),('F1','F2','F4'),'RETAIN_FOR_FINANCIAL_CORE','cross_window_invalidation_required'),
        ('full_actions_and_materialized_outcomes','C',(),('F4','F6'),'CANDIDATE_DEFER_PENDING_SELECTED_ADAPTER','minimal_role_bridge_and_case_detail_path_required'))
    for history in sorted({r['history_requests'] for r in rows}):
        group={r['mode']:r for r in rows if r['history_requests']==history}
        baseline=[c for c in costs if c['mode']=='A' and c['history_requests']==history]
        for feature,mode,operations,lost,recommendation,complexity in definitions:
            value=group.get(mode,{})
            result.append(dict(feature=feature,history_requests=history,
                measured_component_inclusive_seconds=sum(sum(c['trace_inclusive_seconds'].get(op,0) for op in operations) for c in baseline) if operations and baseline else None,
                component_cost_scope='paired_A_lanes' if operations else 'NOT_SEPARATELY_ISOLATED_USE_DOMAIN_COMPARISON',
                comparison_mode=mode,speed_after_change=value.get('diagnostic_file_replay_windows_per_hour'),
                comparison_reduction=value.get('all_boundary_time_reduction'),
                lost_or_deferred_scenarios=list(lost) if mode!='D' else ['ALL_ANALYTIC_SCENARIOS_IN_D'],
                freshness='NOT_EVALUATED_FOR_OMITTED_OUTPUTS',implementation_complexity=complexity,
                recommendation=recommendation,product_capacity_accepted=False))
    for feature in ('query_time_full_journey','general_ad_models'):
        result.append(dict(feature=feature,measured_component_inclusive_seconds=None,speed_after_change=None,
            lost_or_deferred_scenarios=['F6'],freshness='NOT_EVALUATED_IF_DEFERRED',
            implementation_complexity='separate_consumer_contract',recommendation='MEASURE_SEPARATELY_NO_WRITER_SAVING_CLAIM'))
    return result


def run(parameters,*,counts=(16,64,256),histories=(0,4096),pairs=2,max_seconds=1800,
        bundle=None,guard_host=lambda:None,notice=lambda value:None):
    if len(counts)!=3 or any(type(n)is not int or not 1<=n<=32768 for n in counts):raise ValueError('INVALID_INPUT_COUNTS')
    if not histories or any(type(n)is not int or not 0<=n<=131072 for n in histories):raise ValueError('INVALID_HISTORY_COUNTS')
    if pairs!=2:raise ValueError('BALANCED_TWO_ORDERS_REQUIRED')
    if not 30<=max_seconds<=14400:raise ValueError('SCREEN_BUDGET_OUT_OF_RANGE')
    from psycopg import connect,sql
    from psycopg.rows import dict_row
    parameters={k:v for k,v in parameters.items() if k in ('host','port','user','password','connect_timeout')}
    if str(parameters.get('host','127.0.0.1')).lower() not in ('localhost','127.0.0.1','::1'):raise ValueError('LOCAL_SERVER_REQUIRED')
    start=time.perf_counter();deadline=time.monotonic()+max_seconds;created=[];identity=source_identity();lanes=[]
    report=dict(status='RUNNING',scope_identity=identity,base_writer_source_sha256=verify_sources(),
        canonical_runtime_source_sha256=BASE_RUNTIME,product_database_opened=False,
        product_database_modified=False,detector_methods_modified=False,capacity_target='NOT_ACCEPTED',
        scenarios=SCENARIOS,lanes=lanes,correctness=[],cache_pressure='NOT_QUALIFIED',
        actual_es_acquisition='NOT_RUN',eight_hour_whole_product='NOT_RUN',
        duration_budget_seconds=max_seconds,failures=[],cleanup=dict(allocated=0,dropped=0,remaining=[]))
    report['environment']=dict(os=platform.platform(),python=sys.version,
        git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=Path(__file__).resolve().parents[2],text=True).strip(),
        host_load_scope='PROJECT_PROCESS_AND_PG_SESSIONS_ONLY',working_set_outside_effective_cache='NOT_PROVEN')
    admin=connect(**parameters,dbname='postgres',autocommit=True,row_factory=dict_row,
        application_name='P24.FinancialScreen.Control')
    def guard():
        if source_identity()!=identity:raise ValueError('FINANCIAL_SCREEN_SOURCE_CHANGED')
        guard_host();assert_idle(admin,created)
    def lane(mode,purpose,jobs,setup_jobs,**labels):
        guard();clock=time.perf_counter()
        with allocated(admin,parameters,keys,mode,created,report['cleanup']) as db:
            try:
                with Sampler(admin,db,guard,deadline) as samples:
                    value=run_lane(db,jobs,setup_jobs,purpose=purpose,guard=guard,deadline=deadline,notice=notice)
            except LaneFailure as exc:
                exc.partial.update(labels,status='INCOMPLETE_LANE');lanes.append(exc.partial);raise
            value['resources']=samples.report()
        value.update(labels,create_initialize_run_and_drop_seconds=time.perf_counter()-clock)
        lanes.append(value);return value
    try:
        guard()
        if int(admin.execute('SHOW server_version_num').fetchone()['server_version_num'])<180000:raise ValueError('POSTGRESQL_18_REQUIRED')
        report['server_version']=admin.execute('SELECT version() AS value').fetchone()['value']
        with tempfile.TemporaryDirectory(prefix='financial-scope-screen-') as folder:
            root=Path(folder);keys=root/'disposable-keys.json';generate_keys(keys)
            risk=corpus(root,tuple(min(n,8) for n in counts))
            # Complete correctness is measured separately and never warms a
            # capacity database. It precedes the entire balanced capacity series.
            reference=None
            for mode in MODES:
                result=lane(mode,'correctness',risk,[],pair=None,history_requests=0)
                snapshots=[w['full_output_oracle'] for w in result['windows']]
                if mode=='A':reference=snapshots
                equal=[all(reference[i][t]==value for t,value in snap.items()) for i,snap in enumerate(snapshots)]
                report['correctness'].append(dict(mode=mode,boundaries=len(equal),retained_outputs_equal=all(equal),
                    scope_only_not_full_product_equivalence=mode!='A'))
                if not all(equal):raise AssertionError('RETAINED_OUTPUT_DIFFERENCE:'+mode)
            if bundle:
                from viewer_performance.Qualify_Capacity_Candidate import extract_captures
                jobs=capture_jobs(extract_captures(Path(bundle),root))
                report.update(input_kind='VERIFIED_PRIVATE_CAPTURE_FILES',input_bundle_sha256=hashlib.sha256(Path(bundle).read_bytes()).hexdigest())
            else:jobs=corpus(root,counts);report['input_kind']='SYNTHETIC_RISK_CORPUS'
            report['input_jobs']=[{k:v for k,v in job.items() if k!='path'} for job in jobs]
            for history in histories:
                setup_jobs=seed(root,jobs[0]['start'],history)
                for pair in range(pairs):
                    for mode in (MODES if pair==0 else tuple(reversed(MODES))):
                        notice(dict(status='FINANCIAL_SCREEN_LANE',mode=mode,pair=pair,history_requests=history))
                        lane(mode,'capacity',jobs,setup_jobs,pair=pair,history_requests=history)
            guard();report['status']='SCOPE_SCREEN_COMPLETE_NOT_PRODUCT_ACCEPTANCE'
    except BaseException as exc:
        report.update(status='SCOPE_SCREEN_INCOMPLETE',failure=exc.failure if isinstance(exc,LaneFailure) else dict(error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,(ValueError,TimeoutError,AssertionError)) else None,sqlstate=getattr(exc,'sqlstate',None)))
        report['failures'].append(report['failure'])
    finally:
        for name in list(created):
            try:
                admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
                created.remove(name);report['cleanup']['dropped']+=1
            except Exception as exc:report['failures'].append(dict(stage='cleanup',error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None)))
        report['cleanup']['remaining']=list(created);admin.close()
        if created:report['status']='SCOPE_SCREEN_CLEANUP_INCOMPLETE'
    report['decisions']=summarize([l for l in lanes if l.get('status')!='INCOMPLETE_LANE'])
    report['retry_policy']='NO_AUTOMATIC_RETRIES_FAILURES_AND_LOST_TIME_REPORTED'
    report['component_costs']=[dict(mode=l['mode'],pair=l.get('pair'),history_requests=l['history_requests'],
        trace_inclusive_seconds={name:sum(w['trace']['spans'].get(name,{}).get('inclusive_seconds',0) for w in l['windows'])
            for name in ('method:dependency_closure','method:rebuild_payment_contract','method:_rebuild_requests',
                'method:_reconcile_payment_outcomes','method:reconcile_semantic_requests','capture:verify_and_decode')},
        inclusive_components_overlap_and_must_not_be_added=True)
        for l in lanes if l['purpose']=='capacity' and l.get('status')!='INCOMPLETE_LANE']
    report['feature_decision_table']=feature_decisions(report['decisions'],report['component_costs'])
    report['whole_run_including_oracles_seeding_create_drop_seconds']=time.perf_counter()-start
    report['limitations']=['A measures the full Viewer publisher, not an executing AD or query-time web journey.',
        'B1/B2 and D are diagnostic, and C still needs a selected financial detector adapter.',
        'A larger retained fixture is a history-scaling screen, not proof of an out-of-cache active working set.',
        'Input download from Elasticsearch, cold-cache control and eight-hour whole-product capacity are not measured.',
        'Per-backend PG counters may lag; transaction row/buffer counters and mutation callbacks have explicit scope.',
        'Rechecks have work costs but are not counted as newly covered five-minute windows.']
    return report
