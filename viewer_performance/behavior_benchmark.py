"""Fresh-window full/behavior comparison on physical copies of frozen history.

Correctness copies reconcile whole retained behavior and unchanged archives.
Separate capacity copies use balanced AB/BA and contain no output oracle.
No source DDL/publication, FORCE DROP, source cursor or durability changes.
"""
import ast
import json
from pathlib import Path
import shutil
import time

from p24_foundation.viewer_product_scope import FULL,BEHAVIOR,set_scope,read
from p24_foundation.viewer_online import FIVE_NS
from viewer_performance.capacity.baseline import capture_jobs,distribution
from viewer_performance.financial_screen.experiment import run_lane,assert_idle
from viewer_performance.financial_screen.modes import ScreenDB
from viewer_performance.financial_screen.resources import Sampler
from viewer_performance.behavior_resources import CopyOwner,PhaseBudget,wal_codec,behavior_sources
from viewer_performance.behavior_oracle import retained,archives


def literal_settings(project):
    values={}
    for node in ast.parse((project/'viewer_config.local.py').read_text(encoding='utf-8-sig')).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and target.id in ('ELASTICSEARCH','LIVE'):
                    if target.id in values:raise ValueError('AMBIGUOUS_CAPTURE_SETTINGS')
                    try:values[target.id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError):raise ValueError('LITERAL_CAPTURE_SETTINGS_REQUIRED') from None
    return values


def run(project,directory,guard,notice,*,windows=4,max_seconds=21600,parameters=None,options=None,capture_paths=None,qualification_disk_path=None):
    import psycopg
    from psycopg.rows import dict_row
    from viewer_performance.financial_screen.host import parameters as host_parameters
    from viewer_performance.Run_Viewer_Web import existing_options
    from p24_foundation.viewer_data import ViewerDB
    from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture
    from p24_foundation.viewer_runtime import atomic_json
    project=Path(project);directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    if windows not in (2,4,8):raise ValueError('BENCHMARK_WINDOWS_MUST_BE_2_4_OR_8')
    if not 30<=max_seconds<=86400:raise ValueError('BENCHMARK_TIME_BUDGET_OUT_OF_RANGE')
    began=time.monotonic();deadline=began+max_seconds;lanes=[];owner=None;identity=behavior_sources()
    report=dict(status='LARGE_HISTORY_BENCHMARK_RUNNING',lanes=lanes,product_evidence_modified=False,
        product_cursors_modified=False,history='PHYSICAL_COPY_OF_FROZEN_PRODUCT',cold_cache='NOT_CONTROLLED',
        ad_and_web_during_exclusive_benchmark='STOPPED',traffic_representativeness='NOT_ESTABLISHED_BY_TWO_TO_EIGHT_WINDOWS',
        whole_product_acceptance='NOT_RUN',capacity_target_accepted=False,cleanup_failures=[],behavior_tool_identity=identity)
    parameters=parameters or host_parameters(project);options=options or existing_options(project)
    source=options['config']['dbname']
    if source=='p24_design_viewer' and qualification_disk_path is not None:
        raise ValueError('PRODUCT_DISK_GUARD_MUST_USE_SERVER_DATA_DIRECTORY')
    if source!='p24_design_viewer' and not (source.startswith('p24_design_capacity_template_') and source.endswith('_qualification')):
        raise ValueError('PRODUCT_OR_OWNED_QUALIFICATION_TEMPLATE_REQUIRED')
    admin=psycopg.connect(**parameters,dbname='postgres',autocommit=True,row_factory=dict_row,
        application_name='P24.BehaviorBenchmark.Control',options='-c statement_timeout=300000 -c lock_timeout=10000')
    def check():
        if behavior_sources()!=identity:raise ValueError('BEHAVIOR_BENCHMARK_SOURCE_CHANGED')
        guard()
        owned=[r['name'] for r in owner.state['allocations'] if r['state']=='OWNED'] if owner else []
        assert_idle(admin,owned)
        if time.monotonic()>deadline:raise TimeoutError('LARGE_HISTORY_BENCHMARK_BUDGET_EXHAUSTED')
    try:
        check()
        if int(admin.execute('SHOW server_version_num').fetchone()['server_version_num'])<180000:raise ValueError('POSTGRESQL_18_REQUIRED')
        size=admin.execute('SELECT pg_database_size(%s) AS bytes',(source,)).fetchone()['bytes']
        server_directory=admin.execute('SHOW data_directory').fetchone()['data_directory']
        # Docker's server path is in another filesystem namespace. A client
        # path is allowed only for the explicitly disposable test template; it
        # never qualifies server free space or bypasses the product disk gate.
        data=str(Path(qualification_disk_path).resolve()) if qualification_disk_path is not None else server_directory
        report['disk_capacity_scope']='QUALIFICATION_CLIENT_FILESYSTEM_NOT_SERVER_VOLUME' if qualification_disk_path is not None else 'LOCAL_SERVER_DATA_DIRECTORY'
        free=shutil.disk_usage(data).free
        if free<2*size+8*1024**3:raise ValueError('INSUFFICIENT_SPACE_FOR_LARGE_HISTORY_COPY')
        codec=wal_codec(admin)
        report.update(source_database_bytes=size,free_bytes_before=free,wal_compression=codec,
            peak_additional_copy_budget_bytes=2*size,copy_strategy='FILE_COPY_CHECKPOINT_COST_INCLUDED',
            oracle_scope='ALL_RETAINED_ROWS_AND_ALL_OWNED_AD_HISTORY_NOT_AFFECTED_REQUEST_SAMPLE',
            intentionally_different_fields=['financial_links','financial_actions_target_workflow_outcome','financial_contract_projections','scope_ledger'],
            memory_guard='SAMPLED_CLIENT_RSS_2GiB_OS_RESERVE_4GiB_NOT_HARD_OS_LIMIT')
        with ViewerDB(**options) as db:
            db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            current=read(db,refresh=True)
            if current['contract']!=FULL or current['state']!='READY':raise ValueError('READY_FULL_SCOPE_TEMPLATE_REQUIRED')
            state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
            present=db.one("SELECT to_regclass('public.viewer_history_replay_state') AS name")
            history=db.one('SELECT * FROM viewer_history_replay_state WHERE id=1') if present['name'] else None
            start=history['next_ns'] if history and history['status']=='RUNNING' else state['next_ns']
            report['source_history_catalog']=db.all("SELECT relname,n_live_tup,pg_relation_size(relid) AS heap_bytes FROM pg_stat_user_tables WHERE schemaname='public' AND relname IN ('viewer_events','viewer_raw_events','viewer_requests','viewer_links')")
            report['source_checkpoint']=dict(start_ns=state['start_ns'],next_ns=state['next_ns'],generation=state['generation'])
            if any(db.one('SELECT 1 AS yes FROM viewer_live_windows WHERE start_ns=?',(start+n*FIVE_NS,)) for n in range(windows)):
                raise ValueError('BENCHMARK_NEEDS_MISSING_WINDOWS_NOT_PUBLISHED_REPLAY')
        paths=[];capture_seconds=[]
        with PhaseBudget(guard,deadline,disk=data) as capture_budget:
            if capture_paths is not None:
                paths=list(capture_paths);capture_seconds=[0.]*len(paths)
                report['input_acquisition']='VERIFIED_CAPTURE_REPLAY_NOT_MEASURED_ES'
            else:
                cfg=literal_settings(project);settings=cfg.get('LIVE',{})
                seconds=min(settings.get('capture_budget_seconds',240),int(deadline-time.monotonic()))
                capture=ElasticCapture(ElasticREST(cfg['ELASTICSEARCH']),directory/'captures',
                    page_size=settings.get('page_size',5000),max_seconds=seconds)
                for n in range(windows):
                    capture_budget.check();clock=time.monotonic();at=start+n*FIVE_NS
                    paths.append(capture(at,at+FIVE_NS));capture_seconds.append(time.monotonic()-clock)
                report['input_acquisition']='ONCE_FROM_ES_SAME_FILES_IN_ALL_LANES'
            jobs=capture_jobs(paths)
            if len(jobs)!=windows or any(j['start']!=start+i*FIVE_NS for i,j in enumerate(jobs)):
                raise ValueError('CAPTURES_MUST_MATCH_NEXT_MISSING_WINDOWS')
            for job in jobs:job['mode']='manual_recheck' if job['start']<state['next_ns'] else 'forward'
        report['capture_seconds']=capture_seconds;report['capture_peak_sampled_client_rss_bytes']=capture_budget.peak
        with ViewerDB(**options) as db:
            db.sql('SET TRANSACTION READ ONLY')
            for job in jobs:
                if db.one('SELECT 1 AS yes FROM viewer_files WHERE file_hash=?',(job['sha256'],)):
                    raise ValueError('BENCHMARK_CAPTURE_ALREADY_IMPORTED')
        check();owner=CopyOwner(admin,source,directory,check,deadline);reference=None
        for purpose,order in (('correctness',('full','behavior')),('capacity',('full','behavior','behavior','full'))):
            for ordinal,mode in enumerate(order):
                check();clock=time.monotonic();notice(dict(status='LARGE_HISTORY_LANE',purpose=purpose,mode=mode,ordinal=ordinal))
                # A separate monitor can cancel blocking CREATE and oracle SQL.
                with PhaseBudget(guard,deadline,connection=admin,disk=data):
                    with owner.clone() as allocation:
                        config=dict(parameters,dbname=allocation['name'],options='-c jit=off -c work_mem=64MB -c temp_buffers=128MB -c wal_compression='+codec)
                        with ScreenDB(config=config,keys_path=options['keys_path'],mode='A') as db:
                            set_scope(db,FULL if mode=='full' else BEHAVIOR);db.conn.commit()
                            old_archives=None
                            if purpose=='correctness' and mode=='behavior':
                                with PhaseBudget(guard,deadline,connection=db.conn,disk=data):old_archives=archives(db,check)
                                db.conn.rollback()
                            def oracle(db,job):
                                with PhaseBudget(guard,deadline,connection=db.conn,disk=data):
                                    value=retained(db,check)
                                    if old_archives is not None and archives(db,check)!=old_archives:
                                        raise AssertionError('BEHAVIOR_CHANGED_RETAINED_FINANCE_OR_AD_ARCHIVES')
                                    return value
                            with Sampler(admin,db,check,deadline,max_database_bytes=size+16*1024**3) as samples:
                                lane=run_lane(db,jobs,[],purpose=purpose,guard=check,deadline=deadline,notice=notice,
                                    existing_stream=True,boundary_oracle=oracle if purpose=='correctness' else None)
                            lane.update(scope_mode=mode,pair=ordinal//2,copy_seconds=allocation['copy_seconds'],resources=samples.report())
                            for i,w in enumerate(lane['windows']):
                                if jobs[i]['records'] and not w['new_events']:raise ValueError('FRESH_COVERAGE_WITHOUT_NEW_EVIDENCE_REJECTED')
                                w['fresh_coverage_window']=True
                                w['receive_through_commit_seconds']=w['committed_receive_file_to_contract_seconds']+capture_seconds[i]
                            if purpose=='correctness':
                                proof=[w['full_output_oracle'] for w in lane['windows']]
                                if reference is None:reference=proof
                                elif proof!=reference:
                                    differences=[dict(boundary=i,table=table,full=reference[i].get(table),behavior=value)
                                        for i,part in enumerate(proof) for table,value in part.items() if reference[i].get(table)!=value]
                                    report['retained_boundary_differences']=differences
                                    raise AssertionError('BEHAVIOR_RETAINED_BOUNDARY_DIFFERENCE:'+','.join(sorted({d['table'] for d in differences})))
                lane['copy_setup_run_drop_seconds']=time.monotonic()-clock;lanes.append(lane)
                atomic_json(directory/'benchmark.json',report)
        report['decisions']=[]
        for mode in ('full','behavior'):
            values=[w for lane in lanes if lane['purpose']=='capacity' and lane['scope_mode']==mode for w in lane['windows']]
            times=[w['receive_through_commit_seconds'] for w in values]
            final=sum(sum(x['seconds'] for x in w['final_copy_insert'].values()) for w in values)
            report['decisions'].append(dict(scope=mode,distribution=distribution(times),fresh_windows=len(values),
                fresh_windows_per_hour=3600*len(times)/sum(times),final_copy_insert_seconds=final,
                final_copy_insert_share=final/sum(times),deferred_financial_work='OUT_OF_SCOPE_NOT_QUEUED' if mode=='behavior' else 'COMPLETE'))
        report['status']='LARGE_HISTORY_EQUIVALENCE_AND_CAPACITY_COMPLETE'
    except BaseException as exc:
        report.update(status='LARGE_HISTORY_BENCHMARK_INCOMPLETE',failure=dict(error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,(ValueError,AssertionError,TimeoutError)) else None,
            detail=getattr(exc,'failure',None)))
    finally:
        if owner:
            report['cleanup_failures']=owner.cleanup()
            report['remaining_owned_databases']=[r['name'] for r in owner.state['allocations'] if r['state']!='DROPPED']
        else:report['remaining_owned_databases']=[]
        if report['remaining_owned_databases'] or report['cleanup_failures']:report['status']='LARGE_HISTORY_BENCHMARK_CLEANUP_INCOMPLETE'
        admin.close();report['total_including_capture_copies_oracles_cleanup_seconds']=time.monotonic()-began
        atomic_json(directory/'benchmark.json',report)
    return report
