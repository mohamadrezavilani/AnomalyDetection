"""Full versus behavior on native physical copies of the frozen real history.

No source publication, source DDL, reset or FORCE DROP. Each lane starts from
the same product template, uses the same newly captured missing windows and
separately charges copy/setup costs. Capacity runs contain no output oracles.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import time
import uuid

from p24_foundation.viewer_product_scope import FULL,BEHAVIOR,set_scope,read
from p24_foundation.viewer_online import FIVE_NS
from viewer_performance.capacity.baseline import capture_jobs,distribution
from viewer_performance.financial_screen.experiment import run_lane,assert_idle
from viewer_performance.financial_screen.modes import ScreenDB
from viewer_performance.financial_screen.resources import Sampler


def digest_rows(db,table,columns,where,params):
    cursor=db.sql('SELECT '+columns+' FROM '+table+' WHERE '+where+' ORDER BY 1,2',params)
    digest=hashlib.sha256();count=0
    while True:
        rows=cursor.fetchmany(500)
        if not rows:break
        for row in rows:
            digest.update(json.dumps(dict(row),sort_keys=True,default=lambda v:bytes(v).hex()).encode()+b'\n');count+=1
    return dict(rows=count,sha256=digest.hexdigest())


def run(project,directory,guard,notice,*,windows=4,max_seconds=21600,parameters=None,options=None):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    from viewer_performance.financial_screen.host import parameters as host_parameters
    from viewer_performance.Run_Viewer_Web import existing_options
    from p24_foundation.viewer_data import ViewerDB,source_identity,token,opaque
    from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.capacity.oracle import PROJECTIONS
    project=Path(project);directory=Path(directory)
    if windows not in (2,4,8):raise ValueError('BENCHMARK_WINDOWS_MUST_BE_2_4_OR_8')
    began=time.monotonic();deadline=began+max_seconds;owned=[];lanes=[]
    report=dict(status='LARGE_HISTORY_BENCHMARK_RUNNING',lanes=lanes,product_evidence_modified=False,
        product_cursors_modified=False,history='PHYSICAL_COPY_OF_FROZEN_PRODUCT',cold_cache='NOT_CONTROLLED',
        ad_and_web_during_exclusive_benchmark='STOPPED',traffic_representativeness='NOT_ESTABLISHED_BY_FOUR_WINDOWS',whole_product_acceptance='NOT_RUN',cleanup=[])
    parameters=parameters or host_parameters(project);options=options or existing_options(project)
    admin=psycopg.connect(**parameters,dbname='postgres',autocommit=True,row_factory=dict_row,
        application_name='P24.BehaviorBenchmark.Control')
    source=options['config']['dbname']
    if source!='p24_design_viewer':raise ValueError('PRODUCT_TEMPLATE_REQUIRED')
    def check():
        guard();assert_idle(admin,owned)
        if time.monotonic()>deadline:raise TimeoutError('LARGE_HISTORY_BENCHMARK_BUDGET_EXHAUSTED')
    @contextmanager
    def clone():
        check();name='p24_design_capacity_fs_'+uuid.uuid4().hex[:16]+'_qualification';clock=time.monotonic()
        admin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE {} STRATEGY FILE_COPY').format(sql.Identifier(name),sql.Identifier(source)))
        owned.append(name)
        report['last_clone_seconds']=time.monotonic()-clock
        try:yield name
        finally:
            admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
            owned.remove(name);report['cleanup'].append(name)
    try:
        check()
        size=admin.execute('SELECT pg_database_size(%s) AS bytes',(source,)).fetchone()['bytes']
        data=admin.execute("SHOW data_directory").fetchone()['data_directory']
        free=shutil.disk_usage(data).free
        if free<2*size+8*1024**3:raise ValueError('INSUFFICIENT_SPACE_FOR_LARGE_HISTORY_COPY')
        report.update(source_database_bytes=size,free_bytes_before=free,
            peak_additional_copy_budget_bytes=2*size,copy_strategy='FILE_COPY_CHECKPOINT_COST_INCLUDED')
        # Read-only inspection is completed and closed before template copying.
        with ViewerDB(**options) as db:
            db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            if read(db,refresh=True)['contract']!=FULL:raise ValueError('FULL_SCOPE_TEMPLATE_REQUIRED_FOR_FIRST_COMPARISON')
            state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
            present=db.one("SELECT to_regclass('public.viewer_history_replay_state') AS name")
            history=db.one('SELECT * FROM viewer_history_replay_state WHERE id=1') if present['name'] else None
            start=history['next_ns'] if history and history['status']=='RUNNING' else state['next_ns']
            report['source_history_catalog']=db.all("SELECT relname,n_live_tup,pg_relation_size(relid) AS heap_bytes FROM pg_stat_user_tables WHERE schemaname='public' AND relname IN ('viewer_events','viewer_raw_events','viewer_requests','viewer_links')")
            report['source_checkpoint']=dict(start_ns=state['start_ns'],next_ns=state['next_ns'],generation=state['generation'])
            if any(db.one('SELECT 1 AS yes FROM viewer_live_windows WHERE start_ns=?',(start+n*FIVE_NS,)) for n in range(windows)):
                raise ValueError('BENCHMARK_NEEDS_MISSING_WINDOWS_NOT_REPLAY_OF_PUBLISHED_WINDOWS')
        cfg=runpy.run_path(str(project/'viewer_config.local.py'));settings=cfg.get('LIVE',{})
        capture=ElasticCapture(ElasticREST(cfg['ELASTICSEARCH']),directory/'captures',
            page_size=settings.get('page_size',5000),max_seconds=settings.get('capture_budget_seconds',240))
        paths=[];capture_seconds=[]
        for n in range(windows):
            check();at=start+n*FIVE_NS;clock=time.monotonic()
            paths.append(capture(at,at+FIVE_NS));capture_seconds.append(time.monotonic()-clock)
        jobs=capture_jobs(paths)
        for job in jobs:job['mode']='manual_recheck' if job['start']<state['next_ns'] else 'forward'
        report['capture_seconds']=capture_seconds
        # Fixed set of changed origin and old/new RequestID owners. Qualify
        # complete retained rows at each boundary, not a sampled final digest.
        import gzip
        origins=set();requests=set()
        with ViewerDB(**options) as db:
            db.sql('SET TRANSACTION READ ONLY')
            for job in jobs:
                if db.one('SELECT 1 AS yes FROM viewer_files WHERE file_hash=?',(job['sha256'],)):
                    raise ValueError('BENCHMARK_CAPTURE_ALREADY_IMPORTED')
                with gzip.open(job['path'],'rt',encoding='utf-8') as stream:rows=json.load(stream)['logs']
                for row in rows:
                    idx,doc=source_identity(row)
                    if not idx:raise ValueError('BENCHMARK_REQUIRES_AUTHORITATIVE_ORIGIN')
                    origins.add(token(db.keys,'origin',[idx,doc]))
                    if row.get('RequestID'):requests.add(token(db.keys,'request',opaque(row['RequestID'])))
            for offset in range(0,len(origins),1000):
                batch=sorted(origins)[offset:offset+1000]
                requests.update(r['request_key'] for r in db.all('SELECT DISTINCT request_key FROM viewer_events WHERE origin_key=ANY(?) AND request_key IS NOT NULL',(batch,)))
        requests=sorted(requests);origins=sorted(origins)
        def oracle(db,job):
            result={}
            for table,col,columns,values in (
                ('viewer_events','origin_key','*',origins),('viewer_raw_events','origin_key','*',origins),
                ('viewer_requests','request_key','*',requests),
                ('viewer_semantic_occurrences','request_key',PROJECTIONS['viewer_semantic_occurrences'],requests),
                ('viewer_semantic_transitions','request_key',PROJECTIONS['viewer_semantic_transitions'],requests)):
                result[table]=digest_rows(db,table,columns,col+'=ANY(?)',(values,))
            return result
        reference=None
        for purpose,order in (('correctness',('full','behavior')),('capacity',('full','behavior','behavior','full'))):
            for ordinal,mode in enumerate(order):
                check();clock=time.monotonic();notice(dict(status='LARGE_HISTORY_LANE',purpose=purpose,mode=mode,ordinal=ordinal))
                with clone() as name:
                    copied=report['last_clone_seconds']
                    config=dict(parameters,dbname=name,
                        options='-c jit=off -c work_mem=64MB -c temp_buffers=128MB -c wal_compression=zstd')
                    with ScreenDB(config=config,keys_path=options['keys_path'],mode='A') as db:
                        set_scope(db,FULL if mode=='full' else BEHAVIOR);db.conn.commit()
                        with Sampler(admin,db,check,deadline,max_database_bytes=size+16*1024**3) as samples:
                            lane=run_lane(db,jobs,[],purpose=purpose,guard=check,deadline=deadline,notice=notice,
                                existing_stream=True,boundary_oracle=oracle if purpose=='correctness' else None)
                        lane.update(scope_mode=mode,pair=ordinal//2,copy_seconds=copied,resources=samples.report())
                        for i,w in enumerate(lane['windows']):
                            if jobs[i]['records'] and not w['new_events']:raise ValueError('FRESH_COVERAGE_WITHOUT_NEW_EVIDENCE_REJECTED')
                            w['fresh_coverage_window']=True
                            w['receive_through_commit_seconds']=w['committed_receive_file_to_contract_seconds']+capture_seconds[i]
                        if purpose=='correctness':
                            proof=[w['full_output_oracle'] for w in lane['windows']]
                            if reference is None:reference=proof
                            elif proof!=reference:raise AssertionError('BEHAVIOR_RETAINED_BOUNDARY_DIFFERENCE_ON_LARGE_HISTORY')
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
        report.update(status='LARGE_HISTORY_BENCHMARK_INCOMPLETE',failure=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,AssertionError,TimeoutError)) else None))
    finally:
        for name in list(owned):
            try:admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)));owned.remove(name)
            except Exception:pass
        report['remaining_owned_databases']=owned;admin.close()
        report['total_including_capture_copies_oracles_cleanup_seconds']=time.monotonic()-began
        atomic_json(directory/'benchmark.json',report)
    return report
