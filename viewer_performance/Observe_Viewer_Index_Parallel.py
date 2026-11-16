"""READ ONLY 1/2/4-reader calibration; no publication-capacity claim."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

if __package__ in (None,''):sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from viewer_performance.Observe_Viewer_Index_Cost import ReadOnlyProbe,owner,plan_summary
from viewer_performance.capacity.index_prefetch import BATCH,TABLES,probe_sql,STATEMENT_MS


def ad_status(project):
    output=subprocess.run([sys.executable,'-B',str(project/'AnomalyDetection/run_anomaly.py'),'worker-status'],
        cwd=project,capture_output=True,text=True,timeout=8)
    if output.returncode:raise ValueError('ad_status_command_failed')
    value=json.loads(output.stdout);process=value.get('process',{}).get('owner') or {}
    declared=json.loads((project/'AnomalyDetection/RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    age=value.get('heartbeat_age_seconds')
    if not (value.get('running') is True and value.get('observation_matches_process') is True
            and isinstance(age,(int,float)) and 0<=age<30 and process.get('instance_token')
            and process.get('build_id')==declared['build_id']
            and process.get('source_sha256')==declared['source_sha256']):
        raise ValueError('current_ad_process_with_fresh_heartbeat_required')
    worker=value.get('worker') or {}
    return dict(instance_token=process['instance_token'],pid=process['pid'],build_id=process['build_id'],
        source_sha256=process['source_sha256'],health=value['health'],heartbeat_age_seconds=age,
        counters={k:worker.get(k) for k in ('phase','source_pages','evaluated_jobs','audited_requests',
            'cohort_windows','scenario_evaluations','content_reads')})


def observe(config,observe_ad,*,seconds=30,_qualification=False):
    import psycopg
    from psycopg.rows import dict_row
    name=config.get('dbname','')
    if name!='p24_design_viewer' and not (_qualification and name.startswith('p24_design_capacity_')
            and name.endswith('_qualification')):raise ValueError('recorded_viewer_or_owned_test_database_required')
    if not 10<=seconds<=60:raise ValueError('parallel_probe_budget_must_be_10_to_60_seconds')
    total_began=time.perf_counter()
    ad_before=observe_ad()  # No source connection when AD is stopped/unverified.
    if not ad_before.get('instance_token'):raise ValueError('ad_process_identity_required')
    began=time.perf_counter();deadline=began+seconds
    options={k:config[k] for k in ('host','port','dbname','user','password') if k in config}
    options.update(connect_timeout=3,options='-c default_transaction_read_only=on -c jit=off '
        '-c statement_timeout='+str(STATEMENT_MS)+' -c lock_timeout=100 -c max_parallel_workers_per_gather=0',
        application_name='P24.Capacity.parallel-index-readonly')
    result=dict(status='READ_ONLY_PARALLEL_INDEX_OBSERVATION',database_modified=False,workers_restarted=False,
        scope='only_these_readonly_probe_connections_not_the_writer',publication_capacity='NOT_MEASURED',
        physical_disk_reads_inferred=False,cold_cache='NOT_CONTROLLED',shared_host_load='NOT_CONTROLLED',
        actual_user_keys_loaded=False,synthetic_keys_exported=False,max_probe_connections=5,
        max_pending_synthetic_pairs=4*BATCH,ad_before=ad_before,cells=[],failures=[],
        qualification_ad_fixture=_qualification)
    with psycopg.connect(**options,autocommit=True,row_factory=dict_row) as control:
        db=ReadOnlyProbe(control)
        from p24_foundation.viewer_origin_storage import active
        if not active(db):raise ValueError('binary_origin_layout_required')
        result['writer_before']=owner(db)
        if not result['writer_before']:raise ValueError('viewer_writer_lease_required')
        result['settings']=db.sql('SELECT name,setting,unit FROM pg_settings WHERE name=ANY(?)',
            (['server_version','shared_buffers','effective_cache_size','track_io_timing',
              'default_transaction_read_only','statement_timeout','max_parallel_workers_per_gather'],)).fetchall()
        for table in TABLES:
            for round_number,order in enumerate(((1,2,4),(4,2,1))):
                for workers in order:
                    if time.perf_counter()>=deadline:break
                    cell_began=time.perf_counter()
                    pairs=sorted((secrets.token_hex(32),secrets.token_hex(32)) for _ in range(4*BATCH))
                    batches=[pairs[i:i+BATCH] for i in range(0,len(pairs),BATCH)]
                    readers=[]
                    try:
                        for _ in range(workers):
                            if time.perf_counter()>=deadline:break
                            connection=psycopg.connect(**options,autocommit=True)
                            readers.append(connection)
                            if connection.execute("SELECT current_setting('transaction_read_only')").fetchone()[0]!='on':
                                raise ValueError('parallel_probe_connection_not_readonly')
                        if len(readers)!=workers:break
                        setup_seconds=time.perf_counter()-cell_began
                        def lane(number):
                            values=[]
                            for ordinal in range(number,len(batches),workers):
                                batch=batches[ordinal]
                                params=([p[0] for p in batch],[p[1] for p in batch])
                                for access in ('first_observed','repeated_same_keys'):
                                    if time.perf_counter()>=deadline:return values
                                    start=time.perf_counter()
                                    try:
                                        plan=readers[number].execute(probe_sql(table),params).fetchone()[0][0]
                                        values.append(dict(batch=ordinal,access=access,keys=len(batch),
                                            wall_seconds=time.perf_counter()-start,**plan_summary(plan)))
                                    except psycopg.Error as exc:
                                        values.append(dict(batch=ordinal,access=access,keys=len(batch),
                                            wall_seconds=time.perf_counter()-start,error_type=type(exc).__name__,sqlstate=exc.sqlstate))
                                        return values
                            return values
                        with ThreadPoolExecutor(max_workers=workers) as pool:
                            samples=[s for lane_samples in pool.map(lane,range(workers)) for s in lane_samples]
                        result['cells'].append(dict(table=table,round=round_number,workers=workers,
                            order=list(order),setup_seconds=setup_seconds,wall_seconds=time.perf_counter()-cell_began,
                            completed_pair_batches=sum(len([s for s in samples if s['batch']==n and 'error_type' not in s])==2 for n in range(4)),
                            samples=samples))
                    finally:
                        for reader in readers:reader.close()
        result['writer_after']=owner(db)
    result['elapsed_seconds']=time.perf_counter()-began
    try:result['ad_after']=observe_ad()
    except Exception as exc:
        result['ad_after']={};result['failures'].append(dict(stage='ad_after',error_type=type(exc).__name__))
    result['ad_same_verified_instance']=bool(result['ad_after'].get('instance_token')==ad_before['instance_token'])
    identity=lambda rows:{(r['pid'],r['backend_start']) for r in rows}
    result['viewer_same_lease_owner']=bool(identity(result['writer_before'])==identity(result['writer_after']) and result['writer_after'])
    result['workers_observed_alive_and_unchanged']=result['ad_same_verified_instance'] and result['viewer_same_lease_owner']
    result['complete_cells']=sum(c['completed_pair_batches']==4 for c in result['cells'])
    if (result['complete_cells']!=12 or not result['workers_observed_alive_and_unchanged']
            or result['failures']):result['status']='PARTIAL_READ_ONLY_PARALLEL_INDEX_OBSERVATION'
    result['total_seconds_including_ad_observations']=time.perf_counter()-total_began
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True);parser.add_argument('--seconds',type=int,default=30)
    args=parser.parse_args(argv);project=args.project.resolve();sys.path.insert(0,str(project))
    from viewer_performance.Qualify_Capacity_Candidate import EXPECTED_RUNTIME,literal_database
    from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json
    try:
        if runtime_source_digest(project)!=EXPECTED_RUNTIME:raise ValueError('installed_viewer_is_not_the_recorded_baseline')
        result=observe(literal_database(project),lambda:ad_status(project),seconds=args.seconds)
        result.update(runtime_source_sha256=EXPECTED_RUNTIME,
            probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            runtime_still_matches=runtime_source_digest(project)==EXPECTED_RUNTIME)
        if not result['runtime_still_matches']:result['status']='PARTIAL_READ_ONLY_PARALLEL_INDEX_OBSERVATION'
        output=project/'AnomalyDetection/reports'/('Viewer_Index_Parallel_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
        atomic_json(output,result)
        notice={k:result[k] for k in ('status','complete_cells','workers_observed_alive_and_unchanged','database_modified','workers_restarted')}
        notice['output']=str(output)
    except Exception as exc:
        notice=dict(status='READ_ONLY_PARALLEL_INDEX_BLOCKED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,sqlstate=getattr(exc,'sqlstate',None),
            database_modified=False,workers_restarted=False)
    print(json.dumps(notice));return 2 if notice['status']=='READ_ONLY_PARALLEL_INDEX_BLOCKED' else 0


if __name__=='__main__':raise SystemExit(main())
