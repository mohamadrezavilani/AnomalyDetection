"""Current publisher baseline in disposable databases; no production access.

This first diagnostic qualifies measurement and per-publication equivalence.
It deliberately does NOT certify cache pressure, ES acquisition, full AD
evaluation, eight-hour capacity, or a performance candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import gzip
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.viewer_online import bind_stream, initialize_live, publish_capture, resume_recent, single_worker, _read_verified_capture
from p24_foundation.viewer_runtime import atomic_json, runtime_source_digest
from .oracle import evidence_digest, projection_digest
from .fixtures import corpus, START, FIVE
from .trace import Trace
from . import counters

SETTINGS=('server_version','shared_buffers','effective_cache_size','work_mem','temp_buffers',
    'jit','wal_compression','fsync','full_page_writes','synchronous_commit','wal_level',
    'track_io_timing','track_wal_io_timing','statement_timeout','lock_timeout')


def distribution(values):
    if not values:
        return dict(samples=0,mean=None,median=None,p95=None)
    values=sorted(values)
    return dict(samples=len(values),mean=statistics.mean(values),median=statistics.median(values),
        p95=values[max(0,math.ceil(.95*len(values))-1)],p95_method='nearest_rank')


def semantic_snapshot(db):
    result={**projection_digest(db),**evidence_digest(db)}
    rows=db.all('''SELECT request_key,revision,old_kind,new_kind,old_occurrence_key,
        new_occurrence_key,transition FROM viewer_semantic_transitions ORDER BY request_key,revision''')
    result['viewer_semantic_transitions']=dict(rows=len(rows),sha256=hashlib.sha256(
        json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    result['checkpoint']=db.one('SELECT next_ns,generation FROM viewer_live_state WHERE id=1')
    result['windows']=db.all('SELECT start_ns,end_ns,file_hash,records,generation FROM viewer_live_windows ORDER BY start_ns')
    result['receipts']=db.all('''SELECT start_ns,end_ns,file_hash,mode,generation,records,
        new_events,impacted_requests FROM viewer_live_receipts ORDER BY generation,start_ns''')
    return result


def capture_jobs(paths):
    jobs=[]
    for path in paths:
        path=Path(path).resolve()
        with gzip.open(path,'rt',encoding='utf-8') as stream:header=json.load(stream)
        start=utc_ns(header.get('window_start'));end=utc_ns(header.get('window_end'));del header
        proof,payload=_read_verified_capture(path,start,end);del payload
        jobs.append(dict(path=path,start=start,mode='forward',kind='verified_private_capture',
            records=proof['records'],sha256=proof['sha256']))
    jobs.sort(key=lambda j:j['start'])
    if not 2<=len(jobs)<=8 or any(b['start']!=a['start']+FIVE for a,b in zip(jobs,jobs[1:])):
        raise ValueError('two_to_eight_consecutive_verified_captures_required')
    return jobs


def run_lane(options, jobs, *, profiled, history=True, db_type=ViewerDB,notice=None):
    windows=[];schedule_seconds=0;candidate_setup=0;candidate_prepare=None;lane_began=time.perf_counter()
    beginning=jobs[0]['start']
    with db_type(**options) as db:
        db.init();initialize_live(db)
        bind_stream(db,start_ns=beginning,stream_key='capacity-fixed-corpus')
        if not db.sqlite:
            settings=db.all('SELECT name,setting,unit FROM pg_settings WHERE name=ANY(?)',(list(SETTINGS),))
            layout=db.all("SELECT indexrelname,indisvalid FROM pg_index i JOIN pg_stat_user_indexes s ON s.indexrelid=i.indexrelid WHERE schemaname='public' ORDER BY indexrelname")
            db.conn.rollback()
        else:
            settings=[];layout=[]
        for ordinal,job in enumerate(jobs):
            job=dict(job)
            if notice:notice(dict(status='CAPACITY_WINDOW_STARTED',ordinal=ordinal,records=job['records']))
            if history and ordinal==1:
                # Exercise the actual manual_recheck path used by history,
                # with a retained high-watermark, only in this owned test DB.
                setup=time.perf_counter();db.conn.rollback()
                with single_worker(db,Path(options['keys_path']).parent/'capacity.lock'):
                    extent=sum(j['mode']=='forward' for j in jobs)+2
                    resume_recent(db,lookback_windows=1,now=beginning+extent*FIVE+60_000_000_000)
                schedule_seconds=time.perf_counter()-setup
            if ordinal==1 and callable(getattr(db,'prepare_candidate',None)):
                setup=time.perf_counter();candidate_prepare=db.prepare_candidate()
                candidate_setup=time.perf_counter()-setup
            if history and ordinal>0 and job['mode']=='forward':
                job['mode']='manual_recheck'
            trace=Trace();transaction_counts=[]
            if profiled:
                trace.attach(db)
                if not db.sqlite:
                    trace.before_commit=lambda raw:transaction_counts.append(counters.transaction(raw))
            original=db.conn.raw if profiled else db.conn
            before=counters.snapshot(original) if not db.sqlite else None
            began=time.perf_counter()
            try:
                with trace.span('publication'):
                    result=publish_capture(db,job['path'],job['start'],job['start']+FIVE,mode=job['mode'])
                    if callable(getattr(db,'candidate_after_publication',None)):
                        db.candidate_after_publication(result)
                elapsed=time.perf_counter()-began
            finally:
                trace.detach()
            # Readability is a committed contract check, not actual AD progress.
            readable=db.one('SELECT generation FROM viewer_live_windows WHERE start_ns=?',(job['start'],))
            visible_seconds=time.perf_counter()-began
            if not readable or readable['generation']!=result['generation']:
                raise AssertionError('publication_not_committed_readable')
            after=counters.snapshot(db.conn) if not db.sqlite else None
            oracle_began=time.perf_counter();oracle=semantic_snapshot(db)
            states={r['state']:r['n'] for r in db.all(
                'SELECT state,COUNT(*) AS n FROM viewer_semantic_occurrences GROUP BY state')}
            oracle_seconds=time.perf_counter()-oracle_began
            window=dict(ordinal=ordinal,kind=job['kind'],mode=job['mode'],records=job['records'],
                capture_sha256=job['sha256'],elapsed_publication_seconds=elapsed,
                elapsed_to_contract_check_seconds=visible_seconds,new_events=result['new_events'],
                impacted_requests=result['impacted_requests'],generation=result['generation'],
                seconds_per_1000_new_events=elapsed*1000/result['new_events'] if result['new_events'] else None,
                seconds_per_1000_impacted_requests=elapsed*1000/result['impacted_requests'] if result['impacted_requests'] else None,
                trace=trace.report() if profiled else None,transaction_counters=transaction_counts,
                backend_counters=counters.delta(before,after) if before else dict(status='NOT_NATIVE'),
                oracle=oracle,oracle_seconds=oracle_seconds,
                semantic_states=states,
                cycle_including_diagnostics_and_oracle_seconds=time.perf_counter()-began)
            db.conn.rollback()
            windows.append(window)
            if notice:notice(dict(status='CAPACITY_WINDOW_COMMITTED',ordinal=ordinal,
                bootstrap=bool(result['bootstrap']),new_events=result['new_events'],
                seconds=elapsed,semantic_oracle_complete=True))
        return dict(profiled=profiled,windows=windows,writer_settings=settings,index_inventory=layout,
            publication_mode='history' if history else 'forward',
            candidate_prepare_seconds=candidate_setup,candidate_prepare=candidate_prepare,
            candidate_report=db.candidate_report() if callable(getattr(db,'candidate_report',None)) else None,
            qualification_schedule_setup_seconds=schedule_seconds,
            total_lane_seconds_including_setup_diagnostics_and_oracle=time.perf_counter()-lane_began,
            publication_seconds=distribution([w['elapsed_publication_seconds'] for w in windows]),
            bootstrap_reported_separately=True,
            steady_publication_seconds=distribution([w['elapsed_publication_seconds'] for w in windows[1:]
                if w['mode'] in ('forward','manual_recheck')]),
            recheck_seconds=distribution([w['elapsed_publication_seconds'] for w in windows if w['mode']=='recheck']))


def run(*, backend='sqlite', counts=(16,64,256), pairs=1, out=None, history=True,captures=None,experiment='instrumentation',wal_compression=None,notice=None):
    overall_began=time.perf_counter()
    if experiment not in ('instrumentation','origin_filter','contract_fetch_once','local_projection_keys'):
        raise ValueError('unknown_capacity_experiment')
    if not 1<=pairs<=4:
        raise ValueError('capacity_pairs_must_be_1_to_4')
    if wal_compression not in (None,'pglz','lz4','zstd'):
        raise ValueError('unsupported_capacity_wal_compression')
    baseline_variant='contract_fetch_once' if experiment=='local_projection_keys' else 'baseline'
    root=Path(__file__).resolve().parents[2]
    report=dict(status='RUNNING',baseline_git_sha=subprocess.check_output(
        ['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        runtime_source_sha256=runtime_source_digest(),backend=backend,
        environment=dict(os=platform.platform(),python=platform.python_version(),client_cpu_count=os.cpu_count()),
        production_modified=False,production_checkpoint_modified=False,lanes=[],checks=[],
        publication_mode='history' if history else 'forward',
        cache_pressure_qualification='NOT_RUN',cold_os_cache='NOT_CONTROLLED',
        live_elasticsearch_acquisition='NOT_RUN',actual_ad_evaluation='NOT_RUN',
        owner_host_capacity='NOT_RUN',eight_hour_sustained_capacity='NOT_RUN',
        candidate_implemented=experiment!='instrumentation',experiment=experiment,
        requested_writer_wal_compression=wal_compression,
        comparison_baseline_variant=baseline_variant,
        limitations=['Synthetic risk corpus; volume labels are relative within this corpus.',
            'Existing runtime is measured; no cache, batching or storage candidate is enabled.',
            'A database larger than shared_buffers is not evidence of an out-of-cache active working set.',
            'No physical disk I/O, exclusive cluster counters, or owner-server throughput is inferred.',
            'AD-readable contract checks are separate from actual consumption and evaluation.',
            'Bootstrap, diagnostics and oracle costs are not steady-state publication throughput.',
            'Eight-hour web/AD concurrency, migration and rollback qualification remain open.'])
    admin=None;created=[]
    try:
        if backend=='postgresql':
            import psycopg
            from psycopg import sql
            host=os.environ.get('P24_DELTA_PG_HOST')
            if not host:
                raise ValueError('native_postgresql_environment_not_configured')
            settings=dict(host=host,port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
                user=os.environ.get('P24_DELTA_PG_USER','postgres'),connect_timeout=5)
            admin=psycopg.connect(**settings,dbname='postgres',autocommit=True)
            version=int(admin.execute('SHOW server_version_num').fetchone()[0])
            if version<180000:
                raise ValueError('postgresql_18_required_for_backend_attribution')
            report['server_version_num']=version
        with tempfile.TemporaryDirectory(prefix='viewer-capacity-') as folder:
            temp=Path(folder);keys=temp/'keys.json';generate_keys(keys)
            jobs=capture_jobs(captures) if captures else corpus(temp,counts)
            report['input_kind']='verified_private_captures' if captures else 'synthetic_risk_corpus'
            report['corpus']=[{k:v for k,v in j.items() if k!='path'} for j in jobs]
            for pair in range(pairs):
                order=(False,True) if pair%2==0 else (True,False)
                lanes=[]
                for selected in order:
                    profiled=selected if experiment=='instrumentation' else True
                    db_type=ViewerDB
                    if experiment=='origin_filter' and selected:
                        from .origin_filter import OriginFilteredDB
                        db_type=OriginFilteredDB
                    elif experiment=='contract_fetch_once' and selected:
                        from .contract_fetch_once import ContractFetchOnceDB
                        db_type=ContractFetchOnceDB
                    elif experiment=='local_projection_keys':
                        from .contract_fetch_once import ContractFetchOnceDB
                        from .local_projection_keys import LocalProjectionKeysDB
                        db_type=LocalProjectionKeysDB if selected else ContractFetchOnceDB
                    if backend=='postgresql':
                        name='p24_design_capacity_'+uuid.uuid4().hex[:16]+'_qualification'
                        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));created.append(name)
                        profile='-c jit=off -c work_mem=64MB -c temp_buffers=128MB'
                        if wal_compression:profile+=' -c wal_compression='+wal_compression
                        opts=dict(config={**settings,'dbname':name,'options':profile},keys_path=keys)
                    else:
                        opts=dict(sqlite_path=temp/f'{pair}-{selected}.db',keys_path=keys)
                    variant=(experiment if selected else baseline_variant) if experiment!='instrumentation' else ('profiled' if selected else 'plain')
                    if notice:notice(dict(status='CAPACITY_LANE_STARTED',pair=pair,variant=variant))
                    lane=run_lane(opts,jobs,profiled=profiled,history=history,db_type=db_type,notice=notice)
                    lane['pair']=pair;lane['variant']=variant;lanes.append(lane)
                equal=[a['oracle']==b['oracle'] for a,b in zip(lanes[0]['windows'],lanes[1]['windows'])]
                labels=['profiled' if v else 'plain' for v in order] if experiment=='instrumentation' else [experiment if v else baseline_variant for v in order]
                report['checks'].append(dict(pair=pair,order=labels,
                    every_publication_equal=equal,all_equal=all(equal)))
                report['lanes'].extend(lanes)
        report['status']=('PASS_MEASUREMENT_EQUIVALENCE' if experiment=='instrumentation' else 'PASS_CANDIDATE_EQUIVALENCE') if all(c['all_equal'] for c in report['checks']) else 'FAIL_MEASUREMENT_CHANGED_OUTPUT'
    except Exception as exc:
        report.update(status='NOT_RUN' if isinstance(exc,ValueError) else 'FAILED',
            failure=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
                sqlstate=getattr(exc,'sqlstate',None)))
    finally:
        report['qualification_cleanup']=dict(allocated_databases=len(created),dropped_databases=0,failures=[])
        if admin is not None:
            for name in created:
                # Only names allocated by this invocation; never existing DBs.
                try:
                    admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
                    report['qualification_cleanup']['dropped_databases']+=1
                except Exception as exc:
                    report['qualification_cleanup']['failures'].append(dict(database=name,
                        error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None)))
                    report['status']='FAILED_QUALIFICATION_CLEANUP'
            admin.close()
    report['total_run_seconds_including_preflight_setup_oracles_and_cleanup']=time.perf_counter()-overall_began
    if captures:
        report['limitations'][0]='Contiguous verified private Captures; broad traffic/risk representativeness is not established.'
    if experiment!='instrumentation':
        report['limitations'][1]='Only a disposable, source-pinned subclass enables the candidate; production runtime is unchanged.'
        def used(lane):
            if experiment=='origin_filter':return lane['candidate_report']['lookup']['skipped_negatives']>0
            if experiment=='local_projection_keys':
                return (lane['candidate_report']['local_projection_keys']['queries']>0
                    and lane['candidate_report']['fetch_once']['body_pair_lookups']>0)
            return lane['candidate_report']['fetch_once']['body_pair_lookups']>0
        exercised=[used(l) for l in report['lanes'] if l['variant']==experiment]
        report['candidate_exercised']=bool(exercised) and all(exercised)
        if report['status']=='PASS_CANDIDATE_EQUIVALENCE' and not report['candidate_exercised']:
            report['status']='NOT_QUALIFIED_CANDIDATE_UNUSED'
        comparisons=[]
        for pair in range(pairs):
            lanes={l['variant']:l for l in report['lanes'] if l['pair']==pair}
            if len(lanes)!=2:continue
            def charged(lane):
                targets=[w for w in lane['windows'][1:] if w['kind'] not in
                    ('cross_request_conflict','late_arrival_original_event_time')]
                seconds=sum(w['elapsed_to_contract_check_seconds'] for w in targets)
                return dict(windows=len(targets),new_events=sum(w['new_events'] for w in targets),
                    publication_to_contract_seconds=seconds,
                    candidate_build_seconds=lane['candidate_prepare_seconds'],
                    total_charged_seconds=seconds+lane['candidate_prepare_seconds'])
            base=charged(lanes[baseline_variant]);candidate=charged(lanes[experiment])
            comparisons.append(dict(pair=pair,baseline=base,candidate=candidate,
                reduction_fraction=1-candidate['total_charged_seconds']/base['total_charged_seconds']
                    if base['total_charged_seconds'] else None))
        report['candidate_comparisons_including_build']=comparisons
        report['comparison_excludes_diagnostics_oracles_and_bootstrap']=True
        report['local_comparison_is_not_owner_capacity_acceptance']=True
    if out:
        atomic_json(out,report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',choices=('sqlite','postgresql'),required=True)
    parser.add_argument('--counts',type=int,nargs=3,default=(16,64,256))
    parser.add_argument('--pairs',type=int,default=2)
    parser.add_argument('--mode',choices=('history','forward'),default='history')
    parser.add_argument('--captures',type=Path,nargs='+',help='Existing contiguous verified captures; private data is never exported')
    parser.add_argument('--experiment',choices=('instrumentation','origin_filter','contract_fetch_once','local_projection_keys'),default='instrumentation')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--wal-compression',choices=('pglz','lz4','zstd'))
    args=parser.parse_args(argv)
    if not 1<=args.pairs<=4 or any(not 1<=n<=20000 for n in args.counts):
        parser.error('pairs must be 1..4 and each request count 1..20000')
    report=run(backend=args.backend,counts=tuple(args.counts),pairs=args.pairs,out=args.out,history=args.mode=='history',captures=args.captures,experiment=args.experiment,wal_compression=args.wal_compression)
    print(json.dumps({k:report.get(k) for k in ['status','backend','failure','owner_host_capacity']}))
    return 0 if report['status'] in ('PASS_MEASUREMENT_EQUIVALENCE','PASS_CANDIDATE_EQUIVALENCE') else 2


if __name__=='__main__':
    raise SystemExit(main())
