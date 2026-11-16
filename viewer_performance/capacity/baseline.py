"""Current publisher baseline in disposable databases; no production access.

This first diagnostic qualifies measurement and per-publication equivalence.
It deliberately does NOT certify cache pressure, ES acquisition, full AD
evaluation, eight-hour capacity, or a performance candidate.
"""
from __future__ import annotations

import argparse
import hashlib
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
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import bind_stream, initialize_live, publish_capture, resume_recent, single_worker
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


def run_lane(options, jobs, *, profiled, history=True):
    windows=[];schedule_seconds=0;lane_began=time.perf_counter()
    with ViewerDB(**options) as db:
        db.init();initialize_live(db)
        bind_stream(db,start_ns=START,stream_key='capacity-fixed-corpus')
        if not db.sqlite:
            settings=db.all('SELECT name,setting,unit FROM pg_settings WHERE name=ANY(?)',(list(SETTINGS),))
            layout=db.all("SELECT indexrelname,indisvalid FROM pg_index i JOIN pg_stat_user_indexes s ON s.indexrelid=i.indexrelid WHERE schemaname='public' ORDER BY indexrelname")
            db.conn.rollback()
        else:
            settings=[];layout=[]
        for ordinal,job in enumerate(jobs):
            job=dict(job)
            if history and ordinal==1:
                # Exercise the actual manual_recheck path used by history,
                # with a retained high-watermark, only in this owned test DB.
                setup=time.perf_counter();db.conn.rollback()
                with single_worker(db,Path(options['keys_path']).parent/'capacity.lock'):
                    resume_recent(db,lookback_windows=1,now=START+5*FIVE+60_000_000_000)
                schedule_seconds=time.perf_counter()-setup
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
        return dict(profiled=profiled,windows=windows,writer_settings=settings,index_inventory=layout,
            publication_mode='history' if history else 'forward',
            qualification_schedule_setup_seconds=schedule_seconds,
            total_lane_seconds_including_setup_diagnostics_and_oracle=time.perf_counter()-lane_began,
            publication_seconds=distribution([w['elapsed_publication_seconds'] for w in windows]),
            bootstrap_reported_separately=True,
            steady_publication_seconds=distribution([w['elapsed_publication_seconds'] for w in windows[1:]
                if w['mode'] in ('forward','manual_recheck')]),
            recheck_seconds=distribution([w['elapsed_publication_seconds'] for w in windows if w['mode']=='recheck']))


def run(*, backend='sqlite', counts=(16,64,256), pairs=1, out=None, history=True):
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
        candidate_implemented=False,
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
            temp=Path(folder);keys=temp/'keys.json';generate_keys(keys);jobs=corpus(temp,counts)
            report['corpus']=[{k:v for k,v in j.items() if k!='path'} for j in jobs]
            for pair in range(pairs):
                order=(False,True) if pair%2==0 else (True,False)
                lanes=[]
                for profiled in order:
                    if backend=='postgresql':
                        name='p24_design_capacity_'+uuid.uuid4().hex[:16]+'_qualification'
                        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));created.append(name)
                        opts=dict(config={**settings,'dbname':name,
                            'options':'-c jit=off -c work_mem=64MB -c temp_buffers=128MB'},keys_path=keys)
                    else:
                        opts=dict(sqlite_path=temp/f'{pair}-{profiled}.db',keys_path=keys)
                    lane=run_lane(opts,jobs,profiled=profiled,history=history);lane['pair']=pair;lanes.append(lane)
                equal=[a['oracle']==b['oracle'] for a,b in zip(lanes[0]['windows'],lanes[1]['windows'])]
                report['checks'].append(dict(pair=pair,order=['profiled' if v else 'plain' for v in order],
                    every_publication_equal=equal,all_equal=all(equal)))
                report['lanes'].extend(lanes)
        report['status']='PASS_MEASUREMENT_EQUIVALENCE' if all(c['all_equal'] for c in report['checks']) else 'FAIL_MEASUREMENT_CHANGED_OUTPUT'
    except Exception as exc:
        report.update(status='NOT_RUN' if isinstance(exc,ValueError) else 'FAILED',
            failure=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
                sqlstate=getattr(exc,'sqlstate',None)))
    finally:
        if admin is not None:
            for name in created:
                # Only names allocated by this invocation; never existing DBs.
                admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
            admin.close()
    if out:
        atomic_json(out,report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',choices=('sqlite','postgresql'),required=True)
    parser.add_argument('--counts',type=int,nargs=3,default=(16,64,256))
    parser.add_argument('--pairs',type=int,default=2)
    parser.add_argument('--mode',choices=('history','forward'),default='history')
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    if not 1<=args.pairs<=4 or any(not 1<=n<=20000 for n in args.counts):
        parser.error('pairs must be 1..4 and each request count 1..20000')
    report=run(backend=args.backend,counts=tuple(args.counts),pairs=args.pairs,out=args.out,history=args.mode=='history')
    print(json.dumps({k:report.get(k) for k in ['status','backend','failure','owner_host_capacity']}))
    return 0 if report['status']=='PASS_MEASUREMENT_EQUIVALENCE' else 2


if __name__=='__main__':
    raise SystemExit(main())
