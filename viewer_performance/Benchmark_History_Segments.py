"""C6 isolated full-cost storage comparison; never a Viewer capacity claim."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid


def run(*,count=2000,pairs=2):
    if not 1<=count<=20000 or not 1<=pairs<=2:raise ValueError('invalid_segment_benchmark_budget')
    import psycopg
    from psycopg import sql
    from tests.test_viewer_history_segments import changes
    from viewer_performance.history_segments import IndexedBaseline,BuiltSegments
    host=os.environ.get('P24_DELTA_PG_HOST')
    if host not in ('127.0.0.1','localhost','::1'):raise ValueError('explicit_local_qualification_cluster_required')
    config=dict(host=host,port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
        user=os.environ.get('P24_DELTA_PG_USER','postgres'),connect_timeout=5,
        options='-c jit=off -c work_mem=64MB -c temp_buffers=128MB')
    admin=psycopg.connect(**config,dbname='postgres',autocommit=True)
    allocated=[];opened=[];began=time.perf_counter()
    report=dict(candidate='C6_FRESH_SEGMENT_BUILD',scope='TYPED_CHANGESET_STORAGE_ONLY',
        product_database_opened=False,product_modified=False,detectors_run=False,
        correctness=[],capacity=[],comparisons=[],query_path_performance='NOT_RUN',
        canonical_viewer_backend_integration='NOT_RUN',live_capacity='NOT_ACCEPTED',
        cold_cache='NOT_CONTROLLED',effective_working_set_pressure='NOT_QUALIFIED',
        original_permanent_index_count=5,candidate_local_index_count=5,
        candidate_global_directory_index_count=2,
        read_oracles_interleaved_with_capacity=False,windows_per_batch=3,
        costs_excluded_from_storage_column=['Elasticsearch','change detection','request/payment/semantic reconstruction','actual AD'])
    batches=changes(count);rows=sum(batches,[])
    def allocate(kind):
        name='p24_design_segments_'+uuid.uuid4().hex[:16]+'_qualification'
        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));allocated.append(name)
        raw=psycopg.connect(**config,dbname=name);opened.append(raw)
        start=time.perf_counter();store=kind(raw)
        return store,time.perf_counter()-start
    try:
        # Full logical byte/key/revision equality is a separate pair of DBs.
        baseline,_=allocate(IndexedBaseline);candidate,_=allocate(BuiltSegments)
        candidate.prepare(1,rows)
        for sequence,batch in enumerate(batches,1):
            baseline.publish(sequence,batch);candidate.publish(sequence)
            report['correctness'].append(baseline.snapshot()==candidate.snapshot())
            baseline.raw.rollback();candidate.raw.rollback()
        baseline.raw.close();candidate.raw.close()
        for pair in range(pairs):
            totals={}
            for label in (('baseline','segments') if pair%2==0 else ('segments','baseline')):
                store,setup=allocate(IndexedBaseline if label=='baseline' else BuiltSegments)
                start=time.perf_counter();costs={};publish=[]
                if label=='segments':costs=store.prepare(1,rows)
                for sequence,batch in enumerate(batches,1):
                    publish.append(store.publish(sequence,batch) if label=='baseline' else store.publish(sequence))
                # No full snapshot, COUNT or digest of retained logical rows.
                current=store.raw.execute('SELECT publication FROM visible WHERE id=1').fetchone()[0]
                if current!=3:raise AssertionError('publication_prefix_incomplete')
                elapsed=time.perf_counter()-start
                entry=dict(pair=pair,variant=label,setup_seconds=setup,prepare=costs,
                    publication_seconds=publish,total_storage_seconds_including_setup=setup+elapsed,
                    physical_change_rows=len(rows),full_oracle_executed=False)
                report['capacity'].append(entry);totals[label]=entry['total_storage_seconds_including_setup']
                store.raw.close()
            report['comparisons'].append(dict(pair=pair,**totals,reduction_fraction=1-totals['segments']/totals['baseline']))
        report['status']='PASS_STORAGE_BOUNDARY_EQUIVALENCE' if all(report['correctness']) else 'FAIL_STORAGE_EQUIVALENCE'
        report['decision']=('KEEP_FOR_QUERY_PATH_AND_CANONICAL_BACKEND_RESEARCH' if all(c['reduction_fraction']>0 for c in report['comparisons']) else 'DO_NOT_PROMOTE_THIS_STORAGE_LAYOUT')
    finally:
        for raw in opened:
            if not raw.closed:raw.close()
        dropped=0
        for name in allocated:
            admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)));dropped+=1
        admin.close();report['cleanup']=dict(allocated=len(allocated),dropped=dropped)
    report['whole_run_seconds_including_correctness_setup_and_cleanup']=time.perf_counter()-began
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count',type=int,default=2000)
    parser.add_argument('--pairs',type=int,default=2)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv);sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from p24_foundation.viewer_runtime import atomic_json
    result=run(count=args.count,pairs=args.pairs);atomic_json(args.output,result)
    print(json.dumps({k:result[k] for k in ('status','decision','comparisons','cleanup')}))
    return 0 if result['status']=='PASS_STORAGE_BOUNDARY_EQUIVALENCE' else 2


if __name__=='__main__':raise SystemExit(main())
