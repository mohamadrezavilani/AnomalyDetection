"""Synthetic native plan/timing qualification; no production data."""
import argparse
import json
import os
from pathlib import Path
import statistics
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_model_queue_pg import NativeModelQueueTests, LEGACY_SELECT, TARGET
from anomaly_detection import model_queue

def nodes(node):
    yield node
    for child in node.get('Plans', []):
        yield from nodes(child)

queries=[]
class Capture:
    def execute(self, query, args):
        queries.append(query)
        return self
    def fetchone(self):
        return None
model_queue.next_job(type('Store', (), {'raw':Capture()})(), 1000000)
candidate=queries[0]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if os.environ.get('P24_DELTA_PG_HOST') not in ('127.0.0.1','::1') or os.environ.get('P24_DELTA_PG_PORT') in (None,'5432'):
        parser.error('An explicit isolated loopback test cluster on a nondefault port is required')
    NativeModelQueueTests.setUpClass()
    case=NativeModelQueueTests()
    try:
        case.setUp()
        raw=case.raw
        raw.execute('''INSERT INTO anomaly_detection.adp_jobs
            (session_key,target_ns,version,processed_version,dirty,evaluation)
            SELECT lpad(n::text,64,'0'),%s+(n/521)*300000000000,1+mod(n,3),
                CASE WHEN n>122000 THEN 1+mod(n,3) ELSE 0 END,
                n<=122000,repeat('synthetic fixture ',80)
            FROM generate_series(1,199000) n''',(TARGET,))
        raw.execute('''INSERT INTO anomaly_detection.adp_model_queue
            SELECT session_key,target_ns,version,session_key::numeric::bigint,'["rate_5m"]',0
            FROM anomaly_detection.adp_jobs WHERE session_key::numeric<=108103''')
        raw.execute('ANALYZE anomaly_detection.adp_jobs')
        raw.execute('ANALYZE anomaly_detection.adp_model_queue')
        raw.execute('SET max_parallel_workers_per_gather=0')
        raw.execute("SET work_mem='8MB'")
        raw.execute('SET jit=off')
        raw.execute("SET statement_timeout='3s'")
        output={'dataset':'synthetic_only','jobs':199000,'queue':108103,
                'backend':raw.execute('SELECT version() AS version').fetchone()['version'],
                'settings':dict(raw.execute("SELECT current_setting('fsync') AS fsync,"
                    "current_setting('full_page_writes') AS full_page_writes,"
                    "current_setting('synchronous_commit') AS synchronous_commit,"
                    "current_setting('max_parallel_workers_per_gather') AS max_parallel_workers_per_gather,"
                    "current_setting('work_mem') AS work_mem,current_setting('jit') AS jit,"
                    "current_setting('statement_timeout') AS statement_timeout").fetchone()),
                'production_speed_claim':False,'cases':[]}
        for shape,predicate in (('eligible_after_192_stale','session_key::numeric=193'),
                                ('sparse_eligible','mod(session_key::numeric,353)=0 AND session_key::numeric<=108103'),
                                ('eligible_at_queue_tail','session_key::numeric=108103'),
                                ('all_pending_parents_dirty','FALSE')):
            raw.execute('''UPDATE anomaly_detection.adp_jobs SET dirty=TRUE,processed_version=0
                WHERE session_key::numeric<=108103 AND NOT dirty''')
            raw.execute('''UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version
                WHERE '''+predicate)
            raw.execute('ANALYZE anomaly_detection.adp_jobs')
            entry={'shape':shape,'plans':{}}
            for label,query in (('legacy',LEGACY_SELECT),('candidate',candidate)):
                plan=raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query,(1000000,)*query.count('%s')).fetchone()['QUERY PLAN'][0]
                entry['plans'][label]={
                    'execution_ms':plan['Execution Time'],
                    'indexes':sorted({n['Index Name'] for n in nodes(plan['Plan']) if 'Index Name' in n}),
                    'node_types':sorted({n['Node Type'] for n in nodes(plan['Plan'])}),
                    'full_plan':plan,
                }
            timings={'legacy':[],'candidate':[]}
            for pair in range(8):
                results={}
                for label,query in ((('legacy',LEGACY_SELECT),('candidate',candidate)) if pair%2==0 else (('candidate',candidate),('legacy',LEGACY_SELECT))):
                    at=time.perf_counter()
                    results[label]=raw.execute(query,(1000000,)*query.count('%s')).fetchone()
                    timings[label].append((time.perf_counter()-at)*1000)
                if results['legacy']!=results['candidate']:
                    raise AssertionError('SELECTOR_FULL_ROW_MISMATCH')
            entry['times_ms']=timings
            entry['median_ms']={label:statistics.median(values) for label,values in timings.items()}
            output['cases'].append(entry)
            print(shape,entry['median_ms'],entry['plans']['candidate']['indexes'],flush=True)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    finally:
        case.doCleanups()
        NativeModelQueueTests.tearDownClass()


if __name__=='__main__':
    main()
