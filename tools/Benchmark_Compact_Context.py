"""Disposable CI PostgreSQL comparison; only synthetic logs and aggregate output.
Requires explicit P24_DELTA_PG_* test environment, never loads project config.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import uuid


def signature_without_policy_stamp(body,state,digest):
    normalized=copy.deepcopy(body)
    policy=normalized['features'].pop('behavior_policy_version')
    if policy not in ('meaningful-api-roles-1','meaningful-api-roles-2'):
        raise ValueError('unreviewed_benchmark_policy')
    # Owner confirmed ExecutionTime is milliseconds on 2026-11-22. Only these
    # two provenance constants may differ; the measured value remains hashed.
    if 'duration_unit' in normalized:
        unit=normalized.pop('duration_unit')
        meaning=normalized['features'].pop('duration_analysis')
        if (unit,meaning) not in (
            ('UNVERIFIED','OUT_OF_SCOPE_UNVERIFIED_UNIT'),
            ('MILLISECONDS_OWNER_CONFIRMED_20261122','PUBLIC_HTTP_MILLISECONDS_OWNER_CONFIRMED_20261122')):
            raise ValueError('unreviewed_duration_provenance')
    return digest([normalized,state]),policy


def parity(results):
    baseline,candidate=results['baseline'],results['candidate']
    exact=baseline['behavior_hash']==candidate['behavior_hash']
    except_stamp=baseline['behavior_hash_without_policy_stamp']==candidate['behavior_hash_without_policy_stamp']
    allowed_transition=(baseline['behavior_policies'] in (['meaningful-api-roles-1'],['meaningful-api-roles-2']) and
                        candidate['behavior_policies']==['meaningful-api-roles-2'])
    return dict(same_behavior_hash=exact,same_behavior_except_policy_stamp=except_stamp,
        policy_stamp_transition=allowed_transition,
        behavior_parity_accepted=exact or except_stamp and allowed_transition)


def worker(root, count):
    sys.path.insert(0, str(root))
    from compact_behavior.extract import Extractor, iso, digest, materialize
    from compact_behavior.store import Store
    from compact_behavior import FIVE
    schema='p24_compact_meta_bench_'+uuid.uuid4().hex[:12]
    config=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
        user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
    store=Store(config,schema=schema); store.init()
    samples=[]
    try:
        for w in range(5):
            start=1792484400000000000+w*FIVE
            logs=[]
            for i in range(count):
                base=dict(RequestID=f'{w}-{i}',Session=f's-{i%100}',IP=f'192.0.2.{i%250+1}',
                    **{'@timestamp':iso(start+10**9)})
                logs.extend([dict(base,CallPath='Services.v1/WaterBills',message='POST https://example.test/WaterBills HTTP/1.1 (G00000 | successful)',ExecutionTime='12'),
                    dict(base,CallPath='ClientAyanCoInquiry.WaterBillInquiry',message='Input:{"BillID":"123"} Output:{"Amount":10}'),
                    dict(base,CallPath='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @session=s @userAgent=Synthetic Browser/1.0 @ipAddress= @action=v1/WaterBills)')])
            before=time.perf_counter();ex=Extractor()
            for log in logs:ex.add(log)
            states=ex.finish();extract_seconds=time.perf_counter()-before
            report=store.publish('bench',start,start+FIVE,states,len(logs))
            if w>=2:samples.append(dict(extract_seconds=extract_seconds,write_seconds=report['database_seconds'],total_seconds=extract_seconds+report['database_seconds']))
        hashes=store.conn.execute(f'SELECT content_hash FROM {schema}.behaviors ORDER BY behavior_id').fetchall()
        comparable=[];policies=set()
        # Outside timed extraction/write samples: retain the original exact
        # hash, and separately permit only the reviewed provenance-stamp change.
        rows=store.conn.execute(f'''SELECT b.content_hash,p.state FROM {schema}.behaviors b
            JOIN {schema}.behavior_payloads p USING(behavior_id) ORDER BY b.behavior_id''').fetchall()
        for stored in rows:
            body=materialize('bench',stored['state'])
            if digest([body,stored['state']])!=stored['content_hash']:
                raise RuntimeError('Stored behavior hash does not match materialized state')
            signature,policy=signature_without_policy_stamp(body,stored['state'],digest)
            comparable.append(signature);policies.add(policy)
        result=dict(samples=samples,median_seconds={key:statistics.median(r[key] for r in samples) for key in samples[0]},
            behavior_hash=digest(hashes),requests_per_window=count,
            behavior_hash_without_policy_stamp=digest(comparable),behavior_policies=sorted(policies),
            relations=store.conn.execute('SELECT sum(pg_total_relation_size(c.oid))::bigint AS bytes FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind=%s',(schema,'r')).fetchone())
        print(json.dumps(result))
    finally:
        store.conn.execute('DROP SCHEMA '+schema+' CASCADE');store.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',type=Path);p.add_argument('--baseline',type=Path);p.add_argument('--candidate',type=Path);p.add_argument('--output',type=Path);p.add_argument('--requests',type=int,default=3000)
    a=p.parse_args()
    if a.worker:
        worker(a.worker.resolve(),a.requests);return
    results={}
    for name,root in [('baseline',a.baseline),('candidate',a.candidate)]:
        completed=subprocess.run([sys.executable,'-B',__file__,'--worker',str(root.resolve()),'--requests',str(a.requests)],capture_output=True,text=True,check=True)
        results[name]=json.loads(completed.stdout)
    results.update(parity(results))
    results['total_ratio']=results['candidate']['median_seconds']['total_seconds']/results['baseline']['median_seconds']['total_seconds']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(results,indent=2))
    print(json.dumps(results))
    if not results['behavior_parity_accepted']:raise RuntimeError('Existing behavior content changed beyond reviewed policy stamp')

if __name__=='__main__':main()
