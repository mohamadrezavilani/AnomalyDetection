"""Offline CPU/RAM comparison, not an Elasticsearch/PostgreSQL capacity claim."""
import argparse
import inspect
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time


def worker(root,count):
    sys.path.insert(0,str(root))
    from compact_behavior import FIVE
    from compact_behavior.extract import Extractor,materialize,iso,digest
    from compact_ad.engine import summarize,evaluate
    from compact_behavior.__main__ import process_info
    start=1795328400000000000
    logs=[]
    for i in range(count):
        service=('WaterBills','GasBills')[i%2]
        base=dict(RequestID=f'r-{i}',Session=f's-{i//20}',CallPath='Services.v1/'+service,
            **{'@timestamp':iso(start+(i%20)*10*10**9)},ExecutionTime='100')
        logs.extend([dict(base,message='POST https://example.test/api HTTP/1.1 (G00000 | successful)'),
            dict(base,message='Input:{"BillID":"'+str(i%100)+'"} Output:{"Amount":10}')])
    t=time.perf_counter();extractor=Extractor()
    for row in logs:extractor.add(row)
    states=extractor.finish()
    bodies=[materialize('bench',v) for v in states.values()]
    extraction=time.perf_counter()-t
    advanced='previous_events' in inspect.signature(summarize).parameters
    previous={body['session_id']:[] for body in bodies}
    options={'previous_events':previous,'cutoff_ns':start+FIVE} if advanced else {'cutoff_ns':start+FIVE}
    summary,services,actors=summarize(bodies,**options)
    refs=[dict(start_ns=start-i*FIVE,summary=summary,summary_hash=digest(summary)) for i in range(288,0,-1)]
    evaluation_options={'previous_events':previous} if advanced else {}
    if advanced:
        evaluation_options['temporal_references']=[dict(start_ns=start-i*12*FIVE,
            rates={key:[value['count'],value['actor_p95'],True] for key,value in summary['services'].items()},
            complete=True,summary_hash='synthetic-'+str(i)) for i in range(672,0,-1)]
    measurements=[];result=[]
    for attempt in range(4):
        t=time.perf_counter()
        summary,services,actors=summarize(bodies,**options)
        result=evaluate(start,summary,services,actors,refs,**evaluation_options)
        measurements.append(time.perf_counter()-t)
    original={'service_rate','actor_rate','service_mix','reported_result','repeated_target','target_diversity','response_shape','response_numeric'}
    comparable=sorted((r['method'],r['service'],str(r['session_id']),r['status'],r['observed'],r['baseline'],r['threshold'])
        for r in result if r['method'] in original)
    return dict(extract_materialize_seconds=extraction,ad_seconds=measurements,
        warm_median_seconds=statistics.median(measurements[1:]),original_methods_hash=digest(comparable),
        new_methods=sorted({r['method'] for r in result}-original),
        new_method_anomalies=sum(r['status']=='ANOMALY' and r['method'] not in original for r in result),
        logical_requests=count,**process_info())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--worker',type=Path);p.add_argument('--baseline',type=Path)
    p.add_argument('--candidate',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--requests',type=int,default=10000)
    args=p.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker.resolve(),args.requests)));return
    result={}
    for label,root in [('baseline',args.baseline),('candidate',args.candidate)]:
        run=subprocess.run([sys.executable,'-B',__file__,'--worker',str(root.resolve()),'--requests',str(args.requests)],
            capture_output=True,text=True,check=True)
        result[label]=json.loads(run.stdout)
    a,b=result['baseline'],result['candidate']
    result.update(scope='OFFLINE_SYNTHETIC_CPU_RAM_NO_SOURCE_OR_DATABASE',
        original_methods_equal=a['original_methods_hash']==b['original_methods_hash'],
        added_warm_ad_seconds=b['warm_median_seconds']-a['warm_median_seconds'],
        candidate_within_development_budget=b['warm_median_seconds']<=max(5.,a['warm_median_seconds']*3),
        server_capacity='NOT_MEASURED')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
    if not result['original_methods_equal'] or not result['candidate_within_development_budget']:
        raise SystemExit(2)


if __name__=='__main__':main()
