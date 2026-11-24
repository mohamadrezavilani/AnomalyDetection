"""Offline synthetic refusal load; no server connection or private evidence."""
import argparse
import json
import statistics
import time
from pathlib import Path
from compact_behavior import FIVE
from compact_behavior.extract import Extractor, materialize, iso
from compact_behavior.__main__ import process_info
from compact_ad.engine import summarize, evaluate
from compact_ad.security import MAX_COHORTS


def run(count=10000):
    if not 100 <= count <= MAX_COHORTS * 100 or count % 100:
        raise ValueError('use_multiples_of_100_within_security_cohort_budget')
    start=1795328400000000000
    extractor=Extractor()
    began=time.perf_counter()
    for i in range(count):
        group=i//100
        extractor.add(dict(RequestID=f'synthetic-{i}',Session=f'expired-{i%5}',
            IP=f'198.18.{group//256}.{group%256}',CallPath='Services.v1/InvoiceRegister',
            **{'@timestamp':iso(start+(i%100)*2*10**9)},
            message='POST https://example.test/api HTTP/1.1 (G00002 | SessionIsNotValid)'))
    bodies=[materialize('offline',s) for s in extractor.finish().values()]
    extraction=time.perf_counter()-began
    timings=[]
    for _ in range(4):
        began=time.perf_counter()
        summary,services,actors=summarize(bodies,cutoff_ns=start+FIVE)
        refs=[dict(start_ns=start-i*FIVE,summary=summary) for i in range(288,0,-1)]
        results=evaluate(start,summary,services,actors,refs)
        timings.append(time.perf_counter()-began)
    observed=[r for r in results if r['method']=='invalid_session_attempts']
    qualified=all(r['observed']==100 and r['distinct_presented_tokens']==5 and r['session_id'] is None
                  and r['status']=='NORMAL' for r in observed)
    packet=dict(scope='OFFLINE_SYNTHETIC_REFUSALS_NO_DATABASE_OR_SOURCE',logical_requests=count,
                cohorts=len(observed),warm_median_seconds=statistics.median(timings[1:]),
                extract_materialize_seconds=extraction,matched_expected_counts=qualified and len(observed)==count//100,
                retained_summary_bytes=len(json.dumps(summary).encode()),**process_info())
    if not packet['matched_expected_counts'] or packet['warm_median_seconds']>5:
        raise ValueError('security_synthetic_budget_or_correctness_failed')
    return packet


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--requests',type=int,default=10000)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    result=run(args.requests)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':main()
