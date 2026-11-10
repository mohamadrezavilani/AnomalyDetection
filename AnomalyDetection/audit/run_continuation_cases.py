"""Structured continuation evidence against an explicitly selected AD checkout."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,sys

p=argparse.ArgumentParser();p.add_argument('--ad-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
args=p.parse_args();sys.path.insert(0,str(args.ad_root.resolve()))
from audit.request_sample_fixture import FAMILIES,run_sample,T,S
from audit.continuous_fixture import Store,ACTOR,run_continuous
from audit.run_independent_audit import behavior_context,pm
from anomaly_detection.continuous import evaluate

results=[]
def add(family,test,expected,actual,**extra):
    results.append(dict(family=family,test=test,expected=expected,actual=actual,
        status='PASS' if expected==actual else 'FAIL',level='REAL_PYTHON_EVALUATOR_AND_DISPATCHER_WITH_SCRIPTED_SQL',**extra))

for family in FAMILIES:
    for mode in ('valid','stale_revision','withdrawn_fact','source_absent','missing_fact','refresh_pending','technical_without_fact'):
        d,status,publication,store=run_sample(family,mode)
        expected='CANDIDATE' if mode in ('valid','technical_without_fact') else 'INSUFFICIENT_DATA'
        add(family,mode,expected,d['status'],dispatcher_status=status,evidence_verified=d.get('evidence_verified'),
            publication_boundary_called=publication is not None,case_sql_commit='NOT_RUN')
for mode in ('positive','source_gap','stale_evidence','ordinary'):
    if mode=='ordinary':
        store=Store(n=2,offset=0)
        decisions,_=evaluate(store,{'session_key':ACTOR,'target_ns':T},{'windows':[{'start_ns':T,'counts':{S:2}}]})
    else:decisions,_,_=run_continuous(missing=mode=='source_gap',stale=mode=='stale_evidence')
    for d in decisions:
        if mode=='stale_evidence':expected,actual=False,d.get('span_evidence_verified')
        else:
            expected={'positive':'CANDIDATE','ordinary':'NO_DEVIATION_OBSERVED','source_gap':'INSUFFICIENT_DATA'}[mode]
            actual=d['status']
        add('continuous_rate',mode+'_'+str(d['duration_ns']),expected,actual,
            observed=d.get('observed'),reference_actors=d.get('other_session_epochs'),duration_ns=d['duration_ns'])
context,history=behavior_context(current=1_000_000,n=180)
service=next(iter(context['windows'][0]['counts']))
for row in history:row['counts']={service:10}
history[0]['counts']={service:1000}
d=next(x for x in pm.evaluate(context,history) if x['family']=='isolation_forest')
add('isolation_forest','rare_historical_training_point_positive','CANDIDATE',d['status'],score=d['score'],upper=d['upper'])
out=dict(runtime_root=str(args.ad_root.resolve()),summary=dict(Counter(x['status'] for x in results)),results=results,
    runtime_files_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((args.ad_root/'anomaly_detection').glob('*.py'))},
    native_sql='NOT_RUN',live_worker='NOT_RUN',production_access=False,precision_recall='NOT_EVALUATED')
args.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(out['summary']));raise SystemExit(int(any(x['status']!='PASS' for x in results)))
