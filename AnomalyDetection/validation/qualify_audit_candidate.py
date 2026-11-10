"""One offline qualification command. Does not connect, install or deploy."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,zipfile

ROOT=Path(__file__).resolve().parents[1]


def run(output):
    output.mkdir(parents=True,exist_ok=True)
    jobs=[('unit',[sys.executable,'-B','-m','unittest','discover','-s','tests','-v']),
        ('oracle',[sys.executable,'-B','audit/run_independent_audit.py','--label','candidate','--output',str(output/'oracle.json')]),
        ('continuation',[sys.executable,'-B','audit/run_continuation_cases.py','--ad-root',str(ROOT),'--output',str(output/'continuation.json')]),
        ('native_preflight',[sys.executable,'-B','validation/qualify_audit_native.py','--output',str(output/'native_preflight.json')])]
    outcomes=[]
    for name,args in jobs:
        with (output/(name+'.log')).open('w',encoding='utf-8') as log:
            proc=subprocess.run(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,PYTHONIOENCODING='utf-8'))
        outcomes.append(dict(test=name,exit_code=proc.returncode,log=name+'.log'))
    oracle=json.loads((output/'oracle.json').read_text(encoding='utf-8')) if (output/'oracle.json').exists() else {}
    failures=[dict(family=r['family'],test=r['test'],expected=r['expected'],actual=r['actual']) for r in oracle.get('results',[]) if r['status']=='FAIL']
    # Keep the forest's missed scenario visible; do not relabel it as PASS.
    unexpected=any(r['family']!='isolation_forest' or r['test']!='positive' for r in failures)
    bad=outcomes[0]['exit_code']!=0 or outcomes[2]['exit_code']!=0 or unexpected or not oracle
    result=dict(status='FAIL' if bad else 'OFFLINE_CHECKS_WITH_OPEN_LIMITATION' if failures else 'PASS_OFFLINE_ONLY',
        runs=outcomes,oracle_summary=oracle.get('summary'),open_failures=failures,
        native_postgresql='NOT_RUN',live_worker='NOT_RUN',browser='NOT_RUN',production_access=False,
        runtime_files_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'anomaly_detection').glob('*.py'))})
    (output/'qualification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with zipfile.ZipFile(output/'qualification.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.iterdir()):
            if p.suffix in ('.json','.log'):z.write(p,p.name)
    print(json.dumps({k:result[k] for k in ('status','oracle_summary','open_failures','native_postgresql')},ensure_ascii=False))
    return 1 if bad else 2 if failures else 0


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'reports/audit_candidate');args=p.parse_args()
    raise SystemExit(run(args.output.resolve()))
