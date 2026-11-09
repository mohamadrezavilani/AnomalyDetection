"""Non-destructive CLI checks for the v0.2.3 Requests and service catalogue.

Does not modify service classifications or source events. Works against the
same viewer_config.local.py used by run_behavior_viewer.py. Avoids emitting
customer identifiers to stdout/reviewer JSON.
"""
from __future__ import annotations
import argparse, importlib.util, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--out',type=Path)
    p.add_argument('--expect-events',type=int)
    p.add_argument('--expect-requests',type=int)
    p.add_argument('--expect-files',type=int)
    args=p.parse_args()
    if not args.config.is_file():p.error('config file does not exist')
    spec=importlib.util.spec_from_file_location('private_viewer_config',args.config.resolve())
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    key_path=Path(module.KEYS_PATH).expanduser().resolve()
    if getattr(module,'SQLITE_OFFLINE_PATH',None):
        kw=dict(sqlite_path=Path(module.SQLITE_OFFLINE_PATH),keys_path=key_path)
    else:
        kw=dict(config=module.DATABASE,keys_path=key_path)
    checks=[]
    def check(name,got,expected):
        checks.append(dict(name=name,result='PASS' if got==expected else 'FAIL',expected=expected,actual=got))
    with ViewerDB(**kw) as db:
        metrics=db.metrics();raw=db.raw_coverage()
        catalog=db.service_roles(25)
        check('catalog_roles_sum',sum(catalog['role_totals'].values()),catalog['global_total'])
        check('catalog_filter_total_consistent',db.service_roles(1,search='ElectricBills')['global_total'],catalog['global_total'])
        check('complete_raw_storage',raw['missing'],0)
        if args.expect_events is not None:check('events',metrics['events'],args.expect_events)
        if args.expect_requests is not None:check('requests',metrics['requests'],args.expect_requests)
        if args.expect_files is not None:check('files',metrics['files'],args.expect_files)
        example=next((r for r in db.service_roles(1000)['items'] if r['service_path']=='Services.v1/ElectricBills'),None)
        if example:
            matched=db.requests_page(1,0,service_path_filter=example['service_path'])
            check('exact_service_filter_request_count',matched['total'],example['requests'])
            if matched['items']:
                check('exact_service_filter_identity',
                      matched['items'][0]['root_call'].split(' Line:',1)[0],example['service_path'])
            if example['sample_request_key']:
                check('sample_request_link_resolves',bool(db.request(example['sample_request_key'])),True)
        else:
            checks.append(dict(name='electric_sample',result='NOT_RUN',reason='Services.v1/ElectricBills not in observed catalog'))
    result=dict(phase='Behavior Viewer v0.2.3',status='PASS' if not any(x['result']=='FAIL' for x in checks) else 'FAIL',
                checks=checks,metrics=metrics,raw_coverage=raw,
                catalog=dict(total=catalog['global_total'],role_totals=catalog['role_totals']),
                note='No user identifiers in report. Does not validate Flask pages or PostgreSQL performance.')
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
