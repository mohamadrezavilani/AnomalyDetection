"""Reproduce real-data oracle checks without exposing raw session/payment values."""
from __future__ import annotations
import argparse,importlib.util,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB


def validate(db,oracle):
    checks=[]
    def check(name,observed,expected):
        checks.append(dict(id=name,actual=observed,expected=expected,status='PASS' if observed==expected else 'FAIL'))
    for date,exp_event,exp_req,exp_shared in [('20261024',653652,145925,217),('20261020',349910,78937,36)]:
        args=[f'logs_{date}_%']
        ev=db.one('SELECT COUNT(*) n FROM viewer_events WHERE filename LIKE ?',args)['n']
        rq=db.one('SELECT COUNT(DISTINCT request_key) n FROM viewer_events WHERE filename LIKE ?',args)['n']
        shared=db.one('''SELECT COUNT(*) n FROM (SELECT request_key FROM viewer_events WHERE filename LIKE ?
                   GROUP BY request_key HAVING COUNT(DISTINCT filename)>1) AS shared''',args)['n']
        check(date+'.events',ev,exp_event);check(date+'.requests',rq,exp_req);check(date+'.boundaries',shared,exp_shared)
    check('combined.events',db.metrics()['events'],1003562)
    check('combined.requests',db.metrics()['requests'],224862)
    check('combined.conflicts',db.metrics()['conflicting_origins'],0)
    ref=oracle['session_case'];found=db.lookup_request(ref['locator_request_id']);session=found['session_key']
    check('reference.session_rows',db.one('SELECT COUNT(*) n FROM viewer_events WHERE session_key=?',(session,))['n'],653)
    check('reference.session_requests',db.one('SELECT COUNT(*) n FROM viewer_requests WHERE session_key=?',(session,))['n'],146)
    check('reference.complete_request_rows',db.one('SELECT SUM(event_count) n FROM viewer_requests WHERE session_key=?',(session,))['n'],660)
    typed=set();invoice_matched=0
    for expected in ref['inquiries']:
        key=db.lookup_request(expected['rid'])['request_key'];a=db.action(key)
        typed.add((a['target_type'],a['target_key']))
        invoice_matched+=int(any(x['name']=='InvoiceRegister' for x in a['related']))
        check('inquiry.'+expected['rid'][:8]+'.root_code',db.request(key)['root_code'],expected['root_code'])
    check('reference.typed_targets',len(typed),5)
    check('reference.invoice_joins',invoice_matched,9)
    for pay in oracle['payments']:
        name=pay['case'];key=db.lookup_request(pay['initial_rid'])['request_key'];action=db.action(key)
        webhook=db.lookup_request(pay['webhook_rid'])['request_key']
        expected_result='confirmed_success' if name=='electricity' else 'confirmed_after_webhook'
        check(name+'.final',action['current_outcome'],expected_result)
        statuses=[x['status'] for x in action['outcome_history']]
        check(name+'.history',statuses,['paid_true' if name=='electricity' else 'paid_false','webhook_payment_success'])
        check(name+'.webhook_link',any(x['source_request_key']==webhook for x in action['outcome_history']),True)
    return dict(version='p24-viewer-oracle-check.1',status='PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL',
                checks=checks,pass_count=sum(x['status']=='PASS' for x in checks),fail_count=sum(x['status']!='PASS' for x in checks),
                privacy='hash aliases, no raw sessions, request IDs or payment keys')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--oracle',required=True,type=Path)
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    if not args.config.is_file():parser.error(f'Viewer config not found: {args.config.resolve()}')
    if not args.oracle.is_file():parser.error(f'Oracle file not found: {args.oracle.resolve()}; locate expected_results.json in the extracted evaluator handoff package')
    spec=importlib.util.spec_from_file_location('viewer_local',args.config.resolve())
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    kwargs={'keys_path':Path(module.KEYS_PATH)}
    if getattr(module,'SQLITE_OFFLINE_PATH',None):kwargs['sqlite_path']=module.SQLITE_OFFLINE_PATH
    else:kwargs['config']=module.DATABASE
    with ViewerDB(**kwargs) as db:report=validate(db,json.loads(args.oracle.read_text(encoding='utf-8')))
    result=json.dumps(report,ensure_ascii=False,indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(result+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],pass_count=report['pass_count'],fail_count=report['fail_count']),ensure_ascii=False))
    return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
