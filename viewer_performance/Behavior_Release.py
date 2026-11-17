"""Reviewed stop / scope release / restore, including a pre-pull stdin stage.

--prepare-update runs with the old installed tools before git pull. Subsequent
stages use the new installed release. Only the previously active roles/tasks
are restored. Receipts and logs remain private under reports.
"""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import time


def restore(project,receipt,state):
    from viewer_performance.financial_screen import host as h
    from p24_foundation.viewer_runtime import atomic_json
    plan=state['before']['restore_plan'];errors=[]
    version,code=h.command(project,'AnomalyDetection/run_anomaly.py','version')
    if code:raise ValueError('INSTALLED_AD_RELEASE_NOT_VERIFIED')
    for role in ('ad_worker','ad_web'):
        plan['ad_identities'][role]=dict(source_sha256=version['source_sha256'])
    for role in ('viewer_web','ad_worker','ad_web','viewer'):
        if not plan['active'][role]:continue
        try:
            if role.startswith('ad_'):
                current,_=h.command(project,'AnomalyDetection/run_anomaly.py','worker-status')
                part='process' if role=='ad_worker' else 'web'
                if current.get(part,{}).get('locked'):continue
                if role=='ad_web' and plan['active']['ad_worker']:continue
            else:
                script='viewer_performance/Stop_Viewer_Worker.py' if role=='viewer' else 'viewer_performance/Stop_Viewer_Web.py'
                current,_=h.command(project,script)
                if current['status'] in ('VIEWER_WORKER_IDENTIFIED','VIEWER_WEB_IDENTIFIED'):continue
            if role=='ad_worker':
                result,code=h.command(project,*plan['ad_worker_restart'])
                if code:raise ValueError('AD_RESTART_FAILED')
            else:h.start_process(project,plan[role+'_restart'],receipt.parent,role)
        except Exception as exc:errors.append(dict(role=role,error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None))
    try:state['after_restore']=h.verify_restore(project,plan)
    except Exception as exc:errors.append(dict(role='core_health',code=str(exc) if isinstance(exc,ValueError) else type(exc).__name__))
    if not errors:
        try:
            if plan.get('reviewed_proxy'):h.check_sources(plan['reviewed_proxy'])
            for task in plan['task_restore']:h.task_change(task,True)
            if plan.get('reviewed_proxy'):state['proxy_restore']=h.restore_reviewed_proxy(project,plan['reviewed_proxy'])
        except Exception as exc:errors.append(dict(role='supervision',code=str(exc) if isinstance(exc,ValueError) else type(exc).__name__))
    state.update(status='BEHAVIOR_RELEASE_RESTORE_INCOMPLETE' if errors else 'PREVIOUS_ROLES_RESTORED',restore_failures=errors)
    atomic_json(receipt,state)
    if errors:raise ValueError('RELEASE_RESTORE_INCOMPLETE_SEND_RECEIPT')


def prepare(project,receipt,review):
    from viewer_performance.financial_screen import host as h
    from viewer_performance.financial_screen.reviewed_host import load_review,apply_review
    from p24_foundation.viewer_runtime import atomic_json
    before=h.preflight(project)
    if review:before=apply_review(project,before,*load_review(review))
    state=dict(status='RELEASE_PREFLIGHT',before=before,steps=[],restore_failures=[])
    atomic_json(receipt,state)
    if before['status']!='PREFLIGHT_READY':raise ValueError('RELEASE_PREFLIGHT_BLOCKED_SEND_RECEIPT')
    plan=before['restore_plan'];connection=None
    try:
        for task in plan['task_restore']:h.task_change(task,False)
        state['steps'].append('AUTOSTART_DISABLED');atomic_json(receipt,state)
        if plan['active']['ad_worker'] or plan['active']['ad_web']:h.stop_role(project,'ad')
        connection=h.product_reader(project)
        deadline=time.monotonic()+900
        while not connection.execute('SELECT pg_try_advisory_lock(240026,2) AS held').fetchone()['held']:
            if time.monotonic()>deadline:raise TimeoutError('CURRENT_PUBLICATION_DID_NOT_DRAIN')
            print(json.dumps(dict(status='WAITING_FOR_CURRENT_PUBLICATION_COMMIT')),flush=True);time.sleep(2)
        if plan['active']['viewer']:h.stop_role(project,'viewer')
        if plan['active']['viewer_web']:h.stop_role(project,'web')
        if plan.get('reviewed_proxy'):h.stop_reviewed_proxy(project,plan['reviewed_proxy'])
        state['frozen_cursors']=h.cursors(connection);connection.close();connection=None
        h.wait_for_quiescence(project,plan)
        state.update(status='PREPARED_FOR_MAIN_UPDATE',prepared_at_utc=datetime.now(timezone.utc).isoformat())
        atomic_json(receipt,state)
    except BaseException:
        if connection is not None:connection.close()
        restore(project,receipt,state);raise
    return state


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,default=Path.cwd())
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--reviewed-preflight',type=Path)
    parser.add_argument('--action',choices=('prepare-update','benchmark-install','install','rollback','restore'),required=True)
    parser.add_argument('--max-seconds',type=int,default=21600)
    args=parser.parse_args(argv);project=args.project.resolve();receipt=args.receipt.resolve()
    sys.path.insert(0,str(project));receipt.parent.mkdir(parents=True,exist_ok=True)
    from p24_foundation.viewer_runtime import atomic_json
    state=None
    try:
        if args.action=='prepare-update':
            if receipt.exists():raise ValueError('USE_NEW_RELEASE_RECEIPT_PATH')
            state=prepare(project,receipt,args.reviewed_preflight)
        else:
            state=json.loads(receipt.read_text(encoding='utf-8-sig'))
            if args.action=='restore':restore(project,receipt,state)
            else:
                if state['status']!='PREPARED_FOR_MAIN_UPDATE':raise ValueError('FROZEN_UPDATE_RECEIPT_REQUIRED')
                from viewer_performance.financial_screen import host as h
                from tools.check_viewer_install import verify_release
                if verify_release(project)['status']!='PASS':raise ValueError('NEW_INSTALLATION_MANIFEST_FAILED')
                cpu={};plan=state['before']['restore_plan']
                def guard():h.assert_quiescent(project,h.inventory(project),plan,cpu)
                try:
                    guard()
                    with h.product_reader(project) as db:
                        if h.cursors(db)!=state['frozen_cursors']:raise ValueError('PRODUCT_CURSORS_CHANGED_DURING_UPGRADE')
                    if args.action=='benchmark-install':
                        from viewer_performance.behavior_benchmark import run
                        benchmark=run(project,receipt.parent,guard,lambda v:print(json.dumps(v),flush=True),max_seconds=args.max_seconds)
                        state['benchmark_status']=benchmark['status']
                        if benchmark['status']!='LARGE_HISTORY_EQUIVALENCE_AND_CAPACITY_COMPLETE':raise ValueError('LARGE_HISTORY_BENCHMARK_INCOMPLETE')
                    result,code=h.command(project,'viewer_performance/Behavior_Control.py','restore-full' if args.action=='rollback' else 'enable','--project',project)
                    if code:raise ValueError('BEHAVIOR_SCOPE_ACTIVATION_FAILED')
                    state['activation']=result
                    atomic_json(receipt,state)
                finally:restore(project,receipt,state)
        print(json.dumps(dict(status=state['status'],output=str(receipt),benchmark_status=state.get('benchmark_status'),activation=state.get('activation'))),flush=True)
        return 0
    except BaseException as exc:
        if isinstance(exc,KeyboardInterrupt):code='INTERRUPTED_RESTORE_RECEIPT_REQUIRED'
        else:code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else type(exc).__name__
        if state is not None:
            state['release_failure']=dict(code=code);atomic_json(receipt,state)
        print(json.dumps(dict(status='BEHAVIOR_RELEASE_INCOMPLETE',code=code,output=str(receipt))),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
