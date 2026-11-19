"""Pinned update with recorded role restoration; no data reset or benchmark.

Download outside the checkout and run with its venv Python as Administrator.
The old installed control helpers stop processes before Git changes any code.
The PostgreSQL service and its settings are not changed by this installer.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

EXPECTED_BUILD='AD-20261119-BEHAVIOR-RECOVERY'


def git_command(project,*args):
    result=subprocess.run(['git',*map(str,args)],cwd=project,capture_output=True,timeout=120)
    if result.returncode:raise ValueError('GIT_OPERATION_FAILED:'+args[0]+':'+result.stderr.decode('utf-8','replace')[-4000:])
    return result.stdout.decode('utf-8').strip()


def check_manifests(project):
    from tools.check_viewer_install import verify_release
    if verify_release(project)['status']!='PASS':raise ValueError('INSTALLED_MANIFEST_MISMATCH')


def progress_snapshot(host,project):
    status,code=host.command(project,'AnomalyDetection/run_anomaly.py','worker-status')
    with host.product_reader(project) as db:
        source=db.execute('SELECT contract,epoch,state FROM public.viewer_product_scope WHERE id=1').fetchone()
        cursors=host.cursors(db)
    return dict(observed_ns=time.time_ns(),status_exit_code=code,ad=status,viewer_scope=dict(source) if source else None,cursors=cursors)


def install(project,target,release_receipt,*,host,restore,inspect,git=git_command,wait=time.sleep):
    from p24_foundation.viewer_runtime import atomic_json
    if not re.fullmatch('[0-9a-f]{40}',target):raise ValueError('FULL_TARGET_COMMIT_REQUIRED')
    project=Path(project).resolve()
    folder=project/'AnomalyDetection/reports'/('Behavior_Recovery_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
    folder.mkdir(parents=True);receipt=folder/'install.json'
    state=dict(status='RECOVERY_PREPARING',target=target,project=str(project),disabled_tasks=[],attempted_roles=[],
        stopping_started=False,restore_failures=[],new_database_copies=0,checkpoint_seek_performed=False,
        evidence_deleted=False,postgres_restarted=False,settings_modified=False,capacity_acceptance='NOT_ASSIGNED')
    def save(status):
        state['status']=status;atomic_json(receipt,state)
        notice=dict(status=status,output=str(receipt))
        if state.get('failure'):notice['failure']=state['failure']
        print(json.dumps(notice,ensure_ascii=True),flush=True)
    def clean(name,selected):
        result=inspect(project,selected,'git',folder/name)
        if result['status']!='INSTALL_GIT_READY':raise ValueError('TRACKED_CHANGES_BLOCK_UPDATE:'+json.dumps(result['blocking_changes']))
        return result
    code_updated=False;new_roles_attempted=False
    try:
        check_manifests(project)
        old=json.loads(Path(release_receipt).read_text(encoding='utf-8-sig'))
        if old['status'] not in ('PREVIOUS_ROLES_RESTORED','CACHE_TRIAL_APPLIED_ROLES_RESTORED','RECOVERY_INSTALLED_ROLES_RESTORED'):
            raise ValueError('RESTORED_ROLE_RECEIPT_REQUIRED')
        plan=old['before']['restore_plan'];state['before']=dict(restore_plan=plan)
        state['previous_head']=git(project,'rev-parse','HEAD');save('FETCHING_PINNED_RELEASE')
        git(project,'fetch','--no-tags','origin',target)
        git(project,'merge-base','--is-ancestor',state['previous_head'],target)
        target_manifest=json.loads(git(project,'show',target+':AnomalyDetection/RELEASE_MANIFEST.json'))
        if target_manifest.get('build_id')!=EXPECTED_BUILD:raise ValueError('TARGET_IS_NOT_THE_RECOVERY_BUILD')
        state['expected_ad_source_sha256']=target_manifest['source_sha256']
        clean('git-before-stop.json',target)
        # Known short monitor tasks may be finishing; do not race their start.
        known={host.key(t):t for t in plan['task_restore']}
        for attempt in range(31):
            snapshot=host.inventory(project)
            for task in snapshot['tasks']:
                if host.key(task) not in known or task['Actions']!=known[host.key(task)]['Actions']:
                    raise ValueError('SCHEDULED_TASK_ACTIONS_CHANGED:'+task['Name'])
            running=[t['Name'] for t in snapshot['tasks'] if t['State']=='Running' and t['Name']!='P24-Office-LAN-Proxy']
            if not running:break
            if attempt==30:raise ValueError('KNOWN_SUPERVISOR_STILL_RUNNING:'+','.join(running))
            save('WAITING_FOR_KNOWN_SUPERVISOR');wait(2)
        save('DISABLING_AUTOSTART')
        for task in snapshot['tasks']:
            if task['Enabled']:
                state['disabled_tasks'].append(task);save('DISABLING_AUTOSTART');host.task_change(task,False)
        state['stopping_started']=True
        for role in ('ad','viewer','viewer_web'):
            state['attempted_roles'].append(role);save('STOPPING_'+role.upper())
            if role=='viewer':
                for attempt in range(12):
                    result,code=host.command(project,'viewer_performance/Stop_Viewer_Worker.py','--stop')
                    state.setdefault('viewer_stop_attempts',[]).append(dict(return_code=code,result=result));save('STOPPING_VIEWER')
                    if not code and result.get('status') in ('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED'):break
                    if result.get('status')!='VIEWER_BACKEND_STOP_PENDING':raise ValueError('VIEWER_STOP_FAILED:'+json.dumps(result))
                    wait(1)
                else:raise ValueError('VIEWER_STOP_DID_NOT_RELEASE_ITS_LEASE')
            else:host.stop_role(project,'ad' if role=='ad' else 'web')
        with host.product_reader(project) as db:state['frozen_cursors']=host.cursors(db)
        clean('git-frozen.json',target);save('ACTIVATING_PINNED_CODE')
        git(project,'merge','--ff-only',target);code_updated=True
        if git(project,'rev-parse','HEAD')!=target:raise ValueError('UPDATED_HEAD_DIFFERS_FROM_PIN')
        check_manifests(project)
        version,code=host.command(project,'AnomalyDetection/run_anomaly.py','version')
        if code or version.get('build_id')!=EXPECTED_BUILD or version.get('source_sha256')!=state['expected_ad_source_sha256']:
            raise ValueError('UPDATED_AD_BUILD_NOT_VERIFIED')
        state['installed_version']=version;save('STARTING_UPDATED_ROLES');new_roles_attempted=True
        restore(project,receipt,state)
        save('OBSERVING_NEW_AD_PROGRESS')
        def observe():
            try:return progress_snapshot(host,project)
            except Exception as exc:
                return dict(observed_ns=time.time_ns(),ad={},diagnostic_failure=dict(error_type=type(exc).__name__,
                    code=str(exc) if isinstance(exc,ValueError) else None))
        state['progress_before']=observe();wait(20)
        state['progress_after']=observe()
        first=state['progress_before']['ad'];last=state['progress_after']['ad']
        before_owner=(first.get('process') or {}).get('owner') or {};after_owner=(last.get('process') or {}).get('owner') or {}
        comparable=bool(before_owner.get('instance_token') and before_owner==after_owner and
            all(v.get('running') and v.get('observation_matches_process') and
                type(v.get('heartbeat_age_seconds')) in (int,float) and v['heartbeat_age_seconds']<=30 for v in (first,last)))
        state['analysis_counter_delta_verified']=comparable
        counters=('evaluated_jobs','scenario_evaluations','audited_requests','source_pages','cohort_windows','source_failures_total','owned_apply_failures_total')
        a=first.get('worker',{});b=last.get('worker',{})
        state['analysis_counter_delta']={k:b[k]-a[k] for k in counters if comparable and type(a.get(k)) is int and type(b.get(k)) is int}
        state['analysis_progress_verified']=comparable and any(state['analysis_counter_delta'].get(k,0)>0 for k in counters[:5])
        state['runtime_identity_verified']=comparable and all(after_owner.get(k)==v for k,v in dict(
            build_id=EXPECTED_BUILD,source_sha256=state['expected_ad_source_sha256']).items())
        scope=state['progress_after'].get('viewer_scope') or {};contract=b.get('input_contract') or {}
        state['runtime_contract_agreement']=bool(scope.get('state')=='READY' and scope.get('contract')=='viewer-behavior-1'
            and contract.get('input_contract')==scope.get('contract') and contract.get('scope_epoch')==scope.get('epoch'))
        state['runtime_receipt_status']='COMPLETE' if state['runtime_identity_verified'] and state['runtime_contract_agreement'] else 'PARTIAL'
        # Successful process restoration is NOT source/model/capacity acceptance.
        ad=last
        state['analysis_health']=ad.get('health');state['analysis_acceptance']='PENDING_SOURCE_PROGRESS_AND_SCOPE_MIGRATION'
        save('RECOVERY_INSTALLED_ROLES_RESTORED');return state
    except Exception as exc:
        state['failure']=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None)
        if hasattr(exc,'details'):state['failure']['details']=exc.details
        # Before new roles start, an exact unchanged Git head permits rollback.
        # Data, schema, settings, reports and untracked local files remain.
        if code_updated and not new_roles_attempted:
            try:
                if git(project,'rev-parse','HEAD')!=target:raise ValueError('GIT_HEAD_CHANGED_NO_AUTOMATIC_ROLLBACK')
                clean('git-before-rollback.json',state['previous_head'])
                git(project,'reset','--keep',state['previous_head']);state['previous_code_restored']=True
            except Exception as rollback:state['rollback_failure']=dict(error_type=type(rollback).__name__,code=str(rollback))
        if state['stopping_started']:
            try:restore(project,receipt,state)
            except Exception as recovery:state['role_restore_failure']=dict(error_type=type(recovery).__name__,code=str(recovery))
        else:
            for task in reversed(state['disabled_tasks']):
                try:host.task_change(task,True)
                except Exception as recovery:state['restore_failures'].append(dict(task=task['Name'],error_type=type(recovery).__name__))
        save('RECOVERY_UPDATE_INCOMPLETE_SEND_RECEIPT');return state


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,default=Path.cwd());parser.add_argument('--target')
    parser.add_argument('--release-receipt',type=Path);parser.add_argument('--restore-receipt',type=Path);args=parser.parse_args()
    if bool(args.restore_receipt)==bool(args.target or args.release_receipt):parser.error('choose --restore-receipt or --target with --release-receipt')
    if not args.restore_receipt and not (args.target and args.release_receipt):parser.error('--target and --release-receipt are required together')
    if os.name!='nt' or not __import__('ctypes').windll.shell32.IsUserAnAdmin():raise SystemExit('Run in Administrator PowerShell on the Windows server.')
    project=args.project.resolve();sys.path.insert(0,str(project))
    from viewer_performance.financial_screen import host
    from viewer_performance.Behavior_Release import restore
    from viewer_performance.behavior_install_git import inspect
    if args.restore_receipt:
        from p24_foundation.viewer_runtime import atomic_json
        state=json.loads(args.restore_receipt.read_text(encoding='utf-8-sig'))
        if Path(state['project']).resolve()!=project:raise ValueError('RESTORE_RECEIPT_PROJECT_DIFFERS')
        check_manifests(project)
        if state.get('stopping_started'):restore(project,args.restore_receipt,state)
        else:
            for task in reversed(state.get('disabled_tasks',[])):host.task_change(task,True)
        state['status']='RECOVERY_ROLES_RESTORED_RECHECK_INSTALLATION';atomic_json(args.restore_receipt,state)
        print(json.dumps(dict(status=state['status'],output=str(args.restore_receipt))),flush=True);return 0
    result=install(project,args.target,args.release_receipt,host=host,restore=restore,inspect=inspect)
    return 0 if result['status']=='RECOVERY_INSTALLED_ROLES_RESTORED' else 2


if __name__=='__main__':raise SystemExit(main())
