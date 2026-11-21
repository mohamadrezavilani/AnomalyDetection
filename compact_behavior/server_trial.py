"""Windows exclusive short trial. Legacy code is used only to stop/restore roles."""
import argparse
import copy
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile
from .__main__ import save,notice


def source_preflight(project,windows):
    """Check the actual next source page before disabling any project roles."""
    from .source import settings,ElasticWindow
    from .store import Store
    from .probe_elastic import probe
    from . import FIVE
    cfg=settings(project/'viewer_config.local.py');elastic=cfg['ELASTICSEARCH']
    stream=ElasticWindow(elastic,0,FIVE).namespace;store=Store(cfg['DATABASE'])
    try:
        store.conn.execute('SET default_transaction_read_only=on')
        present=store.conn.execute("SELECT to_regclass('p24_compact.streams') AS present").fetchone()['present']
        start=store.cursor(stream) if present else None
    finally:store.close()
    if start is None:start=(time.time_ns()-60_000_000_000)//FIVE*FIVE-windows*FIVE
    return probe(elastic,start)


def save_bundle(folder):
    bundle=folder.with_suffix('.zip')
    with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as archive:
        for file in folder.rglob('*'):
            if file.is_file():archive.write(file,file.relative_to(folder))
    return bundle


def read(path):
    try:return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except (OSError,ValueError):return None


def freeze(project,state,receipt,host):
    plan=state['before']['restore_plan']
    ad,_=host.command('AnomalyDetection/run_anomaly.py','worker-status')
    viewer,_=host.command('viewer_performance/Stop_Viewer_Worker.py')
    web,_=host.command('viewer_performance/Stop_Viewer_Web.py')
    if viewer.get('status') not in ('VIEWER_WORKER_IDENTIFIED','NO_VIEWER_LOCK_OWNER_OBSERVED','VIEWER_BACKEND_WITHOUT_CLIENT'):
        raise ValueError('viewer_control_unavailable')
    if web.get('status') not in ('VIEWER_WEB_IDENTIFIED','NO_VIEWER_WEB_LISTENER'):raise ValueError('web_control_unavailable')
    plan['active']=dict(ad_worker=ad['process']['locked'],ad_web=ad['web']['locked'],
        viewer=viewer['status']=='VIEWER_WORKER_IDENTIFIED' or viewer['status']=='VIEWER_BACKEND_WITHOUT_CLIENT' and plan['active']['viewer'],
        viewer_web=web['status']=='VIEWER_WEB_IDENTIFIED')
    tasks=host.inventory()['tasks'];state['original_task_states']=tasks;state['stopping_started']=True
    state['attempted_roles']=['ad','viewer','viewer_web'];save(receipt,state)
    for task in tasks:
        if task['Enabled']:
            state['disabled_tasks'].append(task);save(receipt,state);host.h.task_change(task,False)
        if task['State']=='Running' and task['Name']!='P24-Office-LAN-Proxy':host.h.task_control(task,'stop')
    for role in ('ad','viewer','web'):
        notice('COMPACT_STOPPING_EXISTING_ROLE',role=role);host.stop(role)
    proxy=plan.get('reviewed_proxy')
    if proxy:
        from viewer_performance.financial_screen.reviewed_host import words,norm
        expected=[norm(v) for v in words(proxy['processes'][0]['CommandLine'])[1:]]
        proxy['processes']=[p for p in host.inventory()['processes'] if [norm(v) for v in words(p.get('CommandLine') or '')[1:]]==expected]
        if proxy['processes']:
            state['attempted_roles'].append('proxy');save(receipt,state);host.h.stop_reviewed_proxy(project,proxy)
    with host.reader() as db:state['frozen_cursors']=host.h.cursors(db)
    # Verify the dedicated conditions immediately before launching the compact writer.
    verify_frozen(host)
    state['exclusive_conditions']='VERIFIED_BEFORE_CHILD';save(receipt,state)


def verify_frozen(host):
    ad,_=host.command('AnomalyDetection/run_anomaly.py','worker-status')
    viewer,_=host.command('viewer_performance/Stop_Viewer_Worker.py')
    web,_=host.command('viewer_performance/Stop_Viewer_Web.py')
    if ad['process']['locked'] or ad['web']['locked'] or viewer.get('status') not in ('NO_VIEWER_LOCK_OWNER_OBSERVED','VIEWER_BACKEND_STOPPED') or web.get('status')!='NO_VIEWER_WEB_LISTENER':
        raise ValueError('exclusive_trial_conditions_not_met')


def stop_child(project,report,token,child,stop_file):
    save(stop_file,{'stop':True})
    try:child.wait(timeout=10);return
    except subprocess.TimeoutExpired:pass
    value=read(report) or {}
    if value.get('command_token')!=token:raise ValueError('trial_child_identity_missing')
    from viewer_performance.Behavior_Release import hard_stop_scope_python
    hard_stop_scope_python(report,token)
    child.wait(timeout=10)


def trial(project,old_receipt,folder,*,host,restore,execute):
    folder.mkdir(parents=True,exist_ok=True);receipt=folder/'trial.json';old=read(old_receipt)
    if not isinstance(old,dict) or not old.get('before',{}).get('restore_plan'):raise ValueError('existing_restore_plan_required')
    state=dict(status='COMPACT_TRIAL_PREPARING',project=str(project),before=copy.deepcopy(old['before']),
        disabled_tasks=[],attempted_roles=[],restore_failures=[],stopping_started=False,
        installed_code_changed=False,postgres_settings_changed=False,legacy_data_reset=False,
        prototype_scope='EXTRACTION_AND_STORAGE_ONLY_AD_AND_WEB_NOT_IMPLEMENTED',started_at_utc=datetime.now(timezone.utc).isoformat())
    save(receipt,state)
    try:
        freeze(project,state,receipt,host)
        result=execute(folder,state);state['prototype_result']=result
        verify_frozen(host)
        with host.reader() as db:after=host.h.cursors(db)
        state['legacy_cursors_unchanged_during_trial']=state['frozen_cursors']==after
        if not state['legacy_cursors_unchanged_during_trial']:raise ValueError('legacy_processing_changed_during_trial')
        state['trial_result']='MEASURED' if result.get('status')=='COMPACT_PROTOTYPE_MEASURED' else 'INCOMPLETE'
    except BaseException as exc:
        state['trial_result']='INCOMPLETE';state['failure']=dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
            sqlstate=getattr(exc,'sqlstate',None),details=getattr(exc,'details',None))
    finally:
        notice('COMPACT_RESTORING_ORIGINAL_ROLES')
        try:restore(project,receipt,state)
        except BaseException as exc:state['restore_error']=dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None)
        state['status']='COMPACT_TRIAL_MEASURED_ROLES_RESTORED' if state.get('trial_result')=='MEASURED' and not state.get('restore_error') and not state['restore_failures'] else 'COMPACT_TRIAL_PARTIAL_SEND_BUNDLE'
        save(receipt,state)
        bundle=save_bundle(folder)
        notice(state['status'],output=str(bundle),receipt=str(receipt))
    return state


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,required=True)
    p.add_argument('--release-receipt',type=Path);p.add_argument('--restore-receipt',type=Path)
    p.add_argument('--seconds',type=int,default=600,choices=range(60,901));p.add_argument('--windows',type=int,default=3,choices=range(1,5))
    a=p.parse_args();project=a.project.resolve()
    if os.name!='nt' or not __import__('ctypes').windll.shell32.IsUserAnAdmin():p.error('Run as Administrator on Windows.')
    from viewer_performance.Diagnose_Three_Modes import ProductionHost,controller_lock
    from viewer_performance.Behavior_Release import restore
    if not (a.release_receipt or a.restore_receipt):p.error('release receipt required')
    with controller_lock(project):
        if a.restore_receipt:
            state=read(a.restore_receipt)
            if not state or Path(state['project']).resolve()!=project:raise ValueError('restore_project_mismatch')
            value=read(a.restore_receipt.parent/'prototype.json') or {}
            if value.get('command_token')==state.get('child_token') and value.get('process_created_epoch_seconds'):
                # Hard termination recovery; a live identity is checked by the installed helper.
                from viewer_performance.Behavior_Release import hard_stop_scope_python
                try:hard_stop_scope_python(a.restore_receipt.parent/'prototype.json',state['child_token'])
                except (ProcessLookupError,OSError):pass
            restore(project,a.restore_receipt,state);notice('COMPACT_ORIGINAL_ROLES_RESTORED');return 0
        folder=project/'AnomalyDetection/reports'/('Compact_Prototype_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
        folder.mkdir(parents=True,exist_ok=True)
        notice('COMPACT_CHECKING_SOURCE_WITH_SERVICES_RUNNING')
        try:preflight=source_preflight(project,a.windows)
        except Exception as exc:preflight={'status':'SOURCE_PREFLIGHT_ERROR','failure':{'type':type(exc).__name__,
            'code':str(exc) if isinstance(exc,ValueError) else None,'details':getattr(exc,'details',None)}}
        save(folder/'source-preflight.json',preflight)
        if preflight.get('status')!='FIRST_SEARCH_PAGE_VALID':
            notice('COMPACT_SOURCE_PREFLIGHT_BLOCKED',services_stopped=False,output=str(save_bundle(folder)))
            return 2
        def execute(directory,state):
            output=directory/'prototype.json';stop_file=directory/'stop.json';token=uuid.uuid4().hex
            command=[sys.executable,'-X','utf8','-B','-m','compact_behavior','--config',str(project/'viewer_config.local.py'),
                '--output',str(output),'--windows',str(a.windows),'--trial-token',token,'--stop-file',str(stop_file)]
            state['child_token']=token;save(directory/'trial.json',state)
            state['maximum_child_seconds']=a.seconds;state['requested_windows']=a.windows
            with (directory/'prototype-console.txt').open('wb') as log:
                child=subprocess.Popen(command,cwd=Path(__file__).resolve().parents[1],stdout=log,stderr=subprocess.STDOUT,
                    env={**os.environ,'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1'},creationflags=getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))
                began=time.monotonic();last_check=began
                try:
                    while child.poll() is None:
                        if time.monotonic()-began>=a.seconds:raise TimeoutError('compact_trial_deadline')
                        if time.monotonic()-last_check>=30:
                            verify_frozen(ProductionHost(project));last_check=time.monotonic()
                        result=read(output) or {}
                        notice('COMPACT_TRIAL_RUNNING',elapsed_seconds=round(time.monotonic()-began),committed_windows=len(result.get('windows',[])))
                        try:child.wait(timeout=15)
                        except subprocess.TimeoutExpired:pass
                finally:
                    if child.poll() is None:stop_child(project,output,token,child,stop_file)
            result=read(output)
            if not result:raise ValueError('prototype_report_missing')
            if child.returncode:
                result['child_exit_code']=child.returncode;result['reported_status_before_exit_check']=result.get('status')
                result['status']='COMPACT_PROTOTYPE_INCOMPLETE'
            return result
        state=trial(project,a.release_receipt,folder,host=ProductionHost(project),restore=restore,execute=execute)
    return 0 if state['status']=='COMPACT_TRIAL_MEASURED_ROLES_RESTORED' else 2


if __name__=='__main__':raise SystemExit(main())
