"""Receipt-driven stop, pinned-code activation and verified role restoration.

Prepare is usable from stdin with the old installed maintenance helpers. No
scope activation precedes reviewed quiescence. An interrupted financial repair
keeps supervisors disabled until an explicit resume or behavior selection.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


@contextmanager
def controller_inventory(h,project,state=None):
    """Allow only our exact invoking installer ancestor, never a name wildcard.

    Windows venv redirectors and the waiting PowerShell installer can otherwise
    look like an unowned worker. Other children, tasks and listeners stay visible.
    PID, creation, image and entire command line are checked on every inventory.
    """
    expected=os.environ.get('P24_BEHAVIOR_INSTALLER_PID');original=h.inventory
    if not expected:yield;return
    initial=original(project);processes={int(p['ProcessId']):p for p in initial['processes']}
    chain=[];current=processes.get(os.getpid());seen=set()
    while current and int(current.get('ParentProcessId',0)) not in seen:
        parent=processes.get(int(current.get('ParentProcessId',0)))
        if not parent:break
        seen.add(parent['ProcessId']);chain.append(parent)
        if int(parent['ProcessId'])==int(expected):break
        if not (parent.get('ExecutablePath') or '').lower().endswith(('python.exe','pythonw.exe')):
            raise ValueError('INSTALLER_ANCESTRY_NOT_VERIFIED')
        current=parent
    from viewer_performance.financial_screen.reviewed_host import words,norm,same_process
    shell=chain[-1] if chain else {}
    args=words(shell.get('CommandLine') or '')
    lower=[a.lower() for a in args]
    if int(shell.get('ProcessId',0))!=int(expected) or not (shell.get('ExecutablePath') or '').lower().endswith(('powershell.exe','pwsh.exe')) or '-file' not in lower:
        raise ValueError('INSTALLER_ANCESTRY_NOT_VERIFIED')
    script=args[lower.index('-file')+1]
    if norm(script)!=norm(os.environ.get('P24_BEHAVIOR_INSTALLER_PATH','')) or __import__('ntpath').basename(script).lower()!='install_behavior.ps1':
        raise ValueError('INSTALLER_SCRIPT_PATH_NOT_VERIFIED')
    if state is not None:
        old=state.get('installer_ancestor')
        if old and not same_process(old,shell):raise ValueError('INSTALLER_PROCESS_REPLACED')
        state['installer_ancestor']=shell
    def inventory(project):
        value=original(project);actual={int(p['ProcessId']):p for p in value['processes']}
        for saved in chain:
            if not same_process(saved,actual.get(saved['ProcessId'],{})):raise ValueError('INSTALLER_ANCESTOR_REPLACED')
        # A new unrelated child is not covered by trusting a waiting installer.
        allowed={os.getpid()}|{p['ProcessId'] for p in chain}
        for p in value['processes']:
            if p.get('ParentProcessId') in allowed-{os.getpid()} and p['ProcessId'] not in allowed:
                if not (p.get('ExecutablePath') or '').lower().endswith('conhost.exe'):
                    raise ValueError('INSTALLER_HAS_UNREVIEWED_CHILD')
        return dict(value,processes=[p for p in value['processes'] if p['ProcessId'] not in {v['ProcessId'] for v in chain}])
    h.inventory=inventory
    try:yield
    finally:h.inventory=original


def scope_ready(h,project):
    with h.product_reader(project) as db:
        exists=db.execute("SELECT to_regclass('public.viewer_product_scope') AS present").fetchone()['present']
        row=db.execute('SELECT state FROM public.viewer_product_scope WHERE id=1').fetchone() if exists else None
        return not row or row['state']=='READY'


def verify_cursors(frozen,after):
    live=frozen.get('viewer_live_state',[]);new=after.get('viewer_live_state',[])
    if live and (not new or any(live[0].get(k)!=new[0].get(k) for k in ('start_ns','stream_key','keys_fingerprint')) or
                 any(new[0][k]<live[0][k] for k in ('next_ns','generation'))):
        raise ValueError('VIEWER_CURSOR_REGRESSED_OR_STREAM_CHANGED')
    key='public.viewer_history_replay_state';old=frozen.get(key,[]);new=after.get(key,[])
    if old and (not new or any(old[0].get(k)!=new[0].get(k) for k in ('run_id','from_ns','end_ns','keys_fingerprint')) or new[0]['next_ns']<old[0]['next_ns']):
        raise ValueError('HISTORY_CURSOR_REGRESSED_OR_RUN_CHANGED')


def restore(project,receipt,state):
    from viewer_performance.financial_screen import host as h
    from p24_foundation.viewer_runtime import atomic_json
    plan=state['before']['restore_plan'];errors=[]
    if not state.get('stopping_started'):return
    if not scope_ready(h,project):
        state.update(status='RESTORING_FULL_SUPERVISORS_LEFT_DISABLED',restore_failures=[dict(code='RESUME_REPAIR_OR_EXPLICITLY_ENABLE_BEHAVIOR')])
        atomic_json(receipt,state);raise ValueError('INCOMPLETE_FINANCIAL_REPAIR_NO_WORKER_RESTART')
    version,code=h.command(project,'AnomalyDetection/run_anomaly.py','version')
    if code or not version.get('source_sha256'):raise ValueError('INSTALLED_AD_RELEASE_NOT_VERIFIED')
    # The target release is verified separately; an old process must never be
    # accepted as the restored new build merely because it owns the old PID.
    for role in ('ad_worker','ad_web'):plan['ad_identities'][role]=dict(source_sha256=version['source_sha256'])
    attempted=set(state.get('attempted_roles',[]))
    for role in ('viewer_web','ad_worker','ad_web','viewer'):
        if not plan['active'][role] or ('ad' if role.startswith('ad_') else role) not in attempted:continue
        try:
            if role.startswith('ad_'):
                current,_=h.command(project,'AnomalyDetection/run_anomaly.py','worker-status')
                if current['process' if role=='ad_worker' else 'web']['locked']:continue
                if role=='ad_web' and plan['active']['ad_worker']:continue
            else:
                script='viewer_performance/Stop_Viewer_Worker.py' if role=='viewer' else 'viewer_performance/Stop_Viewer_Web.py'
                current,_=h.command(project,script)
                if current.get('status') in ('VIEWER_WORKER_IDENTIFIED','VIEWER_WEB_IDENTIFIED'):continue
            if role=='ad_worker':
                result,code=h.command(project,*plan['ad_worker_restart'])
                if code or result.get('status') not in ('STARTED','STARTING','ALREADY_RUNNING'):raise ValueError('AD_RESTART_FAILED')
            else:h.start_process(project,plan[role+'_restart'],receipt.parent,role)
        except Exception as exc:errors.append(dict(role=role,error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None))
    try:state['after_core_restore']=h.verify_restore(project,plan)
    except Exception as exc:errors.append(dict(role='core_health',code=str(exc) if isinstance(exc,ValueError) else type(exc).__name__))
    if not errors:
        try:
            if plan.get('reviewed_proxy'):h.check_sources(plan['reviewed_proxy'])
            for task in reversed(state.get('disabled_tasks',[])):h.task_change(task,True)
            if 'proxy' in attempted:state['proxy_restore']=h.restore_reviewed_proxy(project,plan['reviewed_proxy'])
            state['after_restore']=h.verify_restore(project,plan)
            with h.product_reader(project) as db:after=h.cursors(db)
            verify_cursors(state.get('frozen_cursors',{}),after);state['cursors_after_restore']=after
            restored=h.inventory(project)['tasks']
            for task in state.get('disabled_tasks',[]):
                same=[t for t in restored if h.key(t)==h.key(task)]
                if len(same)!=1 or not same[0]['Enabled'] or same[0]['Actions']!=task['Actions']:
                    raise ValueError('SCHEDULED_TASK_RESTORE_NOT_VERIFIED')
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
    state=dict(status='RELEASE_PREFLIGHT',before=before,steps=[],restore_failures=[],disabled_tasks=[],attempted_roles=[])
    atomic_json(receipt,state)
    if before['status']!='PREFLIGHT_READY':raise ValueError('RELEASE_PREFLIGHT_BLOCKED_SEND_RECEIPT')
    plan=before['restore_plan'];connection=None
    def record(stage):state['steps'].append(stage);atomic_json(receipt,state)
    def stop(group,role):
        state['attempted_roles'].append(group);record('STOPPING_'+group.upper());h.stop_role(project,role)
    try:
        state['stopping_started']=True;record('STOPPING_STARTED')
        for task in plan['task_restore']:
            state['disabled_tasks'].append(task);record('DISABLING_AUTOSTART');h.task_change(task,False)
        after=h.inventory(project)
        known={p['ProcessId']:p for p in before['inventory']['processes']}
        for process in h.project_processes(after,project):
            if not h.same_process(process,known.get(process['ProcessId'],{})):
                raise ValueError('PROJECT_PROCESS_CHANGED_WHILE_DISABLING_AUTOSTART')
        proxy=plan.get('reviewed_proxy',{}).get('task')
        if any(t['Enabled'] or t['State']=='Running' and (not proxy or h.key(t)!=h.key(proxy)) for t in after['tasks']):
            raise ValueError('UNREVIEWED_TASK_RUNNING_AFTER_AUTOSTART_DISABLE')
        if plan['active']['ad_worker'] or plan['active']['ad_web']:stop('ad','ad')
        connection=h.product_reader(project);deadline=time.monotonic()+900
        if plan['active']['viewer']:
            while not connection.execute('SELECT pg_try_advisory_lock(240026,2) AS held').fetchone()['held']:
                if time.monotonic()>deadline:raise TimeoutError('CURRENT_PUBLICATION_DID_NOT_DRAIN')
                print(json.dumps(dict(status='WAITING_FOR_CURRENT_PUBLICATION_COMMIT')),flush=True);time.sleep(2)
            stop('viewer','viewer')
        if plan['active']['viewer_web']:stop('viewer_web','web')
        if plan.get('reviewed_proxy'):
            state['attempted_roles'].append('proxy');record('STOPPING_PROXY');h.stop_reviewed_proxy(project,plan['reviewed_proxy'])
        state['frozen_cursors']=h.cursors(connection);connection.close();connection=None
        with __import__('psycopg').connect(**h.parameters(project),dbname='postgres',autocommit=True) as admin:h.assert_idle(admin)
        h.wait_for_quiescence(project,plan)
        state.update(status='PREPARED_FOR_MAIN_UPDATE',prepared_ns=time.time_ns());record('PROJECT_QUIESCENCE_VERIFIED')
    except BaseException:
        if connection is not None:connection.close()
        restore(project,receipt,state);raise
    return state


def scope_command(project,receipt,state,action,max_seconds):
    """Long child with durable files and a bounded graceful/hard cancellation.

    Popen handles pin the child identity; no PID search/kill. The child's server
    statement timeout bounds PostgreSQL work even after a hard process stop.
    """
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.Run_Viewer_Index_Probe_UTF8 import utf8_environment
    token=__import__('uuid').uuid4().hex
    progress=receipt.parent/'scope-progress.json';cancel=receipt.parent/('scope-cancel-'+token+'.json');output=receipt.parent/'scope-command.log'
    command=[sys.executable,'-B',str(project/'viewer_performance/Behavior_Control.py'),action,'--project',str(project),
        '--progress',str(progress),'--cancel-file',str(cancel),'--max-seconds',str(max_seconds),'--command-token',token]
    with output.open('ab') as log:
        child=subprocess.Popen(command,cwd=project,env=utf8_environment(),stdout=log,stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))
        state['scope_command']=dict(pid=child.pid,action=action,started_ns=time.time_ns(),max_seconds=max_seconds,
                                    progress_file=progress.name,log_file=output.name)
        atomic_json(receipt,state);deadline=time.monotonic()+max_seconds
        try:
            while child.poll() is None:
                if time.monotonic()>=deadline:raise TimeoutError('SCOPE_COMMAND_TIME_BUDGET_EXHAUSTED')
                time.sleep(.25)
        except BaseException:
            atomic_json(cancel,dict(requested_ns=time.time_ns()))
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:hard_stop_scope_python(progress,token)
                finally:
                    if child.poll() is None:child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=10)
            raise
        state['scope_command'].update(return_code=child.returncode,finished_ns=time.time_ns());atomic_json(receipt,state)
        if child.returncode:raise ValueError('BEHAVIOR_SCOPE_CHANGE_FAILED_SEND_PROGRESS')
    if not scope_ready(__import__('viewer_performance.financial_screen.host',fromlist=['host']),project):
        raise ValueError('SCOPE_COMMAND_FINISHED_WITH_INCOMPLETE_REPAIR')


def hard_stop_scope_python(progress,token):
    """Windows venv Popen may own a redirector, not the actual Python process.

    A nonce-bound progress receipt plus a pinned native process handle verifies
    the real child before termination. A stale PID never authorizes a stop.
    """
    if os.name!='nt':return
    from viewer_performance.Stop_Viewer_Worker import WindowsProcess
    value=json.loads(progress.read_text(encoding='utf-8'))
    if value.get('command_token')!=token or not value.get('process_created_epoch_seconds'):
        raise ValueError('SCOPE_CHILD_STOP_IDENTITY_UNVERIFIED')
    handle=WindowsProcess(value['process_pid'],allow_stop=True)
    try:
        normal=lambda p:os.path.normcase(os.path.normpath(str(p)))
        images={normal(sys.executable),normal(getattr(sys,'_base_executable',sys.executable))}
        if normal(handle.image) not in images or abs(handle.created.timestamp()-value['process_created_epoch_seconds'])>.02:
            raise ValueError('SCOPE_CHILD_STOP_PROCESS_REPLACED')
        handle.terminate()
    finally:handle.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,default=Path.cwd());parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--reviewed-preflight',type=Path)
    parser.add_argument('--action',choices=('prepare-update','benchmark-install','install','rollback','restore','resume-rollback','enable-after-repair','cleanup-copies'),required=True)
    parser.add_argument('--max-seconds',type=int,default=21600)
    args=parser.parse_args(argv);project=args.project.resolve();receipt=args.receipt.resolve()
    sys.path.insert(0,str(project));receipt.parent.mkdir(parents=True,exist_ok=True)
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.financial_screen import host as h
    state=None
    try:
        with controller_inventory(h,project):
            if args.action=='prepare-update':
                if receipt.exists():raise ValueError('USE_NEW_RELEASE_RECEIPT_PATH')
                state=prepare(project,receipt,args.reviewed_preflight)
            else:
                state=json.loads(receipt.read_text(encoding='utf-8-sig'))
                if args.action=='cleanup-copies':
                    import psycopg
                    from psycopg.rows import dict_row
                    from viewer_performance.behavior_resources import CopyOwner
                    with psycopg.connect(**h.parameters(project),dbname='postgres',autocommit=True,row_factory=dict_row) as admin:
                        failures=CopyOwner.recover(admin,receipt.parent/'allocations.json')
                    state['copy_cleanup_failures']=failures;atomic_json(receipt,state)
                    if failures:raise ValueError('COPY_CLEANUP_INCOMPLETE_NO_FORCE_DROP')
                elif args.action=='restore':restore(project,receipt,state)
                else:
                    recovery=args.action in ('resume-rollback','enable-after-repair')
                    if state['status']!=('RESTORING_FULL_SUPERVISORS_LEFT_DISABLED' if recovery else 'PREPARED_FOR_MAIN_UPDATE'):
                        raise ValueError('FROZEN_UPDATE_OR_REPAIR_RECEIPT_REQUIRED')
                    from tools.check_viewer_install import verify_release
                    if verify_release(project)['status']!='PASS':raise ValueError('NEW_INSTALLATION_MANIFEST_FAILED')
                    cpu={};plan=state['before']['restore_plan'];guard_lock=threading.Lock()
                    def guard():
                        # Phase and backend samplers share the idle-CPU cursor.
                        # Serialize inventories so a late sample cannot move
                        # that identity/CPU receipt backwards across threads.
                        with guard_lock:h.assert_quiescent(project,h.inventory(project),plan,cpu)
                    try:
                        guard()
                        with h.product_reader(project) as db:
                            if h.cursors(db)!=state['frozen_cursors']:raise ValueError('PRODUCT_CURSORS_CHANGED_DURING_UPGRADE')
                        if args.action=='benchmark-install':
                            from viewer_performance.behavior_benchmark import run
                            result=run(project,receipt.parent,guard,lambda v:print(json.dumps(v),flush=True),max_seconds=args.max_seconds)
                            state['benchmark_status']=result['status'];atomic_json(receipt,state)
                            if result['status']!='LARGE_HISTORY_EQUIVALENCE_AND_CAPACITY_COMPLETE':raise ValueError('LARGE_HISTORY_BENCHMARK_INCOMPLETE')
                            guard()
                            with h.product_reader(project) as db:
                                if h.cursors(db)!=state['frozen_cursors']:raise ValueError('PRODUCT_CURSORS_CHANGED_DURING_BENCHMARK')
                        scope_command(project,receipt,state,'restore-full' if args.action in ('rollback','resume-rollback') else 'enable',args.max_seconds)
                    finally:restore(project,receipt,state)
        print(json.dumps(dict(status=state['status'],receipt=str(receipt))),flush=True);return 0
    except BaseException as exc:
        if state:
            state['failure']=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None)
            atomic_json(receipt,state)
        print(json.dumps(dict(status='BEHAVIOR_RELEASE_INCOMPLETE',receipt=str(receipt),error_type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None)),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
