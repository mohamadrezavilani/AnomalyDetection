"""Windows maintenance with a durable restore plan and fail-closed inventory.

Product connections in this module are READ ONLY, apart from session advisory
locks. Experiments in experiment.py open only postgres and their new databases.
Unknown services, running scheduled tasks, collectors and frontends block the
preflight; they are never killed or given a guessed restart command.
"""
import base64
from contextlib import contextmanager
from datetime import datetime,timezone
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
import uuid

from p24_foundation.viewer_runtime import atomic_json
from viewer_performance.writer_identity import LEASE_SQL,read_identity
from viewer_performance.fast_writer import verify_sources,BUILD
from viewer_performance.Qualify_Capacity_Candidate import literal_database
from .experiment import assert_idle


INVENTORY=r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$root=$env:P24_SCREEN_PROJECT_ROOT
$needle=[regex]::Escape($root)
$processes=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine)
$tasks=@(Get-ScheduledTask | Where-Object {
    (($_.Actions | ForEach-Object { $_.Execute+' '+$_.Arguments+' '+$_.WorkingDirectory }) -join ' ') -match ($needle+'|Run_Viewer|run_anomaly|run_behavior_viewer|observe_viewer|Qualify_Viewer|Screen_Financial')
} | ForEach-Object {
    [pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;State=[string]$_.State;
        Enabled=$_.Settings.Enabled;Actions=@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)}
})
$services=@(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $needle } |
    Select-Object Name,State,StartMode,ProcessId,PathName)
$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
    $_.LocalPort -in @(5021,5022) } | Select-Object LocalAddress,LocalPort,OwningProcess)
[pscustomobject]@{processes=$processes;tasks=$tasks;services=$services;listeners=$listeners} | ConvertTo-Json -Depth 8 -Compress
'''


class HostOperationError(ValueError):
    def __init__(self,code,details):super().__init__(code);self.details=details


def powershell(code,environment=None):
    encoded=base64.b64encode(code.encode('utf-16le')).decode('ascii')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
        env={**os.environ,**(environment or {})},capture_output=True,encoding='utf-8-sig',timeout=30)
    if result.returncode:raise HostOperationError('WINDOWS_INVENTORY_OR_TASK_OPERATION_FAILED',
        dict(exit_code=result.returncode,stderr=(result.stderr or '')[-4096:]))
    return json.loads(result.stdout) if result.stdout.strip() else None


def inventory(project):
    if os.name!='nt':raise ValueError('WINDOWS_OWNER_HOST_REQUIRED')
    return powershell(INVENTORY,{'P24_SCREEN_PROJECT_ROOT':str(project)})


def command(project,script,*arguments):
    process=subprocess.run([sys.executable,'-B',str(project/script),*map(str,arguments)],
        cwd=project,capture_output=True,encoding='utf-8-sig',timeout=90)
    try:result=json.loads(process.stdout)
    except (ValueError,TypeError):raise HostOperationError('CONTROL_COMMAND_JSON_UNAVAILABLE:'+script,
        dict(exit_code=process.returncode,stderr=(process.stderr or '')[-4096:],stdout=(process.stdout or '')[-4096:])) from None
    return result,process.returncode


def parameters(project):
    config=literal_database(project)
    return {k:v for k,v in config.items() if k in ('host','port','user','password','connect_timeout')}


def product_reader(project):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(**parameters(project),dbname='p24_design_viewer',autocommit=True,
        row_factory=dict_row,application_name='P24.ScopeScreen.ReadOnlyControl',
        options='-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=100')


def cursors(connection):
    result={}
    for name in ('viewer_live_state','public.viewer_history_replay_state','anomaly_detection.adp_state'):
        exists=connection.execute('SELECT to_regclass(%s) AS relation',(name,)).fetchone()['relation']
        if exists:
            # These are small control tables, not evidence/model/feedback scans.
            rows=connection.execute('SELECT * FROM '+name+' LIMIT 513').fetchall()
            if len(rows)>512:raise ValueError('CONTROL_SNAPSHOT_ROW_BUDGET_EXCEEDED')
            result[name]=sorted([dict(r) for r in rows],key=lambda row:json.dumps(row,sort_keys=True))
    return result


def project_processes(snapshot,project):
    needle=str(project).replace('/','\\').lower()
    pattern=r'(run_viewer|run_anomaly|run_behavior_viewer|observe_viewer|qualify_viewer|collect_capacity|screen_financial|financial_screen|benchmark_history)'
    return [p for p in snapshot['processes'] if needle in (p.get('CommandLine') or '').replace('/','\\').lower()
        or re.search(pattern,p.get('CommandLine') or '',re.I)]


def own_process_ids(snapshot):
    result={os.getpid()}
    current=next((p for p in snapshot['processes'] if int(p['ProcessId'])==os.getpid()),None)
    parent=next((p for p in snapshot['processes'] if current and int(p['ProcessId'])==int(current.get('ParentProcessId',0))),None)
    if parent and (parent.get('ExecutablePath') or '').lower().endswith(('python.exe','pythonw.exe')) and 'screen_financial_product.py' in (parent.get('CommandLine') or '').lower():
        result.add(int(parent['ProcessId']))
    return result


def make_plan(project,snapshot,ad,viewer,web,identity):
    """Pure inventory policy; unknown ownership must be resolved before stop."""
    issues=[];active={};owners={}
    if ad.get('diagnostic_failures'):issues.append('AD_PROCESS_IDENTITY_NOT_VERIFIED')
    for role,part in (('ad_worker',ad.get('process',{})),('ad_web',ad.get('web',{}))):
        active[role]=bool(part.get('locked'))
        if active[role]:
            owner=part.get('owner') or {}
            if not owner.get('pid') or not owner.get('instance_token'):issues.append('AD_OWNER_INCOMPLETE:'+role)
            else:owners[role]=int(owner['pid'])
    active['viewer']=viewer.get('status')=='VIEWER_WORKER_IDENTIFIED'
    if viewer.get('status') not in ('VIEWER_WORKER_IDENTIFIED','NO_VIEWER_LOCK_OWNER_OBSERVED'):
        issues.append('VIEWER_WORKER_NOT_VERIFIED')
    if active['viewer']:
        owners['viewer']=viewer['python_pid']
        if not identity or identity.get('implementation_build')!=BUILD or identity.get('implementation_source_sha256')!=verify_sources():
            issues.append('UNSUPPORTED_WRITER_RESTORE_IDENTITY')
    active['viewer_web']=web.get('status')=='VIEWER_WEB_IDENTIFIED'
    if web.get('status') not in ('VIEWER_WEB_IDENTIFIED','NO_VIEWER_WEB_LISTENER'):issues.append('VIEWER_WEB_NOT_VERIFIED')
    if active['viewer_web']:owners['viewer_web']=web['python_pid']
    processes={int(p['ProcessId']):p for p in snapshot['processes']}
    allowed=set(owners.values())|own_process_ids(snapshot)
    # Windows venv redirectors can be parents of the verified real Python PID.
    for pid in list(allowed):
        child=processes.get(pid)
        if not child:continue
        parent=processes.get(int(child.get('ParentProcessId',0)))
        if parent and (parent.get('ExecutablePath') or '').lower().endswith(('python.exe','pythonw.exe')):
            if any(tag in (parent.get('CommandLine') or '').lower() for tag in ('run_viewer','run_anomaly')):allowed.add(int(parent['ProcessId']))
    for p in project_processes(snapshot,project):
        if int(p['ProcessId']) not in allowed:
            # The invoking PowerShell script is an idle controller ancestor.
            commandline=(p.get('CommandLine') or '').lower()
            if 'invoke_financial_screen.ps1' not in commandline:issues.append('UNCONTROLLED_PROJECT_PROCESS:'+str(p['ProcessId']))
    for p in snapshot['listeners']:
        if int(p['OwningProcess']) not in allowed:
            issues.append('FRONTEND_STOP_AND_RESTORE_PLAN_REQUIRED:'+str(p['OwningProcess']))
    for s in snapshot['services']:
        if s['State']=='Running' or s['StartMode']=='Auto':issues.append('PROJECT_SERVICE_RESTORE_PLAN_REQUIRED:'+s['Name'])
    for task in snapshot['tasks']:
        if task['State']=='Running':issues.append('RUNNING_SCHEDULED_TASK_RESTORE_PLAN_REQUIRED:'+task['Name'])
    if not all(pid in processes for pid in owners.values()):issues.append('OWNED_PROCESS_DISAPPEARED')
    return dict(active=active,owners=owners,issues=sorted(set(issues)),
        ad_identities={role:(ad.get('process' if role=='ad_worker' else 'web',{}).get('owner') or {})
            for role in ('ad_worker','ad_web')},
        viewer_restart=['viewer_performance/Run_Viewer_Fast.py','--trial'],
        viewer_web_restart=['viewer_performance/Run_Viewer_Web.py','--host','127.0.0.1'],
        ad_worker_restart=['AnomalyDetection/run_anomaly.py','worker-start'],
        ad_web_restart=['AnomalyDetection/run_anomaly.py','web-run'],
        task_restore=[t for t in snapshot['tasks'] if t['Enabled']])


def preflight(project):
    project=Path(project).resolve();verify_sources(project)
    from tools.check_viewer_install import verify_release
    release=verify_release(project)
    if release['status']!='PASS':raise HostOperationError('SCOPE_SCREEN_SOURCE_INVENTORY_MISMATCH',release)
    snapshot=inventory(project)
    ad,_=command(project,'AnomalyDetection/run_anomaly.py','worker-status')
    ad_version,version_code=command(project,'AnomalyDetection/run_anomaly.py','version')
    viewer,_=command(project,'viewer_performance/Stop_Viewer_Worker.py')
    web,_=command(project,'viewer_performance/Stop_Viewer_Web.py')
    identity=None
    with product_reader(project) as connection:
        leases=[dict(r) for r in connection.execute(LEASE_SQL).fetchall()]
        if leases:
            try:identity=read_identity(project,leases)
            except ValueError:pass
        before=cursors(connection)
        sessions=[dict(r) for r in connection.execute("""SELECT pid,backend_start,application_name,state,
            xact_start,client_port FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()""").fetchall()]
    plan=make_plan(project,snapshot,ad,viewer,web,identity)
    for part in ('process','web'):
        if ad.get(part,{}).get('locked') and (version_code or
                ad[part].get('owner',{}).get('source_sha256')!=ad_version.get('source_sha256')):
            plan['issues'].append('AD_RELEASE_DIFFERS_FROM_ACTIVE_ROLE:'+part)
    result=dict(status='PREFLIGHT_BLOCKED' if plan['issues'] else 'PREFLIGHT_READY',
        inventory=snapshot,restore_plan=plan,ad=ad,ad_release=ad_version,source_inventory=release,viewer=viewer,viewer_web=web,
        writer_identity=identity,cursors_before=before,postgres_sessions=sessions,
        database_modified=False,workers_stopped=False)
    return json.loads(json.dumps(result,default=lambda value:value.isoformat() if hasattr(value,'isoformat') else str(value)))


def task_change(task,enabled):
    verb='Enable-ScheduledTask' if enabled else 'Disable-ScheduledTask'
    # Arguments are passed through environment data, never interpolated as code.
    code="$ErrorActionPreference='Stop'; "+verb+" -TaskName $env:P24_SCREEN_TASK_NAME -TaskPath $env:P24_SCREEN_TASK_PATH | Out-Null"
    powershell(code,{'P24_SCREEN_TASK_NAME':task['Name'],'P24_SCREEN_TASK_PATH':task['Path']})


def stop_role(project,role):
    if role=='ad':script='AnomalyDetection/run_anomaly.py';args=('worker-stop',);done=('STOPPED','ALREADY_STOPPED');pending=('STOP_REQUESTED',)
    elif role=='viewer':script='viewer_performance/Stop_Viewer_Worker.py';args=('--stop',);done=('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED');pending=('VIEWER_BACKEND_STOP_PENDING',)
    else:script='viewer_performance/Stop_Viewer_Web.py';args=('--stop',);done=('VIEWER_WEB_STOPPED','NO_VIEWER_WEB_LISTENER');pending=()
    for _ in range(12):
        result,code=command(project,script,*args)
        if result.get('status') in done and code==0:return result
        if result.get('status') not in pending:raise ValueError('CONTROLLED_STOP_BLOCKED:'+role+':'+str(result.get('status')))
        time.sleep(1)
    raise ValueError('CONTROLLED_STOP_TIMEOUT:'+role)


def start_process(project,args,logs,role):
    output=(logs/(role+'.log')).open('ab')
    try:
        child=subprocess.Popen([sys.executable,'-B',str(project/args[0]),*args[1:]],cwd=project,
            stdout=output,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))
        return child.pid
    finally:output.close()


@contextmanager
def maintenance(project,before,directory,notice=lambda value:None):
    """Persist each completed step so a failed restore has a concrete record."""
    if before['status']!='PREFLIGHT_READY':raise ValueError('PREFLIGHT_MUST_PASS_BEFORE_STOP')
    plan=before['restore_plan'];state=dict(status='MAINTENANCE_PREPARED',before=before,steps=[],restore=[],restore_failures=[])
    receipt=directory/'maintenance.json';atomic_json(receipt,state)
    disabled=[];attempted=set();connection=None;fenced=False
    def record(stage,value=None):
        state['steps'].append(dict(stage=stage,result=value));atomic_json(receipt,state);notice(dict(status=stage))
    try:
        for task in plan['task_restore']:
            disabled.append(task);task_change(task,False);record('AUTOSTART_DISABLED',dict(name=task['Name'],path=task['Path']))
        if plan['active']['ad_worker'] or plan['active']['ad_web']:
            attempted.add('ad');record('AD_STOPPED',stop_role(project,'ad'))
        connection=product_reader(project)
        # Acquire only after the current publication finishes. The next writer
        # cannot start another publication while the fence is held.
        until=time.monotonic()+900
        if plan['active']['viewer']:
            while not connection.execute('SELECT pg_try_advisory_lock(240026,2) AS held').fetchone()['held']:
                if time.monotonic()>until:raise ValueError('PUBLICATION_DID_NOT_FINISH_WITHIN_MAINTENANCE_BUDGET')
                notice(dict(status='WAITING_FOR_CURRENT_PUBLICATION_COMMIT'));time.sleep(2)
            fenced=True;record('CURRENT_PUBLICATION_FINISHED_AND_FENCED')
            attempted.add('viewer');record('VIEWER_STOPPED',stop_role(project,'viewer'))
        if plan['active']['viewer_web']:
            attempted.add('viewer_web');record('VIEWER_WEB_STOPPED',stop_role(project,'web'))
        state['frozen_cursors']=cursors(connection);atomic_json(receipt,state)
        connection.close();connection=None;fenced=False
        with __import__('psycopg').connect(**parameters(project),dbname='postgres',autocommit=True) as admin:
            assert_idle(admin)
        # Unknown replacement processes or observers also block measurement.
        after=inventory(project)
        residual=[p for p in project_processes(after,project) if int(p['ProcessId']) not in own_process_ids(after)
            and 'invoke_financial_screen.ps1' not in (p.get('CommandLine') or '').lower()]
        if residual:raise ValueError('PROJECT_PROCESS_REMAINS_AFTER_STOP')
        record('PROJECT_QUIESCENCE_VERIFIED');state['status']='EXCLUSIVE_TEST_RUNNING';atomic_json(receipt,state)
        yield state
        with product_reader(project) as check:
            if cursors(check)!=state['frozen_cursors']:raise ValueError('PRODUCT_CURSORS_CHANGED_DURING_ISOLATED_TEST')
        record('FROZEN_PRODUCT_CURSORS_UNCHANGED')
    finally:
        if connection is not None:
            if fenced:connection.execute('SELECT pg_advisory_unlock(240026,2)')
            connection.close()
        # Restore only roles that were active. A failed stop may already have
        # exited; verified start tools reject duplicate workers.
        for role in ('viewer_web','ad_worker','ad_web','viewer'):
            if not plan['active'][role]:continue
            group='ad' if role.startswith('ad_') else role
            if group not in attempted:continue
            if role=='ad_web' and plan['active']['ad_worker']:continue
            try:
                if role=='ad_worker':
                    result,code=command(project,*plan['ad_worker_restart'])
                    if code or result.get('status') not in ('STARTED','STARTING','ALREADY_RUNNING'):raise ValueError('AD_RESTORE_NOT_CONFIRMED')
                    state['restore'].append(dict(role=role,result=result))
                else:
                    # Reinspection prevents duplicating a process after a
                    # stop command reported a failure without stopping it.
                    if role in ('viewer','viewer_web'):
                        script='viewer_performance/Stop_Viewer_Worker.py' if role=='viewer' else 'viewer_performance/Stop_Viewer_Web.py'
                        current,_=command(project,script)
                        identified='VIEWER_WORKER_IDENTIFIED' if role=='viewer' else 'VIEWER_WEB_IDENTIFIED'
                        if current.get('status')==identified:
                            state['restore'].append(dict(role=role,result='ALREADY_ACTIVE'));continue
                    if role=='ad_web':
                        current,_=command(project,'AnomalyDetection/run_anomaly.py','worker-status')
                        if current.get('web',{}).get('locked'):
                            state['restore'].append(dict(role=role,result='ALREADY_ACTIVE'));continue
                    pid=start_process(project,plan[role+'_restart'],directory,role)
                    state['restore'].append(dict(role=role,launcher_pid=pid))
            except Exception as exc:state['restore_failures'].append(dict(role=role,error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None))
            atomic_json(receipt,state)
        for task in reversed(disabled):
            try:task_change(task,True)
            except Exception as exc:state['restore_failures'].append(dict(role='scheduled_task',name=task['Name'],error_type=type(exc).__name__))
        try:
            state['after_restore']=verify_restore(project,plan)
            with product_reader(project) as check:
                state['cursors_after_restore']=cursors(check)
            frozen=state.get('frozen_cursors',{})
            live=frozen.get('viewer_live_state',[]);after=state['cursors_after_restore'].get('viewer_live_state',[])
            if live and after:
                if any(live[0].get(k)!=after[0].get(k) for k in ('start_ns','stream_key','keys_fingerprint')) or any(after[0][k]<live[0][k] for k in ('next_ns','generation')):
                    raise ValueError('VIEWER_CURSOR_REGRESSED_OR_STREAM_CHANGED')
            history='public.viewer_history_replay_state'
            old=frozen.get(history,[]);new=state['cursors_after_restore'].get(history,[])
            if old and (not new or any(old[0].get(k)!=new[0].get(k) for k in ('run_id','from_ns','end_ns','keys_fingerprint')) or new[0]['next_ns']<old[0]['next_ns']):
                raise ValueError('HISTORY_CURSOR_REGRESSED_OR_RUN_CHANGED')
            restored_tasks=inventory(project)['tasks']
            for task in disabled:
                same=[t for t in restored_tasks if t['Name']==task['Name'] and t['Path']==task['Path']]
                if len(same)!=1 or not same[0]['Enabled'] or same[0]['Actions']!=task['Actions']:
                    raise ValueError('SCHEDULED_TASK_RESTORE_NOT_VERIFIED')
        except Exception as exc:state['restore_failures'].append(dict(role='verify_restore',error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None))
        state['status']='RESTORE_INCOMPLETE' if state['restore_failures'] else 'PREVIOUS_ROLES_RESTORED'
        atomic_json(receipt,state);notice(dict(status=state['status'],output=str(receipt)))


def verify_restore(project,plan):
    last={};began=time.monotonic();until=began+90;web_repaired=False
    while time.monotonic()<until:
        ad,_=command(project,'AnomalyDetection/run_anomaly.py','worker-status')
        worker,_=command(project,'viewer_performance/Stop_Viewer_Worker.py')
        web,_=command(project,'viewer_performance/Stop_Viewer_Web.py')
        actual=dict(ad_worker=bool(ad.get('process',{}).get('locked')),ad_web=bool(ad.get('web',{}).get('locked')),
            viewer=worker.get('status')=='VIEWER_WORKER_IDENTIFIED',viewer_web=web.get('status')=='VIEWER_WEB_IDENTIFIED')
        last=dict(active=actual,ad=ad,viewer=worker,viewer_web=web)
        if actual==plan['active'] and (not actual['ad_worker'] or ad.get('observation_matches_process')):
            if actual['viewer']:
                try:
                    with product_reader(project) as connection:
                        identity=read_identity(project,[dict(r) for r in connection.execute(LEASE_SQL).fetchall()])
                    if identity['implementation_source_sha256']!=verify_sources():raise ValueError('RESTORED_WRITER_SOURCE_DIFFERS')
                except ValueError:time.sleep(1);continue
                last['writer_identity']=identity
            for role in ('ad_worker','ad_web'):
                if actual[role]:
                    owner=ad['process' if role=='ad_worker' else 'web'].get('owner') or {}
                    if owner.get('source_sha256')!=plan['ad_identities'][role].get('source_sha256'):
                        raise ValueError('RESTORED_AD_SOURCE_DIFFERS')
            return last
        if actual['ad_worker'] and plan['active']['ad_web'] and not actual['ad_web'] and not web_repaired and time.monotonic()-began>5:
            start_process(project,plan['ad_web_restart'],project/'AnomalyDetection/reports','scope-restored-ad-web');web_repaired=True
        # The existing AD worker starts its web once during initialization. If
        # it was previously stopped, stop that new web by its verified token.
        if actual['ad_worker'] and actual['ad_web'] and not plan['active']['ad_web']:
            owner=ad['web'].get('owner') or {}
            if owner.get('job')=='product_web' and owner.get('instance_token'):
                atomic_json(project/'AnomalyDetection/data/web_stop_request.json',dict(instance_token=owner['instance_token'],requested_at_ns=time.time_ns()))
        time.sleep(1)
    raise ValueError('RESTORED_PROCESS_HEALTH_OR_ROLES_NOT_VERIFIED')
