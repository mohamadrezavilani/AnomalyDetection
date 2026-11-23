"""Migrate a stopped, disabled, owned history task to an existing verified release.
Does not stop core roles, modify data, delete tasks, or change the history job range.
"""
import argparse
import json
import ntpath
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def worker_args(code, project, python):
    return subprocess.list2cmdline(['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',ntpath.join(code,'compact_product','History_Compact_Product.ps1'),
        '-Action','Worker','-Project',project,'-Python',python])


def validate_owner(snapshot, project, python):
    actions=snapshot.get('actions') or []
    if len(actions)!=1:
        raise ValueError('HISTORY_TASK_ACTION_COUNT_MISMATCH')
    action=actions[0]
    old=action.get('WorkingDirectory')
    if not old or not ntpath.isabs(old):
        raise ValueError('HISTORY_TASK_CODE_ROOT_REQUIRED')
    if (action.get('Execute','').lower()!='powershell.exe' or
        action.get('Arguments')!=worker_args(old,project,python)):
        raise ValueError('HISTORY_TASK_OWNERSHIP_MISMATCH')
    return old


def state_code(snapshot):
    # MSFT_ScheduledTask.State is a CIM UInt16 on some Windows hosts,
    # and an enum with a friendly string on others. Never infer from locale.
    value = snapshot.get('state_code', snapshot.get('state'))
    if type(value) is int:
        return value
    return {'Disabled': 1, 'Queued': 2, 'Ready': 3, 'Running': 4,
            '1': 1, '2': 2, '3': 3, '4': 4}.get(value)


def validate_task(snapshot, project, python):
    old = validate_owner(snapshot, project, python)
    if snapshot.get('enabled') is not False or state_code(snapshot) != 1:
        raise ValueError('HISTORY_TASK_MUST_BE_STOPPED_AND_DISABLED')
    return old


def wait_for_stopped_task(read, project, python, *, timeout=30,
                          clock=time.monotonic, sleep=time.sleep):
    """Worker lease has stopped; allow its PowerShell launcher to finish too.

    Never stop processes or weaken ownership/disabled checks. Revalidate every
    snapshot and fail closed if another controller changes the task.
    """
    deadline = clock() + timeout
    first_owner = None
    while True:
        snapshot = read()
        owner = validate_owner(snapshot, project, python)
        if first_owner is None:
            first_owner = owner
        if owner != first_owner:
            raise ValueError('HISTORY_TASK_OWNER_CHANGED_WHILE_WAITING')
        if snapshot.get('enabled') is not False:
            raise ValueError('HISTORY_TASK_MUST_BE_STOPPED_AND_DISABLED')
        if state_code(snapshot) == 1:
            validate_task(snapshot, project, python)
            return snapshot
        if state_code(snapshot) not in (2, 4):
            raise ValueError('HISTORY_TASK_MUST_BE_STOPPED_AND_DISABLED')
        if clock() >= deadline:
            raise TimeoutError('HISTORY_TASK_LAUNCHER_STILL_RUNNING')
        sleep(0.5)


SNAPSHOT = r'''
$ErrorActionPreference='Stop'
$t=Get-ScheduledTask -TaskName 'P24-CompactHistory' -ErrorAction Stop
@{actions=@($t.Actions | Select-Object Execute,Arguments,WorkingDirectory);enabled=[bool]$t.Settings.Enabled;state=[string]$t.State;state_code=[int]$t.State;xml=(Export-ScheduledTask -TaskName 'P24-CompactHistory')} | ConvertTo-Json -Depth 6 -Compress
'''

CHANGE = r'''
$ErrorActionPreference='Stop'
$t=Get-ScheduledTask -TaskName 'P24-CompactHistory' -ErrorAction Stop
$a=@($t.Actions)
if($a.Count -ne 1 -or $a[0].Execute -ne 'powershell.exe' -or $a[0].Arguments -cne $env:P24_OLD_ARGS -or $a[0].WorkingDirectory -cne $env:P24_OLD_ROOT){throw 'History task changed since inspection'}
if($t.Settings.Enabled -or [int]$t.State -ne 1){throw 'History task must remain disabled'}
$new=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $env:P24_NEW_ARGS -WorkingDirectory $env:P24_NEW_ROOT
Set-ScheduledTask -TaskName 'P24-CompactHistory' -Action $new | Out-Null
@{status='HISTORY_TASK_ACTION_MIGRATED'} | ConvertTo-Json -Compress
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--code-root',type=Path,required=True)
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--expected-from')
    parser.add_argument('--resume-existing', action='store_true',
                        help='Require the existing task to belong to this very release')
    args=parser.parse_args()
    project=args.project.resolve();root=args.code_root.resolve()
    sys.path.insert(0,str(root))
    from compact_product.version import verify
    from compact_product.operations import require_windows_admin
    from compact_product.history import control
    from compact_behavior.extract import instant, iso
    from viewer_performance.financial_screen.host import powershell
    from viewer_performance.Diagnose_Three_Modes import controller_lock
    require_windows_admin()
    verify(root)
    report=project/'AnomalyDetection'/'reports'/('Compact_History_Task_Repair_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    report.parent.mkdir(parents=True,exist_ok=True)
    result={'status':'PREPARING','core_roles_restarted':False,'data_reset':False}
    migrated=False
    def mark(stage):
        result['stage']=stage
        print(json.dumps(dict(status='COMPACT_HISTORY_REPAIR_PROGRESS',stage=stage)),flush=True)
    with controller_lock(project):
        try:
            mark('CHECKING_EXISTING_HISTORY')
            state=control(project,'status')
            before=json.loads(Path(state['output']).read_text(encoding='utf-8'))
            if before.get('history_role',{}).get('running'):
                raise ValueError('HISTORY_WORKER_STILL_RUNNING')
            def read_snapshot():
                current = powershell(SNAPSHOT)
                result['task_snapshot'] = {k: v for k, v in current.items() if k != 'xml'}
                return current
            mark('CHECKING_DISABLED_TASK')
            snapshot=wait_for_stopped_task(read_snapshot,str(project),sys.executable)
            old=validate_task(snapshot,str(project),sys.executable)
            if not (Path(old)/'compact_product/History_Compact_Product.ps1').is_file():
                raise ValueError('PREVIOUS_HISTORY_SCRIPT_MISSING')
            job=before.get('job')
            if not job or job['state']=='COMPLETE':
                raise ValueError('ACTIVE_HISTORY_JOB_REQUIRED')
            if args.expected_from and instant(args.expected_from) != job['from_ns']:
                raise ValueError('HISTORY_RANGE_CHANGED')
            if args.resume_existing and Path(old).resolve() != root:
                raise ValueError('PREVIOUS_HISTORY_TASK_ROOT_CHANGED')
            result.update(previous_code_root=old,new_code_root=str(root),before=job)
            backup=report.with_suffix('.task.xml')
            backup.write_text(snapshot['xml'],encoding='utf-8')
            result['task_backup']=str(backup)
            if args.check_only:
                result['status']='HISTORY_TASK_MIGRATION_CHECKED_NO_CHANGE'
            else:
                if Path(old).resolve() != root:
                    mark('MIGRATING_TASK_ACTION')
                    powershell(CHANGE,dict(P24_OLD_ARGS=snapshot['actions'][0]['Arguments'],P24_OLD_ROOT=old,
                        P24_NEW_ARGS=worker_args(str(root),str(project),sys.executable),P24_NEW_ROOT=str(root)))
                    migrated=True
                mark('STARTING_EXISTING_HISTORY')
                outcome=control(project,'install',from_value=iso(job['from_ns']))
                after=json.loads(Path(outcome['output']).read_text(encoding='utf-8'))
                next_job=after['job']
                if (any(next_job[k] != job[k] for k in ('job_id','from_ns','target_ns'))
                        or next_job['next_ns'] < job['next_ns']):
                    raise ValueError('HISTORY_CHECKPOINT_MISMATCH')
                result.update(status='COMPACT_HISTORY_TASK_REPAIRED_AND_STARTED',after=next_job,
                    history_role=after['history_role'],history_status_report=outcome['output'])
        except Exception as exc:
            result.update(status='COMPACT_HISTORY_TASK_REPAIR_INCOMPLETE',task_action_migrated=migrated,
                failure=dict(type=type(exc).__name__,code=str(exc),details=getattr(exc,'details',None)))
            # Preserve the migrated task and original XML for inspection. Never
            # overwrite another task or attempt a second unverified migration.
        report.write_text(json.dumps(result,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],output=str(report),failure=result.get('failure')),ensure_ascii=True),flush=True)
    return 0 if result['status'] in ('COMPACT_HISTORY_TASK_REPAIRED_AND_STARTED','HISTORY_TASK_MIGRATION_CHECKED_NO_CHANGE') else 2


if __name__=='__main__':
    raise SystemExit(main())
