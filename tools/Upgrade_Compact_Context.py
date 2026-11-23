"""Upgrade core, then migrate the owned history task; never rewind either cursor."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import queue
import threading
from contextlib import contextmanager


@contextmanager
def context_lock(project):
    path=project/'AnomalyDetection/reports/Compact_Context_Controller.lock'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as file:
        file.seek(0)
        if sys.platform=='win32':
            import msvcrt
            if path.stat().st_size==0:file.write(b'0');file.flush();file.seek(0)
            msvcrt.locking(file.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:
            if sys.platform=='win32':file.seek(0);msvcrt.locking(file.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(file.fileno(),fcntl.LOCK_UN)


def run(args, cwd):
    child=subprocess.Popen([sys.executable,'-X','utf8','-u','-B',*map(str,args)],cwd=cwd,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
    packets=queue.Queue(maxsize=64);done=threading.Event()
    def read():
        try:
            while True:
                line=child.stdout.readline(65537)
                if not line:break
                if len(line)>65536:continue
                try:value=json.loads(line)
                except ValueError:continue
                if isinstance(value,dict):
                    while not done.is_set():
                        try:packets.put(value,timeout=.2);break
                        except queue.Full:pass
        finally:
            child.stdout.close()
    thread=threading.Thread(target=read,daemon=True);thread.start()
    began=last=time.monotonic();value=None
    try:
        while child.poll() is None or thread.is_alive() or not packets.empty():
            try:
                value=packets.get(timeout=.2)
                print(json.dumps(value,ensure_ascii=True),flush=True)
            except queue.Empty:pass
            now=time.monotonic()
            if now-last>=10:
                print(json.dumps(dict(status='COMPACT_UPGRADE_WAITING',elapsed_seconds=round(now-began))),flush=True);last=now
            if now-began>900:
                # Terminate only this controller child, not any product worker.
                # Its state is unknown: the caller must not start a rollback loop.
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
                return 2,dict(status='CONTROLLER_TIMEOUT_STATE_REQUIRES_REVIEW')
        return child.wait(), value or dict(status='COMMAND_DID_NOT_RETURN_JSON')
    finally:
        done.set();thread.join(1)


def upgrade(project, root, old, history, sha, *, execute=run):
    report=dict(status='PREPARING',data_reset=False,steps=[])
    def step(name,args,cwd):
        print(json.dumps(dict(status='COMPACT_CONTEXT_UPGRADE_PROGRESS',stage=name)),flush=True)
        try:
            code,result=execute(args,cwd)
        except Exception as exc:
            report['steps'].append(dict(step=name,failure_type=type(exc).__name__))
            report['status']='COMPACT_CONTEXT_UPGRADE_INCOMPLETE'
            return None
        report['steps'].append(dict(step=name,exit_code=code,result=result))
        if code:
            report['status']='COMPACT_CONTEXT_UPGRADE_INCOMPLETE'
            return None
        return result
    previous=step('previous_package',['-m','compact_product','version'],old)
    if previous is None:return report
    before=step('history_status',['-m','compact_product','history-status','--project',project],history)
    if before is None:return report
    preflight=step('candidate_preflight',[root/'tools/Upgrade_Compact_Product.py','--action','preflight',
        '--project',project,'--code-root',root,'--old-code-root',old,'--expected-source-sha',sha],root)
    if preflight is None:return report
    active=before.get('history_state') in ('ACTIVE','SOURCE_COMPLETE')
    if active:
        stopped=step('history_stop',['-m','compact_product','history-stop','--project',project],history)
        if stopped is None:return report
        checked=step('history_launcher_drain',[root/'tools/Repair_Compact_History_Task.py',
            '--project',project,'--code-root',history,'--check-only'],history)
        if checked is None:return report
    core=step('core_upgrade',[root/'tools/Upgrade_Compact_Product.py','--project',project,'--code-root',root,'--old-code-root',old,'--expected-source-sha',sha],root)
    if core is None:
        last=report['steps'][-1].get('result',{}).get('status')
        if active and last in ('COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED','COMPACT_UPGRADE_FAILED'):
            if old != history and before.get('from_utc'):
                step('previous_history_resume',['-m','compact_product','history-install',
                     '--project',project,'--history-from',before['from_utc']],history)
            else:
                step('previous_history_resume',[root/'tools/Upgrade_Compact_Product.py','--action','resume-history',
                    '--project',project,'--code-root',history,'--old-code-root',old,
                    '--expected-source-sha',previous['source_sha256']],history)
        return report
    if before.get('history_state')=='COMPLETE':
        report['status']='COMPACT_CONTEXT_CORE_UPGRADED_HISTORY_ALREADY_COMPLETE';return report
    if before.get('history_state') not in ('ACTIVE','SOURCE_COMPLETE'):
        report['status']='COMPACT_CONTEXT_CORE_UPGRADED_NO_ACTIVE_HISTORY';return report
    migrated=step('history_migration',[root/'tools/Repair_Compact_History_Task.py','--project',project,'--code-root',root],root)
    if migrated is None:return report  # Preserve guarded migration receipt; no blind rollback of another task.
    report['status']='COMPACT_CONTEXT_CORE_AND_HISTORY_UPGRADED'
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','code-root','old-code-root','history-code-root'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--expected-source-sha',required=True);a=p.parse_args()
    project=a.project.resolve();root=a.code_root.resolve()
    folder=project/'AnomalyDetection/reports';folder.mkdir(parents=True,exist_ok=True)
    output=folder/('Compact_Context_Upgrade_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    try:
        with context_lock(project):
            result=upgrade(project,root,a.old_code_root.resolve(),a.history_code_root.resolve(),a.expected_source_sha)
    except Exception as exc:result=dict(status='COMPACT_CONTEXT_UPGRADE_INCOMPLETE',failure_type=type(exc).__name__)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],output=str(output),data_reset=False)),flush=True)
    return 2 if result['status'].endswith('INCOMPLETE') else 0

if __name__=='__main__':raise SystemExit(main())
