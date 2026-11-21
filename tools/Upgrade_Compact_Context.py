"""Upgrade core, then migrate the owned history task; never rewind either cursor."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def run(args, cwd):
    completed=subprocess.run([sys.executable,'-X','utf8','-B',*map(str,args)],cwd=cwd,capture_output=True,text=True,encoding='utf-8',timeout=600)
    value=None
    for line in completed.stdout.splitlines():
        try: value=json.loads(line)
        except ValueError: pass
    return completed.returncode, value or dict(status='COMMAND_DID_NOT_RETURN_JSON')


def upgrade(project, root, old, history, sha, *, execute=run):
    report=dict(status='PREPARING',data_reset=False,steps=[])
    def step(name,args,cwd):
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
    before=step('history_status',['-m','compact_product','history-status','--project',project],history)
    if before is None:return report
    core=step('core_upgrade',[root/'tools/Upgrade_Compact_Product.py','--project',project,'--code-root',root,'--old-code-root',old,'--expected-source-sha',sha],root)
    if core is None:return report  # Existing core tool restores old roles; history untouched.
    if before.get('history_state')=='COMPLETE':
        report['status']='COMPACT_CONTEXT_CORE_UPGRADED_HISTORY_ALREADY_COMPLETE';return report
    if before.get('history_state') not in ('ACTIVE','SOURCE_COMPLETE'):
        report['status']='COMPACT_CONTEXT_CORE_UPGRADED_NO_ACTIVE_HISTORY';return report
    stopped=step('history_stop',['-m','compact_product','history-stop','--project',project],history)
    if stopped is None:return report
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
    try:result=upgrade(project,root,a.old_code_root.resolve(),a.history_code_root.resolve(),a.expected_source_sha)
    except Exception as exc:result=dict(status='COMPACT_CONTEXT_UPGRADE_INCOMPLETE',failure_type=type(exc).__name__)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],output=str(output),data_reset=False)),flush=True)
    return 2 if result['status'].endswith('INCOMPLETE') else 0

if __name__=='__main__':raise SystemExit(main())
