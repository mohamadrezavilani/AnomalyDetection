"""Bind reviewed external supervision to fresh identities; never trust PID alone.

The review is private input selected by the operator. No host addresses, task
names, script hashes or customer data are built into the public implementation.
"""
import copy
import hashlib
import json
import ntpath
from pathlib import Path
import re
import time

from .resources import process_usage


def words(value):
    result=[];end=0
    for match in re.finditer(r'''"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+''',value):
        if value[end:match.start()].strip():raise ValueError('REVIEW_COMMAND_SYNTAX_UNSUPPORTED')
        item=match[0];result.append(item[1:-1] if item[:1] in ('"',"'") else item);end=match.end()
    if value[end:].strip():raise ValueError('REVIEW_COMMAND_SYNTAX_UNSUPPORTED')
    return result


def norm(value):return ntpath.normcase(ntpath.normpath(str(value)))
def key(task):return task['Path'],task['Name']
def same_process(a,b):
    return all(a.get(k)==b.get(k) for k in ('ProcessId','ParentProcessId','CreationDate','ExecutablePath','CommandLine'))


def load_review(path):
    path=Path(path)
    if path.stat().st_size>4*1024**2:raise ValueError('REVIEW_FILE_BYTE_BUDGET_EXCEEDED')
    raw=path.read_bytes();value=json.loads(raw.decode('utf-8-sig'))
    if not isinstance(value,dict) or 'inventory' not in value or 'external_supervision' not in value:
        raise ValueError('REVIEW_PREFLIGHT_REPORT_REQUIRED')
    return value,hashlib.sha256(raw).hexdigest()


def source_map(value):
    records=value.get('external_supervision',{}).get('sources',[])
    return {norm(r['path']):r for r in records if r.get('status')=='READ_ONLY_SOURCE'}


def service_action(task):
    actions=task.get('Actions',[])
    if len(actions)!=1 or ntpath.basename(actions[0]['Execute']).lower()!='powershell.exe':return None
    args=words(actions[0].get('Arguments') or '')
    lowered=[a.lower() for a in args]
    if '-file' not in lowered:return None
    index=lowered.index('-file')
    if lowered[index+2:]!=['-service','lan_proxy'] or len(args)!=index+4:return None
    if ntpath.basename(args[index+1]).lower()!='service_entry.ps1':return None
    prefix=lowered[:index];i=0
    while i<len(prefix):
        flag=prefix[i]
        if flag in ('-nologo','-noprofile','-noninteractive'):i+=1
        elif prefix[i:i+2] in (['-executionpolicy','bypass'],['-windowstyle','hidden']):i+=2
        else:return None
    if '-noprofile' not in prefix or '-noninteractive' not in prefix:return None
    return args,index,actions[0]


def reviewed_proxy(fresh,reviewed):
    current=source_map(fresh);old=source_map(reviewed);processes={p['ProcessId']:p for p in fresh['inventory']['processes']}
    candidates=[]
    for task in fresh['inventory']['tasks']:
        parsed=service_action(task)
        if not parsed or task['State']!='Running' or not task['Enabled']:continue
        args,index,action=parsed;entry=norm(args[index+1]);prior=[t for t in reviewed['inventory']['tasks'] if key(t)==key(task)]
        if len(prior)!=1 or prior[0]['Actions']!=task['Actions']:continue
        if entry not in current or entry not in old or current[entry]['sha256']!=old[entry]['sha256']:continue
        for listener in fresh['inventory']['listeners']:
            pid=listener['OwningProcess'];proxy=processes.get(pid,{})
            if ntpath.basename(proxy.get('ExecutablePath') or '').lower()!='python.exe':continue
            command=words(proxy.get('CommandLine') or '')
            if len(command)<5 or command[1]!='-B' or ntpath.basename(command[2]).lower()!='lan_proxy.py':continue
            source=norm(command[2])
            if source not in current or source not in old or current[source]['sha256']!=old[source]['sha256']:continue
            known=[p for p in reviewed['inventory']['processes'] if ntpath.basename(p.get('ExecutablePath') or '').lower()=='python.exe'
                and 'lan_proxy.py' in (p.get('CommandLine') or '').lower() and words(p.get('CommandLine') or '')[1:]==command[1:]]
            if not known:continue
            if '--bind' not in command:continue
            bind=command[command.index('--bind')+1]
            endpoints=[r for r in fresh['inventory']['listeners'] if r['OwningProcess']==pid]
            if {r['LocalPort'] for r in endpoints}!={5021,5022} or any(r['LocalAddress']!=bind for r in endpoints):continue
            chain=[proxy];parent=processes.get(proxy.get('ParentProcessId'),{})
            if ntpath.basename(parent.get('ExecutablePath') or '').lower()=='python.exe':
                if words(parent.get('CommandLine') or '')[1:]!=command[1:]:continue
                chain.append(parent);parent=processes.get(parent.get('ParentProcessId'),{})
            if ntpath.basename(parent.get('ExecutablePath') or '').lower()!='powershell.exe':continue
            if [norm(a) for a in words(parent.get('CommandLine') or '')[1:]]!=[norm(a) for a in args]:continue
            chain.append(parent)
            candidates.append(dict(task=task,processes=chain,endpoints=endpoints,
                sources=[dict(path=current[p]['path'],sha256=current[p]['sha256']) for p in (entry,source)]))
    unique={candidate['processes'][0]['ProcessId']:candidate for candidate in candidates}
    if len(unique)>1 or len({key(c['task']) for c in candidates})>1:raise ValueError('REVIEW_FRONTEND_NOT_UNIQUE')
    return next(iter(unique.values()),None)


def reviewed_idle_shell(project,fresh,reviewed):
    processes={p['ProcessId']:p for p in fresh['inventory']['processes']};result=[]
    expected=['-NoExit','-Command','&',ntpath.join(str(project),'.venv','Scripts','python.exe'),
        '-B','viewer_performance/Run_Viewer_Web.py','--host','127.0.0.1']
    for prior in reviewed['inventory']['processes']:
        if ntpath.basename(prior.get('ExecutablePath') or '').lower()!='powershell.exe':continue
        current=processes.get(prior['ProcessId'],{})
        if not same_process(prior,current):continue
        args=words(current.get('CommandLine') or '')[1:]
        if [norm(a) for a in args]==[norm(a) for a in expected]:result.append(current)
    return result


def apply_review(project,fresh,reviewed,digest):
    result=copy.deepcopy(fresh);plan=result['restore_plan'];resolved=set()
    if result.get('control_failure'):return result
    proxy=reviewed_proxy(result,reviewed)
    if proxy:
        plan['reviewed_proxy']=proxy
        resolved.add('RUNNING_SCHEDULED_TASK_RESTORE_PLAN_REQUIRED:'+proxy['task']['Name'])
        for process in proxy['processes']:
            resolved.add('UNCONTROLLED_PROJECT_PROCESS:'+str(process['ProcessId']))
            resolved.add('FRONTEND_STOP_AND_RESTORE_PLAN_REQUIRED:'+str(process['ProcessId']))
    idle=reviewed_idle_shell(project,result,reviewed)
    plan['idle_launchers']=idle
    for process in idle:resolved.add('UNCONTROLLED_PROJECT_PROCESS:'+str(process['ProcessId']))
    plan['issues']=[issue for issue in plan['issues'] if issue not in resolved]
    plan['reviewed_report_sha256']=digest;plan['resolved_issues']=sorted(resolved)
    result['status']='PREFLIGHT_BLOCKED' if plan['issues'] else 'PREFLIGHT_READY'
    return result


def check_sources(proxy):
    from .supervision import MAX_FILE_BYTES
    for record in proxy['sources']:
        with Path(record['path']).open('rb') as stream:body=stream.read(MAX_FILE_BYTES+1)
        if len(body)>MAX_FILE_BYTES or hashlib.sha256(body).hexdigest()!=record['sha256']:
            raise ValueError('REVIEWED_SUPERVISOR_SOURCE_CHANGED')


def created_epoch(process):
    match=re.fullmatch(r'/Date\((\d+)(?:[+-]\d+)?\)/',process['CreationDate'])
    if not match:raise ValueError('REVIEWED_PROCESS_CREATION_TIME_UNAVAILABLE')
    return int(match[1])/1000


def idle_ids(snapshot,plan,cpu,*,usage=process_usage,wait=time.sleep):
    processes={p['ProcessId']:p for p in snapshot['processes']};allowed=set()
    for saved in plan.get('idle_launchers',[]):
        pid=saved['ProcessId'];current=processes.get(pid)
        if current is None:continue
        if not same_process(saved,current):raise ValueError('REVIEWED_LAUNCH_SHELL_IDENTITY_CHANGED')
        if any(p.get('ParentProcessId')==pid for p in processes.values()):raise ValueError('REVIEWED_LAUNCH_SHELL_HAS_ACTIVE_CHILD')
        row=usage(pid)
        if row.get('status')!='READ' or row.get('image_name')!='powershell.exe' or abs(row['created_epoch_seconds']-created_epoch(saved))>.02:
            raise ValueError('REVIEWED_LAUNCH_SHELL_OS_IDENTITY_UNAVAILABLE')
        previous=cpu.get(pid)
        if previous is None:
            previous=row;wait(.2);row=usage(pid)
        if row.get('status')!='READ' or row.get('identity')!=previous.get('identity'):
            raise ValueError('REVIEWED_LAUNCH_SHELL_OS_IDENTITY_CHANGED')
        delta=row['cpu_seconds']-previous['cpu_seconds']
        if not 0<=delta<=.05:raise ValueError('REVIEWED_LAUNCH_SHELL_IS_NOT_IDLE')
        cpu[pid]=row;allowed.add(pid)
    return allowed
