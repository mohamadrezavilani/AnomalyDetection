"""Independent worker/web lifecycle and local-only diagnostic exports."""
from datetime import datetime,timezone
from pathlib import Path
import json
import os
import subprocess
import sys
import time
import uuid
import zipfile

from . import BUILD_ID
from .process_control import process_owner,read_json,write_json


def status(root):
    root=Path(root);owner=process_owner(root);identity=owner.get('owner') or {}
    worker=read_json(root/'reports/product_status.json',{})
    if worker.get('instance_token')!=identity.get('instance_token'):
        previous=read_json(root/'reports/A2W_worker_status.json',{})
        worker=previous if previous.get('instance_token')==identity.get('instance_token') else {}
    same=bool(worker and worker.get('instance_token')==identity.get('instance_token'))
    running=bool(owner['locked'] and identity.get('job')=='baseline_worker')
    age=max(0,(time.time_ns()-worker.get('heartbeat_ns',0))/1e9) if same else None
    return {'health':worker.get('state','STARTING') if running and same and age is not None and age<30 else
        'RUNNING_HEARTBEAT_STALE' if running and same else 'STARTING' if running else 'STOPPED',
        'running':running,'observation_matches_process':same,'heartbeat_age_seconds':age,'process':owner,'worker':worker,
        'web':process_owner(root,'web'),'web_url':'http://127.0.0.1:5022/'}


def spawn(root,command,*,instance_token=None):
    options=dict(cwd=Path(root).parent,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    if os.name=='nt':options['creationflags']=subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP
    else:options['start_new_session']=True
    args=[sys.executable,str(Path(root)/'run_anomaly.py'),command]
    if instance_token is not None:args+=['--instance-token',instance_token]
    return subprocess.Popen(args,**options)


def release_owner(process,build,sha,job='baseline_worker'):
    identity=process.get('owner') or {}
    if (process.get('locked') and identity.get('job')==job and identity.get('build_id')==build
            and identity.get('source_sha256')==sha and identity.get('instance_token')):
        return identity
    return {}


def start(root,sha):
    before=status(root)
    if before['process']['locked']:
        owner=release_owner(before['process'],BUILD_ID,sha)
        if owner:return dict(before,status='ALREADY_RUNNING',expected_instance_token=owner['instance_token'])
        return dict(before,status='EXISTING_WORKER_VERSION_DIFFERENT')
    token=uuid.uuid4().hex
    child=spawn(root,'worker-run',instance_token=token);deadline=time.monotonic()+5
    launch={'child_pid':child.pid,'expected_instance_token':token}
    while time.monotonic()<deadline:
        current=status(root)
        owner=release_owner(current['process'],BUILD_ID,sha)
        # Windows venv may start the interpreter through a redirector process.
        if owner.get('instance_token')==token:
            return dict(current,status='STARTED',**launch)
        if child.poll() is not None:
            prior=before['process'].get('owner') or {}
            if owner and owner['instance_token']!=prior.get('instance_token') and current['observation_matches_process']:
                return dict(current,status='ALREADY_RUNNING',expected_instance_token=owner['instance_token'])
            return dict(current,status='START_FAILED',child_exit_code=child.returncode,**launch)
        time.sleep(.05)
    return dict(status(root),status='STARTING',**launch)


def stop(root,wait_seconds=20):
    root=Path(root);requests=[]
    for resource,file,job in [('baseline','A2W_stop_request.json','baseline_worker'),('web','web_stop_request.json','product_web')]:
        owner=process_owner(root,resource)
        if owner['locked'] and (owner.get('owner') or {}).get('job')==job:
            token=owner['owner']['instance_token'];write_json(root/'data'/file,{'instance_token':token,'requested_at_ns':time.time_ns()})
            requests.append((resource,token))
    deadline=time.monotonic()+wait_seconds
    while time.monotonic()<deadline:
        alive=[]
        for resource,token in requests:
            current=process_owner(root,resource)
            if current['locked'] and (current.get('owner') or {}).get('instance_token')==token:alive.append(resource)
        if not alive:return {'status':'STOPPED' if requests else 'ALREADY_STOPPED'}
        time.sleep(.1)
    return {'status':'STOP_REQUESTED'}


def export_report(root,sha, *, observe_seconds=0,clock=None,wait=None):
    root=Path(root);clock=clock or time;wait=wait or time.sleep
    first=status(root);last=first;began=clock.monotonic();samples=[]
    first_token=(first['process'].get('owner') or {}).get('instance_token')
    deadline=began+observe_seconds
    while first['running'] and clock.monotonic()<deadline:
        wait(min(1,deadline-clock.monotonic()));last=status(root)
        token=(last['process'].get('owner') or {}).get('instance_token')
        if not last['running'] or token!=first_token:break
        if not samples or clock.monotonic()-samples[-1]['elapsed_seconds']-began>=5:
            worker=last['worker'];samples.append({'elapsed_seconds':round(clock.monotonic()-began,3),'state':last['health'],
                'phase':worker.get('phase'),'source_pages':worker.get('source_pages',0),'evaluated_jobs':worker.get('evaluated_jobs',0),
                'audited_requests':worker.get('audited_requests',0),'source':worker.get('source_status'),
                'statistics_at_ns':worker.get('statistics_at_ns'),
                'statistics_status':worker.get('statistics_status'),'statistics_section_failures':worker.get('statistics_section_failures'),
                'content_reads':worker.get('content_reads',0),'scenario_evaluations':worker.get('scenario_evaluations',0),
                'scenario_phase':worker.get('scenario_phase'),'last_scenario_failure':worker.get('last_scenario_failure'),
                'last_technical_census':worker.get('last_technical_census'),
                'jobs':worker.get('statistics',{}).get('jobs'),
                'incidents':worker.get('statistics',{}).get('incidents'),
                'window_lanes':worker.get('window_lanes'),
                'source_failures_total':worker.get('source_failures_total',0),
                'evaluation_timeouts_total':worker.get('evaluation_timeouts_total',0),
                'owned_apply_failures_total':worker.get('owned_apply_failures_total',0),
                'job_scope_backfill':worker.get('job_scope_backfill')})
            samples=samples[-72:]
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]
    path=root/'reports'/('AnomalyDetection_Report_'+stamp+'.zip');path.parent.mkdir(exist_ok=True,parents=True)
    same=first_token==(last['process'].get('owner') or {}).get('instance_token')
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('worker_status.json',json.dumps(last,ensure_ascii=False,indent=2))
        archive.writestr('release.json',json.dumps({'build_id':BUILD_ID,'source_sha256':sha,'storage_backend':'postgresql'}))
        archive.writestr('worker_observation.json',json.dumps({'same_instance':same,'elapsed_seconds':clock.monotonic()-began,
            'samples':samples,'source_connections_by_observer':0,'capacity_acceptance':'NOT_EVALUATED'},ensure_ascii=False,indent=2))
        from .product_diagnostics import snapshot
        archive.writestr('evaluation_queue.json',json.dumps(snapshot(root),ensure_ascii=False,indent=2))
    return last,path
