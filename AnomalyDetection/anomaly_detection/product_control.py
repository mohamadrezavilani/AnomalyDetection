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
from .process_control import process_owner,read_observed_json,write_json


def status(root):
    root=Path(root);owner=process_owner(root);identity=owner.get('owner') or {}
    failures=[]
    def failure(stage, value):
        if value: failures.append(dict(stage=stage, failure=value))
    failure('worker_identity',owner.get('owner_read_failure'))
    worker,error=read_observed_json(root/'reports/product_status.json')
    failure('worker_heartbeat',error)
    token=identity.get('instance_token')
    unverified=worker
    if not token or worker.get('instance_token')!=token:
        previous,error=read_observed_json(root/'reports/A2W_worker_status.json')
        failure('previous_worker_heartbeat',error)
        worker=previous if token and previous.get('instance_token')==token else {}
    same=bool(owner['locked'] and identity.get('job')=='baseline_worker' and token and worker and worker.get('instance_token')==token)
    unknown=bool(owner['locked'] and not (token and identity.get('job')))
    if unknown and not owner.get('owner_read_failure'):
        failure('worker_identity',{'code':'PROCESS_METADATA_UNAVAILABLE'})
    running=None if unknown else bool(owner['locked'] and identity.get('job')=='baseline_worker')
    age=max(0,(time.time_ns()-worker.get('heartbeat_ns',0))/1e9) if same else None
    web=process_owner(root,'web')
    failure('web_identity',web.get('owner_read_failure'))
    if web['locked'] and not (web.get('owner') or {}).get('instance_token') and not web.get('owner_read_failure'):
        failure('web_identity',{'code':'PROCESS_METADATA_UNAVAILABLE'})
    return {'health':'PROCESS_IDENTITY_UNAVAILABLE' if unknown else
        worker.get('state','STARTING') if running and same and age is not None and age<30 else
        'RUNNING_HEARTBEAT_STALE' if running and same else 'STARTING' if running else 'STOPPED',
        'running':running,'observation_matches_process':same,'heartbeat_age_seconds':age,'process':owner,'worker':worker,
        'unverified_worker_status':unverified if not same else {},'diagnostic_failures':failures,
        'web':web,'web_url':'http://127.0.0.1:5022/'}


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
        identity=before['process'].get('owner') or {}
        if not (identity.get('instance_token') and identity.get('job')):
            return dict(before,status='PROCESS_IDENTITY_UNAVAILABLE')
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
    root=Path(root);requests=[];blocked=[]
    for resource,file,job in [('baseline','A2W_stop_request.json','baseline_worker'),('web','web_stop_request.json','product_web')]:
        owner=process_owner(root,resource)
        if owner['locked'] and not ((owner.get('owner') or {}).get('instance_token') and (owner.get('owner') or {}).get('job')):
            blocked.append(resource)
            continue
        if owner['locked'] and (owner.get('owner') or {}).get('job')==job:
            requests.append((resource,owner['owner']['instance_token'],file))
    if blocked:return {'status':'STOP_BLOCKED_IDENTITY_UNAVAILABLE','resources':blocked}
    for resource,token,file in requests:
        write_json(root/'data'/file,{'instance_token':token,'requested_at_ns':time.time_ns()})
    deadline=time.monotonic()+wait_seconds
    while time.monotonic()<deadline:
        alive=[]
        for resource,token,file in requests:
            current=process_owner(root,resource)
            current_token=(current.get('owner') or {}).get('instance_token')
            if current['locked'] and (not current_token or current_token==token):alive.append(resource)
        if not alive:return {'status':'STOPPED' if requests else 'ALREADY_STOPPED'}
        time.sleep(.1)
    return {'status':'STOP_REQUESTED'}


def export_report(root,sha, *, observe_seconds=0,clock=None,wait=None):
    root=Path(root);clock=clock or time;wait=wait or time.sleep
    first=status(root);last=first;began=clock.monotonic();samples=[]
    observation_failures={}
    def remember(value):
        for failure in value.get('diagnostic_failures',[]):
            observation_failures[json.dumps(failure,sort_keys=True)]=failure
    remember(first)
    first_token=(first['process'].get('owner') or {}).get('instance_token')
    deadline=began+observe_seconds
    while first['running'] and clock.monotonic()<deadline:
        wait(min(1,deadline-clock.monotonic()));last=status(root)
        remember(last)
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
    last=dict(last,diagnostic_failures=list(observation_failures.values()))
    path=root/'reports'/('AnomalyDetection_Report_'+stamp+'.zip');path.parent.mkdir(exist_ok=True,parents=True)
    same=bool(first['process']['locked'] and last['process']['locked'] and first_token
              and first_token==(last['process'].get('owner') or {}).get('instance_token'))
    verified=bool(same and first['observation_matches_process'] and last['observation_matches_process'])
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('worker_status.json',json.dumps(last,ensure_ascii=False,indent=2))
        archive.writestr('release.json',json.dumps({'build_id':BUILD_ID,'source_sha256':sha,'storage_backend':'postgresql',
            'identity_scope':'REPORT_COLLECTOR_NOT_RUNNING_WORKER'}))
        archive.writestr('worker_observation.json',json.dumps({'same_instance':same,'elapsed_seconds':clock.monotonic()-began,
            'process_identity_verified':verified,
            'observation_complete':not first.get('diagnostic_failures') and not last.get('diagnostic_failures'),
            'samples':samples,'source_connections_by_observer':0,'capacity_acceptance':'NOT_EVALUATED'},ensure_ascii=False,indent=2))
        from .product_diagnostics import snapshot
        archive.writestr('evaluation_queue.json',json.dumps(snapshot(root),ensure_ascii=False,indent=2))
    return last,path
