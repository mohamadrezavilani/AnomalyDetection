"""Verified staged upgrade confined to AnomalyDetection; preserves all data."""
from __future__ import annotations
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

BUILD='AD-20261110-AUDIT-CODE'
PREVIOUS_BUILDS={
    'AD-20261108-WINSTART':'56c64aaf2e9a35e237feb2e29f7f253958adfd0987426ef4f6c0e8809235ad4b',
    'AD-20261108-RELEASE':'53f11f082e23e45a3d8df0af5bf5dc83069681477c39c894e9e873d7bb16e48b',
    'AD-FAMILY-AUDIT-20261108':'d8db97b02bda732f6d4359b84eec6650ff5cae9cb138f9940cfdf1d30e2c275c',
    'AD-INPUT-PUBLICATION-20261108':'a202a5bfc87564f56e5c2d98e38ca09975dcd98750543dd5ad89165993acf9cc',
    'AD-QUALIFICATION-20261107-R3':'c0f6015ccfe36c63912b2cd11faa7b1bc0155d10364af00b6331300626b27325',
    'AD-R3-INPUT-20261108':'055a9e400e56c5b6baa7df61114335dd821152893ebec5f2e9e41b6d4916b24b',
    'AD-R3-INPUT-20261108-R2':'5b8c2e3d6249b1b2f303c5db60b3dafeaea5ed5673a0a7a9e66de1e121a0ae17',
}
STAGING=Path(__file__).resolve().parent


class InstallFailure(RuntimeError):
    def __init__(self,code,**details):
        super().__init__(code)
        self.details=details


def verified(root,build=BUILD,source_sha=None):
    manifest=json.loads((root/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    if manifest.get('build_id')!=build:raise ValueError('UNEXPECTED_BUILD:'+build)
    entries=manifest.get('files_sha256',{})
    if not all(name in entries for name in ('Install_Update.py','run_anomaly.py','anomaly_detection/product_cli.py')):
        raise ValueError('INCOMPLETE_STAGED_BUILD')
    for name,expected in entries.items():
        member=root/name;path=member.resolve()
        if not path.is_relative_to(root) or not path.is_file() or member.is_symlink():raise ValueError('UNSAFE_STAGED_MEMBER')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('STAGED_CHECKSUM_MISMATCH:'+name)
    digest=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if digest!=manifest.get('source_sha256') or (source_sha is not None and digest!=source_sha):raise ValueError('STAGED_MANIFEST_MISMATCH')
    return entries


def verified_previous(root):
    build=json.loads((root/'RELEASE_MANIFEST.json').read_text(encoding='utf-8')).get('build_id')
    if build not in PREVIOUS_BUILDS:raise ValueError('UNSUPPORTED_PREVIOUS_AD_BUILD:'+str(build))
    return build,verified(root,build,PREVIOUS_BUILDS[build])


def command(project,script,*args,timeout=40):
    result=subprocess.run([sys.executable,str(script),*args],cwd=project,capture_output=True,text=True,
        encoding='utf-8',errors='replace',timeout=timeout)
    if result.returncode:
        try:response=json.loads(result.stdout)
        except ValueError:response={}
        fields=('status','child_exit_code','child_pid','failure')
        child={key:response[key] for key in fields if isinstance(response,dict) and key in response}
        raise InstallFailure('COMMAND_FAILED:'+args[0],child_command=dict(child,returncode=result.returncode))
    return result.stdout


def web_status_matches(worker):
    from http.client import HTTPConnection,HTTPException

    connection=HTTPConnection('127.0.0.1',5022,timeout=1)
    try:
        connection.request('GET','/api/status')
        response=connection.getresponse()
        if response.status!=200:return False
        receipt=json.loads(response.read(8*1024*1024+1))
        return (isinstance(receipt,dict) and receipt.get('state')=='RUNNING'
            and all(receipt.get(key)==worker[key] for key in ('instance_token','pid','build_id','source_sha256')))
    except (OSError,ValueError,HTTPException):return False
    finally:connection.close()


def startup_snapshot(current,owner,seconds,launcher_pid):
    # A detached worker's private DB errors are already reduced to safe codes.
    worker=current['worker'] if owner else {}
    observed=current['process'].get('owner') or {}
    value={'elapsed_seconds':round(seconds,2),'health':current['health'],
        'matching_process':bool(owner),'phase':worker.get('phase'),
        'launcher_pid':launcher_pid,'observed_worker_pid':observed.get('pid'),
        'observed_build_id':observed.get('build_id'),'observed_source_sha256':observed.get('source_sha256'),
        'heartbeat_age_seconds':current.get('heartbeat_age_seconds'),
        'storage_ready':worker.get('storage_ready') is True,
        'viewer_read_confirmed':(worker.get('source_status') or {}).get('source_read_only') is True}
    for key in ('last_storage_failure','last_source_failure','last_fatal_failure','stop_reason'):
        if worker.get(key):value[key]=worker[key]
    failure=worker.get('last_initialization_failure')
    if failure:value['last_initialization_failure']={key:failure.get(key) for key in ('phase','step','failure')}
    return value


def await_worker(target,build,sha,started,wait_seconds):
    from anomaly_detection.product_control import release_owner,status

    began=time.monotonic()
    launcher_pid=started.get('child_pid')
    initial=release_owner(started.get('process') or {},build,sha)
    expected_token=started.get('expected_instance_token')
    if expected_token is None and started.get('status')!='STARTING':expected_token=initial.get('instance_token')
    seen=bool(initial and initial.get('instance_token')==expected_token)
    first_healthy=None
    trace=[]
    next_notice=8
    while True:
        current=status(target)
        owner=release_owner(current['process'],build,sha)
        worker=current['worker']
        matching=bool(owner and (expected_token is None or owner['instance_token']==expected_token))
        elapsed=time.monotonic()-began
        sample=startup_snapshot(current,owner if matching else {},elapsed,launcher_pid)
        if not trace or any(sample.get(key)!=trace[-1].get(key) for key in
                ('health','phase','matching_process','observed_worker_pid','observed_build_id',
                 'last_storage_failure','last_source_failure','stop_reason')):
            trace=(trace+[sample])[-12:]
        last_owner=current['process'].get('owner') or {}
        last_attempt=bool(expected_token and last_owner.get('instance_token')==expected_token
            and last_owner.get('build_id')==build and last_owner.get('source_sha256')==sha)
        if not matching and (seen or last_attempt):
            # The status file of a just-exited instance is retained for diagnosis.
            if last_attempt:sample=startup_snapshot(current,last_owner,elapsed,launcher_pid)
            raise InstallFailure('UPDATED_WORKER_EXITED_OR_REPLACED',startup=dict(sample,trace=trace))
        if matching:
            seen=True
            expected_token=owner['instance_token']
            healthy=(current['health']=='RUNNING' and current['observation_matches_process']
                and all(worker.get(key)==owner.get(key) for key in ('instance_token','pid','build_id','source_sha256'))
                and sample['storage_ready'] and sample['viewer_read_confirmed']
                and worker['source_status'].get('semantic_state')=='ready')
            if healthy:
                heartbeat=worker['heartbeat_ns']
                if first_healthy is None:first_healthy=heartbeat
                elif heartbeat>first_healthy:
                    web=release_owner(current['web'],build,sha,'product_web')
                    if web and web_status_matches(worker):
                        return dict(sample,health='RUNNING',web='PASS_LOCAL_STATUS_GET',
                            instance_token=expected_token,pid=owner['pid'],trace=trace)
                    sample['web']='WAITING_FOR_MATCHING_LOCAL_STATUS'
            else:first_healthy=None
        if elapsed>=wait_seconds:
            raise InstallFailure('UPDATED_WORKER_STARTUP_TIMEOUT',startup=dict(sample,trace=trace))
        if elapsed>=next_notice:
            print(json.dumps({'status':'WAITING_FOR_AD_READY','startup':sample}),file=sys.stderr,flush=True)
            next_notice=elapsed+15
        time.sleep(min(.5,wait_seconds-elapsed))


@contextmanager
def stopped_ad(target, *, wait_seconds=300):
    """Wait for the owned processes, then reserve their locks during the file swap."""
    from anomaly_detection.process_control import busy_error,lock_handle,unlock_handle
    from anomaly_detection.product_control import stop
    deadline=time.monotonic()+wait_seconds
    waiting=False
    while True:
        # STOP_REQUESTED is an intermediate result. Reissue for any web
        # instance started while the worker is finishing its current cycle.
        stop(target,wait_seconds=max(0,min(2,deadline-time.monotonic())))
        blocked=[]
        with ExitStack() as locks:
            for resource in ('baseline','actor','web'):
                path=target/'data'/f'{resource}_process.lock'
                handle=locks.enter_context(path.open('a+b'))
                if not path.stat().st_size:
                    handle.write(b'0');handle.flush()
                try:lock_handle(handle)
                except OSError as exc:
                    if not busy_error(exc):raise
                    blocked.append(resource)
                else:locks.callback(unlock_handle,handle)
            if not blocked:
                yield
                return
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('AD_STOP_TIMEOUT:'+','.join(blocked))
        if not waiting:
            print(json.dumps({'status':'WAITING_FOR_AD_STOP','locked_resources':blocked,
                'timeout_seconds':wait_seconds}),file=sys.stderr,flush=True)
            waiting=True
        time.sleep(min(.25,remaining))


def install(project, *, start=True,observe_seconds=0,startup_seconds=240,rollback=None,acceptance=None):
    project=Path(project).resolve();target=(project/'AnomalyDetection').resolve()
    if not project.is_dir() or target.parent!=project:raise ValueError('INVALID_PROJECT_DIRECTORY')
    if target==STAGING or target.is_relative_to(STAGING):raise ValueError('EXTRACT_TO_A_SEPARATE_STAGING_DIRECTORY')
    from anomaly_detection.pg_source import installed_source_identity
    from anomaly_detection.process_control import lock_handle,unlock_handle
    installed_source_identity(project)
    if rollback is None:
        base_build,base=verified_previous(target)
        source,build,entries=STAGING,BUILD,verified(STAGING)
    else:
        base_build,base=BUILD,verified(target)
        source=Path(rollback).resolve()
        if source.parent!=target/'legacy_code':raise ValueError('ROLLBACK_REQUIRES_OWNED_CODE_BACKUP')
        build,entries=verified_previous(source)
    # Fail before stopping/replacing anything if the existing PG driver is absent.
    if start:__import__('psycopg')
    lock=target/'data/input_release_install.lock';lock.parent.mkdir(parents=True,exist_ok=True)
    with lock.open('a+b') as handle:
        if not lock.stat().st_size:
            handle.write(b'0');handle.flush()
        lock_handle(handle)
        try:
            # Detect a completed competing installer between verification and lock.
            verified(target,base_build,PREVIOUS_BUILDS.get(base_build))
            return replace(project,target,source,build,base,entries,start,observe_seconds,startup_seconds,acceptance)
        finally:unlock_handle(handle)


def acceptance_command(project,script,*args,timeout,expected_sha):
    try:
        result=json.loads(command(project,script,*args,timeout=timeout))
    except subprocess.TimeoutExpired:
        return {'status':'INPUT_ACCEPTANCE_TIMEOUT'}
    except (RuntimeError,ValueError):
        return {'status':'INPUT_ACCEPTANCE_COMMAND_FAILED'}
    if result.get('build_id')!=BUILD or result.get('source_sha256')!=expected_sha:
        return {'status':'INPUT_ACCEPTANCE_RELEASE_MISMATCH'}
    return result


def replace(project,target,source,build,base,entries,start,observe_seconds,startup_seconds,acceptance=None):
    old=target/'run_anomaly.py'
    was_running=bool(json.loads(command(project,old,'worker-status')).get('running')) if start else False
    backup=target/'legacy_code'/(time.strftime('%Y%m%d_%H%M%S',time.gmtime())+'_'+uuid.uuid4().hex[:8])
    backup.mkdir(parents=True)
    inventory=set(entries)|{'RELEASE_MANIFEST.json'}
    obsolete=set()
    for directory,suffix in (('anomaly_detection','.py'),('tests','.py'),('fixtures','.json')):
        obsolete.update(path.relative_to(target).as_posix() for path in (target/directory).rglob('*'+suffix)
            if '__pycache__' not in path.parts and path.relative_to(target).as_posix() not in inventory)
    existing=set()
    for name in sorted(inventory|obsolete|set(base)):
        path=target/name
        if path.is_symlink() or not path.resolve().is_relative_to(target):raise ValueError('UNSAFE_INSTALLED_MEMBER')
        if path.is_file():
            saved=backup/name;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved);existing.add(name)
    replaced=[];stopped=False
    try:
        with stopped_ad(target):
            stopped=True
            for name in sorted(obsolete):(target/name).unlink()
            # The manifest is the final commit marker and processes cannot
            # acquire their runtime locks while this swap is in progress.
            for name in sorted(entries)+['RELEASE_MANIFEST.json']:
                destination=target/name;destination.parent.mkdir(parents=True,exist_ok=True)
                temporary=destination.with_name(destination.name+'.install-'+uuid.uuid4().hex)
                try:shutil.copy2(source/name,temporary);os.replace(temporary,destination)
                finally:
                    if temporary.exists():temporary.unlink()
                replaced.append(name)
            version=json.loads(command(project,target/'run_anomaly.py','version'))
            if version.get('build_id')!=build or version.get('sqlite_loaded') is not False:raise ValueError('PRODUCT_VERIFICATION_FAILED')
        result={'status':'INSTALLED' if build==BUILD else 'ROLLED_BACK','build_id':build,
            'source_sha256':version['source_sha256'],'backup':str(backup),'storage_backend':'postgresql',
            'archived_source_files':len(obsolete),'web_url':'http://127.0.0.1:5022/'}
        if start:
            if acceptance:
                session,target_tehran=acceptance
                scope_args=('--session',session,'--target-tehran',target_tehran)
                print('RECHECKING_INSTALLED_AD_INPUT',file=sys.stderr,flush=True)
                result['input_recheck']=acceptance_command(project,target/'validation/recheck_input.py',
                    *scope_args,timeout=75,expected_sha=version['source_sha256'])
            started=json.loads(command(project,target/'run_anomaly.py','worker-start'))
            result['worker']=started['status']
            startup=await_worker(target,build,version['source_sha256'],started,startup_seconds)
            result.update(health='RUNNING',startup=startup)
            if observe_seconds:
                # Collection is optional. A diagnostic timeout cannot undo a verified start.
                try:
                    report=json.loads(command(project,target/'run_anomaly.py','worker-observe','--seconds',
                        str(observe_seconds),timeout=observe_seconds+20))
                    if report.get('build_id')!=build or report.get('source_sha256')!=version['source_sha256']:
                        raise ValueError('REPORT_RELEASE_VERIFICATION_FAILED')
                    result.update(report=report['output'],report_health=report['health'])
                except (RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as exc:
                    result['report_status']='REPORT_UNAVAILABLE_AFTER_VERIFIED_START'
                    result['report_error_type']=type(exc).__name__
            if acceptance:
                result['input_acceptance']=acceptance_command(project,target/'run_anomaly.py',
                    'presentation-check',*scope_args,timeout=25,expected_sha=version['source_sha256'])
        return result
    except BaseException as error:
        if not stopped:
            raise
        details=getattr(error,'details',{}).copy()
        details['backup']=str(backup)
        prior=json.loads((backup/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
        recovery={'build_id':prior['build_id'],'source_sha256':prior['source_sha256']}
        try:
            with stopped_ad(target):
                # Restore the backed-up code and commit its manifest last.
                for name in replaced:
                    destination=target/name
                    if name not in existing and destination.is_file():destination.unlink()
                for name in sorted(existing-{'RELEASE_MANIFEST.json'})+['RELEASE_MANIFEST.json']:
                    destination=target/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(backup/name,destination)
                verified(target,prior['build_id'],prior['source_sha256'])
            recovery['status']='PREVIOUS_CODE_RESTORED'
        except Exception as exc:
            recovery.update(status='RESTORE_NOT_CONFIRMED',error_type=type(exc).__name__,error=str(exc))
        if recovery['status']=='PREVIOUS_CODE_RESTORED' and was_running:
            try:
                restarted=json.loads(command(project,target/'run_anomaly.py','worker-start'))
                recovery.update(worker=restarted['status'],health=restarted.get('health'))
            except Exception as exc:
                recovery.update(worker='RESTART_FAILED',error_type=type(exc).__name__,error=str(exc))
        if not isinstance(error,Exception):raise
        raise InstallFailure(str(error),**details,recovery=recovery) from error


def main():
    parser=argparse.ArgumentParser(description='Install the verified PostgreSQL AnomalyDetection product')
    parser.add_argument('--project',required=True,type=Path)
    parser.add_argument('--observe-seconds',type=int,default=0,choices=range(0,91),metavar='0..90',
        help='Optionally observe longer and export a separate worker report after readiness')
    parser.add_argument('--startup-seconds',type=int,default=240,choices=range(2,301),metavar='2..300')
    parser.add_argument('--no-start',action='store_true',help='Install and verify code only')
    parser.add_argument('--rollback',type=Path,help='Restore the verified previous source from the reported backup path')
    parser.add_argument('--acceptance-session')
    parser.add_argument('--acceptance-target-tehran')
    args=parser.parse_args()
    acceptance=None
    if args.acceptance_session or args.acceptance_target_tehran:
        if not args.acceptance_session or not args.acceptance_target_tehran or args.no_start or args.rollback:
            parser.error('acceptance requires a session, target time, and a normal running upgrade')
        acceptance=(args.acceptance_session,args.acceptance_target_tehran)
    try:
        result=install(args.project,start=not args.no_start,observe_seconds=args.observe_seconds,
            startup_seconds=args.startup_seconds,rollback=args.rollback,acceptance=acceptance)
        code=0
    except Exception as exc:
        result={'status':'INSTALL_FAILED','error_type':type(exc).__name__,'error':str(exc),**getattr(exc,'details',{})}
        code=1
    project=args.project.resolve();target=(project/'AnomalyDetection').resolve()
    if target.parent==project and target.is_dir():
        from anomaly_detection.process_control import write_json
        receipt=target/'reports'/('AD_Install_'+time.strftime('%Y%m%d_%H%M%S',time.gmtime())+'_'+uuid.uuid4().hex[:8]+'.json')
        result['receipt']=str(receipt)
        try:write_json(receipt,result)
        except OSError:result.pop('receipt')
    print(json.dumps(result,ensure_ascii=True,indent=2));return code


if __name__=='__main__':raise SystemExit(main())
