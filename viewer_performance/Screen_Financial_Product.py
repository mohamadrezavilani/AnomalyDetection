"""Prepare, or explicitly run, the exclusive financial-product scope screen.

The default preflight never stops processes. --exclusive-run is the only owner
host experiment entrypoint; unrecognized process/restore plans block before stop.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))


@contextmanager
def run_lock(path):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as stream:
        stream.seek(0)
        if os.name=='nt':
            import msvcrt
            if path.stat().st_size==0:stream.write(b'0');stream.flush();stream.seek(0)
            try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            except OSError:raise ValueError('ANOTHER_FINANCIAL_SCREEN_IS_RUNNING') from None
            try:yield
            finally:stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            try:fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:raise ValueError('ANOTHER_FINANCIAL_SCREEN_IS_RUNNING') from None
            try:yield
            finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,default=ROOT)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--preflight',action='store_true')
    group.add_argument('--exclusive-run',action='store_true')
    parser.add_argument('--captures-zip',type=Path)
    parser.add_argument('--reviewed-preflight',type=Path,
        help='Previously reviewed private preflight; fresh identities and script hashes must match.')
    parser.add_argument('--counts',default='16,64,256')
    parser.add_argument('--history-requests',default='0,4096')
    parser.add_argument('--max-seconds',type=int,default=1800)
    args=parser.parse_args(argv)
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.financial_screen.host import preflight,maintenance,parameters,inventory,assert_quiescent
    from viewer_performance.financial_screen.experiment import run
    from viewer_performance.financial_screen.reviewed_host import load_review,apply_review
    project=args.project.resolve()
    directory=project/'AnomalyDetection/reports'/('Financial_Screen_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
    directory.mkdir(parents=True,exist_ok=False)
    result=dict(status='SCREEN_PREPARING',output=str(directory/'screen.json'));exported_preflight=None
    done=threading.Event();began=time.monotonic()
    def notice(value):print(json.dumps(value,ensure_ascii=True),flush=True)
    def heartbeat():
        while not done.wait(15):notice(dict(status='FINANCIAL_SCREEN_RUNNING',elapsed_seconds=round(time.monotonic()-began,1)))
    thread=threading.Thread(target=heartbeat,daemon=True)
    try:
        with run_lock(project/'AnomalyDetection/reports/financial_screen.lock'):
            if project!=ROOT:raise ValueError('PROJECT_ROOT_MUST_MATCH_TOOL_INSTALLATION')
            review=load_review(args.reviewed_preflight) if args.reviewed_preflight else None
            before=preflight(project)
            if review:before=apply_review(project,before,*review)
            before.update(collection_run=directory.name,collected_at_utc=datetime.now(timezone.utc).isoformat())
            atomic_json(directory/'preflight.json',before)
            exported_preflight=project/'AnomalyDetection/reports/preflight_to_send.json'
            atomic_json(exported_preflight,before)
            result.update(status=before['status'],preflight_output=str(directory/'preflight.json'),
                blocking_issues=before['restore_plan']['issues'],workers_stopped=False)
            if args.exclusive_run and before['status']=='PREFLIGHT_READY':
                counts=tuple(int(n) for n in args.counts.split(','));histories=tuple(int(n) for n in args.history_requests.split(','))
                if args.captures_zip and not args.captures_zip.is_file():raise ValueError('CAPTURE_BUNDLE_MISSING')
                # All simple validation happens before maintenance stops anything.
                if len(counts)!=3 or any(n<1 or n>32768 for n in counts) or not histories or any(n<0 or n>131072 for n in histories):raise ValueError('INVALID_SCREEN_COUNTS')
                if not 30<=args.max_seconds<=14400:raise ValueError('SCREEN_BUDGET_OUT_OF_RANGE')
                if args.captures_zip:
                    from viewer_performance.Qualify_Capacity_Candidate import extract_captures
                    from viewer_performance.capacity.baseline import capture_jobs
                    with tempfile.TemporaryDirectory(prefix='screen-input-check-') as validation:
                        capture_jobs(extract_captures(args.captures_zip,Path(validation)))
                thread.start();last_check=0;idle_cpu={}
                def guard_host():
                    nonlocal last_check
                    if time.monotonic()-last_check<5:return
                    last_check=time.monotonic();snapshot=inventory(project)
                    assert_quiescent(project,snapshot,before['restore_plan'],idle_cpu)
                with maintenance(project,before,directory,notice) as control:
                    result=run(parameters(project),counts=counts,histories=histories,max_seconds=args.max_seconds,
                        bundle=args.captures_zip,guard_host=guard_host,notice=notice)
                    atomic_json(directory/'experiment.json',result)
                result.update(maintenance_status=control['status'],restore_output=str(directory/'maintenance.json'))
                if control['restore_failures']:result['status']='SCREEN_RESTORE_INCOMPLETE'
    except Exception as exc:
        result.update(status='SCREEN_BLOCKED_OR_INCOMPLETE',failure=dict(error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,sqlstate=getattr(exc,'sqlstate',None),
            details=getattr(exc,'details',None)))
    finally:
        done.set()
        if thread.ident is not None:thread.join(1)
    atomic_json(directory/'screen.json',result)
    notice({k:v for k,v in result.items() if k in ('status','blocking_issues','failure','maintenance_status')}|
        dict(output=str(directory/'screen.json'),preflight_output=str(exported_preflight) if exported_preflight else None,
             experiment_output=str(directory/'experiment.json') if (directory/'experiment.json').exists() else None))
    return 0 if result['status'] in ('PREFLIGHT_READY','SCOPE_SCREEN_COMPLETE_NOT_PRODUCT_ACCEPTANCE') else 2


if __name__=='__main__':raise SystemExit(main())
