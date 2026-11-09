"""Run exactly one normal live window with a deadline and a safe timing report."""
from __future__ import annotations
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB
from tools.run_behavior_viewer import main as run_viewer
from tools.run_viewer_pilot import PilotDeadline
from p24_foundation.viewer_runtime import ProgressConsole,atomic_json,runtime_source_digest
from p24_foundation.viewer_acceptance import nonnegative_number
from tools.viewer_pg_observer import PostgreSQLObserver,load_viewer_database


def wal_compression_preflight(database,method):
    """Read-only permission/settings gate; no window is fetched on rejection."""
    if method not in ('pglz','lz4','zstd'):
        raise ValueError('unsupported_wal_compression_method')
    import psycopg
    options=dict(database)
    options['connect_timeout']=min(5,int(options.get('connect_timeout',5)))
    with psycopg.connect(**options) as conn:
        with conn.cursor() as cur:
            cur.execute('SHOW wal_compression')
            current=cur.fetchone()[0]
            cur.execute("SELECT has_parameter_privilege(current_user,'wal_compression','SET')")
            allowed=bool(cur.fetchone()[0])
    if current!='off':
        # Do not benchmark by replacing an already-active compression method.
        return dict(status='ALREADY_ENABLED',existing=current,requested=method)
    if not allowed:
        return dict(status='PERMISSION_UNAVAILABLE',existing=current,requested=method)
    return dict(status='READY',existing=current,requested=method)


class WindowConsole(io.TextIOBase):
    def __init__(self,stream):
        self.stream=stream;self.pending='';self.result=None
    def write(self,value):
        self.pending+=value
        while '\n' in self.pending:
            line,self.pending=self.pending.split('\n',1)
            try:message=json.loads(line)
            except (ValueError,TypeError):continue
            if isinstance(message,dict):
                self.stream.emit(message)
                if 'status' in message:self.result=message
        return len(value)
    def flush(self):pass


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--out',type=Path,default=Path('validation/viewer_one_window.json'))
    parser.add_argument('--max-minutes',type=int,default=10)
    parser.add_argument('--wal-compression',choices=('pglz','lz4','zstd'),
                        help='Opt-in transaction-local, lossless compression; preflight checks permission')
    args=parser.parse_args(argv)
    if not 1<=args.max_minutes<=60:parser.error('--max-minutes must be 1..60')
    compression_check=dict(status='NOT_REQUESTED')
    if args.wal_compression:
        try:
            database=load_viewer_database(args.config)
            compression_check=wal_compression_preflight(database,args.wal_compression)
        except Exception as exc:
            compression_check=dict(status='NOT_AVAILABLE',reason=type(exc).__name__)
        if compression_check['status']!='READY':
            # In this case no capture, ingest or checkpoint operation starts.
            report=dict(status='WAL_COMPRESSION_PREFLIGHT_STOPPED',mode='read_only_preflight',
                wal_compression=compression_check,production_modified=False,
                runtime_source_sha256=runtime_source_digest())
            atomic_json(args.out,report)
            print(json.dumps(dict(status=report['status'],output=str(args.out))))
            return 2
    started=time.monotonic();budget=PilotDeadline(args.max_minutes*60)
    progress=[];output=ProgressConsole();console=WindowConsole(output)
    absent=object();previous=ViewerDB.__dict__.get('progress_callback',absent)
    previous_d1=ViewerDB.__dict__.get('d1_explain',absent)
    saved_argv=sys.argv;exit_code=0;interrupted=False
    def record(db,event):
        nonlocal observer,observer_data
        budget.connection=db.conn
        if observer is None and observer_data.get('status')=='STARTING' and observer_data.get('reason')=='publisher_pid_not_yet_observed':
            try:
                writer_pid=db.conn.info.backend_pid
                observer=PostgreSQLObserver(database,writer_pid).start()
                observer_data=dict(status='STARTING')
            except Exception as exc:
                observer_data=dict(status='NOT_AVAILABLE',reason=type(exc).__name__)
        budget.check()
        item=dict(progress=event,elapsed_seconds=round(time.monotonic()-started,3))
        progress.append(item)
        output.progress(event)
    ViewerDB.progress_callback=record
    # Diagnostic plans execute only in this bounded one-window probe, never
    # in ordinary worker cycles. EXPLAIN is intentionally without ANALYZE.
    ViewerDB.d1_explain=True
    sys.argv=['run_behavior_viewer.py','live-once','--config',str(args.config)]
    if args.wal_compression:sys.argv+=['--wal-compression',args.wal_compression]
    observer=None;observer_data=dict(status='NOT_STARTED')
    try:
        database=load_viewer_database(args.config)
        observer_data=dict(status='STARTING',reason='publisher_pid_not_yet_observed')
    except Exception as exc:
        observer_data=dict(status='NOT_AVAILABLE',reason=type(exc).__name__)
    budget.timer.start()
    try:
        with contextlib.redirect_stdout(console):
            try:run_viewer()
            except SystemExit as exc:exit_code=exc.code if isinstance(exc.code,int) else 2
            except KeyboardInterrupt:interrupted=True;exit_code=130
            except Exception as exc:
                exit_code=2
                print(json.dumps(dict(status='FAILED',exception_type=type(exc).__name__)),flush=True)
    finally:
        budget.connection=None;budget.timer.cancel();sys.argv=saved_argv
        if observer is not None:observer_data=observer.stop()
        if previous is absent:del ViewerDB.progress_callback
        else:ViewerDB.progress_callback=previous
        if previous_d1 is absent:del ViewerDB.d1_explain
        else:ViewerDB.d1_explain=previous_d1
    result=console.result or {}
    cycle=result.get('total_cycle_seconds')
    if budget.expired.is_set():status='TIME_BUDGET_EXCEEDED'
    elif interrupted:status='STOPPED'
    elif exit_code==0 and result.get('status')=='PUBLISHED' and nonnegative_number(cycle):
        status='PUBLISHED_UNDER_BUDGET' if cycle<=300 else 'PUBLISHED_OVER_BUDGET'
    else:status='FAILED' if exit_code else result.get('status','INCOMPLETE')
    report=dict(status=status,mode='one_normal_live_window',result=result,progress=progress,
        wal_compression=compression_check,pg_observer=observer_data,
        elapsed_seconds=round(time.monotonic()-started,3),cycle_budget_seconds=300,
        runtime_source_sha256=runtime_source_digest(),
        operational_acceptance='REQUIRES_SIX_WINDOWS_RESTART_RECHECK_AND_HTTP',
        production_modified=False)
    atomic_json(args.out,report)
    output.emit(dict(status=status,output=str(args.out)));output.close()
    return 0 if status=='PUBLISHED_UNDER_BUDGET' else (exit_code or 2)


if __name__=='__main__':raise SystemExit(main())
