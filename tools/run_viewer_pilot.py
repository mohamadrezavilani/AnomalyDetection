"""Bounded live pilot: full acceptance (6+2) or explicit two-window development smoke.

Uses only the configured Viewer DB and read-only Elasticsearch transport.
Never resets a DB or starts a detector. Produces a compact safe JSON result.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from urllib.request import urlopen
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from werkzeug.serving import make_server,WSGIRequestHandler
from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.viewer_online import (LiveWorker,single_worker,initialize_live,bind_stream,live_status,now_ns,FIVE_NS)
from p24_foundation.viewer_online import peak_rss_kib
from p24_foundation.viewer_elastic import ElasticCapture,ElasticREST,stream_key
from p24_foundation.viewer_prefetch import OneWindowPrefetch
from p24_foundation.viewer_ui import create_viewer_app
from p24_foundation.viewer_failure import describe_failure
from p24_foundation.viewer_runtime import ProgressConsole,atomic_json,runtime_source_digest
from p24_foundation.viewer_acceptance import evaluate_pilot,evaluate_development_smoke


class QuietHandler(WSGIRequestHandler):
    def log(self,*args,**kwargs):pass


class PilotBudgetExceeded(RuntimeError):pass


class PilotDeadline:
    """Cancel current SQL at the wall-clock budget; stop between CPU batches."""
    def __init__(self,seconds):
        self.expired=threading.Event();self.connection=None
        self.timer=threading.Timer(seconds,self.expire);self.timer.daemon=True
    def expire(self):
        self.expired.set()
        connection=self.connection
        cancel=getattr(connection,'cancel_safe',None) or getattr(connection,'cancel',None)
        if callable(cancel):
            try:cancel()
            except Exception:pass
    def check(self):
        if self.expired.is_set():raise PilotBudgetExceeded('pilot_time_budget_exceeded')


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--windows',type=int,default=6)
    ap.add_argument('--out',type=Path,default=Path('validation/live_acceptance.json'))
    ap.add_argument('--max-minutes',type=int,default=45)
    ap.add_argument('--smoke',action='store_true',help='Development-only small sample; never operational acceptance')
    ap.add_argument('--rechecks',type=int,default=None,help='Smoke: 0..2. Full pilot requires 2.')
    ap.add_argument('--no-prefetch',action='store_true',help='Fetch windows serially for comparison')
    args=ap.parse_args(argv)
    if args.smoke:
        if not 1<=args.windows<=5 or not 5<=args.max_minutes<=45:
            ap.error('Development smoke requires 1..5 windows and 5..45 minutes')
        required_rechecks=0 if args.rechecks is None else args.rechecks
        if not 0<=required_rechecks<=2:ap.error('Smoke rechecks must be 0..2')
    else:
        if not 6<=args.windows<=288 or not 5<=args.max_minutes<=1440 or args.rechecks not in (None,2):
            ap.error('Full pilot requires >=6 windows and exactly 2 rechecks')
        required_rechecks=2

    spec=importlib.util.spec_from_file_location('viewer_pilot_config',args.config.resolve())
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    keys=Path(cfg.KEYS_PATH).resolve()
    if not keys.is_file():ap.error('Run Viewer init first; preserve the existing key file')
    opts={'keys_path':keys}
    if getattr(cfg,'SQLITE_OFFLINE_PATH',None):ap.error('Live acceptance requires PostgreSQL Viewer DB')
    opts['config']=cfg.DATABASE
    settings=getattr(cfg,'LIVE',{});es=cfg.ELASTICSEARCH
    capture_dir=Path(settings.get('capture_dir','private/viewer_captures')).resolve()
    capture=ElasticCapture(ElasticREST(es),capture_dir,page_size=settings.get('page_size',5000),
                          max_seconds=settings.get('capture_budget_seconds',240))
    capture_stop=threading.Event();ui_sampled=threading.Event()
    samples={};http_errors=[];routes={'home':'/'}
    console=ProgressConsole(min_interval=5)
    progress_started=time.monotonic();phase_trace=[]
    budget=PilotDeadline(args.max_minutes*60)
    def show_progress(event):
        budget.check()
        phase_trace.append(dict(progress=event,elapsed_seconds=round(time.monotonic()-progress_started,3)))
        if len(phase_trace)>1000:del phase_trace[:100]
        console.progress(event)
    app=create_viewer_app(opts)
    server=make_server('127.0.0.1',0,app,threaded=True,request_handler=QuietHandler)
    server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
    base='http://127.0.0.1:'+str(server.server_port)
    def probe():
        while not capture_stop.is_set():
            for kind in ('home','session','request'):
                if capture_stop.is_set():break
                path=routes.get(kind)
                if path is None:continue
                began=time.monotonic()
                try:
                    with urlopen(base+path,timeout=15) as response:body=response.read().decode('utf-8')
                    samples.setdefault(kind,[]).append(time.monotonic()-began)
                    if kind=='home':
                        found=re.search(r'href="(/session/[0-9a-f]{64}/behavior)',body)
                        if found:routes['session']=found[1]
                    if kind=='session':
                        found=re.search(r'href="(/request/[0-9a-f]{64})',body)
                        if found:routes['request']=found[1]
                except Exception:http_errors.append(kind)
            if all(samples.get(kind) for kind in ('home','session','request')):ui_sampled.set()
            capture_stop.wait(2)
    probe_thread=threading.Thread(target=probe,daemon=True);probe_thread.start()
    report=dict(mode='live_owner_postgresql_smoke' if args.smoke else 'live_owner_postgresql_pilot',
        status='RUNNING',smoke_mode=bool(args.smoke),windows=[],
        rechecks=[],restart_performed=False,production_modified=False,
        full_r5_acceptance=0,capacity_800k_requests_per_hour='NOT_PROVEN_BY_SMALL_PILOT',
        requested_windows=args.windows,required_rechecks=required_rechecks,cycle_budget_seconds=300,
        runtime_source_sha256=runtime_source_digest(),max_minutes=args.max_minutes,
        time_budget_covers_all_cycle_limits=(args.max_minutes*60>=(args.windows+required_rechecks)*300+120),
        prefetch=dict(enabled=not args.no_prefetch,depth=1,max_age_seconds=300,
                      database_writers=1,rechecks='always_fresh'))
    def persist():
        report['phase_trace']=list(phase_trace)
        atomic_json(args.out,report)
    persist()
    deadline=time.monotonic()+args.max_minutes*60
    cpu_began=time.process_time()
    budget.timer.start()
    phase='connect_viewer_database'
    prefetch=None if args.no_prefetch else OneWindowPrefetch(capture)
    try:
        forwards=0;restart_at=max(1,args.windows//2);restarted=False;overlap_done=0
        while time.monotonic()<deadline:
            phase='connect_viewer_database'
            show_progress(dict(stage=phase))
            with ViewerDB(**opts) as db:
                budget.connection=getattr(db,'conn',None)
                db.progress_callback=show_progress
                info=getattr(budget.connection,'info',None)
                if info is not None:show_progress(dict(stage='worker_database',backend_pid=info.backend_pid))
                if not getattr(db,'sqlite',True):
                    db.sql("SELECT set_config('statement_timeout', ?, false)",('300000',))
                phase='acquire_worker_lock'
                show_progress(dict(stage=phase))
                with single_worker(db,capture_dir/'viewer_worker.lock'):
                    phase='initialize_viewer_schema'
                    show_progress(dict(stage=phase))
                    db.init();initialize_live(db)
                    phase='bind_stream'
                    show_progress(dict(stage=phase))
                    bind_stream(db,start_ns=utc_ns(cfg.LIVE_START_UTC),stream_key=stream_key(es),
                        lag_seconds=settings.get('lag_seconds',60),overlap_windows=settings.get('overlap_windows',2))
                    if 'before' not in report:report['before']=live_status(db)
                    worker=LiveWorker(db,capture,prefetch=prefetch)
                    expected=db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
                    if restarted:
                        report['restart_checkpoint_preserved']=(expected==report['restart_expected_ns'])
                        report['restart_performed']=True
                        persist()
                    while time.monotonic()<deadline:
                        phase='worker_step'
                        if forwards>=args.windows:
                            if overlap_done>=report['required_rechecks']:break
                            # Explicit rechecks after the measured six forward
                            # windows, even if catch-up still has a backlog.
                            start=expected-(overlap_done+1)*FIVE_NS
                            result=worker.step(recheck_start=start);overlap_done+=1
                            report['rechecks'].append(result)
                            persist()
                        else:
                            result=worker.step(prefetch_next=forwards+1<args.windows)
                            if result.get('mode')=='forward':
                                forwards+=1;report['windows'].append(result)
                                expected=db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
                                persist()
                                console.emit(dict(published=forwards,records=result['records'],cycle_seconds=result['total_cycle_seconds'],capture_method=result.get('capture_method')))
                            elif result.get('mode')=='recheck':report['rechecks'].append(result)
                        if not restarted and forwards==restart_at:
                            report['restart_expected_ns']=expected
                            break
                        if result.get('status')=='WAITING':time.sleep(min(30,max(0,deadline-time.monotonic())))
                    if forwards>=args.windows and overlap_done>=report['required_rechecks']:
                        report['after']=live_status(db);break
            if not restarted and forwards==restart_at:restarted=True
        ui_sampled.wait(timeout=10)
        capture_stop.set();probe_thread.join(timeout=20)
        report.pop('restart_expected_ns',None)
        def latency(values):
            values=sorted(values)
            return dict(samples=len(values),p95_seconds=round(values[max(0,math.ceil(.95*len(values))-1)],4),
                        max_seconds=round(max(values),4))
        report['http_latency']={k:latency(v) for k,v in samples.items() if v}
        report['http_errors']=len(http_errors)
        report['cpu_seconds']=round(time.process_time()-cpu_began,3)
        report['peak_rss_kib']=peak_rss_kib()
        report['cycle_budget_seconds']=300
        report['all_cycles_under_budget']=all(r['total_cycle_seconds']<=300 for r in report['windows']+report['rechecks'])
        report['steady_state_cycles_under_budget']=all(r['total_cycle_seconds']<=300 for r in report['windows']+report['rechecks'] if not r.get('bootstrap'))
        # Historical adoption is separately visible, never hidden in an SLA claim.
        report['bootstrap_cycles']=[r for r in report['windows'] if r.get('bootstrap')]
        report['ui_budget_met']=(all(samples.get(k) for k in ('home','session','request')) and
            report['http_latency']['home']['p95_seconds']<=2 and
            all(v['p95_seconds']<=3 for k,v in report['http_latency'].items() if k!='home'))
        report['backlog_not_growing']=(report.get('after',{}).get('backlog_windows',10**9)<=report['before']['backlog_windows'])
        report['checks']=evaluate_pilot(report)
        if args.smoke:
            report['smoke_checks']=evaluate_development_smoke(report)
            report['status']='SMOKE_PASS' if all(report['smoke_checks'].values()) else 'SMOKE_CONDITIONAL'
        else:
            report['status']='PASS' if all(report['checks'].values()) else 'CONDITIONAL'
    except KeyboardInterrupt:report['status']='INTERRUPTED'
    except Exception as exc:
        report['status']='FAILED';report['error']=type(exc).__name__
        report['failure']=describe_failure(exc,stage=phase)
        if budget.expired.is_set():report['failure']['code']='pilot_time_budget_exceeded'
    finally:
        if prefetch is not None:prefetch.close()
        budget.connection=None;budget.timer.cancel()
        capture_stop.set();probe_thread.join(timeout=20)
        server.shutdown();server.server_close()
        if 'after' not in report:
            try:
                final_options=dict(opts);final_options['config']=dict(opts['config'])
                final_options['config'].setdefault('connect_timeout',10)
                with ViewerDB(**final_options) as final_db:
                    final_db.sql('SET TRANSACTION READ ONLY')
                    final_db.sql('SET LOCAL statement_timeout=10000')
                    report['after']=live_status(final_db)
            except Exception:report['after_status']='UNAVAILABLE'
        report['checks']=evaluate_pilot(report)
        if args.smoke:report['smoke_checks']=evaluate_development_smoke(report)
        report['prefetch'].update(
            windows_prefetched=sum(r.get('prefetched') is True for r in report['windows']),
            capture_work_seconds=round(sum(r.get('capture_seconds',0) for r in report['windows']),3),
            capture_wait_seconds=round(sum(r.get('capture_wait_seconds',r.get('capture_seconds',0)) for r in report['windows']),3),
            capture_overlap_seconds=round(sum(r.get('capture_overlap_seconds',0) for r in report['windows']),3))
        report['console_messages_dropped']=console.dropped
        report['console_io_errors']=console.io_errors
        persist()
    summary=dict(status=report['status'],output=str(args.out))
    if report.get('failure'):summary['failure']=report['failure']
    console.emit(summary);console.close()
    return 0 if report['status'] in ('PASS','SMOKE_PASS') else 2

if __name__=='__main__':raise SystemExit(main())
