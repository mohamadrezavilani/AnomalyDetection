"""Import verified local gzip windows and run the isolated real-data Viewer.

Examples:
 python tools/run_behavior_viewer.py init --config viewer_config.local.py
 python tools/run_behavior_viewer.py import --config viewer_config.local.py --path PRIVATE/EVIDENCE
 python tools/run_behavior_viewer.py serve --config viewer_config.local.py
"""
from __future__ import annotations
import argparse,contextlib,importlib.util,json,sys,time,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('init','import','rebuild','backfill','hydrate-raw','backfill-identity','raw-status','stats','contract-build','semantic-index-build','semantic-index-status','catalog-status','catalog-sync','serve','live','live-once','live-status','live-recent','recheck'))
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--path',type=Path,action='append',default=[])
    parser.add_argument('--host',choices=('127.0.0.1','localhost'),default='127.0.0.1')
    parser.add_argument('--port',type=int,default=5021)
    parser.add_argument('--window-start',help='Explicit UTC five-minute window for recheck')
    parser.add_argument('--progress',action='store_true',help='Show non-blocking phase progress for the live worker')
    parser.add_argument('--no-prefetch',action='store_true',help='Live worker: fetch each window serially')
    startup=parser.add_mutually_exclusive_group()
    startup.add_argument('--debug-recent-start',dest='debug_recent_start',action='store_true',
                         help='Debug only: start at the latest fully closed window; retain evidence and record gaps')
    startup.add_argument('--resume-checkpoint',dest='debug_recent_start',action='store_false',
                         help='Continue the durable checkpoint without a debug seek')
    parser.set_defaults(debug_recent_start=None)
    parser.add_argument('--wal-compression',choices=('pglz','lz4','zstd'),default=None,
                        help='Optional lossless transaction-local WAL compression for Viewer live publication')
    parser.add_argument('--lookback-windows',type=int,default=2,help='live-recent only: retained recent five-minute closed windows (default 2)')
    args=parser.parse_args()
    if args.debug_recent_start is not None and args.command not in ('live','live-once'):
        parser.error('Startup mode is only valid for live or live-once')
    if args.wal_compression and args.command not in ('live','live-once','recheck'):
        parser.error('--wal-compression is only valid for live, live-once or recheck')
    if args.command=='live-recent' and not 1<=args.lookback_windows<=288:
        parser.error('--lookback-windows must be 1..288')
    if not args.config.is_file():parser.error('Viewer config file not found')
    spec=importlib.util.spec_from_file_location('viewer_private_config',args.config.resolve())
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    keys_path=Path(mod.KEYS_PATH).expanduser().resolve()
    if not keys_path.exists():
        if args.command!='init':parser.error('Generate local private keys first with the init command')
        keys_path.parent.mkdir(exist_ok=True,parents=True)
        generate_keys(keys_path)
    if getattr(mod,'SQLITE_OFFLINE_PATH',None):
        opts={'sqlite_path':Path(mod.SQLITE_OFFLINE_PATH),'keys_path':keys_path}
    else:
        opts={'config':mod.DATABASE,'keys_path':keys_path}
        if not str(mod.DATABASE.get('dbname','')).startswith('p24_design_'):
            parser.error('Only disposable p24_design_* PostgreSQL databases allowed')
    if args.command=='serve':
        from p24_foundation.viewer_runtime import ProgressConsole
        console=ProgressConsole() if args.progress else None
        try:
            with ViewerDB(**opts) as db:
                if console:db.progress_callback=console.progress
                db.progress('viewer_web_initializing')
                db.init();db.init_semantic_index()
                db.progress('viewer_web_ready')
        finally:
            if console:console.close()
        from p24_foundation.viewer_ui import create_viewer_app
        app=create_viewer_app(opts);app.run(host=args.host,port=args.port,use_reloader=False,debug=False)
        return
    if args.command=='live-recent':
        from p24_foundation.viewer_online import initialize_live,bind_stream,single_worker,resume_recent,utc_ns
        from p24_foundation.viewer_elastic import stream_key
        from p24_foundation.viewer_runtime import atomic_json
        from p24_foundation.viewer_failure import describe_failure
        settings=getattr(mod,'LIVE',{})
        out=Path(settings.get('capture_dir','private/viewer_captures')).expanduser().resolve()
        try:
            with ViewerDB(**opts) as db:
                with single_worker(db,out/'viewer_worker.lock'):
                    db.init();initialize_live(db)
                    bind_stream(db,start_ns=utc_ns(getattr(mod,'LIVE_START_UTC',None)),
                        stream_key=stream_key(mod.ELASTICSEARCH),lag_seconds=settings.get('lag_seconds',60),
                        overlap_windows=settings.get('overlap_windows',2))
                    result=resume_recent(db,lookback_windows=args.lookback_windows)
            atomic_json(Path('validation/live_recent_start.json'),result)
            print(json.dumps(result,ensure_ascii=False,indent=2))
        except Exception as exc:
            failure=describe_failure(exc,stage='recent_start')
            if isinstance(exc,ValueError) and str(exc) in ('viewer_worker_already_running',
                    'live_stream_or_keys_changed','live_keys_changed','invalid_closed_window'):
                failure['code']=str(exc)
            print(json.dumps(dict(status='FAILED',failure=failure)))
            raise SystemExit(2)
        return
    if args.command in ('live','live-once','live-status','recheck'):
        from p24_foundation.viewer_online import (initialize_live,bind_stream,live_status,
             LiveWorker,single_worker,utc_ns)
        from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture,stream_key
        from p24_foundation.viewer_prefetch import OneWindowPrefetch
        if args.command=='live-status':
            with ViewerDB(**opts) as db:result=live_status(db)
            print(json.dumps(result,ensure_ascii=False,indent=2));return
        start=utc_ns(getattr(mod,'LIVE_START_UTC',None))
        if start is None:parser.error('Set explicit aligned LIVE_START_UTC in the private config')
        es=getattr(mod,'ELASTICSEARCH',{})
        settings=getattr(mod,'LIVE',{})
        # This owner-requested debug build defaults continuous launches to a
        # recent CLOSED window, also for existing private configs. One-shot
        # checks/rechecks retain their checkpoint unless explicitly requested.
        debug_recent=(settings.get('debug_recent_start',True) if args.command=='live' else False)
        if args.debug_recent_start is not None:debug_recent=args.debug_recent_start
        if type(debug_recent) is not bool:parser.error('LIVE.debug_recent_start must be True or False')
        out=Path(settings.get('capture_dir','private/viewer_captures')).expanduser().resolve()
        try:
            capture=ElasticCapture(ElasticREST(es),out,page_size=settings.get('page_size',5000),
                max_seconds=settings.get('capture_budget_seconds',240))
        except (ValueError,TypeError):parser.error('Invalid private Elasticsearch/LIVE settings')
        poll=settings.get('poll_seconds',30)
        if type(poll) is not int or not 1<=poll<=60:parser.error('LIVE.poll_seconds must be 1..60')
        recheck=utc_ns(args.window_start) if args.window_start else None
        if args.command=='recheck' and recheck is None:parser.error('recheck requires --window-start with UTC offset')
        from p24_foundation.viewer_runtime import ProgressConsole
        console=ProgressConsole()
        startup_pending=True
        try:
            while True:
                try:
                    with ViewerDB(**opts) as db:
                        if args.wal_compression:
                            if db.sqlite:raise ValueError('wal_compression_requires_postgresql')
                            db._publication_wal_compression=args.wal_compression
                        if args.progress:db.progress_callback=console.progress
                        # A second worker never runs initialization while another
                        # holds the session lock. No background start on web GET.
                        with single_worker(db,out/'viewer_worker.lock'):
                            db.init();initialize_live(db)
                            bind_stream(db,start_ns=start,stream_key=stream_key(es),
                              overlap_windows=settings.get('overlap_windows',2),
                              lag_seconds=settings.get('lag_seconds',60))
                            if startup_pending:
                                from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest
                                from p24_foundation.viewer_display_time import tehran_time
                                from p24_foundation.viewer_online import now_ns,iso
                                if debug_recent:
                                    from p24_foundation.viewer_online import resume_recent
                                    recent=resume_recent(db,lookback_windows=1)
                                    # Reconnecting after a publication failure
                                    # must retry that same window, never seek again.
                                    startup_pending=False
                                    receipt=dict(mode='DEBUG_RECENT_START',runtime_source_sha256=runtime_source_digest(),**recent)
                                else:
                                    startup_pending=False
                                    receipt=dict(mode='RESUME_CHECKPOINT',runtime_source_sha256=runtime_source_digest(),live=live_status(db))
                                receipt.update(pid=os.getpid(),started_at_utc=iso(now_ns()))
                                receipt['started_at_tehran']=tehran_time(receipt['started_at_utc'])
                                receipt['selected_from_tehran']=tehran_time(receipt['live']['continuous_published_to_utc'])
                                atomic_json(Path('validation/viewer_startup.json'),receipt)
                                console.emit(dict(stage='startup',**receipt))
                            preparation=(OneWindowPrefetch(capture) if args.command=='live' and not args.no_prefetch
                                         else contextlib.nullcontext(None))
                            with preparation as prefetch:
                                worker=LiveWorker(db,capture,prefetch=prefetch)
                                while True:
                                    result=worker.step(recheck_start=recheck)
                                    console.emit(result)
                                    if args.command!='live':return
                                    # Backlog drains without a 30-second sleep per
                                    # window; rechecks/waiting use a bounded poll.
                                    if result.get('status')=='WAITING' or result.get('mode')!='forward':time.sleep(poll)
                except ValueError as exc:
                    allowed={'viewer_worker_already_running','live_stream_or_keys_changed',
                             'invalid_closed_window','window_not_closed'}
                    console.emit(dict(status='STOPPED',error=str(exc) if str(exc) in allowed else 'invalid_live_configuration'))
                    raise SystemExit(2)
                except Exception as exc:
                    from p24_foundation.viewer_failure import describe_failure
                    console.emit(dict(status='RETRY_PENDING',error='capture_or_publication_failed',failure=describe_failure(exc)))
                    if args.command!='live':raise SystemExit(2)
                    time.sleep(poll)
        except KeyboardInterrupt:
            console.emit(dict(status='STOPPED',checkpoint='durable_last_committed_window'))
        finally:console.close()
        return
    with ViewerDB(**opts) as db:
        if args.command=='init':
            db.init();db.init_semantic_index()
            if getattr(mod,'LIVE_START_UTC',None) and getattr(mod,'ELASTICSEARCH',None):
                from p24_foundation.viewer_online import initialize_live,bind_stream,utc_ns
                from p24_foundation.viewer_elastic import stream_key
                settings=getattr(mod,'LIVE',{})
                initialize_live(db)
                bind_stream(db,start_ns=utc_ns(mod.LIVE_START_UTC),stream_key=stream_key(mod.ELASTICSEARCH),
                    overlap_windows=settings.get('overlap_windows',2),lag_seconds=settings.get('lag_seconds',60))
            result={'status':'INITIALIZED'}
        elif args.command=='rebuild':result={'model':db.rebuild()}
        elif args.command=='backfill-identity':result={'identity_assertions':db.backfill_identity_assertions(),'model_state':'STALE_UNTIL_REBUILD'}
        elif args.command in ('import','backfill','hydrate-raw'):
            paths=[]
            for root in args.path:
                if root.is_dir():paths.extend(root.rglob('*.json.gz'))
                elif root.is_file() and root.name.endswith('.json.gz'):paths.append(root)
                else:parser.error(f'Input path missing or unsupported: {root.resolve()} (expected directory or .json.gz file)')
            if not paths:parser.error('No *.json.gz files found under the supplied paths; check the extracted evidence folder')
            if args.command=='import':result={'import':db.ingest(sorted(set(paths))),'model_state':'STALE_UNTIL_REBUILD'}
            elif args.command=='hydrate-raw':result={'hydration':db.hydrate_raw(sorted(set(paths))),'coverage':db.raw_coverage()}
            else:result={'backfill':db.backfill_payment_observations(sorted(set(paths))),'model_state':'STALE_UNTIL_REBUILD'}
        elif args.command=='raw-status':result=db.raw_coverage()
        elif args.command=='catalog-status':result=db.service_catalog_status()
        elif args.command=='catalog-sync':result=db.sync_service_catalog()
        elif args.command=='semantic-index-build':result=db.build_semantic_index()
        elif args.command=='semantic-index-status':result=db.semantic_checkpoint() or {'status':'NOT_READY'}
        elif args.command=='contract-build':result={'contract':db.rebuild_payment_contract()}
        else:result=db.metrics()
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if args.command=='import' and any(x['status']=='REJECTED' for x in result['import']):
        raise SystemExit(2)
    if args.command=='hydrate-raw' and any(x['status']!='HYDRATED' for x in result['hydration']):
        raise SystemExit(2)

if __name__=='__main__':main()
