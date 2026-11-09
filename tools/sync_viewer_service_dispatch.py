"""Repair only the three already captured OTP test requests and report safe facts."""
from pathlib import Path
import argparse,importlib.util,json,sys,traceback,uuid,zipfile
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from p24_foundation.viewer_data import ViewerDB,token
from p24_foundation.viewer_online import single_worker,live_status
from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json,ProgressConsole
from p24_foundation.viewer_dispatch_sync import repair_captured_dispatches
from tools.check_viewer_install import verify_release

DEFAULT_REQUESTS=('e8a40768-f9ec-4dc6-8b99-126e16fa187e','27661051-9b74-49c2-87b6-fb6a75de2d51',
                  'd5f7a094-9468-4dc6-84a3-7c1d376ca18e')


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--request-id',action='append',default=[])
    args=ap.parse_args(argv);raw_ids=args.request_id or DEFAULT_REQUESTS
    if not 1<=len(set(raw_ids))<=32:ap.error('Use 1..32 exact RequestIDs')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]
    private=ROOT/'private/service_dispatch_sync'/stamp;private.mkdir(parents=True,exist_ok=False)
    report=dict(status='RUNNING',runtime_source_sha256=runtime_source_digest(),
        native_postgresql='NOT_RUN',new_database_created=False,source_postgresql_restarted=False,
        source_capture_started=False,capacity_or_long_pilot_repeated=False)
    console=ProgressConsole()
    try:
        report['release']=verify_release(ROOT)
        if report['release']['status']!='PASS':raise ValueError('release_manifest_mismatch')
        spec=importlib.util.spec_from_file_location('dispatch_private_config',args.config.resolve());cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
        if getattr(cfg,'SQLITE_OFFLINE_PATH',None):raise ValueError('native_viewer_required')
        database=cfg.DATABASE
        if not str(database.get('dbname','')).startswith('p24_design_'):raise ValueError('isolated_viewer_database_required')
        keys=Path(cfg.KEYS_PATH).expanduser()
        if not keys.is_absolute():keys=ROOT/keys
        opts=dict(config=database,keys_path=keys)
        out=Path(getattr(cfg,'LIVE',{}).get('capture_dir','private/viewer_captures')).resolve()
        with ViewerDB(**opts) as db:
            with single_worker(db,out/'viewer_worker.lock'):
                db.progress_callback=console.progress
                request_keys=[token(db.keys,'request',r) for r in raw_ids]
                # Never increase the database's existing statement limit.
                existing=int(db.one("SELECT setting FROM pg_settings WHERE name='statement_timeout'")['setting'])
                limit=min(existing,30000) if existing else 30000
                db.sql("SELECT set_config('statement_timeout', ?, false)",(str(limit),));db.conn.commit()
                report['repair']=repair_captured_dispatches(db,request_keys)
                report['requests']=[]
                for rid,key in zip(raw_ids,request_keys):
                    card=db.request(key);context=card.get('service_context') if card else None
                    semantic=db.one('SELECT anchor_key,state,kind,root_call FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
                    report['requests'].append(dict(raw_request_id=rid,request_key=key,
                        phase=context['phase'] if context else 'UNRESOLVED',
                        service_api=context['service_path'] if context else None,
                        http_transport=context['transport_api'] if context else None,
                        otp_validation_codes=context['otp_validation_codes'] if context else [],
                        inquiry_result_codes=context['inquiry_result_codes'] if context else [],
                        semantic=semantic,viewer_url='http://127.0.0.1:5021/request/'+key))
                report['live']=live_status(db)
                checks=dict(preservation=report['repair']['raw_events_links_and_manual_roles_preserved'],
                            cursor_preserved=not report['repair']['checkpoint_advanced'])
                if tuple(raw_ids)==DEFAULT_REQUESTS:
                    items=report['requests'];checks.update(
                        exact_three_phases=[r['phase'] for r in items]==['otp_required','selection_pending','inquiry_result_reported'],
                        original_service_identified=all(r['service_api']=='Services.v1/SocialSecurityInsuranceElectronicPrescription' for r in items),
                        actual_http_transport_preserved=all(r['http_transport']=='Services.v1/InvoiceRegister' for r in items),
                        one_completed_service_occurrence=sum(bool(r['semantic'] and r['semantic']['state']=='active') for r in items)==1,
                        final_service_active=bool(items[-1]['semantic'] and items[-1]['semantic']['state']=='active' and items[-1]['semantic']['kind']=='service_execution'))
                report['native_feature_checks']=checks
                report['native_postgresql']='PASS_CAPTURED_REQUEST_REPAIR' if all(checks.values()) else 'NEEDS_REVIEW'
                report['cross_request_otp_link']='NOT_ESTABLISHED_NO_SHARED_CHALLENGE_ID'
                report['actual_browser_review']='NOT_RUN'
                report['status']=report['repair']['status'] if all(checks.values()) else 'REPAIRED_BUT_NEEDS_REVIEW'
    except Exception as exc:
        (private/'failure.private.log').write_text(traceback.format_exc(),encoding='utf-8')
        report.update(status='FAILED',error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
        allowed={'viewer_worker_already_running','requested_dispatches_not_all_captured',
            'existing_ready_semantic_index_required','existing_keys_fingerprint_mismatch','release_manifest_mismatch'}
        if str(exc) in allowed:report['error_code']=str(exc)
    finally:console.close()
    atomic_json(private/'service_dispatch_sync.json',report)
    out=ROOT/'validation'/('service_dispatch_sync_'+stamp+'.zip');out.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('service_dispatch_sync.json',json.dumps(report,ensure_ascii=True,indent=2))
    print(json.dumps(dict(status=report['status'],output=str(out))))
    return 2 if report['status']=='FAILED' else 0


if __name__=='__main__':raise SystemExit(main())
