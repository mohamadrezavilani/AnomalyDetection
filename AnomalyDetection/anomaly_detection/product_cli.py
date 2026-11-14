"""The production command surface is PostgreSQL-only, including fresh installs."""
import argparse
import json
from pathlib import Path
import sys

from . import BUILD_ID
from .process_control import safe_failure
from .product_control import start,stop,status,export_report

ROOT=Path(__file__).resolve().parents[1]


def main(sha):
    parser=argparse.ArgumentParser(description='Autonomous PostgreSQL AnomalyDetection')
    parser.add_argument('command',choices=('version','worker-start','worker-stop','worker-status','worker-run','worker-report',
        'case-review','acceptance-report','history-reset','history-rescan','worker-observe','worker-follow','web-run','serve','product-check','reference-report','presentation-check'))
    parser.add_argument('--seconds',type=int,choices=range(0,91),metavar='0..90',default=None)
    parser.add_argument('--session',default=None)
    parser.add_argument('--target-tehran',default=None)
    parser.add_argument('--from-tehran-date',metavar='YYYY-MM-DD')
    parser.add_argument('--pg-data-dir',type=Path)
    parser.add_argument('--replay-id',help='Durable Viewer history replay identity')
    parser.add_argument('--instance-token',help=argparse.SUPPRESS)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if args.command in ('history-reset','history-rescan') and not args.from_tehran_date:
        parser.error('history command requires --from-tehran-date')
    if args.command=='history-rescan' and not args.replay_id:
        parser.error('history-rescan requires --replay-id')
    if args.command!='history-rescan' and args.replay_id:
        parser.error('--replay-id requires history-rescan')
    if args.command=='history-rescan' and (args.apply or args.pg_data_dir):
        parser.error('history-rescan preserves data and does not use reset flags')
    if args.command not in ('history-reset','history-rescan') and (args.from_tehran_date or args.apply or args.pg_data_dir):
        parser.error('history reset arguments require history-reset')
    if args.command!='worker-run' and args.instance_token is not None:
        parser.error('the startup token requires worker-run')
    try:
        command=args.command
        if command=='version':value={'build_id':BUILD_ID,'source_sha256':sha,'storage_backend':'postgresql','sqlite_loaded':'sqlite3' in sys.modules}
        elif command=='worker-start':
            value=start(ROOT,sha)
            print(json.dumps(value,ensure_ascii=False,indent=2));return 0 if value['status'] in ('STARTED','STARTING','ALREADY_RUNNING') else 2
        elif command=='worker-stop':
            value=stop(ROOT);print(json.dumps(value,ensure_ascii=False));return 0 if value['status'] in ('STOPPED','ALREADY_STOPPED') else 2
        elif command=='worker-status':value=status(ROOT)
        elif command=='history-rescan':
            from .history_rescan import run as rescan_history
            value=rescan_history(ROOT,sha,args.from_tehran_date,args.replay_id)
        elif command=='history-reset':
            from .history_reset import run as reset_history
            value=reset_history(ROOT,sha,args.from_tehran_date,apply=args.apply,pg_data_dir=args.pg_data_dir)
            value.update(build_id=BUILD_ID,source_sha256=sha)
            print(json.dumps(value,ensure_ascii=False,indent=2))
            return 2 if value['status']=='HISTORY_RESET_BLOCKED' else 0
        elif command=='worker-run':
            from .product_worker import run
            return run(ROOT,sha,instance_token=args.instance_token)
        elif command in ('web-run','serve'):
            from .product_web import serve
            return serve(ROOT,sha)
        elif command=='acceptance-report':
            from .acceptance_report import collect
            value=collect(ROOT,sha,seconds=args.seconds if args.seconds is not None else 60)
        elif command=='case-review':
            from .case_export import main as case_review
            return case_review(project=ROOT.parent)
        elif command=='presentation-check':
            if not args.session or not args.target_tehran:raise ValueError('--session and --target-tehran are required')
            from .native_pg import database
            from .product_store import ProductStore
            from .presentation_proof import collect,target_time
            from datetime import datetime,timezone
            import uuid
            with database(ROOT,readonly=True) as raw:
                with raw.transaction():
                    raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                    value=collect(ProductStore(raw),args.session,target_time(args.target_tehran))
            value['source_sha256']=sha
            output=ROOT/'reports'/('presentation_proof_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.json')
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            value['output']=str(output)
        elif command=='reference-report':
            from .native_pg import database
            from .product_store import ProductStore
            from .service_reference import case_report
            from datetime import datetime,timezone
            import zipfile
            with database(ROOT,readonly=True) as raw:value=case_report(ProductStore(raw))
            value.update(build_id=BUILD_ID,source_sha256=sha,status='READ_ONLY_PERSISTED_REFERENCE_REPORT')
            output=ROOT/'reports'/('reference_cases_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.zip')
            output.parent.mkdir(parents=True,exist_ok=True)
            with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('reference_cases.json',json.dumps(value,ensure_ascii=False,indent=2))
            value={'status':value['status'],'output':str(output),'cases':value['cases'],'reference_import':value['reference_import']}
        elif command=='product-check':
            from .native_pg import database
            with database(ROOT,readonly=True) as raw:
                row=raw.execute("SELECT current_database() AS db,current_user AS role,current_setting('transaction_read_only') AS read_only,"
                    "to_regclass('anomaly_detection.adp_facts')::text AS facts,to_regclass('anomaly_detection.adp_incidents')::text AS incidents").fetchone()
            value={'status':'PASS' if row['facts'] and row['incidents'] else 'WAITING_FOR_WORKER_INITIALIZATION','database':dict(row),
                'storage_backend':'postgresql','sqlite_loaded':'sqlite3' in sys.modules,'native_accuracy':'NOT_EVALUATED'}
        else:
            seconds=args.seconds if args.seconds is not None else 90 if command=='worker-follow' else 45 if command=='worker-observe' else 0
            observed,path=export_report(ROOT,sha,observe_seconds=seconds)
            value={'status':'REPORT_EXPORTED','health':observed['health'],'output':str(path),'web_url':'http://127.0.0.1:5022/',
                'build_id':BUILD_ID,'source_sha256':sha}
        print(json.dumps(value,ensure_ascii=False,indent=2));return 0
    except Exception as exc:
        print(json.dumps({'status':'ERROR','failure':safe_failure(exc)},ensure_ascii=False));return 1
