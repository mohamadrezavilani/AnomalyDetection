"""Finite native PG checks in NEW synthetic qualification databases only.

No live ingestion, owner-DB restore, server crash/restart, tuning, or ES access.
Existing Viewer credentials are reused locally; no secrets enter the report ZIP.
The created test databases are retained. Full owner-backup restore and 800K/h
capacity remain separate gates, even when all these small tests pass.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import unittest
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_runtime import atomic_json, runtime_source_digest
from p24_foundation.viewer_online import initialize_live, bind_stream, publish_capture, FIVE_NS
from tools.qualify_viewer_online import projection_digest
from tests.test_viewer_online import START, verified_file, OnlinePublisherTests
from tests.test_viewer_r6_service_journey import log

TEST_DB = re.compile(r'^p24_design_native_[a-f0-9]{8}_[a-z0-9_]+_qualification$')


def safe_error(exc):
    result=dict(error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
    codes={'real_d5_bidirectional_link_missing','real_d5_financial_finality_inferred',
        'real_d5_explicit_sql_pointer_missing','real_d5_render_or_navigation_failed',
        'child_requires_own_qualification_database','hard_cut_point_not_reached',
        'manifest_requires_own_synthetic_database','invalid_qualification_name','hard_cut_child_failed',
        'hard_cut_checkpoint_inconsistent','pre_commit_partial_publication','post_commit_receipt_count',
        'post_commit_full_rebuild_mismatch','reader_saw_partial_generation','reader_snapshot_changed',
        'fresh_snapshot_not_published','synthetic_restore_command_failed','synthetic_restore_full_row_hash_mismatch',
        'restore_recheck_advanced_checkpoint','restore_recheck_duplicated_raw',
        'existing_native_viewer_configuration_required'}
    if str(exc) in codes:
        result['error_code']=str(exc)
    return result


def owner_d5_readonly(database, keys):
    """Reconcile the previously supplied real example; no initialization."""
    raw_ids=('43d82ea2-6562-4fbb-ba8a-3c8bca723a21','b654298d-4028-4f8e-8378-8c8c3fa3996c',
             'c39022d5-4a3d-41ed-a01a-e713f50f054b')
    with ViewerDB(config=database,keys_path=keys) as db:
        db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        cards=[db.lookup_request(raw) for raw in raw_ids]
        if any(card is None for card in cards):
            return dict(status='NOT_RUN',reason='previous_real_d5_example_not_in_this_database')
        expected={card['request_key'] for card in cards}
        for card in cards:
            journey=card['bill_item_journey']
            present={x['request_key'] for kind in ('inquiries','basket_additions','payment_attempts') for x in journey[kind]}
            if not expected.issubset(present):
                raise RuntimeError('real_d5_bidirectional_link_missing')
            if journey['financial_confirmation']!='unverified':
                raise RuntimeError('real_d5_financial_finality_inferred')
            if not any('ud_prc_billsBelongs' in item['evidence']['callpath']
                       for item in journey['basket_additions'] if item['relation']=='explicit_item_selection'):
                raise RuntimeError('real_d5_explicit_sql_pointer_missing')
    from p24_foundation.viewer_ui import create_viewer_app
    client=create_viewer_app(dict(config=database,keys_path=keys)).test_client()
    timings=[]
    for card in cards:
        began=time.monotonic()
        response=client.get('/request/'+card['request_key'],base_url='http://127.0.0.1')
        html=response.get_data(as_text=True)
        if response.status_code!=200 or 'id="bill-item-journey"' not in html or not all(raw in html for raw in raw_ids):
            raise RuntimeError('real_d5_render_or_navigation_failed')
        timings.append(round(time.monotonic()-began,3))
    return dict(status='PASS',three_real_entry_points=True,sql_evidence_pointer=True,
                three_local_flask_page_seconds=timings,scope='real_sample_readonly_not_browser_or_load_p95')


def child(payload):
    opts=payload['opts']
    if 'config' in opts and not TEST_DB.fullmatch(str(opts['config'].get('dbname',''))):
        raise ValueError('child_requires_own_qualification_database')
    with ViewerDB(**opts) as db:
        def fault(stage):
            if stage==payload['point']:
                os._exit(73)
        publish_capture(db,Path(payload['capture']),payload['start'],payload['start']+FIVE_NS,fault=fault)
    raise RuntimeError('hard_cut_point_not_reached')


def manifest(db):
    """Full row hashes for the SMALL synthetic test databases, never owner DB."""
    if not db.sqlite:
        name=db.one('SELECT current_database() AS name')['name']
        if not TEST_DB.fullmatch(name):
            raise ValueError('manifest_requires_own_synthetic_database')
        tables=[x['tablename'] for x in db.all("SELECT tablename FROM pg_tables "
            "WHERE schemaname=current_schema() AND left(tablename,7)='viewer_' ORDER BY tablename")]
    else:
        tables=[x['name'] for x in db.all("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    result={}
    for table in tables:
        if not re.fullmatch('viewer_[a-z0-9_]+',table):
            continue
        rows=[json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True,
            default=lambda value:bytes(value).hex() if isinstance(value,(bytes,bytearray,memoryview)) else str(value))
            for row in db.all('SELECT * FROM '+table)]
        digest=hashlib.sha256()
        for row in sorted(rows):
            digest.update(row.encode());digest.update(b'\n')
        result[table]=dict(rows=len(rows),sha256=digest.hexdigest())
    return result


class Suite:
    def __init__(self, database, directory, report, out):
        self.database=dict(database);self.directory=directory;self.report=report;self.out=out
        self.run_id=uuid.uuid4().hex[:8];self.created=[]

    def record(self, name, value):
        self.report['checks'][name]=value
        atomic_json(self.directory/'native_final_checks.json',self.report)
        atomic_json(self.out,self.report)
        print(json.dumps(dict(check=name,status=value.get('status','UNKNOWN'))),flush=True)

    def create(self, purpose):
        import psycopg
        from psycopg import sql
        name='p24_design_native_'+self.run_id+'_'+purpose+'_qualification'
        if not TEST_DB.fullmatch(name) or len(name)>63:
            raise ValueError('invalid_qualification_name')
        config=dict(self.database,dbname=name)
        admin=dict(self.database,dbname='postgres',connect_timeout=10)
        with psycopg.connect(**admin,autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
        self.created.append(name)
        self.report['created_synthetic_databases']=list(self.created)
        return config

    def seed(self, purpose):
        config=self.create(purpose)
        root=self.directory/purpose;root.mkdir()
        keys=root/'keys.json';generate_keys(keys)
        opts=dict(config=config,keys_path=str(keys))
        first=log(1,'baseline','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        second=log(2,'next','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        second['@timestamp']='2026-10-24T04:20:01Z'
        a=verified_file(root/'a.gz',[first]);b=verified_file(root/'b.gz',[second],START+FIVE_NS)
        with ViewerDB(**opts) as db:
            db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='synthetic_native_qualification')
            publish_capture(db,a,START,START+FIVE_NS)
        return opts,a,b

    def hard_cuts(self):
        opts,a,b=self.seed('recovery')
        with ViewerDB(**opts) as db:
            before=manifest(db)
        checks=[]
        for point in ('after_ingest','after_requests','after_relations','after_semantics','before_commit','after_commit'):
            payload=dict(opts=opts,capture=str(b),start=START+FIVE_NS,point=point)
            run=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child'],
                input=json.dumps(payload),capture_output=True,text=True,timeout=90)
            if run.returncode!=73:
                (self.directory/'child_error.private.log').write_text(run.stderr,encoding='utf-8')
                raise RuntimeError('hard_cut_child_failed')
            with ViewerDB(**opts) as db:
                after=manifest(db);state=db.one('SELECT next_ns,generation FROM viewer_live_state WHERE id=1')
                expected=START+(2 if point=='after_commit' else 1)*FIVE_NS
                if state['next_ns']!=expected:
                    raise RuntimeError('hard_cut_checkpoint_inconsistent')
                if point!='after_commit' and after!=before:
                    raise RuntimeError('pre_commit_partial_publication')
                if point=='after_commit':
                    if db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n']!=2:
                        raise RuntimeError('post_commit_receipt_count')
                    inc=projection_digest(db)
                    db.rebuild();db.rebuild_payment_contract();db.build_semantic_index()
                    if inc!=projection_digest(db):
                        raise RuntimeError('post_commit_full_rebuild_mismatch')
            checks.append(dict(point=point,status='PASS',checkpoint_safe=True))
            self.record('publisher_cut_'+point,checks[-1])
        self.record('six_publisher_hard_cuts',dict(status='PASS',cases=checks,
            scope='actual_process_exit_on_native_postgresql_not_server_crash'))
        return opts,a,b

    def snapshot_reader(self):
        opts,a,b=self.seed('snapshot')
        with ViewerDB(**opts) as writer,ViewerDB(**opts) as reader:
            reader.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            old=manifest(reader)
            def observe(stage):
                if stage=='after_requests' and manifest(reader)!=old:
                    raise RuntimeError('reader_saw_partial_generation')
            publish_capture(writer,b,START+FIVE_NS,START+2*FIVE_NS,fault=observe)
            if manifest(reader)!=old:
                raise RuntimeError('reader_snapshot_changed')
            reader.conn.rollback()
            reader.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            if reader.one('SELECT COUNT(*) AS n FROM viewer_requests')['n']!=2:
                raise RuntimeError('fresh_snapshot_not_published')
        self.record('two_connection_atomic_snapshot',dict(status='PASS'))

    def late_cases(self):
        suite=self
        class NativeCases(OnlinePublisherTests):
            def setUp(self):
                purpose='late'+str(len(suite.created))
                config=suite.create(purpose)
                self.root=suite.directory/purpose;self.root.mkdir()
                self.keys=self.root/'keys.json';generate_keys(self.keys)
                self.opts=dict(config=config,keys_path=self.keys)
                self.db=ViewerDB(**self.opts);self.addCleanup(self.db.close)
                self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='synthetic')
        methods=('test_incremental_late_root_repeat_ip_and_batch_parity',
            'test_conflict_retracts_old_and_new_request_with_payment_dependency',
            'test_duplicate_capture_keeps_counts_roles_keys_and_restart_cursor',
            'test_reverse_late_rechecks_match_chronological_batch',
            'test_changed_payment_origin_invalidates_old_group_and_session_head',
            'test_capture_proof_and_corruption_rejected_without_database_changes')
        results=[]
        for method in methods:
            result=unittest.TestResult();NativeCases(method).run(result)
            ok=result.wasSuccessful()
            if not ok:
                (self.directory/(method+'.private.log')).write_text(
                    '\n'.join(text for _,text in result.errors+result.failures),encoding='utf-8')
            results.append(dict(test=method,status='PASS' if ok else 'FAIL'))
            self.record(method,results[-1])
        return all(x['status']=='PASS' for x in results)

    def logical_restore(self, opts, first, second, bindir):
        if bindir is None:
            self.record('synthetic_logical_restore',dict(status='NOT_RUN',reason='matching_pg_dump_pg_restore_not_found'))
            return
        suffix='.exe' if os.name=='nt' else ''
        pgdump=bindir/('pg_dump'+suffix);pgrestore=bindir/('pg_restore'+suffix)
        source=opts['config'];target=self.create('restore')
        archive=self.directory/'synthetic_restore.dump'
        env=dict(os.environ)
        if source.get('password') is not None:
            env['PGPASSWORD']=str(source['password'])
        args=['--host',str(source.get('host','127.0.0.1')),'--port',str(source.get('port',5432)),
              '--username',str(source.get('user','postgres')),'--no-password']
        with ViewerDB(**opts) as db:
            before=manifest(db)
        for command in ([str(pgdump),*args,'--format=custom','--file',str(archive),source['dbname']],
                        [str(pgrestore),*args,'--exit-on-error','--no-owner','--no-privileges','--dbname',target['dbname'],str(archive)]):
            run=subprocess.run(command,env=env,capture_output=True,timeout=180)
            if run.returncode:
                (self.directory/'restore_error.private.log').write_bytes(run.stderr)
                raise RuntimeError('synthetic_restore_command_failed')
        with ViewerDB(config=target,keys_path=opts['keys_path']) as db:
            if manifest(db)!=before:
                raise RuntimeError('synthetic_restore_full_row_hash_mismatch')
            state=db.one('SELECT next_ns FROM viewer_live_state WHERE id=1')['next_ns']
            raw=db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']
            publish_capture(db,first,START,START+FIVE_NS,mode='manual_recheck')
            if db.one('SELECT next_ns FROM viewer_live_state WHERE id=1')['next_ns']!=state:
                raise RuntimeError('restore_recheck_advanced_checkpoint')
            if db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']!=raw:
                raise RuntimeError('restore_recheck_duplicated_raw')
            empty=verified_file(self.directory/'restored_empty.gz',[],state)
            publish_capture(db,empty,state,state+FIVE_NS)
        self.record('synthetic_logical_restore',dict(status='PASS',full_viewer_table_row_hashes_match=True,
            fresh_recheck_and_forward=True,scope='small_synthetic_fixture_not_owner_backup'))


def pg_binaries(database):
    import psycopg
    candidates=[]
    found=shutil.which('pg_dump')
    connection=dict(database,connect_timeout=10)
    try:
        with psycopg.connect(**connection,autocommit=True) as conn:
            conn.execute('SET default_transaction_read_only=on')
            data=Path(conn.execute('SHOW data_directory').fetchone()[0])
            candidates.append(data.parent/'bin')
            version=int(conn.execute('SHOW server_version_num').fetchone()[0])//10000
        if os.name=='nt':
            candidates.append(Path(os.environ.get('ProgramFiles','C:/Program Files'))/'PostgreSQL'/str(version)/'bin')
        if found:
            candidates.append(Path(found).parent)
        for folder in candidates:
            suffix='.exe' if os.name=='nt' else ''
            if all((folder/(name+suffix)).is_file() for name in ('pg_dump','pg_restore')):
                probe=subprocess.run([str(folder/('pg_dump'+suffix)),'--version'],capture_output=True,text=True,timeout=5)
                match=re.search(r'(\d+)\.',probe.stdout)
                if probe.returncode==0 and match and int(match.group(1))==version:
                    return folder
    except Exception:
        pass
    return None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'viewer_config.local.py')
    parser.add_argument('--out',type=Path,default=ROOT/'validation/native_final_checks.json')
    parser.add_argument('--child',action='store_true')
    args=parser.parse_args(argv)
    if args.child:
        try:child(json.load(sys.stdin))
        except Exception as exc:
            print(json.dumps(safe_error(exc)),file=sys.stderr)
            return 2
    report=dict(status='RUNNING',mode='finite_native_synthetic_qualification',checks={},
        runtime_source_sha256=runtime_source_digest(ROOT),owner_viewer_database_written_by_runner=False,
        server_crash='NOT_RUN',owner_actual_backup_restore='NOT_RUN',capacity_800k_logical_requests_per_hour='NOT_RUN',
        financial='DEFERRED_BACKEND_LOGS_INCOMPLETE')
    directory=ROOT/'private/qualification_runs'/(datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
    directory.mkdir(parents=True,exist_ok=False)
    try:
        import psycopg
        spec=importlib.util.spec_from_file_location('viewer_native_existing_config',args.config.resolve())
        cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
        if getattr(cfg,'SQLITE_OFFLINE_PATH',None) or not str(cfg.DATABASE.get('dbname','')).startswith('p24_design_'):
            raise ValueError('existing_native_viewer_configuration_required')
        with psycopg.connect(**cfg.DATABASE,autocommit=True) as conn:
            conn.execute('SET default_transaction_read_only=on')
            report['server_version']=conn.execute('SHOW server_version').fetchone()[0]
        suite=Suite(cfg.DATABASE,directory,report,args.out)
        atomic_json(args.out,report)
        report['stage']='real_d5_readonly'
        keys=Path(cfg.KEYS_PATH).expanduser()
        if not keys.is_absolute():
            keys=ROOT/keys
        suite.record('real_d5_bidirectional_and_sql_witness',owner_d5_readonly(cfg.DATABASE,keys))
        from tools.qualify_viewer_postgres import qualify
        report['stage']='native_copy_sql'
        dialect=qualify(suite.create('sql'),directory/'sql_result.json')
        suite.record('native_copy_sql_and_preservation',dialect)
        report['stage']='reader_snapshot'
        suite.snapshot_reader()
        report['stage']='publisher_hard_cuts'
        opts,first,second=suite.hard_cuts()
        report['stage']='late_evidence'
        late_ok=suite.late_cases()
        report['stage']='synthetic_restore'
        suite.logical_restore(opts,first,second,pg_binaries(cfg.DATABASE))
        failed=any(x.get('status') in ('FAIL','FAILED') for x in report['checks'].values())
        pending=any(x.get('status')=='NOT_RUN' for x in report['checks'].values())
        report['status']=('FAIL' if failed or not late_ok else
            'QUICK_CHECKS_CONDITIONAL_FINAL_ACCEPTANCE_PENDING' if pending else 'QUICK_CHECKS_PASS_FINAL_ACCEPTANCE_PENDING')
        report['stage']='complete'
    except Exception as exc:
        (directory/'failure.private.log').write_text(traceback.format_exc(),encoding='utf-8')
        report.update(safe_error(exc));report['status']='FAILED'
    atomic_json(args.out,report)
    atomic_json(directory/'native_final_checks.json',report)
    bundle=args.out.with_name(args.out.stem+'_'+directory.name+'.zip')
    with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.write(args.out,'native_final_checks.json')
    print(json.dumps(dict(status=report['status'],output=str(bundle))))
    return 2 if report['status'] in ('FAILED','FAIL') else 0


if __name__=='__main__':
    raise SystemExit(main())
