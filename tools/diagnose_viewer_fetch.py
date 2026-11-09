"""Bounded old/new SQL reader probe; only connection-local temp tables change.

Stop the Viewer worker first. Uses existing published evidence, no ES capture,
ingestion, projection rebuild, checkpoint advance or permanent DDL/DML.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_contract import CONTRACT_PATTERNS
from p24_foundation.viewer_failure import describe_failure
from tools.run_viewer_pilot import PilotDeadline


def _digest(rows):
    value=hashlib.sha256()
    for row in rows:
        value.update(row['origin_key'].encode());value.update(row['version_key'].encode())
        value.update(bytes(row['payload']))
    return value.hexdigest()


def probe_readers(db,*,events=400,progress=None):
    """Caller commits its prepared temporary scope before entering."""
    result={};digests={};generations=[]
    for label in ('old','new'):
        start=time.monotonic();timings={}
        try:
            if progress:progress(dict(reader=label,events=events))
            db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            state=db.one('SELECT generation FROM viewer_live_state WHERE id=1')
            generations.append(state['generation'] if state else None)
            if label=='old':
                db.sql('SET LOCAL cursor_tuple_fraction=0.1')
                with db.conn.cursor(name='viewer_old_probe_'+uuid.uuid4().hex) as cursor:
                    cursor.execute(db._contract_read_query(scoped=True).replace('?',db.param),CONTRACT_PATTERNS)
                    rows=[dict(row) for row in cursor.fetchmany(events)]
            else:
                with db.contract_event_batches(scoped=True,timings=timings,prepared_scope=True) as batches:
                    rows=next(batches,[])[:events]
            digests[label]=_digest(rows)
            result[label]=dict(status='READ',rows=len(rows),seconds=round(time.monotonic()-start,3),
                stored_payload_bytes=sum(len(row['payload']) for row in rows),
                timings={k:round(v,3) if isinstance(v,float) else v for k,v in timings.items()})
        except Exception as exc:
            result[label]=dict(status='FAILED',seconds=round(time.monotonic()-start,3),failure=describe_failure(exc,stage=label+'_reader'))
        finally:db.conn.rollback()
    stable=len(generations)==2 and generations[0]==generations[1]
    equal=stable and len(digests)==2 and digests['old']==digests['new']
    status=('SOURCE_CHANGED' if not stable else 'READERS_MATCH' if equal and result['new']['rows'] else
            'EMPTY_SAMPLE' if equal else 'READER_MISMATCH' if len(digests)==2 and stable else
            'NEW_READER_MEASURED' if result.get('new',{}).get('rows') and 'old' not in digests else 'INCOMPLETE')
    return dict(status=status,readers=result,source_generation_unchanged=stable,
                first_batch_equal=equal if len(digests)==2 else None,
                permanent_viewer_data_modified=False,cache_controlled=False,
                operational_capacity='NOT_QUALIFIED_BY_READER_PROBE')


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--requests',type=int,default=17000)
    ap.add_argument('--events',type=int,default=400)
    ap.add_argument('--out',type=Path,default=Path('validation/viewer_sql_fetch.json'))
    args=ap.parse_args(argv)
    if not 1<=args.requests<=25000 or not 1<=args.events<=400:ap.error('Invalid bounded sample')
    spec=importlib.util.spec_from_file_location('viewer_fetch_probe_config',args.config.resolve())
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    if getattr(cfg,'SQLITE_OFFLINE_PATH',None):ap.error('This probe requires the existing PostgreSQL Viewer database')
    budget=PilotDeadline(60);budget.timer.start();report={}
    try:
        with ViewerDB(config=cfg.DATABASE,keys_path=Path(cfg.KEYS_PATH).resolve()) as db:
            budget.connection=db.conn;db.progress_callback=lambda event:budget.check()
            db.sql("SELECT set_config('statement_timeout', ?, false)",('20000',))
            # Only TEMP relations are created/modified in this setup transaction.
            # PostgreSQL forbids CREATE even for TEMP inside READ ONLY, so the
            # actual old/new probes each start a fresh READ ONLY transaction.
            db.sql('CREATE TEMP TABLE viewer_projection_scope(request_key TEXT PRIMARY KEY)')
            db.init_contract_candidate_scope()
            db.sql('INSERT INTO viewer_projection_scope SELECT request_key FROM viewer_requests ORDER BY COALESCE(root_ns,started_ns) DESC,request_key DESC LIMIT ?',(args.requests,))
            selected=db.one('SELECT COUNT(*) AS n FROM viewer_projection_scope')['n']
            db.conn.commit();budget.check()
            report=probe_readers(db,events=args.events,progress=lambda event:print(json.dumps(dict(progress=event)),flush=True))
            report.update(mode='owner_postgresql_scoped_reader_probe',scope_requests=selected,worker_backend_pid=db.conn.info.backend_pid)
            budget.check()
    except Exception as exc:
        report.update(status='FAILED',failure=describe_failure(exc,stage='reader_probe'))
        if budget.expired.is_set():report['failure']['code']='probe_time_budget_exceeded'
    finally:
        budget.connection=None;budget.timer.cancel()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],output=str(args.out))))
    return 0 if report['status'] in ('READERS_MATCH','NEW_READER_MEASURED') else 2


if __name__=='__main__':raise SystemExit(main())
