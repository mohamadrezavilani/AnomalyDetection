"""Local native-PostgreSQL A/B: unmodified COPY vs strict server INSERT SELECT.

Only an already provisioned isolated p24_design_*_qualification database; creates
An owned, uniquely named LOGGED schema plus TEMP inputs. No production capture,
no checkpoint, no live secret output. The initial history is committed before
each measured trial, so target WAL and index maintenance are not bypassed.
No result from a small synthetic benchmark proves owner-host performance.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest

METHODS=('copy_binary','insert_select_ordered','insert_select_unordered')
TABLES=('viewer_events','viewer_links')


def _load(path):
    spec=importlib.util.spec_from_file_location('viewer_pg_benchmark_private',Path(path).resolve())
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    settings=dict(cfg.DATABASE)
    name=str(settings.get('dbname',''))
    if not (name.startswith('p24_design_') and name.endswith('_qualification')):
        raise ValueError('requires_isolated_p24_design_qualification_database')
    return settings


def _seed_query(table,kind,rows):
    # Synthetic content with reproducible 64-hex-character HMAC-shaped tokens;
    # IDs never belong to an actual customer or origin.
    ids="SELECT generate_series(1,%s) AS i"
    prefix='h' if kind=='history' else 'n'
    digest=lambda expr:"(md5("+expr+") || md5("+expr+"))"
    origin=digest("'"+prefix+"-origin-'||i::text")
    version=digest("'version-'||i::text")
    request=digest("'request-'||(i/5)::text")
    if table=='viewer_events':
        return ('''INSERT INTO bench_'''+kind+''' SELECT '''+origin+','+version+
                ", 'file', 'window', i, i::bigint, "+request+','+digest("'session-'||(i/10)::text")+
                ','+digest("'ip-'||(i/20)::text")+
                ", 'Services.v1/WaterBills Line:1', 'client', 'G00000', NULL FROM ("+ids+") AS n",(rows,))
    return ('''INSERT INTO bench_'''+kind+''' SELECT '''+origin+','+version+','+request+
            ", 'platform_payment', "+digest("'payment-'||(i/3)::text")+" FROM ("+ids+") AS n",(rows,))


def _compare(db,stage,dest,columns):
    # Full multiset equality (both directions) and row count. No sampled digest.
    a='SELECT '+columns+' FROM '+stage
    b='SELECT '+columns+' FROM '+dest
    result=db.one('SELECT (NOT EXISTS(('+a+' EXCEPT ALL '+b+') LIMIT 1) AND '
                  'NOT EXISTS(('+b+' EXCEPT ALL '+a+') LIMIT 1)) AS equal')
    return bool(result['equal'])


def benchmark(config,*,rows=5000,history=15000,pairs=3):
    settings=_load(config)
    if rows<1 or history<0 or not 1<=pairs<=10:raise ValueError('invalid_benchmark_bounds')
    report=dict(status='NOT_RUN',database_kind='qualification_only',
        rows_per_trial=rows,history_rows=history,pairs=pairs,
        runtime_source_sha256=runtime_source_digest(),production_modified=False,
        table_results={},target_persistence='permanent_logged',
        limitations=['Synthetic data; defaults are a microbenchmark, not owner-scale history',
            'A/B order is alternated; cache conditions can still differ',
            'WAL LSN deltas are cluster-wide, not exclusive to this connection'])
    with tempfile.TemporaryDirectory() as temp:
        key_path=Path(temp)/'synthetic_keys.json';generate_keys(key_path)
        with ViewerDB(config=settings,keys_path=key_path) as db:
            schema='p24_write_bench_'+uuid.uuid4().hex
            try:
                engine=db.one('SELECT version() AS v')['v']
                if 'PostgreSQL' not in engine or 'PGlite' in engine:raise ValueError('native_postgres_required')
                report['server_version']=db.one('SHOW server_version')['server_version']
                db.sql('CREATE SCHEMA '+schema)
                db.conn.commit()
                for table in TABLES:
                    if not db.one('SELECT to_regclass(?) AS obj',(table,))['obj']:
                        raise ValueError('qualification_schema_missing_'+table)
                    db.sql('CREATE TEMP TABLE bench_history (LIKE '+table+') ON COMMIT PRESERVE ROWS')
                    db.sql('CREATE TEMP TABLE bench_new (LIKE '+table+') ON COMMIT PRESERVE ROWS')
                    destination=schema+'.bench_dest'
                    db.sql('CREATE TABLE '+destination+' (LIKE '+table+' INCLUDING ALL)')
                    columns=ViewerDB._INGEST_INSERTS[table][0]
                    order=ViewerDB._INGEST_ORDER[table]
                    query,params=_seed_query(table,'history',history)
                    db.sql(query,params)
                    query,params=_seed_query(table,'new',rows)
                    db.sql(query,params)
                    result=[]
                    sequence=[METHODS if i%2==0 else tuple(reversed(METHODS)) for i in range(pairs)]
                    for pair,methods in enumerate(sequence,1):
                        for method in methods:
                            # Baseline history and its indexes are rebuilt identically.
                            # Commit before measurement: this is an existing,
                            # durable target, not a TEMP or new transaction table.
                            db.sql('TRUNCATE '+destination)
                            db.sql('INSERT INTO '+destination+' SELECT * FROM bench_history')
                            db.conn.commit()
                            before_wal=db.one('SELECT pg_current_wal_insert_lsn()::text AS lsn')['lsn']
                            events=[];db.progress_callback=lambda e:events.append(e)
                            started=time.monotonic()
                            if method=='copy_binary':
                                db._copy_ingest_stage_into_table('bench_new',destination,columns,order)
                            else:
                                db._insert_ingest_stage_into_table('bench_new',destination,columns,
                                    order if method=='insert_select_ordered' else None)
                            seconds=time.monotonic()-started
                            db.progress_callback=None
                            wal_bytes=db.one('SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),?::pg_lsn) AS n',
                                             (before_wal,))['n']
                            db.conn.commit()
                            equal=_compare(db,'bench_new',destination,columns) if history==0 else None
                            if history:
                                # Compare against a separate expected temp relation,
                                # including unchanged history and new rows.
                                db.sql('CREATE TEMP TABLE bench_expected (LIKE '+table+') ON COMMIT DROP')
                                db.sql('INSERT INTO bench_expected SELECT * FROM bench_history')
                                db.sql('INSERT INTO bench_expected SELECT * FROM bench_new')
                                equal=_compare(db,'bench_expected',destination,columns)
                                db.sql('DROP TABLE bench_expected')
                            result.append(dict(pair=pair,method=method,write_seconds=round(seconds,3),
                                cluster_wal_bytes=int(wal_bytes),
                                exact_multiset_equal=equal,copy_phases=[x for x in events
                                if x.get('stage','').startswith('ingest_bulk_copy')]))
                    db.sql('DROP TABLE bench_new,bench_history,'+destination)
                    report['table_results'][table]=result
                report['status']='PASS_SYNTHETIC_NATIVE' if all(
                    entry['exact_multiset_equal'] for trials in report['table_results'].values()
                    for entry in trials) else 'FAIL_MISMATCH'
            finally:
                db.conn.rollback()
                # Only the schema created by this invocation is removed.
                # Never truncate or drop the pre-existing Viewer schema.
                db.sql('DROP SCHEMA IF EXISTS '+schema+' CASCADE')
                db.conn.commit()
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--rows',type=int,default=5000)
    parser.add_argument('--history',type=int,default=15000)
    parser.add_argument('--pairs',type=int,default=3)
    args=parser.parse_args(argv)
    try:report=benchmark(args.config,rows=args.rows,history=args.history,pairs=args.pairs)
    except Exception as exc:
        report=dict(status='NOT_RUN',reason=type(exc).__name__,
                    detail=str(exc) if isinstance(exc,ValueError) else None,production_modified=False)
    atomic_json(args.out,report)
    print(json.dumps(dict(status=report['status'],output=str(args.out))))
    return 0 if report['status']=='PASS_SYNTHETIC_NATIVE' else 2

if __name__=='__main__':raise SystemExit(main())
