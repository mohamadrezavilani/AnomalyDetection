"""Read-only PostgreSQL/SQLite evidence audit for R5 N28/N29; no rebuild.

The runtime refuses PostgreSQL databases outside the p24_design_* namespace.
PowerShell: python tools/run_lc3b_readmodel.py --config viewer_config.local.py --out lc3b_readmodel_evidence.json
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from p24_foundation.lc3_readmodel_audit import audit


class ReadModelQueryError(RuntimeError):
    """Sanitized SQL error: no query text, arguments or database credentials."""
    def __init__(self, stage, source):
        self.stage = stage
        self.driver_error = type(source).__name__
        sqlstate = getattr(source, 'sqlstate', None)
        self.sqlstate = sqlstate if isinstance(sqlstate, str) and re.fullmatch(r'[0-9A-Z]{5}', sqlstate) else None
        super().__init__('readmodel_select_failed')


def _query_stage(query):
    if 'FROM viewer_events' in query:
        return 'event_provenance'
    if 'FROM viewer_files' in query:
        return 'source_window_provenance'
    if 'JOIN viewer_actions' in query:
        return 'cross_window_service_samples'
    if 'FROM viewer_requests' in query:
        return 'request_inventory'
    return 'readmodel_select'


class ReadOnlyDB:
    def __init__(self, conn, *, postgres=False):
        self.conn=conn
        self.postgres=postgres

    def all(self, query, args=()):
        if self.postgres:
            query=query.replace('?', '%s')
        try:
            rows=self.conn.execute(query,args).fetchall()
        except Exception as exc:
            raise ReadModelQueryError(_query_stage(query), exc) from None
        return [dict(row) for row in rows]

    def one(self, query, args=()):
        rows=self.all(query,args)
        return rows[0] if rows else None


def read_options(config):
    if not config.is_file():
        raise ValueError('viewer_config_missing')
    spec=importlib.util.spec_from_file_location('lc3b_local_viewer_config',config.resolve())
    if not spec or not spec.loader:
        raise ValueError('unloadable_viewer_config')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod,'SQLITE_OFFLINE_PATH',None):
        return 'sqlite', Path(mod.SQLITE_OFFLINE_PATH).expanduser().resolve()
    db=dict(mod.DATABASE)
    if not re.fullmatch(r'p24_design_[a-zA-Z0-9_]+',str(db.get('dbname',''))):
        raise ValueError('only_isolated_p24_design_database_allowed')
    return 'postgres',db


def execute_audit(config, *, sample_limit=5):
    kind, opts=read_options(Path(config))
    if kind=='sqlite':
        # mode=ro is enforced by SQLite, not merely a coding convention.
        conn=sqlite3.connect(opts.as_uri()+'?mode=ro',uri=True)
        conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        try:return audit(ReadOnlyDB(conn),sample_limit=sample_limit)
        finally:conn.close()
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(**opts,row_factory=dict_row) as conn:
        # Enforce read-only even if the viewer's database user is privileged.
        conn.read_only=True
        ro=conn.execute('SHOW transaction_read_only').fetchone()
        if str(ro['transaction_read_only']).lower() != 'on':
            raise RuntimeError('read_only_transaction_not_enforced')
        try:return audit(ReadOnlyDB(conn,postgres=True),sample_limit=sample_limit)
        finally:conn.rollback()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--sample-limit',type=int,default=5)
    args=parser.parse_args(argv)
    try:
        if args.sample_limit<0 or args.sample_limit>20:
            raise ValueError('sample_limit_must_be_between_0_and_20')
        result=execute_audit(args.config,sample_limit=args.sample_limit)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'output':str(args.out),'counts':result['counts'],
            'sampled_cross_window_service_requests':len(result['sampled_cross_window_service_requests']),
            'full_r5_end_to_end_accepted_cases':0, 'read_only':True},ensure_ascii=False))
        return 0
    except Exception as ex:
        # Do not print connection strings, passwords, SQL parameters, or raw logs.
        if isinstance(ex, ReadModelQueryError):
            details = (f' stage={ex.stage} driver={ex.driver_error}'
                       + (f' sqlstate={ex.sqlstate}' if ex.sqlstate else ''))
            print('LC3B_READMODEL_AUDIT_FAILED: ReadModelQueryError' + details, file=sys.stderr)
        else:
            print('LC3B_READMODEL_AUDIT_FAILED: ' + type(ex).__name__, file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
