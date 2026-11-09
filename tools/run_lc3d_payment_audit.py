"""LC3D strictly read-only payment evidence and provenance audit.

Uses only an isolated p24_design_* Viewer database (or SQLITE_OFFLINE_PATH).
Does not query operational databases, ingest raw logs, rebuild or modify state.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from p24_foundation.lc3_payment_integrity_audit import audit_payment_evidence
from tools.run_lc3b_readmodel import ReadModelQueryError, ReadOnlyDB, read_options


def execute_audit(config,*,sample_limit=8):
    kind,options=read_options(Path(config))
    if kind=='sqlite':
        conn=sqlite3.connect(options.as_uri()+'?mode=ro',uri=True)
        conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        try:return audit_payment_evidence(ReadOnlyDB(conn),sample_limit=sample_limit)
        finally:conn.close()
    import psycopg
    from psycopg.rows import dict_row
    from psycopg import IsolationLevel
    with psycopg.connect(**options,row_factory=dict_row) as conn:
        # Configure before the first SELECT, then ensure read-only transaction.
        conn.isolation_level=IsolationLevel.REPEATABLE_READ
        conn.read_only=True
        ro=conn.execute('SHOW transaction_read_only').fetchone()
        if str(ro['transaction_read_only']).lower()!='on':
            raise RuntimeError('read_only_transaction_not_enforced')
        try:return audit_payment_evidence(ReadOnlyDB(conn,postgres=True),sample_limit=sample_limit)
        finally:conn.rollback()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--sample-limit',type=int,default=8)
    args=parser.parse_args(argv)
    try:
        result=execute_audit(args.config,sample_limit=args.sample_limit)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'output':str(args.out),'read_only':True,
            'identifier_kinds':len(result['inventory']['identifier_kinds']),
            'relation_groups':len(result['inventory']['relation_evidence']),
            'status_axes':len(result['inventory']['independent_status_axes']),
            'provenance_consistent':result['evidence_integrity']['all_checked_references_consistent'],
            'fully_accepted_end_to_end_cases':0},ensure_ascii=False))
        return 0
    except Exception as exc:
        # Never print SQL, connection details, raw values, file path or payload.
        if isinstance(exc,ReadModelQueryError):
            state=f' sqlstate={exc.sqlstate}' if exc.sqlstate else ''
            print('LC3D_AUDIT_FAILED: ReadModelQueryError'+state,file=sys.stderr)
        else:
            print('LC3D_AUDIT_FAILED: '+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
