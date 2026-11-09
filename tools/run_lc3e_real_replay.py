"""Read-only PostgreSQL → bounded isolated SQLite replay of REAL Viewer events.

Never writes to the isolated PostgreSQL database or operational DB. Real raw
payloads are privately replayed under auto-deleted TemporaryDirectory files;
only privacy-safe aggregate statistics and digests appear in the output.
"""
from __future__ import annotations
import argparse,importlib.util,json,re,sqlite3,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from p24_foundation.lc3_real_subset_replay import replay_real_readmodel_subset
from tools.run_lc3b_readmodel import ReadOnlyDB,ReadModelQueryError,read_options


def _local_keys_path(config):
    spec=importlib.util.spec_from_file_location('lc3e_config',config.resolve())
    if spec is None or spec.loader is None:raise ValueError('unreadable_local_config')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    p=Path(mod.KEYS_PATH).expanduser()
    return p if p.is_absolute() else config.parent/p


def execute(config, *, sample_limit=2):
    config=Path(config)
    kind,options=read_options(config)
    keys_path=_local_keys_path(config)
    if kind=='sqlite':
        conn=sqlite3.connect(options.as_uri()+'?mode=ro',uri=True)
        conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        try:return replay_real_readmodel_subset(ReadOnlyDB(conn),keys_path=keys_path,sample_limit=sample_limit)
        finally:conn.close()
    import psycopg
    from psycopg.rows import dict_row
    from psycopg import IsolationLevel
    with psycopg.connect(**options,row_factory=dict_row) as conn:
        conn.isolation_level=IsolationLevel.REPEATABLE_READ
        conn.read_only=True
        mode=conn.execute('SHOW transaction_read_only').fetchone()
        if str(mode['transaction_read_only']).lower()!='on':
            raise RuntimeError('read_only_transaction_not_enforced')
        try:return replay_real_readmodel_subset(ReadOnlyDB(conn,postgres=True),keys_path=keys_path,sample_limit=sample_limit)
        finally:conn.rollback()


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--sample-limit',type=int,default=2)
    args=p.parse_args(argv)
    try:
        result=execute(args.config,sample_limit=args.sample_limit)
        args.out.parent.mkdir(exist_ok=True,parents=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
        print(json.dumps({'output':str(args.out),'status':result['status'],
               'replayed_requests':result['replayable_requests'],
               'order_independent':result.get('order_independent_derived_snapshot'),
               'source_projection_matches':result.get('selected_request_projection_matches_source'),
               'full_r5_acceptance':0,'read_only':True},ensure_ascii=False))
        return 0 if result['status']=='COMPLETED' and result['order_independent_derived_snapshot'] and result['repeat_import_idempotent'] and result['selected_request_projection_matches_source'] and result['selected_evidence_projection_matches_source'] else 3
    except Exception as exc:
        # Don't leak private tokens, path, raw payload, credentials or SQL.
        if isinstance(exc,ReadModelQueryError):
            print('LC3E_REPLAY_FAILED: ReadModelQueryError'+ (' sqlstate='+exc.sqlstate if exc.sqlstate else ''),file=sys.stderr)
        else:
            print('LC3E_REPLAY_FAILED: '+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
