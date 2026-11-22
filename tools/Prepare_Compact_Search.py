"""Build the bounded IP-value index online; do not restart workers or rewrite evidence."""
import argparse
import json
from pathlib import Path
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--code-root',type=Path,required=True)
    p.add_argument('--expected-source-sha',required=True)
    p.add_argument('--statement-timeout-seconds',type=int,default=900,
                   help='Bound each cleanup/build statement, including lock waits (30..3600).')
    a=p.parse_args();root=a.code_root.resolve();sys.path.insert(0,str(root))
    from compact_product.version import verify
    from compact_product.config import load
    from compact_behavior.store import Store,stream_lock
    from compact_product.search import prepare_index,index_state
    from compact_product.search_maintenance import configure_wait,ProgressMonitor
    if verify(root)['source_sha256']!=a.expected_source_sha:
        raise ValueError('PINNED_RELEASE_HASH_MISMATCH')
    cfg,source,stream=load(a.project)
    db=Store(source['DATABASE'],schema=cfg.source_schema,application='search-index-prepare')
    emit=lambda value: print(json.dumps(value),flush=True)
    monitor=None
    try:
        configure_wait(db.conn,a.statement_timeout_seconds)
        if not db.conn.execute('SELECT pg_try_advisory_lock(%s) AS acquired',
                (stream_lock(['compact-search-index',cfg.source_schema]),)).fetchone()['acquired']:
            raise ValueError('SEARCH_INDEX_PREPARATION_ALREADY_RUNNING')
        emit(dict(status='COMPACT_SEARCH_INDEX_STARTING',
                  statement_timeout_seconds=a.statement_timeout_seconds,
                  workers_restarted=False,data_reset=False))
        with ProgressMonitor(lambda: Store(source['DATABASE'],schema=cfg.source_schema,
                application='search-index-monitor'),db.conn.info.backend_pid,emit) as monitor:
            result=prepare_index(db.conn,cfg.source_schema,progress=monitor.set_stage)
        print(json.dumps(dict(status='COMPACT_SEARCH_INDEX_READY',index=result,workers_restarted=False,data_reset=False)),flush=True)
    except Exception as exc:
        state=None
        try:
            db.conn.execute('SET statement_timeout=3000')
            saved=index_state(db.conn,cfg.source_schema)
            state=dict(exists=saved is not None,valid=bool(saved and saved['indisvalid']),
                       ready=bool(saved and saved['indisready']))
        except Exception:pass
        print(json.dumps(dict(status='COMPACT_SEARCH_INDEX_INCOMPLETE',failure_type=type(exc).__name__,
            sqlstate=getattr(exc,'sqlstate',None),index=state,
            stage=monitor.stage if monitor else 'PREPARING',
            last_observation=monitor.last if monitor else None,
            workers_restarted=False,data_reset=False)),flush=True)
        return 2
    finally:db.close()
    return 0


if __name__=='__main__':raise SystemExit(main())
