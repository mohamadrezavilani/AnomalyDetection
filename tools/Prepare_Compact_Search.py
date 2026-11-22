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
    a=p.parse_args();root=a.code_root.resolve();sys.path.insert(0,str(root))
    from compact_product.version import verify
    from compact_product.config import load
    from compact_behavior.store import Store,stream_lock
    from compact_product.search import prepare_index
    if verify(root)['source_sha256']!=a.expected_source_sha:
        raise ValueError('PINNED_RELEASE_HASH_MISMATCH')
    cfg,source,stream=load(a.project)
    db=Store(source['DATABASE'],schema=cfg.source_schema,application='search-index-prepare')
    try:
        db.conn.execute('SET statement_timeout=900000')
        db.conn.execute('SET lock_timeout=5000')
        if not db.conn.execute('SELECT pg_try_advisory_lock(%s) AS acquired',
                (stream_lock(['compact-search-index',cfg.source_schema]),)).fetchone()['acquired']:
            raise ValueError('SEARCH_INDEX_PREPARATION_ALREADY_RUNNING')
        result=prepare_index(db.conn,cfg.source_schema)
        print(json.dumps(dict(status='COMPACT_SEARCH_INDEX_READY',index=result,workers_restarted=False,data_reset=False)),flush=True)
    except Exception as exc:
        print(json.dumps(dict(status='COMPACT_SEARCH_INDEX_INCOMPLETE',failure_type=type(exc).__name__,
            sqlstate=getattr(exc,'sqlstate',None),workers_restarted=False,data_reset=False)),flush=True)
        return 2
    finally:db.close()
    return 0


if __name__=='__main__':raise SystemExit(main())
