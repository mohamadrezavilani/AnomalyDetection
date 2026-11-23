"""Prepare the sparse role index used by the existing unknown page, online."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from psycopg import ClientCursor, sql
from compact_behavior.store import Store, stream_lock
from compact_product.config import load
from compact_product.search import unknown_scope
from compact_product.search_maintenance import configure_wait, ProgressMonitor


def index_spec(conn):
    predicate, args = unknown_scope()
    key = hashlib.sha256(json.dumps([predicate, args]).encode()).hexdigest()[:16]
    with ClientCursor(conn) as cur:
        where = cur.mogrify(predicate, args)
    return 'compact_unknown_' + key, sql.SQL(where)


def state(conn, schema, name):
    return conn.execute("""SELECT i.indisvalid, i.indisready, i.indisunique,
        i.indoption::text AS options, am.amname, t.relname, n.nspname,
        ARRAY(SELECT pg_get_indexdef(i.indexrelid,k,true)
              FROM generate_series(1,i.indnatts) k) AS keys,
        pg_get_expr(i.indpred,i.indrelid) AS predicate
        FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
        JOIN pg_am am ON am.oid=idx.relam JOIN pg_class t ON t.oid=i.indrelid
        JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE i.indexrelid=to_regclass(%s)""", (schema + '.' + name,)).fetchone()


def prepare(conn, schema, progress):
    name, where = index_spec(conn)
    keys = ['stream_id', 'observed_at_ns', 'behavior_id']
    table = sql.Identifier(schema, 'behaviors')
    create = sql.SQL('CREATE INDEX {} {} ON {} (stream_id,observed_at_ns,behavior_id) WHERE {}')
    # Compare the server's normalized predicate before claiming or repairing an
    # existing object. The scratch table is empty and private to this connection.
    with conn.transaction():
        conn.execute('CREATE TEMP TABLE unknown_role_shape (stream_id text,observed_at_ns bigint,'
                     'behavior_id text,api text,result_code text,features jsonb) ON COMMIT DROP')
        conn.execute(create.format(sql.SQL(''), sql.Identifier('unknown_role_expected'),
                                   sql.Identifier('pg_temp','unknown_role_shape'), where))
        expected = state(conn, 'pg_temp', 'unknown_role_expected')['predicate']

    def verify(saved):
        if not saved or (saved['nspname'], saved['relname'], saved['amname'], saved['keys'],
                saved['options'], saved['indisunique'], saved['predicate']) != (
                schema, 'behaviors', 'btree', keys, '0 0 0', False, expected):
            raise ValueError('UNKNOWN_INDEX_DEFINITION_MISMATCH')

    saved = state(conn, schema, name)
    if saved:
        verify(saved)
        if saved['indisvalid'] and saved['indisready']:
            return 'ALREADY_READY'
        progress('REMOVING_INVALID_OWNED_INDEX')
        conn.execute(sql.SQL('DROP INDEX CONCURRENTLY {}').format(sql.Identifier(schema, name)))
    progress('BUILDING_SPARSE_INDEX_CONCURRENTLY')
    conn.execute(create.format(sql.SQL('CONCURRENTLY'), sql.Identifier(name), table, where))
    saved = state(conn, schema, name)
    verify(saved)
    if not saved['indisvalid'] or not saved['indisready']:
        raise ValueError('UNKNOWN_INDEX_NOT_READY')
    return 'CREATED'


def page_probe(port):
    began = time.monotonic()
    try:
        with urlopen(f'http://127.0.0.1:{int(port)}/?scope=unknown', timeout=10) as response:
            code = response.status
            body = response.read(1024 * 1024)
            valid = code == 200 and 'behavior-table' in body.decode('utf-8', 'replace')
    except (HTTPError, URLError, OSError) as exc:
        code = getattr(exc, 'code', None)
        valid = False
    return dict(http_status=code, page_rendered=valid, seconds=round(time.monotonic()-began, 2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--statement-timeout-seconds', type=int, default=3600)
    args = parser.parse_args()
    cfg, source, _ = load(args.project)
    def connect(label):
        return Store(source['DATABASE'], schema=cfg.source_schema, application=label)
    def emit(value):
        print(json.dumps(value), flush=True)
    emit(dict(status='CHECKING_UNKNOWN_PAGE', before=page_probe(cfg.web_ports[0])))
    db = connect('unknown-role-index')
    try:
        configure_wait(db.conn, args.statement_timeout_seconds)
        if not db.conn.execute('SELECT pg_try_advisory_lock(%s) AS ok',
                (stream_lock(['unknown-role-index', cfg.source_schema]),)).fetchone()['ok']:
            raise ValueError('UNKNOWN_INDEX_PREPARATION_ALREADY_RUNNING')
        with ProgressMonitor(lambda: connect('unknown-index-progress'), db.conn.info.backend_pid, emit) as monitor:
            result = prepare(db.conn, cfg.source_schema, monitor.set_stage)
        after = page_probe(cfg.web_ports[0])
        emit(dict(status='UNKNOWN_PAGE_VERIFIED' if after['page_rendered'] else 'UNKNOWN_PAGE_REQUIRES_DIAGNOSIS',
                  index=result, after=after, workers_restarted=False))
        return 0 if after['page_rendered'] else 2
    except Exception as exc:
        emit(dict(status='UNKNOWN_INDEX_INCOMPLETE', failure_type=type(exc).__name__,
                  code=str(exc) if type(exc) is ValueError else None, sqlstate=getattr(exc,'sqlstate',None)))
        return 2
    finally:
        db.close()


if __name__ == '__main__':
    raise SystemExit(main())
